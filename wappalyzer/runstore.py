import errno
import hashlib
import json
import os
import sqlite3
import stat
import time
import uuid
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any, BinaryIO, Dict, Iterator, Optional, Sequence, Tuple

try:
    import fcntl
except ImportError:  # pragma: no cover - the production CLI currently targets POSIX.
    fcntl = None  # type: ignore[assignment]

from wappalyzer.models import (
    PROTOCOL_ORDER,
    CanonicalRecord,
    ClaimToken,
    Endpoint,
    EventKind,
    EvidenceLimit,
    EvidenceTruncation,
    Failure,
    FailureCode,
    FailureDisposition,
    OccurrenceStatus,
    Protocol,
    ProtocolObservation,
    ProtocolResult,
    ProtocolStatus,
    ResponseIdentity,
    RunEvent,
    RunLifecycle,
    RunSpec,
    RunStatus,
    StageName,
    StageResult,
    StageStatus,
    StaleClaimError,
    TargetOccurrence,
    Technology,
    TLSMetadata,
    TLSTrust,
    aggregate_occurrence_status,
    canonical_json_bytes,
)
from wappalyzer.models import (
    _protocol_document as _canonical_protocol_document,
)
from wappalyzer.targets import TargetFileSummary, ingest_targets

LEDGER_SCHEMA_VERSION = 1

_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_SQLITE_TIMEOUT_SECONDS = 5.0
_BUSY_TIMEOUT_MILLISECONDS = 5000
_WAL_AUTOCHECKPOINT_PAGES = 1000
_HASH_CHUNK_BYTES = 64 * 1024
_VERIFY_RESULT_CACHE_SIZE = 256
_PROTOCOL_RANK = {protocol: index for index, protocol in enumerate(PROTOCOL_ORDER)}

_SCHEMA = """
CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE endpoint_work (
    endpoint_id INTEGER PRIMARY KEY,
    address TEXT NOT NULL,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    state TEXT NOT NULL CHECK (state IN ('pending', 'claimed', 'terminal')),
    claim_epoch INTEGER,
    attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    UNIQUE (address, port),
    CHECK (
        (state = 'claimed' AND claim_epoch IS NOT NULL)
        OR (state <> 'claimed' AND claim_epoch IS NULL)
    )
);

CREATE INDEX endpoint_work_state_endpoint_id ON endpoint_work(state, endpoint_id);

CREATE TABLE occurrences (
    sequence INTEGER PRIMARY KEY CHECK (sequence >= 0),
    line_number INTEGER NOT NULL CHECK (line_number >= 1),
    byte_offset INTEGER NOT NULL CHECK (byte_offset >= 0),
    line_digest TEXT NOT NULL,
    address TEXT,
    port INTEGER,
    endpoint_id INTEGER REFERENCES endpoint_work(endpoint_id),
    terminal INTEGER NOT NULL DEFAULT 0 CHECK (terminal IN (0, 1)),
    status TEXT,
    UNIQUE (line_number, byte_offset),
    CHECK (
        (endpoint_id IS NULL AND address IS NULL AND port IS NULL)
        OR (endpoint_id IS NOT NULL AND address IS NOT NULL AND port IS NOT NULL)
    ),
    CHECK (
        (terminal = 0 AND status IS NULL)
        OR (terminal = 1 AND status IS NOT NULL)
    )
);

CREATE INDEX occurrences_endpoint_id ON occurrences(endpoint_id);

CREATE TABLE endpoint_results (
    endpoint_id INTEGER PRIMARY KEY REFERENCES endpoint_work(endpoint_id),
    payload BLOB NOT NULL,
    payload_sha256 TEXT NOT NULL
);

CREATE TABLE occurrence_outbox (
    occurrence_sequence INTEGER PRIMARY KEY
        REFERENCES occurrences(sequence),
    payload BLOB NOT NULL,
    byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
    payload_sha256 TEXT NOT NULL,
    output_offset INTEGER CHECK (output_offset >= 0),
    prefix_sha256 TEXT,
    CHECK (
        (output_offset IS NULL AND prefix_sha256 IS NULL)
        OR (output_offset IS NOT NULL AND prefix_sha256 IS NOT NULL)
    )
);

CREATE TABLE outbox_frontier (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    next_sequence INTEGER NOT NULL CHECK (next_sequence >= 0),
    byte_offset INTEGER NOT NULL CHECK (byte_offset >= 0),
    prefix_sha256 TEXT NOT NULL
);

CREATE TABLE projection_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    next_sequence INTEGER NOT NULL CHECK (next_sequence >= 0),
    byte_offset INTEGER NOT NULL CHECK (byte_offset >= 0),
    prefix_sha256 TEXT NOT NULL
);

CREATE TABLE run_events (
    sequence INTEGER PRIMARY KEY CHECK (sequence >= 0),
    kind TEXT NOT NULL,
    epoch INTEGER NOT NULL CHECK (epoch >= 0),
    status TEXT NOT NULL,
    timestamp_ns INTEGER NOT NULL CHECK (timestamp_ns >= 0),
    failure_code TEXT,
    failure_disposition TEXT,
    CHECK (
        (failure_code IS NULL AND failure_disposition IS NULL)
        OR (failure_code IS NOT NULL AND failure_disposition IS NOT NULL)
    )
);
"""


class RunStoreError(RuntimeError):
    """Base class for durable run-store failures."""


class ArtifactSafetyError(RunStoreError):
    """Raised when an artifact path cannot be used without following aliases."""


class RunSpecMismatchError(RunStoreError):
    """Raised when an existing ledger belongs to a different semantic run."""


class IngestionStateError(RunStoreError):
    """Raised when ingestion is requested more than once."""


class SourceChangedError(RunStoreError):
    """Raised when the source identity or contents changed between passes."""


class RunStateError(RunStoreError):
    """Raised when an operation is invalid for the persisted run state."""


class CompletionPreconditionError(RunStateError):
    """Raised when a forward lifecycle boundary is not durably satisfied."""


class GenerationLockedError(RunStoreError):
    """Raised when another owner holds a generation's kernel lock."""


class LedgerIntegrityError(RunStoreError):
    """Raised when persisted ledger facts do not reconcile."""


@dataclass(frozen=True)
class SQLiteSettings:
    journal_mode: str
    foreign_keys: bool
    synchronous: str


@dataclass(frozen=True)
class RunCounts:
    occurrences: int
    endpoint_work: int
    terminal_occurrences: int
    pending_endpoints: int
    active_claims: int
    occurrence_outbox: int
    operational_events: int


@dataclass(frozen=True)
class EndpointClaim:
    endpoint_id: int
    endpoint: Endpoint
    token: ClaimToken


@dataclass(frozen=True)
class OccurrenceOutboxEntry:
    occurrence_sequence: int
    payload: bytes
    byte_length: int
    payload_sha256: str
    output_offset: Optional[int]
    prefix_sha256: Optional[str]


@dataclass(frozen=True)
class ProjectionState:
    next_sequence: int
    byte_offset: int
    prefix_sha256: str


@dataclass(frozen=True)
class _SourceIdentity:
    path: str
    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclass
class _OutboxHashCache:
    next_sequence: int
    byte_offset: int
    hasher: Any


def _canonical_json(document: object) -> str:
    return json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _serialize_run_spec(spec: RunSpec) -> str:
    if not isinstance(spec, RunSpec):
        raise TypeError("spec must be a RunSpec")
    return _canonical_json(asdict(spec))


def _deserialize_run_spec(payload: str) -> RunSpec:
    try:
        document = json.loads(payload)
    except (TypeError, json.JSONDecodeError) as error:
        raise LedgerIntegrityError("run specification is not valid JSON") from error
    expected_keys = {field.name for field in fields(RunSpec)}
    if not isinstance(document, dict) or set(document) != expected_keys:
        raise LedgerIntegrityError("run specification fields do not match this ledger version")
    try:
        spec = RunSpec(**document)
    except (TypeError, ValueError) as error:
        raise LedgerIntegrityError("run specification is invalid") from error
    if _serialize_run_spec(spec) != payload:
        raise LedgerIntegrityError("run specification is not canonically serialized")
    return spec


def _summary_document(summary: TargetFileSummary) -> Dict[str, object]:
    return asdict(summary)


def _deserialize_summary(payload: str) -> TargetFileSummary:
    try:
        document = json.loads(payload)
        summary = TargetFileSummary(**document)
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise LedgerIntegrityError("target source summary is invalid") from error
    if _canonical_json(_summary_document(summary)) != payload:
        raise LedgerIntegrityError("target source summary is not canonical")
    return summary


def _identity_from_stat(path: Path, value: os.stat_result) -> _SourceIdentity:
    return _SourceIdentity(
        path=str(path.absolute()),
        device=value.st_dev,
        inode=value.st_ino,
        size=value.st_size,
        mtime_ns=value.st_mtime_ns,
        ctime_ns=value.st_ctime_ns,
    )


def _deserialize_identity(payload: str) -> _SourceIdentity:
    try:
        document = json.loads(payload)
        identity = _SourceIdentity(**document)
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise LedgerIntegrityError("target source identity is invalid") from error
    if _canonical_json(asdict(identity)) != payload:
        raise LedgerIntegrityError("target source identity is not canonical")
    return identity


def _identity_matches(
    expected: _SourceIdentity,
    path: Path,
    value: os.stat_result,
) -> bool:
    return expected == _identity_from_stat(path, value)


def _protocol_document(result: ProtocolResult) -> Dict[str, object]:
    document = _canonical_protocol_document(result)
    document["tls"]["certificate_sha256"] = result.tls.certificate_sha256
    return document


def _protocol_from_document(document: object) -> ProtocolResult:
    if not isinstance(document, dict):
        raise LedgerIntegrityError("protocol result is not an object")
    try:
        tls_document = document["tls"]
        if not isinstance(tls_document, dict):
            raise TypeError("TLS metadata must be an object")
        tls = TLSMetadata(
            present=tls_document["present"],
            trust=TLSTrust(tls_document["trust"]),
            certificate_sha256=tls_document.get("certificate_sha256"),
        )
        stages_document = document["stages"]
        technologies_document = document["technologies"]
        if not isinstance(stages_document, list) or not isinstance(technologies_document, list):
            raise TypeError("protocol result collections must be arrays")

        def technology_from_document(technology):
            return Technology(
                name=technology["name"],
                version=technology["version"],
                confidence=technology["confidence"],
                categories=tuple(technology["categories"]),
                groups=tuple(technology["groups"]),
            )

        stages = []
        for stage in stages_document:
            identity_document = stage.get("response_identity")
            identity = (
                ResponseIdentity(
                    effective_url=identity_document["effective_url"],
                    http_status=identity_document["http_status"],
                    content_sha256=identity_document["content_sha256"],
                )
                if identity_document is not None
                else None
            )
            stages.append(
                StageResult(
                    name=StageName(stage["name"]),
                    status=StageStatus(stage["status"]),
                    error_codes=tuple(FailureCode(code) for code in stage["error_codes"]),
                    response_identity=identity,
                    technologies=tuple(
                        technology_from_document(technology)
                        for technology in stage.get("technologies", ())
                    ),
                    truncations=tuple(
                        EvidenceTruncation(
                            channel=truncation["channel"],
                            limits=tuple(EvidenceLimit(limit) for limit in truncation["limits"]),
                        )
                        for truncation in stage.get("truncations", ())
                    ),
                )
            )
        technologies = tuple(
            technology_from_document(technology) for technology in technologies_document
        )
        return ProtocolResult(
            protocol=Protocol(document["protocol"]),
            status=ProtocolStatus(document["status"]),
            requested_url=document["requested_url"],
            effective_url=document["effective_url"],
            http_status=document["http_status"],
            tls=tls,
            observation=ProtocolObservation(
                document.get("observation", ProtocolObservation.SINGLE.value)
            ),
            stages=tuple(stages),
            technologies=technologies,
            error_codes=tuple(FailureCode(code) for code in document["error_codes"]),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise LedgerIntegrityError("protocol result payload is invalid") from error


def _serialize_protocols(results: Sequence[ProtocolResult]) -> bytes:
    ordered = tuple(sorted(results, key=lambda item: _PROTOCOL_RANK[item.protocol]))
    return _canonical_json([_protocol_document(result) for result in ordered]).encode("utf-8")


def _deserialize_protocols(payload: bytes) -> Tuple[ProtocolResult, ...]:
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LedgerIntegrityError("endpoint result is not valid UTF-8 JSON") from error
    if not isinstance(document, list):
        raise LedgerIntegrityError("endpoint result payload is not an array")
    results = tuple(_protocol_from_document(item) for item in document)
    if len({result.protocol for result in results}) != len(results):
        raise LedgerIntegrityError("endpoint result contains duplicate protocols")
    if _serialize_protocols(results) != payload:
        raise LedgerIntegrityError("endpoint result is not canonically serialized")
    return results


def _occurrence_errors(results: Sequence[ProtocolResult]) -> Tuple[FailureCode, ...]:
    present = {
        code
        for result in results
        for code in tuple(result.error_codes)
        + tuple(code for stage in result.stages for code in stage.error_codes)
    }
    return tuple(code for code in FailureCode if code in present)


def _require_private_directory(path: Path, create: bool) -> None:
    try:
        value = path.lstat()
    except FileNotFoundError:
        if not create:
            raise ArtifactSafetyError(f"artifact directory does not exist: {path}")
        path.mkdir(parents=True, mode=0o700)
        value = path.lstat()
    if stat.S_ISLNK(value.st_mode) or not stat.S_ISDIR(value.st_mode):
        raise ArtifactSafetyError(f"artifact directory is not a real directory: {path}")
    os.chmod(str(path), 0o700)


def _assert_regular_private_file(path: Path) -> os.stat_result:
    try:
        value = path.lstat()
    except FileNotFoundError as error:
        raise ArtifactSafetyError(f"artifact does not exist: {path}") from error
    if stat.S_ISLNK(value.st_mode) or not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
        raise ArtifactSafetyError(f"artifact is not an unaliased regular file: {path}")
    os.chmod(str(path), 0o600)
    return value


def _stream_sha256(stream: BinaryIO) -> Tuple[int, str]:
    hasher = hashlib.sha256()
    byte_count = 0
    while True:
        chunk = stream.read(_HASH_CHUNK_BYTES)
        if not chunk:
            break
        byte_count += len(chunk)
        hasher.update(chunk)
    return byte_count, hasher.hexdigest()


def _create_private_file(path: Path) -> None:
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(str(path), flags, 0o600)
    except FileExistsError as error:
        raise ArtifactSafetyError(f"artifact already exists: {path}") from error
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.EMLINK}:
            raise ArtifactSafetyError(f"unsafe artifact path: {path}") from error
        raise
    try:
        value = os.fstat(descriptor)
        if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
            raise ArtifactSafetyError(f"artifact is not a private regular file: {path}")
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)


def _file_sha256(path: Path) -> Tuple[int, str]:
    _assert_regular_private_file(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(str(path), flags)
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            return _stream_sha256(stream)
    finally:
        os.close(descriptor)


@contextmanager
def _transaction(connection: sqlite3.Connection) -> Iterator[None]:
    connection.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()


class RunStore:
    """SQLite authority for one immutable scan-run generation."""

    LEDGER_FILENAME = "run.sqlite3"
    CANONICAL_FILENAME = "canonical.ndjson"
    MANIFEST_FILENAME = "manifest.json"
    LOCK_FILENAME = "generation.lock"

    def __init__(
        self,
        generation_path: Path,
        connection: sqlite3.Connection,
        settings: SQLiteSettings,
        run_id: str,
        spec: RunSpec,
    ) -> None:
        self.generation_path = generation_path
        self.ledger_path = generation_path / self.LEDGER_FILENAME
        self._connection = connection
        self._sqlite_settings = settings
        self._run_id = run_id
        self._run_spec = spec
        self._closed = False
        self._outbox_cache: Optional[_OutboxHashCache] = None

    @classmethod
    def create(
        cls,
        generation_path: os.PathLike,
        run_id: str,
        spec: RunSpec,
    ) -> "RunStore":
        if not isinstance(run_id, str) or not run_id:
            raise ValueError("run_id must be a non-empty string")
        serialized_spec = _serialize_run_spec(spec)
        generation = Path(generation_path)
        _require_private_directory(generation, create=True)
        ledger_path = generation / cls.LEDGER_FILENAME
        _create_private_file(ledger_path)
        connection: Optional[sqlite3.Connection] = None
        try:
            connection, settings = cls._connect(ledger_path)
            connection.executescript(_SCHEMA)
            with _transaction(connection):
                metadata = {
                    "schema_version": str(LEDGER_SCHEMA_VERSION),
                    "run_id": run_id,
                    "run_spec": serialized_spec,
                    "status": RunStatus.INGESTING.value,
                    "epoch": "0",
                    "resume_status": "",
                    "ingested": "0",
                    "source_verified": "0",
                    "source_identity": "",
                    "source_summary": "",
                    "workers_closed": "0",
                    "data_revision": "0",
                    "reconciled_revision": "-1",
                    "reconciled_counts": "",
                    "manifest_sha256": "",
                    "manifest_byte_count": "",
                }
                connection.executemany(
                    "INSERT INTO metadata(key, value) VALUES (?, ?)",
                    tuple(metadata.items()),
                )
                connection.execute(
                    """
                    INSERT INTO outbox_frontier(
                        singleton, next_sequence, byte_offset, prefix_sha256
                    ) VALUES (1, 0, 0, ?)
                    """,
                    (_EMPTY_SHA256,),
                )
                connection.execute(
                    """
                    INSERT INTO projection_state(
                        singleton, next_sequence, byte_offset, prefix_sha256
                    ) VALUES (1, 0, 0, ?)
                    """,
                    (_EMPTY_SHA256,),
                )
                cls._insert_event(
                    connection,
                    EventKind.RUN_TRANSITION,
                    RunLifecycle(status=RunStatus.INGESTING, epoch=0),
                )
            _assert_regular_private_file(ledger_path)
            return cls(generation, connection, settings, run_id, spec)
        except BaseException:
            if connection is not None:
                connection.close()
            raise

    @classmethod
    def open(
        cls,
        generation_path: os.PathLike,
        expected_spec: Optional[RunSpec] = None,
    ) -> "RunStore":
        generation = Path(generation_path)
        _require_private_directory(generation, create=False)
        ledger_path = generation / cls.LEDGER_FILENAME
        _assert_regular_private_file(ledger_path)
        connection: Optional[sqlite3.Connection] = None
        try:
            connection, settings = cls._connect(ledger_path)
            metadata = {
                row["key"]: row["value"]
                for row in connection.execute("SELECT key, value FROM metadata")
            }
            required = {
                "schema_version",
                "run_id",
                "run_spec",
                "status",
                "epoch",
            }
            if not required.issubset(metadata):
                raise LedgerIntegrityError("ledger metadata is incomplete")
            try:
                schema_version = int(metadata["schema_version"])
            except ValueError as error:
                raise LedgerIntegrityError("ledger schema version is invalid") from error
            if schema_version != LEDGER_SCHEMA_VERSION:
                raise LedgerIntegrityError(f"unsupported ledger schema version: {schema_version}")
            spec = _deserialize_run_spec(metadata["run_spec"])
            if expected_spec is not None:
                serialized_expected = _serialize_run_spec(expected_spec)
                if serialized_expected != metadata["run_spec"]:
                    raise RunSpecMismatchError(
                        "existing generation has a different semantic run specification"
                    )
            run_id = metadata["run_id"]
            if not run_id:
                raise LedgerIntegrityError("ledger run ID is empty")
            RunStatus(metadata["status"])
            int(metadata["epoch"])
            foreign_key_failure = connection.execute("PRAGMA foreign_key_check").fetchone()
            if foreign_key_failure is not None:
                raise LedgerIntegrityError("ledger foreign-key integrity check failed")
            return cls(generation, connection, settings, run_id, spec)
        except BaseException:
            if connection is not None:
                connection.close()
            raise

    @staticmethod
    def _connect(
        ledger_path: Path,
    ) -> Tuple[sqlite3.Connection, SQLiteSettings]:
        connection = sqlite3.connect(
            str(ledger_path),
            timeout=_SQLITE_TIMEOUT_SECONDS,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MILLISECONDS}")
        connection.execute("PRAGMA foreign_keys=ON")
        journal_mode = str(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]).lower()
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute(f"PRAGMA wal_autocheckpoint={_WAL_AUTOCHECKPOINT_PAGES}")
        foreign_keys = bool(connection.execute("PRAGMA foreign_keys").fetchone()[0])
        synchronous_value = int(connection.execute("PRAGMA synchronous").fetchone()[0])
        synchronous_names = {0: "off", 1: "normal", 2: "full", 3: "extra"}
        settings = SQLiteSettings(
            journal_mode=journal_mode,
            foreign_keys=foreign_keys,
            synchronous=synchronous_names.get(synchronous_value, str(synchronous_value)),
        )
        if (
            settings.journal_mode != "wal"
            or not settings.foreign_keys
            or settings.synchronous != "full"
        ):
            connection.close()
            raise RunStoreError("SQLite durability settings could not be enforced")
        return connection, settings

    @property
    def schema_version(self) -> int:
        return LEDGER_SCHEMA_VERSION

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def run_spec(self) -> RunSpec:
        return self._run_spec

    @property
    def sqlite_settings(self) -> SQLiteSettings:
        return self._sqlite_settings

    @property
    def status(self) -> RunStatus:
        return RunStatus(self._metadata("status"))

    @property
    def counts(self) -> RunCounts:
        return self._counts()

    @property
    def projection_state(self) -> ProjectionState:
        row = self._connection.execute(
            """
            SELECT next_sequence, byte_offset, prefix_sha256
            FROM projection_state
            WHERE singleton = 1
            """
        ).fetchone()
        if row is None:
            raise LedgerIntegrityError("projection state is missing")
        return ProjectionState(
            next_sequence=row["next_sequence"],
            byte_offset=row["byte_offset"],
            prefix_sha256=row["prefix_sha256"],
        )

    def _ensure_open(self) -> None:
        if self._closed:
            raise RunStoreError("run store is closed")

    def _metadata(self, key: str) -> str:
        self._ensure_open()
        row = self._connection.execute(
            "SELECT value FROM metadata WHERE key = ?",
            (key,),
        ).fetchone()
        if row is None:
            raise LedgerIntegrityError(f"required metadata is missing: {key}")
        return row["value"]

    @staticmethod
    def _set_metadata(connection: sqlite3.Connection, key: str, value: object) -> None:
        changed = connection.execute(
            "UPDATE metadata SET value = ? WHERE key = ?",
            (str(value), key),
        ).rowcount
        if changed != 1:
            raise LedgerIntegrityError(f"required metadata is missing: {key}")

    @staticmethod
    def _lifecycle(connection: sqlite3.Connection) -> RunLifecycle:
        rows = {
            row["key"]: row["value"]
            for row in connection.execute(
                """
                SELECT key, value
                FROM metadata
                WHERE key IN ('status', 'epoch', 'resume_status')
                """
            )
        }
        try:
            status = RunStatus(rows["status"])
            epoch = int(rows["epoch"])
            resume_status = RunStatus(rows["resume_status"]) if rows["resume_status"] else None
            return RunLifecycle(status=status, epoch=epoch, resume_status=resume_status)
        except (KeyError, TypeError, ValueError) as error:
            raise LedgerIntegrityError("persisted lifecycle is invalid") from error

    @classmethod
    def _persist_lifecycle(
        cls,
        connection: sqlite3.Connection,
        lifecycle: RunLifecycle,
    ) -> None:
        cls._set_metadata(connection, "status", lifecycle.status.value)
        cls._set_metadata(connection, "epoch", lifecycle.epoch)
        cls._set_metadata(
            connection,
            "resume_status",
            lifecycle.resume_status.value if lifecycle.resume_status is not None else "",
        )

    @staticmethod
    def _insert_event(
        connection: sqlite3.Connection,
        kind: EventKind,
        lifecycle: RunLifecycle,
    ) -> None:
        sequence = connection.execute(
            "SELECT COALESCE(MAX(sequence), -1) + 1 FROM run_events"
        ).fetchone()[0]
        failure_code = None
        failure_disposition = None
        if lifecycle.failure is not None:
            failure_code = lifecycle.failure.code.value
            failure_disposition = lifecycle.failure.disposition.value
        connection.execute(
            """
            INSERT INTO run_events(
                sequence, kind, epoch, status, timestamp_ns,
                failure_code, failure_disposition
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sequence,
                kind.value,
                lifecycle.epoch,
                lifecycle.status.value,
                time.time_ns(),
                failure_code,
                failure_disposition,
            ),
        )

    def _counts(self) -> RunCounts:
        self._ensure_open()
        row = self._connection.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM occurrences) AS occurrences,
                (SELECT COUNT(*) FROM endpoint_work) AS endpoint_work,
                (SELECT COUNT(*) FROM occurrences WHERE terminal = 1)
                    AS terminal_occurrences,
                (SELECT COUNT(*) FROM endpoint_work WHERE state = 'pending')
                    AS pending_endpoints,
                (SELECT COUNT(*) FROM endpoint_work WHERE state = 'claimed')
                    AS active_claims,
                (SELECT COUNT(*) FROM occurrence_outbox) AS occurrence_outbox,
                (SELECT COUNT(*) FROM run_events) AS operational_events
            """
        ).fetchone()
        return RunCounts(**dict(row))

    def _bump_data_revision(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            UPDATE metadata
            SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT)
            WHERE key = 'data_revision'
            """
        )

    def ingest(self, source_path: os.PathLike) -> TargetFileSummary:
        self._ensure_open()
        source = Path(source_path)
        if self.status is not RunStatus.INGESTING or self._metadata("ingested") != "0":
            raise IngestionStateError("target source has already been ingested")

        try:
            stream = source.open("rb")
        except OSError as error:
            raise SourceChangedError(f"cannot open target source: {source}") from error

        new_cache: Optional[_OutboxHashCache] = None
        try:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise SourceChangedError("target source must be a regular file")
            identity = _identity_from_stat(source, before)
            with _transaction(self._connection):
                if (
                    self._lifecycle(self._connection).status is not RunStatus.INGESTING
                    or self._metadata("ingested") != "0"
                ):
                    raise IngestionStateError("target source has already been ingested")

                summary = ingest_targets(
                    stream,
                    lambda occurrence: self._insert_occurrence(self._connection, occurrence),
                )
                after = os.fstat(stream.fileno())
                try:
                    path_value = source.stat()
                except OSError as error:
                    raise SourceChangedError(
                        "target source disappeared during ingestion"
                    ) from error
                if (
                    not _identity_matches(identity, source, after)
                    or not _identity_matches(identity, source, path_value)
                    or summary.byte_count != identity.size
                    or summary.file_sha256 != self._run_spec.input_sha256
                ):
                    raise SourceChangedError("target source changed during ingestion")

                new_cache = self._advance_outbox_frontier(self._connection)
                self._set_metadata(
                    self._connection,
                    "source_identity",
                    _canonical_json(asdict(identity)),
                )
                self._set_metadata(
                    self._connection,
                    "source_summary",
                    _canonical_json(_summary_document(summary)),
                )
                self._set_metadata(self._connection, "ingested", "1")
                self._bump_data_revision(self._connection)
        finally:
            stream.close()
        self._outbox_cache = new_cache
        return summary

    def _insert_occurrence(
        self,
        connection: sqlite3.Connection,
        occurrence: TargetOccurrence,
    ) -> None:
        endpoint_id = None
        terminal = 0
        status_value = None
        if occurrence.endpoint is not None:
            connection.execute(
                """
                INSERT INTO endpoint_work(address, port, state)
                VALUES (?, ?, 'pending')
                ON CONFLICT(address, port) DO NOTHING
                """,
                (occurrence.endpoint.address, occurrence.endpoint.port),
            )
            endpoint_row = connection.execute(
                """
                SELECT endpoint_id
                FROM endpoint_work
                WHERE address = ? AND port = ?
                """,
                (occurrence.endpoint.address, occurrence.endpoint.port),
            ).fetchone()
            if endpoint_row is None:
                raise LedgerIntegrityError("endpoint identity was not persisted")
            endpoint_id = endpoint_row["endpoint_id"]
        else:
            terminal = 1
            status_value = OccurrenceStatus.INVALID_INPUT.value

        connection.execute(
            """
            INSERT INTO occurrences(
                sequence, line_number, byte_offset, line_digest,
                address, port, endpoint_id, terminal, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                occurrence.sequence,
                occurrence.line_number,
                occurrence.byte_offset,
                occurrence.line_digest,
                occurrence.endpoint.address if occurrence.endpoint is not None else None,
                occurrence.endpoint.port if occurrence.endpoint is not None else None,
                endpoint_id,
                terminal,
                status_value,
            ),
        )
        if occurrence.endpoint is None:
            record = CanonicalRecord(
                run_id=self._run_id,
                occurrence=occurrence,
                status=OccurrenceStatus.INVALID_INPUT,
                error_codes=(FailureCode.INVALID_INPUT,),
            )
            self._insert_outbox(connection, occurrence.sequence, canonical_json_bytes(record))

    @staticmethod
    def _insert_outbox(
        connection: sqlite3.Connection,
        occurrence_sequence: int,
        payload: bytes,
    ) -> None:
        connection.execute(
            """
            INSERT INTO occurrence_outbox(
                occurrence_sequence, payload, byte_length, payload_sha256
            ) VALUES (?, ?, ?, ?)
            """,
            (
                occurrence_sequence,
                sqlite3.Binary(payload),
                len(payload),
                hashlib.sha256(payload).hexdigest(),
            ),
        )

    def _frontier_hash_cache(
        self,
        connection: sqlite3.Connection,
    ) -> _OutboxHashCache:
        row = connection.execute(
            """
            SELECT next_sequence, byte_offset, prefix_sha256
            FROM outbox_frontier
            WHERE singleton = 1
            """
        ).fetchone()
        if row is None:
            raise LedgerIntegrityError("outbox frontier is missing")
        next_sequence = row["next_sequence"]
        byte_offset = row["byte_offset"]
        if (
            self._outbox_cache is not None
            and self._outbox_cache.next_sequence == next_sequence
            and self._outbox_cache.byte_offset == byte_offset
            and self._outbox_cache.hasher.hexdigest() == row["prefix_sha256"]
        ):
            return _OutboxHashCache(
                next_sequence=next_sequence,
                byte_offset=byte_offset,
                hasher=self._outbox_cache.hasher.copy(),
            )

        hasher = hashlib.sha256()
        observed_offset = 0
        expected_sequence = 0
        for entry in connection.execute(
            """
            SELECT occurrence_sequence, payload, byte_length, payload_sha256,
                   output_offset, prefix_sha256
            FROM occurrence_outbox
            WHERE occurrence_sequence < ?
            ORDER BY occurrence_sequence
            """,
            (next_sequence,),
        ):
            payload = bytes(entry["payload"])
            if (
                entry["occurrence_sequence"] != expected_sequence
                or entry["byte_length"] != len(payload)
                or entry["payload_sha256"] != hashlib.sha256(payload).hexdigest()
                or entry["output_offset"] != observed_offset
            ):
                raise LedgerIntegrityError("outbox prefix metadata is inconsistent")
            hasher.update(payload)
            hasher.update(b"\n")
            observed_offset += len(payload) + 1
            if entry["prefix_sha256"] != hasher.hexdigest():
                raise LedgerIntegrityError("outbox prefix digest is inconsistent")
            expected_sequence += 1
        if (
            expected_sequence != next_sequence
            or observed_offset != byte_offset
            or hasher.hexdigest() != row["prefix_sha256"]
        ):
            raise LedgerIntegrityError("outbox frontier does not match its records")
        return _OutboxHashCache(
            next_sequence=next_sequence,
            byte_offset=byte_offset,
            hasher=hasher,
        )

    def _advance_outbox_frontier(
        self,
        connection: sqlite3.Connection,
    ) -> _OutboxHashCache:
        cache = self._frontier_hash_cache(connection)
        starting_sequence = cache.next_sequence
        while True:
            row = connection.execute(
                """
                SELECT payload, byte_length, payload_sha256, output_offset, prefix_sha256
                FROM occurrence_outbox
                WHERE occurrence_sequence = ?
                """,
                (cache.next_sequence,),
            ).fetchone()
            if row is None:
                break
            payload = bytes(row["payload"])
            if (
                row["byte_length"] != len(payload)
                or row["payload_sha256"] != hashlib.sha256(payload).hexdigest()
            ):
                raise LedgerIntegrityError("outbox payload metadata is inconsistent")
            if row["output_offset"] is not None or row["prefix_sha256"] is not None:
                raise LedgerIntegrityError("uncommitted outbox prefix metadata is present")
            output_offset = cache.byte_offset
            cache.hasher.update(payload)
            cache.hasher.update(b"\n")
            cache.byte_offset += len(payload) + 1
            prefix_sha256 = cache.hasher.hexdigest()
            changed = connection.execute(
                """
                UPDATE occurrence_outbox
                SET output_offset = ?, prefix_sha256 = ?
                WHERE occurrence_sequence = ?
                  AND output_offset IS NULL
                  AND prefix_sha256 IS NULL
                """,
                (output_offset, prefix_sha256, cache.next_sequence),
            ).rowcount
            if changed != 1:
                raise LedgerIntegrityError("outbox prefix update was not exclusive")
            cache.next_sequence += 1
        if cache.next_sequence != starting_sequence:
            connection.execute(
                """
                UPDATE outbox_frontier
                SET next_sequence = ?, byte_offset = ?, prefix_sha256 = ?
                WHERE singleton = 1
                """,
                (cache.next_sequence, cache.byte_offset, cache.hasher.hexdigest()),
            )
        return cache

    def verify_source(self, source_path: os.PathLike) -> TargetFileSummary:
        self._ensure_open()
        source = Path(source_path)
        if (
            self.status is not RunStatus.INGESTING
            or self._metadata("ingested") != "1"
            or self._metadata("source_verified") != "0"
        ):
            raise IngestionStateError("target source is not awaiting verification")
        expected_identity = _deserialize_identity(self._metadata("source_identity"))
        expected_summary = _deserialize_summary(self._metadata("source_summary"))

        try:
            stream = source.open("rb")
        except OSError as error:
            raise SourceChangedError(f"cannot reopen target source: {source}") from error
        try:
            before = os.fstat(stream.fileno())
            if not _identity_matches(expected_identity, source, before):
                raise SourceChangedError("target source identity changed before verification")
            observed_byte_count, observed_sha256 = _stream_sha256(stream)
            after = os.fstat(stream.fileno())
            try:
                path_value = source.stat()
            except OSError as error:
                raise SourceChangedError("target source disappeared during verification") from error
            if (
                not _identity_matches(expected_identity, source, after)
                or not _identity_matches(expected_identity, source, path_value)
                or observed_byte_count != expected_summary.byte_count
                or observed_sha256 != expected_summary.file_sha256
                or observed_sha256 != self._run_spec.input_sha256
            ):
                raise SourceChangedError("target source changed before verification")

            with _transaction(self._connection):
                lifecycle = self._lifecycle(self._connection)
                if (
                    lifecycle.status is not RunStatus.INGESTING
                    or self._metadata("source_verified") != "0"
                ):
                    raise IngestionStateError("target source is not awaiting verification")
                after_transaction = os.fstat(stream.fileno())
                try:
                    path_transaction = source.stat()
                except OSError as error:
                    raise SourceChangedError(
                        "target source disappeared during ready commit"
                    ) from error
                if not _identity_matches(
                    expected_identity, source, after_transaction
                ) or not _identity_matches(expected_identity, source, path_transaction):
                    raise SourceChangedError("target source changed before ready commit")
                self._set_metadata(self._connection, "source_verified", "1")
                ready = lifecycle.transition(RunStatus.READY)
                self._persist_lifecycle(self._connection, ready)
                self._insert_event(self._connection, EventKind.RUN_TRANSITION, ready)
        finally:
            stream.close()
        return expected_summary

    def iter_occurrences(self) -> Iterator[TargetOccurrence]:
        self._ensure_open()
        cursor = self._connection.execute(
            """
            SELECT sequence, line_number, byte_offset, line_digest, address, port
            FROM occurrences
            ORDER BY sequence
            """
        )
        for row in cursor:
            endpoint = None
            if row["address"] is not None:
                endpoint = Endpoint(address=row["address"], port=row["port"])
            yield TargetOccurrence(
                sequence=row["sequence"],
                line_number=row["line_number"],
                byte_offset=row["byte_offset"],
                line_digest=row["line_digest"],
                endpoint=endpoint,
            )

    def iter_occurrence_outbox(self) -> Iterator[OccurrenceOutboxEntry]:
        self._ensure_open()
        cursor = self._connection.execute(
            """
            SELECT occurrence_sequence, payload, byte_length, payload_sha256,
                   output_offset, prefix_sha256
            FROM occurrence_outbox
            ORDER BY occurrence_sequence
            """
        )
        for row in cursor:
            yield OccurrenceOutboxEntry(
                occurrence_sequence=row["occurrence_sequence"],
                payload=bytes(row["payload"]),
                byte_length=row["byte_length"],
                payload_sha256=row["payload_sha256"],
                output_offset=row["output_offset"],
                prefix_sha256=row["prefix_sha256"],
            )

    def contiguous_outbox(
        self,
        start_sequence: int,
        max_records: Optional[int] = None,
    ) -> Tuple[OccurrenceOutboxEntry, ...]:
        if type(start_sequence) is not int or start_sequence < 0:
            raise ValueError("start_sequence must be a non-negative integer")
        if max_records is not None and (type(max_records) is not int or max_records < 1):
            raise ValueError("max_records must be a positive integer or None")
        frontier = self._connection.execute(
            "SELECT next_sequence FROM outbox_frontier WHERE singleton = 1"
        ).fetchone()
        if frontier is None:
            raise LedgerIntegrityError("outbox frontier is missing")
        stop_sequence = frontier["next_sequence"]
        if start_sequence >= stop_sequence:
            return ()
        if max_records is not None:
            stop_sequence = min(stop_sequence, start_sequence + max_records)
        rows = self._connection.execute(
            """
            SELECT occurrence_sequence, payload, byte_length, payload_sha256,
                   output_offset, prefix_sha256
            FROM occurrence_outbox
            WHERE occurrence_sequence >= ? AND occurrence_sequence < ?
            ORDER BY occurrence_sequence
            """,
            (start_sequence, stop_sequence),
        ).fetchall()
        if len(rows) != stop_sequence - start_sequence:
            raise LedgerIntegrityError("outbox frontier contains a sequence gap")
        return tuple(
            OccurrenceOutboxEntry(
                occurrence_sequence=row["occurrence_sequence"],
                payload=bytes(row["payload"]),
                byte_length=row["byte_length"],
                payload_sha256=row["payload_sha256"],
                output_offset=row["output_offset"],
                prefix_sha256=row["prefix_sha256"],
            )
            for row in rows
        )

    def claim_endpoint(self) -> Optional[EndpointClaim]:
        self._ensure_open()
        with _transaction(self._connection):
            lifecycle = self._lifecycle(self._connection)
            if lifecycle.status is not RunStatus.EXECUTING:
                raise RunStateError("endpoints may be claimed only while executing")
            row = self._connection.execute(
                """
                SELECT endpoint_id, address, port, attempt
                FROM endpoint_work
                WHERE state = 'pending'
                ORDER BY endpoint_id
                LIMIT 1
                """
            ).fetchone()
            if row is None:
                return None
            attempt = row["attempt"] + 1
            changed = self._connection.execute(
                """
                UPDATE endpoint_work
                SET state = 'claimed', claim_epoch = ?, attempt = ?
                WHERE endpoint_id = ? AND state = 'pending'
                """,
                (lifecycle.epoch, attempt, row["endpoint_id"]),
            ).rowcount
            if changed != 1:
                raise RunStateError("endpoint claim raced with another owner")
            return EndpointClaim(
                endpoint_id=row["endpoint_id"],
                endpoint=Endpoint(address=row["address"], port=row["port"]),
                token=ClaimToken(epoch=lifecycle.epoch, attempt=attempt),
            )

    def commit_endpoint(
        self,
        claim: EndpointClaim,
        results: Sequence[ProtocolResult],
    ) -> int:
        self._ensure_open()
        if not isinstance(claim, EndpointClaim):
            raise TypeError("claim must be an EndpointClaim")
        normalized_results = tuple(results)
        if any(not isinstance(result, ProtocolResult) for result in normalized_results):
            raise TypeError("results must contain only ProtocolResult values")
        if len({result.protocol for result in normalized_results}) != len(normalized_results):
            raise ValueError("results must contain at most one result per protocol")
        normalized_results = tuple(
            sorted(normalized_results, key=lambda item: _PROTOCOL_RANK[item.protocol])
        )
        result_payload = _serialize_protocols(normalized_results)
        fanout_count = 0
        new_cache: Optional[_OutboxHashCache] = None
        with _transaction(self._connection):
            lifecycle = self._lifecycle(self._connection)
            if lifecycle.status is not RunStatus.EXECUTING:
                raise RunStateError("endpoint results may be committed only while executing")
            row = self._connection.execute(
                """
                SELECT address, port, state, claim_epoch, attempt
                FROM endpoint_work
                WHERE endpoint_id = ?
                """,
                (claim.endpoint_id,),
            ).fetchone()
            if (
                row is None
                or row["state"] != "claimed"
                or row["claim_epoch"] != claim.token.epoch
                or row["attempt"] != claim.token.attempt
                or claim.token.epoch != lifecycle.epoch
                or row["address"] != claim.endpoint.address
                or row["port"] != claim.endpoint.port
            ):
                raise StaleClaimError("claim is no longer current")

            self._connection.execute(
                """
                INSERT INTO endpoint_results(endpoint_id, payload, payload_sha256)
                VALUES (?, ?, ?)
                """,
                (
                    claim.endpoint_id,
                    sqlite3.Binary(result_payload),
                    hashlib.sha256(result_payload).hexdigest(),
                ),
            )
            occurrences = self._connection.execute(
                """
                SELECT sequence, line_number, byte_offset, line_digest, address, port
                FROM occurrences
                WHERE endpoint_id = ? AND terminal = 0
                ORDER BY sequence
                """,
                (claim.endpoint_id,),
            )
            status = aggregate_occurrence_status(claim.endpoint, normalized_results)
            error_codes = _occurrence_errors(normalized_results)
            while True:
                occurrence_batch = occurrences.fetchmany(256)
                if not occurrence_batch:
                    break
                for occurrence_row in occurrence_batch:
                    occurrence = TargetOccurrence(
                        sequence=occurrence_row["sequence"],
                        line_number=occurrence_row["line_number"],
                        byte_offset=occurrence_row["byte_offset"],
                        line_digest=occurrence_row["line_digest"],
                        endpoint=Endpoint(
                            address=occurrence_row["address"],
                            port=occurrence_row["port"],
                        ),
                    )
                    record = CanonicalRecord(
                        run_id=self._run_id,
                        occurrence=occurrence,
                        status=status,
                        error_codes=error_codes,
                        protocols=normalized_results,
                    )
                    changed = self._connection.execute(
                        """
                        UPDATE occurrences
                        SET terminal = 1, status = ?
                        WHERE sequence = ? AND terminal = 0
                        """,
                        (status.value, occurrence.sequence),
                    ).rowcount
                    if changed != 1:
                        raise LedgerIntegrityError("occurrence terminalization was not exclusive")
                    self._insert_outbox(
                        self._connection,
                        occurrence.sequence,
                        canonical_json_bytes(record),
                    )
                    fanout_count += 1
            changed = self._connection.execute(
                """
                UPDATE endpoint_work
                SET state = 'terminal', claim_epoch = NULL
                WHERE endpoint_id = ? AND state = 'claimed'
                  AND claim_epoch = ? AND attempt = ?
                """,
                (claim.endpoint_id, claim.token.epoch, claim.token.attempt),
            ).rowcount
            if changed != 1:
                raise StaleClaimError("claim became stale before terminal commit")
            new_cache = self._advance_outbox_frontier(self._connection)
            self._bump_data_revision(self._connection)
        self._outbox_cache = new_cache
        return fanout_count

    def endpoint_protocol_results(
        self,
        endpoint_id: int,
    ) -> Tuple[ProtocolResult, ...]:
        self._ensure_open()
        row = self._connection.execute(
            """
            SELECT payload, payload_sha256
            FROM endpoint_results
            WHERE endpoint_id = ?
            """,
            (endpoint_id,),
        ).fetchone()
        if row is None:
            return ()
        payload = bytes(row["payload"])
        if hashlib.sha256(payload).hexdigest() != row["payload_sha256"]:
            raise LedgerIntegrityError("endpoint result digest does not match its payload")
        return _deserialize_protocols(payload)

    def transition(self, next_status: RunStatus) -> None:
        self._ensure_open()
        if not isinstance(next_status, RunStatus):
            raise TypeError("next_status must be a RunStatus")
        with _transaction(self._connection):
            lifecycle = self._lifecycle(self._connection)
            self._assert_transition_preconditions(
                self._connection,
                lifecycle.status,
                next_status,
            )
            next_lifecycle = lifecycle.transition(next_status)
            self._persist_lifecycle(self._connection, next_lifecycle)
            self._insert_event(
                self._connection,
                EventKind.RUN_TRANSITION,
                next_lifecycle,
            )

    def _assert_transition_preconditions(
        self,
        connection: sqlite3.Connection,
        current_status: RunStatus,
        next_status: RunStatus,
    ) -> None:
        if current_status is RunStatus.INGESTING and next_status is RunStatus.READY:
            if self._metadata("source_verified") != "1":
                raise CompletionPreconditionError("target source has not been verified")
        elif current_status is RunStatus.READY and next_status is RunStatus.EXECUTING:
            if self._metadata("source_verified") != "1":
                raise CompletionPreconditionError("target source has not been verified")
        elif current_status is RunStatus.EXECUTING and next_status is RunStatus.PROJECTING:
            self._assert_endpoint_completion(connection)
        elif current_status is RunStatus.PROJECTING and next_status is RunStatus.PUBLISH_READY:
            self._assert_endpoint_completion(connection)
            counts = self._counts()
            projection = self.projection_state
            if (
                projection.next_sequence != counts.occurrences
                or self._metadata("workers_closed") != "1"
                or self._metadata("reconciled_revision") != self._metadata("data_revision")
            ):
                raise CompletionPreconditionError(
                    "projection, workers, and reconciliation must be complete"
                )
            output_path = self.generation_path / self.CANONICAL_FILENAME
            try:
                byte_count, digest = _file_sha256(output_path)
            except (OSError, ArtifactSafetyError) as error:
                raise CompletionPreconditionError(
                    "canonical projection is missing or unsafe"
                ) from error
            if byte_count != projection.byte_offset or digest != projection.prefix_sha256:
                raise CompletionPreconditionError(
                    "canonical projection does not match its durable cursor"
                )
        elif current_status is RunStatus.PUBLISH_READY and next_status is RunStatus.COMPLETE:
            digest = self._metadata("manifest_sha256")
            byte_count_text = self._metadata("manifest_byte_count")
            if not digest or not byte_count_text:
                raise CompletionPreconditionError("manifest has not been published")
            manifest_path = self.generation_path / self.MANIFEST_FILENAME
            try:
                byte_count, observed_digest = _file_sha256(manifest_path)
            except (OSError, ArtifactSafetyError) as error:
                raise CompletionPreconditionError("manifest is missing or unsafe") from error
            if byte_count != int(byte_count_text) or observed_digest != digest:
                raise CompletionPreconditionError("published manifest does not match the ledger")

    def _assert_endpoint_completion(self, connection: sqlite3.Connection) -> None:
        counts = self._counts()
        frontier = connection.execute(
            "SELECT next_sequence FROM outbox_frontier WHERE singleton = 1"
        ).fetchone()
        if (
            counts.pending_endpoints != 0
            or counts.active_claims != 0
            or counts.terminal_occurrences != counts.occurrences
            or counts.occurrence_outbox != counts.occurrences
            or frontier is None
            or frontier["next_sequence"] != counts.occurrences
        ):
            raise CompletionPreconditionError("endpoint execution is not complete")

    def interrupt(self) -> None:
        self._ensure_open()
        with _transaction(self._connection):
            lifecycle = self._lifecycle(self._connection)
            interrupted = lifecycle.interrupt()
            self._connection.execute(
                """
                UPDATE endpoint_work
                SET state = 'pending', claim_epoch = NULL
                WHERE state = 'claimed'
                """
            )
            self._persist_lifecycle(self._connection, interrupted)
            self._insert_event(
                self._connection,
                EventKind.RUN_INTERRUPTED,
                interrupted,
            )

    def resume(self) -> None:
        self._ensure_open()
        with _transaction(self._connection):
            lifecycle = self._lifecycle(self._connection)
            resumed = lifecycle.resume()
            active_claim = self._connection.execute(
                "SELECT 1 FROM endpoint_work WHERE state = 'claimed' LIMIT 1"
            ).fetchone()
            if active_claim is not None:
                raise LedgerIntegrityError("interrupted run retained an active claim")
            self._persist_lifecycle(self._connection, resumed)
            self._insert_event(self._connection, EventKind.RUN_RESUMED, resumed)

    def mark_workers_closed(self) -> None:
        self._ensure_open()
        with _transaction(self._connection):
            status = self._lifecycle(self._connection).status
            if status is not RunStatus.PROJECTING:
                raise RunStateError("workers may be closed only while projecting")
            self._set_metadata(self._connection, "workers_closed", "1")

    def reconcile_counts(self) -> RunCounts:
        self._ensure_open()
        with _transaction(self._connection):
            if self._connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise LedgerIntegrityError("ledger foreign-key integrity check failed")
            counts = self._counts()
            mismatched_occurrence = self._connection.execute(
                """
                SELECT 1
                FROM occurrences AS occurrence
                LEFT JOIN occurrence_outbox AS outbox
                  ON outbox.occurrence_sequence = occurrence.sequence
                WHERE (occurrence.terminal = 1 AND outbox.occurrence_sequence IS NULL)
                   OR (occurrence.terminal = 0 AND outbox.occurrence_sequence IS NOT NULL)
                LIMIT 1
                """
            ).fetchone()
            mismatched_endpoint = self._connection.execute(
                """
                SELECT 1
                FROM endpoint_work AS work
                LEFT JOIN endpoint_results AS result
                  ON result.endpoint_id = work.endpoint_id
                WHERE (work.state = 'terminal' AND result.endpoint_id IS NULL)
                   OR (work.state <> 'terminal' AND result.endpoint_id IS NOT NULL)
                LIMIT 1
                """
            ).fetchone()
            if mismatched_occurrence is not None or mismatched_endpoint is not None:
                raise LedgerIntegrityError("terminal facts and durable results do not match")
            self._verify_outbox()
            revision = self._metadata("data_revision")
            self._set_metadata(self._connection, "reconciled_revision", revision)
            self._set_metadata(
                self._connection,
                "reconciled_counts",
                _canonical_json(asdict(counts)),
            )
        return counts

    def _verify_outbox(self) -> None:
        frontier_row = self._connection.execute(
            """
            SELECT next_sequence, byte_offset, prefix_sha256
            FROM outbox_frontier
            WHERE singleton = 1
            """
        ).fetchone()
        if frontier_row is None:
            raise LedgerIntegrityError("outbox frontier is missing")
        hasher = hashlib.sha256()
        byte_offset = 0
        expected_sequence = 0
        endpoint_results = OrderedDict()
        for row in self._connection.execute(
            """
            SELECT
                outbox.occurrence_sequence AS outbox_sequence,
                outbox.payload AS outbox_payload,
                outbox.byte_length AS outbox_byte_length,
                outbox.payload_sha256 AS outbox_payload_sha256,
                outbox.output_offset AS outbox_output_offset,
                outbox.prefix_sha256 AS outbox_prefix_sha256,
                occurrence.sequence AS occurrence_sequence,
                occurrence.line_number AS occurrence_line_number,
                occurrence.byte_offset AS occurrence_byte_offset,
                occurrence.line_digest AS occurrence_line_digest,
                occurrence.address AS occurrence_address,
                occurrence.port AS occurrence_port,
                occurrence.endpoint_id AS occurrence_endpoint_id,
                occurrence.terminal AS occurrence_terminal,
                occurrence.status AS occurrence_status,
                result.endpoint_id AS result_endpoint_id,
                result.payload AS result_payload,
                result.payload_sha256 AS result_payload_sha256
            FROM occurrence_outbox AS outbox
            LEFT JOIN occurrences AS occurrence
              ON occurrence.sequence = outbox.occurrence_sequence
            LEFT JOIN endpoint_results AS result
              ON result.endpoint_id = occurrence.endpoint_id
            ORDER BY outbox.occurrence_sequence
            """
        ):
            payload = bytes(row["outbox_payload"])
            sequence = row["outbox_sequence"]
            if (
                row["outbox_byte_length"] != len(payload)
                or row["outbox_payload_sha256"] != hashlib.sha256(payload).hexdigest()
            ):
                raise LedgerIntegrityError("outbox payload metadata is inconsistent")
            self._verify_canonical_payload(row, payload, endpoint_results)
            if sequence == expected_sequence:
                if row["outbox_output_offset"] != byte_offset:
                    raise LedgerIntegrityError("outbox output offset is inconsistent")
                hasher.update(payload)
                hasher.update(b"\n")
                byte_offset += len(payload) + 1
                if row["outbox_prefix_sha256"] != hasher.hexdigest():
                    raise LedgerIntegrityError("outbox prefix digest is inconsistent")
                expected_sequence += 1
            elif (
                sequence > expected_sequence
                and row["outbox_output_offset"] is None
                and row["outbox_prefix_sha256"] is None
            ):
                continue
            else:
                raise LedgerIntegrityError("outbox sequence metadata is inconsistent")
        if (
            expected_sequence != frontier_row["next_sequence"]
            or byte_offset != frontier_row["byte_offset"]
            or hasher.hexdigest() != frontier_row["prefix_sha256"]
        ):
            raise LedgerIntegrityError("outbox frontier is inconsistent")

    def _verify_canonical_payload(
        self,
        row: sqlite3.Row,
        payload: bytes,
        endpoint_results,
    ) -> None:
        if row["occurrence_sequence"] is None or row["occurrence_terminal"] != 1:
            raise LedgerIntegrityError("outbox row has no terminal occurrence")
        endpoint = None
        protocols: Tuple[ProtocolResult, ...] = ()
        error_codes: Tuple[FailureCode, ...]
        if row["occurrence_address"] is None:
            error_codes = (FailureCode.INVALID_INPUT,)
        else:
            endpoint = Endpoint(
                address=row["occurrence_address"],
                port=row["occurrence_port"],
            )
            endpoint_id = row["occurrence_endpoint_id"]
            if row["result_endpoint_id"] != endpoint_id:
                raise LedgerIntegrityError("terminal occurrence has no endpoint result")
            try:
                protocols = endpoint_results.pop(endpoint_id)
            except KeyError:
                result_payload = bytes(row["result_payload"])
                if hashlib.sha256(result_payload).hexdigest() != row["result_payload_sha256"]:
                    raise LedgerIntegrityError("endpoint result digest is inconsistent")
                protocols = _deserialize_protocols(result_payload)
            endpoint_results[endpoint_id] = protocols
            if len(endpoint_results) > _VERIFY_RESULT_CACHE_SIZE:
                endpoint_results.popitem(last=False)
            error_codes = _occurrence_errors(protocols)
        occurrence = TargetOccurrence(
            sequence=row["occurrence_sequence"],
            line_number=row["occurrence_line_number"],
            byte_offset=row["occurrence_byte_offset"],
            line_digest=row["occurrence_line_digest"],
            endpoint=endpoint,
        )
        record = CanonicalRecord(
            run_id=self._run_id,
            occurrence=occurrence,
            status=OccurrenceStatus(row["occurrence_status"]),
            error_codes=error_codes,
            protocols=protocols,
        )
        if canonical_json_bytes(record) != payload:
            raise LedgerIntegrityError("outbox payload is not the canonical terminal record")

    def iter_events(self) -> Iterator[RunEvent]:
        self._ensure_open()
        cursor = self._connection.execute(
            """
            SELECT sequence, kind, epoch, status, timestamp_ns,
                   failure_code, failure_disposition
            FROM run_events
            ORDER BY sequence
            """
        )
        for row in cursor:
            failure = None
            if row["failure_code"] is not None:
                failure = Failure(
                    code=FailureCode(row["failure_code"]),
                    disposition=FailureDisposition(row["failure_disposition"]),
                )
            yield RunEvent(
                sequence=row["sequence"],
                kind=EventKind(row["kind"]),
                epoch=row["epoch"],
                status=RunStatus(row["status"]),
                timestamp_ns=row["timestamp_ns"],
                failure=failure,
            )

    def advance_projection(
        self,
        expected: ProjectionState,
        next_state: ProjectionState,
    ) -> None:
        self._ensure_open()
        if not isinstance(expected, ProjectionState) or not isinstance(next_state, ProjectionState):
            raise TypeError("projection states must be ProjectionState values")
        if (
            next_state.next_sequence < expected.next_sequence
            or next_state.byte_offset < expected.byte_offset
        ):
            raise ValueError("projection cursor cannot move backwards")
        with _transaction(self._connection):
            row = self._connection.execute(
                """
                SELECT next_sequence, byte_offset, prefix_sha256
                FROM projection_state
                WHERE singleton = 1
                """
            ).fetchone()
            current = ProjectionState(**dict(row))
            if current != expected:
                raise RunStateError("projection cursor changed concurrently")
            if next_state.next_sequence:
                outbox = self._connection.execute(
                    """
                    SELECT byte_length, output_offset, prefix_sha256
                    FROM occurrence_outbox
                    WHERE occurrence_sequence = ?
                    """,
                    (next_state.next_sequence - 1,),
                ).fetchone()
                if outbox is None:
                    raise LedgerIntegrityError("projection cursor exceeds the outbox")
                expected_offset = outbox["output_offset"] + outbox["byte_length"] + 1
                if (
                    expected_offset != next_state.byte_offset
                    or outbox["prefix_sha256"] != next_state.prefix_sha256
                ):
                    raise LedgerIntegrityError("projection cursor does not match the outbox prefix")
            elif next_state != ProjectionState(0, 0, _EMPTY_SHA256):
                raise LedgerIntegrityError("empty projection cursor is invalid")
            self._connection.execute(
                """
                UPDATE projection_state
                SET next_sequence = ?, byte_offset = ?, prefix_sha256 = ?
                WHERE singleton = 1
                """,
                (
                    next_state.next_sequence,
                    next_state.byte_offset,
                    next_state.prefix_sha256,
                ),
            )

    def record_manifest(self, byte_count: int, sha256: str) -> None:
        self._ensure_open()
        if type(byte_count) is not int or byte_count < 0:
            raise ValueError("byte_count must be a non-negative integer")
        if (
            not isinstance(sha256, str)
            or len(sha256) != 64
            or any(character not in "0123456789abcdef" for character in sha256)
        ):
            raise ValueError("sha256 must be a lowercase SHA-256 digest")
        with _transaction(self._connection):
            if self._lifecycle(self._connection).status is not RunStatus.PUBLISH_READY:
                raise RunStateError("manifest may be recorded only while publish-ready")
            if self._metadata("manifest_sha256"):
                raise RunStateError("manifest has already been recorded")
            manifest_path = self.generation_path / self.MANIFEST_FILENAME
            observed_count, observed_digest = _file_sha256(manifest_path)
            if observed_count != byte_count or observed_digest != sha256:
                raise LedgerIntegrityError("manifest file does not match publication metadata")
            self._set_metadata(self._connection, "manifest_byte_count", byte_count)
            self._set_metadata(self._connection, "manifest_sha256", sha256)

    @property
    def manifest_recorded(self) -> bool:
        return bool(self._metadata("manifest_sha256"))

    @property
    def source_summary(self) -> TargetFileSummary:
        payload = self._metadata("source_summary")
        if not payload:
            raise RunStateError("target source has not been ingested")
        return _deserialize_summary(payload)

    def close(self) -> None:
        if self._closed:
            return
        try:
            self._connection.execute("PRAGMA wal_checkpoint(PASSIVE)")
        finally:
            self._connection.close()
            self._closed = True

    def __enter__(self) -> "RunStore":
        self._ensure_open()
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()


def _open_generation_lock(path: Path) -> int:
    if fcntl is None:
        raise ArtifactSafetyError("kernel file locking is unavailable")
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(str(path), flags, 0o600)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.EMLINK}:
            raise ArtifactSafetyError(f"unsafe generation lock path: {path}") from error
        raise
    try:
        value = os.fstat(descriptor)
        if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
            raise ArtifactSafetyError("generation lock is not an unaliased regular file")
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise GenerationLockedError(f"generation is locked: {path.parent}") from error
        diagnostic = f"pid={os.getpid()}\n".encode("ascii")
        os.ftruncate(descriptor, 0)
        os.write(descriptor, diagnostic)
        os.fsync(descriptor)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _close_generation_lock(descriptor: int) -> None:
    if fcntl is not None:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    os.close(descriptor)


class AcquiredGeneration:
    def __init__(
        self,
        path: Path,
        store: RunStore,
        lock_descriptor: int,
        resumed: bool,
    ) -> None:
        self.path = path
        self.store = store
        self.resumed = resumed
        self._lock_descriptor = lock_descriptor
        self._closed = False

    def close(self) -> None:
        if self._closed:
            return
        try:
            self.store.close()
        finally:
            _close_generation_lock(self._lock_descriptor)
            self._closed = True

    def __enter__(self) -> "AcquiredGeneration":
        if self._closed:
            raise RunStoreError("generation lease is closed")
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()


class GenerationRepository:
    """Selects and exclusively owns immutable generation directories."""

    def __init__(self, root: os.PathLike) -> None:
        self.root = Path(root)

    def acquire(self, spec: RunSpec) -> AcquiredGeneration:
        _serialize_run_spec(spec)
        _require_private_directory(self.root, create=True)
        candidates = []
        for entry in os.scandir(str(self.root)):
            if entry.name.startswith("generation-"):
                if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                    raise ArtifactSafetyError(
                        f"generation entry is not a real directory: {entry.path}"
                    )
                candidates.append(Path(entry.path))

        for generation in sorted(candidates, key=lambda item: item.name, reverse=True):
            _require_private_directory(generation, create=False)
            lock_descriptor = _open_generation_lock(generation / RunStore.LOCK_FILENAME)
            try:
                store = RunStore.open(generation, expected_spec=spec)
            except RunSpecMismatchError:
                _close_generation_lock(lock_descriptor)
                continue
            except BaseException:
                _close_generation_lock(lock_descriptor)
                raise
            try:
                status = store.status
                if status is RunStatus.COMPLETE:
                    store.close()
                    _close_generation_lock(lock_descriptor)
                    continue
                if status is RunStatus.INTERRUPTED:
                    store.resume()
                elif status in {
                    RunStatus.INGESTING,
                    RunStatus.READY,
                    RunStatus.EXECUTING,
                    RunStatus.PROJECTING,
                    RunStatus.PUBLISH_READY,
                }:
                    if store.counts.active_claims:
                        store.interrupt()
                        store.resume()
                else:
                    raise RunStateError(f"generation cannot be resumed from {status.value}")
            except BaseException:
                store.close()
                _close_generation_lock(lock_descriptor)
                raise
            return AcquiredGeneration(
                path=generation,
                store=store,
                lock_descriptor=lock_descriptor,
                resumed=True,
            )

        generation = self._create_generation_directory()
        lock_descriptor = _open_generation_lock(generation / RunStore.LOCK_FILENAME)
        try:
            run_id = uuid.uuid4().hex
            store = RunStore.create(generation, run_id=run_id, spec=spec)
        except BaseException:
            _close_generation_lock(lock_descriptor)
            raise
        return AcquiredGeneration(
            path=generation,
            store=store,
            lock_descriptor=lock_descriptor,
            resumed=False,
        )

    def _create_generation_directory(self) -> Path:
        for _attempt in range(100):
            name = f"generation-{time.time_ns():020d}-{uuid.uuid4().hex}"
            generation = self.root / name
            try:
                generation.mkdir(mode=0o700)
            except FileExistsError:
                continue
            os.chmod(str(generation), 0o700)
            return generation
        raise RunStoreError("could not allocate a unique generation directory")
