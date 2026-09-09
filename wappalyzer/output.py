import errno
import hashlib
import json
import os
import stat
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any, BinaryIO, Callable, Optional, Tuple

from wappalyzer.models import RunStatus
from wappalyzer.runstore import (
    LEDGER_SCHEMA_VERSION,
    ArtifactSafetyError,
    CompletionPreconditionError,
    LedgerIntegrityError,
    OccurrenceOutboxEntry,
    ProjectionState,
    RunStateError,
    RunStore,
)


class OutputError(RuntimeError):
    """Base class for canonical output failures."""


class ProjectionIntegrityError(OutputError):
    """Raised when durable output bytes disagree with the ledger cursor."""


class ArtifactExistsError(OutputError):
    """Raised when publication would replace an existing immutable artifact."""


def _open_projection(path: Path) -> Tuple[int, bool]:
    created = False
    flags = os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(str(path), flags)
    except FileNotFoundError:
        try:
            descriptor = os.open(str(path), flags | os.O_CREAT | os.O_EXCL, 0o600)
            created = True
        except FileExistsError:
            try:
                descriptor = os.open(str(path), flags)
            except OSError as error:
                if error.errno in {errno.ELOOP, errno.EMLINK}:
                    raise ArtifactSafetyError(f"unsafe projection path: {path}") from error
                raise
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.EMLINK}:
                raise ArtifactSafetyError(f"unsafe projection path: {path}") from error
            raise
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.EMLINK}:
            raise ArtifactSafetyError(f"unsafe projection path: {path}") from error
        raise
    try:
        value = os.fstat(descriptor)
        if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
            raise ArtifactSafetyError("canonical projection is not an unaliased regular file")
        os.fchmod(descriptor, 0o600)
        return descriptor, created
    except BaseException:
        os.close(descriptor)
        raise


def _sync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(str(path), flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _verified_prefix(stream: BinaryIO, state: ProjectionState) -> Any:
    hasher = hashlib.sha256()
    remaining = state.byte_offset
    stream.seek(0)
    while remaining:
        chunk = stream.read(min(64 * 1024, remaining))
        if not chunk:
            raise ProjectionIntegrityError("canonical projection is shorter than its cursor")
        hasher.update(chunk)
        remaining -= len(chunk)
    if hasher.hexdigest() != state.prefix_sha256:
        raise ProjectionIntegrityError("canonical projection prefix is corrupt")
    return hasher


def _validate_entry(
    entry: OccurrenceOutboxEntry,
    expected_sequence: int,
    expected_offset: int,
) -> None:
    if entry.occurrence_sequence != expected_sequence:
        raise LedgerIntegrityError("projected outbox sequence is not contiguous")
    if entry.byte_length != len(entry.payload):
        raise LedgerIntegrityError("outbox byte length does not match its payload")
    if entry.payload_sha256 != hashlib.sha256(entry.payload).hexdigest():
        raise LedgerIntegrityError("outbox payload digest does not match its payload")
    if entry.output_offset != expected_offset or entry.prefix_sha256 is None:
        raise LedgerIntegrityError("outbox projection metadata is incomplete")


class CanonicalProjector:
    """Replays the ledger's contiguous occurrence outbox into canonical NDJSON."""

    def __init__(
        self,
        store: RunStore,
        sync_file: Callable[[int], None] = os.fsync,
    ) -> None:
        if not isinstance(store, RunStore):
            raise TypeError("store must be a RunStore")
        if not callable(sync_file):
            raise TypeError("sync_file must be callable")
        self.store = store
        self.path = store.generation_path / store.CANONICAL_FILENAME
        self._sync_file = sync_file

    def project(self, max_records: Optional[int] = None) -> int:
        if self.store.status not in {RunStatus.EXECUTING, RunStatus.PROJECTING}:
            raise RunStateError("canonical output may be projected only after execution starts")
        if max_records is not None and (type(max_records) is not int or max_records < 1):
            raise ValueError("max_records must be a positive integer or None")

        descriptor, created = _open_projection(self.path)
        if created:
            _sync_directory(self.path.parent)
        stream = os.fdopen(descriptor, "r+b", buffering=0)
        try:
            state = self.store.projection_state
            size = os.fstat(descriptor).st_size
            if size < state.byte_offset:
                raise ProjectionIntegrityError(
                    "canonical projection is shorter than its durable cursor"
                )
            hasher = _verified_prefix(stream, state)
            truncated = size > state.byte_offset
            if truncated:
                stream.truncate(state.byte_offset)
            stream.seek(state.byte_offset)

            entries = self.store.contiguous_outbox(
                state.next_sequence,
                max_records=max_records,
            )
            next_sequence = state.next_sequence
            byte_offset = state.byte_offset
            for entry in entries:
                _validate_entry(entry, next_sequence, byte_offset)
                stream.write(entry.payload)
                stream.write(b"\n")
                hasher.update(entry.payload)
                hasher.update(b"\n")
                byte_offset += entry.byte_length + 1
                next_sequence += 1
                if entry.prefix_sha256 != hasher.hexdigest():
                    raise LedgerIntegrityError(
                        "outbox prefix digest does not match projected bytes"
                    )

            if entries or truncated or created:
                stream.flush()
                self._sync_file(descriptor)
            if entries:
                self.store.advance_projection(
                    state,
                    ProjectionState(
                        next_sequence=next_sequence,
                        byte_offset=byte_offset,
                        prefix_sha256=hasher.hexdigest(),
                    ),
                )
            return len(entries)
        finally:
            stream.close()


def build_manifest_bytes(store: RunStore) -> bytes:
    if not isinstance(store, RunStore):
        raise TypeError("store must be a RunStore")
    if store.status not in {RunStatus.PUBLISH_READY, RunStatus.COMPLETE}:
        raise RunStateError("manifest may be built only for a publish-ready run")
    counts = store.counts
    projection = store.projection_state
    if (
        projection.next_sequence != counts.occurrences
        or projection.byte_offset < 0
        or len(projection.prefix_sha256) != 64
    ):
        raise CompletionPreconditionError("canonical projection is not complete")
    counts_document = asdict(counts)
    if store.status is RunStatus.PUBLISH_READY:
        counts_document["operational_events"] += 1
    document = {
        "schema_version": store.run_spec.schema_version,
        "ledger_schema_version": LEDGER_SCHEMA_VERSION,
        "run_id": store.run_id,
        "run_spec": asdict(store.run_spec),
        "source": asdict(store.source_summary),
        "counts": counts_document,
        "canonical_output": {
            "record_count": projection.next_sequence,
            "byte_count": projection.byte_offset,
            "sha256": projection.prefix_sha256,
        },
    }
    return (
        json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def _manifest_matches(path: Path, expected: bytes) -> bool:
    try:
        value = path.lstat()
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(value.st_mode) or not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
        raise ArtifactExistsError(f"manifest path is occupied by an unsafe artifact: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(str(path), flags)
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            return stream.read() == expected
    finally:
        os.close(descriptor)


def _write_manifest_temporary(path: Path, payload: bytes) -> Path:
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(str(temporary), flags, 0o600)
    try:
        value = os.fstat(descriptor)
        if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
            raise ArtifactSafetyError("manifest temporary is not a private regular file")
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
    os.close(descriptor)
    return temporary


def publish_manifest(store: RunStore) -> Path:
    if not isinstance(store, RunStore):
        raise TypeError("store must be a RunStore")
    if store.status is not RunStatus.PUBLISH_READY or store.manifest_recorded:
        raise ArtifactExistsError("manifest is already published or run is not publish-ready")
    payload = build_manifest_bytes(store)
    path = store.generation_path / store.MANIFEST_FILENAME
    digest = hashlib.sha256(payload).hexdigest()

    if os.path.lexists(str(path)):
        if _manifest_matches(path, payload):
            store.record_manifest(len(payload), digest)
            return path
        raise ArtifactExistsError(f"manifest already exists: {path}")

    temporary = _write_manifest_temporary(path, payload)
    try:
        try:
            os.link(
                str(temporary),
                str(path),
                src_dir_fd=None,
                dst_dir_fd=None,
                follow_symlinks=False,
            )
        except FileExistsError as error:
            raise ArtifactExistsError(f"manifest already exists: {path}") from error
        os.chmod(str(path), 0o600)
        _sync_directory(path.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    _sync_directory(path.parent)
    store.record_manifest(len(payload), digest)
    return path
