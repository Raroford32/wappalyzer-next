import errno
import hashlib
import json
import os
import sqlite3
import stat
from contextlib import contextmanager
from dataclasses import asdict, replace
from pathlib import Path

import pytest

import wappalyzer.runstore as runstore_module
from wappalyzer.models import (
    CANONICAL_SCHEMA_VERSION,
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
    RunLifecycle,
    RunSpec,
    RunStatus,
    StageName,
    StageResult,
    StageStatus,
    StaleClaimError,
    TLSMetadata,
    TLSTrust,
    TargetOccurrence,
    Technology,
    canonical_json_bytes,
)
from wappalyzer.output import CanonicalProjector, publish_manifest
from wappalyzer.runstore import (
    AcquiredGeneration,
    ArtifactSafetyError,
    CompletionPreconditionError,
    EndpointClaim,
    GenerationLockedError,
    GenerationRepository,
    IngestionStateError,
    LedgerIntegrityError,
    ProjectionState,
    RunStateError,
    RunStore,
    RunStoreError,
    SQLiteSettings,
    SourceChangedError,
)


def _sha256(value):
    return hashlib.sha256(value).hexdigest()


def _run_spec(input_bytes, **changes):
    spec = RunSpec(
        input_sha256=_sha256(input_bytes),
        parser_version="endpoint-v1",
        schema_version=CANONICAL_SCHEMA_VERSION,
        serializer_version="canonical-json-v1",
        engine_version="complete-v1",
        redirect_policy_version="redirect-v1",
        tls_policy_version="tls-v1",
        retry_policy_version="retry-v1",
        timeout_policy_version="timeout-v1",
        evidence_limits_sha256="b" * 64,
        fingerprint_sha256="c" * 64,
        extension_sha256="d" * 64,
        runtime_identity="chromium-test",
        scanner_build="build-test",
    )
    return replace(spec, **changes)


def _success_empty(endpoint, protocol=Protocol.HTTP):
    requested_url = f"{protocol.value}://{endpoint.authority}/"
    return ProtocolResult(
        protocol=protocol,
        status=ProtocolStatus.SUCCESS_EMPTY,
        requested_url=requested_url,
        effective_url=requested_url,
        http_status=200,
        tls=TLSMetadata(
            present=protocol is Protocol.HTTPS,
            trust=(
                TLSTrust.TRUSTED
                if protocol is Protocol.HTTPS
                else TLSTrust.NOT_APPLICABLE
            ),
        ),
        stages=(
            StageResult(name=StageName.STATIC, status=StageStatus.SUCCESS_EMPTY),
            StageResult(name=StageName.BROWSER, status=StageStatus.SUCCESS_EMPTY),
        ),
    )


def _rich_result(endpoint):
    identity = ResponseIdentity(
        effective_url=f"https://{endpoint.authority}/final",
        http_status=200,
        content_sha256="a" * 64,
    )
    nginx = Technology(
        name="Nginx",
        version="1.25",
        confidence=90,
        categories=("Web servers", "Web servers"),
        groups=("Servers", "Servers"),
    )
    return ProtocolResult(
        protocol=Protocol.HTTPS,
        status=ProtocolStatus.PARTIAL,
        requested_url=f"https://{endpoint.authority}/",
        effective_url=identity.effective_url,
        http_status=identity.http_status,
        tls=TLSMetadata(
            present=True,
            trust=TLSTrust.TRUSTED,
            certificate_sha256="b" * 64,
        ),
        observation=ProtocolObservation.SINGLE,
        stages=(
            StageResult(
                name=StageName.STATIC,
                status=StageStatus.PARTIAL,
                error_codes=(FailureCode.SCAN_TIMEOUT, FailureCode.SCAN_TIMEOUT),
                response_identity=identity,
                technologies=(nginx,),
                truncations=(
                    EvidenceTruncation(
                        channel="html",
                        limits=(EvidenceLimit.BYTES, EvidenceLimit.COUNT),
                    ),
                ),
            ),
            StageResult(name=StageName.BROWSER, status=StageStatus.SUCCESS_EMPTY),
        ),
        technologies=(nginx,),
        error_codes=(FailureCode.SCAN_TIMEOUT, FailureCode.SCAN_TIMEOUT),
    )


def _executing_store(tmp_path, raw, name="generation"):
    source = tmp_path / f"{name}.txt"
    source.write_bytes(raw)
    store = RunStore.create(tmp_path / name, f"run-{name}", _run_spec(raw))
    store.ingest(source)
    store.verify_source(source)
    store.transition(RunStatus.EXECUTING)
    return store


def _terminal_store(tmp_path, raw=b"192.0.2.10:80\n", name="generation"):
    store = _executing_store(tmp_path, raw, name)
    while True:
        claim = store.claim_endpoint()
        if claim is None:
            break
        store.commit_endpoint(claim, (_success_empty(claim.endpoint),))
    store.transition(RunStatus.PROJECTING)
    return store


def _publish_ready_store(tmp_path, raw=b"", name="generation"):
    store = _terminal_store(tmp_path, raw, name)
    CanonicalProjector(store).project()
    store.mark_workers_closed()
    store.reconcile_counts()
    store.transition(RunStatus.PUBLISH_READY)
    return store


def _set_metadata(store, key, value):
    store._connection.execute(
        "UPDATE metadata SET value = ? WHERE key = ?",
        (str(value), key),
    )


def _close_and_mutate_metadata(store, key, value=None, delete=False):
    ledger = store.ledger_path
    store.close()
    connection = sqlite3.connect(str(ledger))
    try:
        if delete:
            connection.execute("DELETE FROM metadata WHERE key = ?", (key,))
        else:
            connection.execute(
                "UPDATE metadata SET value = ? WHERE key = ?",
                (value, key),
            )
        connection.commit()
    finally:
        connection.close()


def test_run_spec_and_summary_deserializers_reject_noncanonical_corruption():
    spec = _run_spec(b"")
    serialized = runstore_module._serialize_run_spec(spec)
    document = asdict(spec)

    with pytest.raises(TypeError, match="RunSpec"):
        runstore_module._serialize_run_spec(object())
    with pytest.raises(LedgerIntegrityError, match="valid JSON"):
        runstore_module._deserialize_run_spec("{")
    with pytest.raises(LedgerIntegrityError, match="fields"):
        runstore_module._deserialize_run_spec("[]")
    document["input_sha256"] = "invalid"
    with pytest.raises(LedgerIntegrityError, match="invalid"):
        runstore_module._deserialize_run_spec(
            json.dumps(document, sort_keys=True, separators=(",", ":"))
        )
    with pytest.raises(LedgerIntegrityError, match="canonically"):
        runstore_module._deserialize_run_spec(json.dumps(asdict(spec), indent=2))
    assert runstore_module._deserialize_run_spec(serialized) == spec

    with pytest.raises(LedgerIntegrityError, match="summary"):
        runstore_module._deserialize_summary("{")
    noncanonical_summary = json.dumps(
        {
            "file_sha256": _sha256(b""),
            "byte_count": 0,
            "physical_line_count": 0,
            "ignored_line_count": 0,
            "occurrence_count": 0,
            "valid_occurrence_count": 0,
            "invalid_occurrence_count": 0,
        },
        indent=2,
    )
    with pytest.raises(LedgerIntegrityError, match="canonical"):
        runstore_module._deserialize_summary(noncanonical_summary)


def test_source_identity_deserializer_rejects_invalid_and_noncanonical_payloads(tmp_path):
    value = tmp_path.stat()
    identity = runstore_module._identity_from_stat(tmp_path, value)
    serialized = runstore_module._canonical_json(asdict(identity))

    with pytest.raises(LedgerIntegrityError, match="identity"):
        runstore_module._deserialize_identity("{")
    with pytest.raises(LedgerIntegrityError, match="canonical"):
        runstore_module._deserialize_identity(json.dumps(asdict(identity), indent=2))
    assert runstore_module._deserialize_identity(serialized) == identity
    assert runstore_module._identity_matches(identity, tmp_path, value)


def test_protocol_serialization_round_trips_rich_ordered_evidence():
    endpoint = Endpoint("192.0.2.10", 443)
    rich = _rich_result(endpoint)
    empty = _success_empty(endpoint)

    payload = runstore_module._serialize_protocols((rich, empty))
    document = json.loads(payload)

    assert [item["protocol"] for item in document] == ["http", "https"]
    assert document[1]["tls"]["certificate_sha256"] == "b" * 64
    assert document[1]["stages"][0]["response_identity"]["http_status"] == 200
    assert document[1]["stages"][0]["technologies"][0]["categories"] == ["Web servers"]
    assert document[1]["stages"][0]["truncations"][0]["limits"] == ["count", "bytes"]
    assert runstore_module._deserialize_protocols(payload) == (empty, rich)


def test_protocol_deserializer_rejects_structural_and_canonical_corruption():
    endpoint = Endpoint("192.0.2.10", 443)
    payload = runstore_module._serialize_protocols((_rich_result(endpoint),))
    document = json.loads(payload)

    with pytest.raises(LedgerIntegrityError, match="not an object"):
        runstore_module._protocol_from_document([])
    broken_tls = dict(document[0], tls=[])
    with pytest.raises(LedgerIntegrityError, match="payload is invalid"):
        runstore_module._protocol_from_document(broken_tls)
    broken_collections = dict(document[0], stages={}, technologies=[])
    with pytest.raises(LedgerIntegrityError, match="payload is invalid"):
        runstore_module._protocol_from_document(broken_collections)
    missing_protocol = dict(document[0])
    del missing_protocol["protocol"]
    with pytest.raises(LedgerIntegrityError, match="payload is invalid"):
        runstore_module._protocol_from_document(missing_protocol)

    with pytest.raises(LedgerIntegrityError, match="UTF-8 JSON"):
        runstore_module._deserialize_protocols(b"\xff")
    with pytest.raises(LedgerIntegrityError, match="not an array"):
        runstore_module._deserialize_protocols(b"{}")
    duplicate = json.dumps([document[0], document[0]], sort_keys=True, separators=(",", ":"))
    with pytest.raises(LedgerIntegrityError, match="duplicate"):
        runstore_module._deserialize_protocols(duplicate.encode())
    with pytest.raises(LedgerIntegrityError, match="canonically"):
        runstore_module._deserialize_protocols(json.dumps(document, indent=2).encode())


def test_private_directory_and_file_guards_reject_missing_and_aliased_artifacts(tmp_path):
    missing = tmp_path / "missing"
    with pytest.raises(ArtifactSafetyError, match="does not exist"):
        runstore_module._require_private_directory(missing, create=False)

    regular = tmp_path / "regular"
    regular.write_bytes(b"value")
    with pytest.raises(ArtifactSafetyError, match="real directory"):
        runstore_module._require_private_directory(regular, create=False)
    with pytest.raises(ArtifactSafetyError, match="does not exist"):
        runstore_module._assert_regular_private_file(missing)

    alias = tmp_path / "alias"
    os.link(regular, alias)
    with pytest.raises(ArtifactSafetyError, match="unalias"):
        runstore_module._assert_regular_private_file(alias)
    assert regular.read_bytes() == b"value"


def test_create_private_file_validates_existing_io_failures_and_descriptor(
    tmp_path,
    monkeypatch,
):
    existing = tmp_path / "existing"
    existing.write_bytes(b"immutable")
    with pytest.raises(ArtifactSafetyError, match="already exists"):
        runstore_module._create_private_file(existing)

    def alias_failure(_path, _flags, _mode):
        raise OSError(errno.ELOOP, "alias")

    monkeypatch.setattr(runstore_module.os, "open", alias_failure)
    with pytest.raises(ArtifactSafetyError, match="unsafe artifact"):
        runstore_module._create_private_file(tmp_path / "alias")

    def storage_failure(_path, _flags, _mode):
        raise OSError(errno.EIO, "storage")

    monkeypatch.setattr(runstore_module.os, "open", storage_failure)
    with pytest.raises(OSError, match="storage"):
        runstore_module._create_private_file(tmp_path / "failed")


def test_create_private_file_rejects_nonregular_descriptor_and_closes_it(
    tmp_path,
    monkeypatch,
):
    path = tmp_path / "ledger"
    original_fstat = os.fstat
    descriptor_seen = None

    def nonregular_fstat(descriptor):
        nonlocal descriptor_seen
        descriptor_seen = descriptor
        value = original_fstat(descriptor)
        return os.stat_result(
            (
                stat.S_IFDIR | 0o700,
                value.st_ino,
                value.st_dev,
                1,
                value.st_uid,
                value.st_gid,
                value.st_size,
                value.st_atime,
                value.st_mtime,
                value.st_ctime,
            )
        )

    monkeypatch.setattr(runstore_module.os, "fstat", nonregular_fstat)

    with pytest.raises(ArtifactSafetyError, match="private regular file"):
        runstore_module._create_private_file(path)

    with pytest.raises(OSError):
        original_fstat(descriptor_seen)


def test_private_file_hash_supports_platform_without_nofollow(tmp_path, monkeypatch):
    path = tmp_path / "artifact"
    payload = b"x" * (runstore_module._HASH_CHUNK_BYTES + 13)
    path.write_bytes(payload)
    monkeypatch.delattr(runstore_module.os, "O_NOFOLLOW")

    assert runstore_module._file_sha256(path) == (len(payload), _sha256(payload))
    created = tmp_path / "created"
    runstore_module._create_private_file(created)
    assert stat.S_IMODE(created.stat().st_mode) == 0o600


def test_transaction_rolls_back_all_mutations_on_base_exception():
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.execute("CREATE TABLE facts(value INTEGER)")

    with pytest.raises(KeyboardInterrupt):
        with runstore_module._transaction(connection):
            connection.execute("INSERT INTO facts VALUES (1)")
            raise KeyboardInterrupt

    assert connection.execute("SELECT * FROM facts").fetchall() == []
    connection.close()


def test_create_validates_run_id_and_closes_partial_connection(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="run_id"):
        RunStore.create(tmp_path / "invalid", "", _run_spec(b""))

    class FailingConnection:
        def __init__(self):
            self.closed = False

        def executescript(self, _schema):
            raise sqlite3.OperationalError("injected schema failure")

        def close(self):
            self.closed = True

    connection = FailingConnection()
    settings = SQLiteSettings("wal", True, "full")
    monkeypatch.setattr(
        RunStore,
        "_connect",
        staticmethod(lambda _path: (connection, settings)),
    )

    with pytest.raises(sqlite3.OperationalError, match="schema failure"):
        RunStore.create(tmp_path / "partial", "run", _run_spec(b""))

    assert connection.closed is True


def test_create_preserves_connect_failure_without_unbound_cleanup(tmp_path, monkeypatch):
    def fail_connect(_path):
        raise sqlite3.OperationalError("injected connect failure")

    monkeypatch.setattr(RunStore, "_connect", staticmethod(fail_connect))

    with pytest.raises(sqlite3.OperationalError, match="connect failure"):
        RunStore.create(tmp_path / "generation", "run", _run_spec(b""))


@pytest.mark.parametrize(
    ("key", "value", "delete", "message"),
    [
        ("status", None, True, "incomplete"),
        ("schema_version", "not-an-integer", False, "schema version is invalid"),
        ("schema_version", "999", False, "unsupported"),
        ("run_spec", "{", False, "valid JSON"),
        ("run_id", "", False, "run ID is empty"),
    ],
)
def test_open_rejects_corrupt_required_metadata(tmp_path, key, value, delete, message):
    store = RunStore.create(tmp_path / "generation", "run", _run_spec(b""))
    _close_and_mutate_metadata(store, key, value, delete)

    with pytest.raises(LedgerIntegrityError, match=message):
        RunStore.open(tmp_path / "generation")


@pytest.mark.parametrize(("key", "value"), [("status", "unknown"), ("epoch", "NaN")])
def test_open_rejects_invalid_lifecycle_scalars(tmp_path, key, value):
    store = RunStore.create(tmp_path / "generation", "run", _run_spec(b""))
    _close_and_mutate_metadata(store, key, value)

    with pytest.raises(ValueError):
        RunStore.open(tmp_path / "generation")


def test_open_rejects_foreign_key_corruption(tmp_path):
    raw = b"192.0.2.10:80\n"
    source = tmp_path / "targets"
    source.write_bytes(raw)
    store = RunStore.create(tmp_path / "generation", "run", _run_spec(raw))
    store.ingest(source)
    ledger = store.ledger_path
    store.close()
    connection = sqlite3.connect(str(ledger))
    try:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute("UPDATE occurrences SET endpoint_id = 999")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(LedgerIntegrityError, match="foreign-key"):
        RunStore.open(tmp_path / "generation")


def test_open_closes_partial_state_when_connect_itself_fails(tmp_path, monkeypatch):
    generation = tmp_path / "generation"
    generation.mkdir()
    (generation / RunStore.LEDGER_FILENAME).write_bytes(b"ledger")

    def fail_connect(_path):
        raise sqlite3.OperationalError("injected open failure")

    monkeypatch.setattr(RunStore, "_connect", staticmethod(fail_connect))
    with pytest.raises(sqlite3.OperationalError, match="open failure"):
        RunStore.open(generation)


@pytest.mark.parametrize(
    ("journal_mode", "foreign_keys", "synchronous"),
    [
        ("delete", True, 2),
        ("wal", False, 2),
        ("wal", True, 1),
        ("wal", True, 99),
    ],
)
def test_connect_rejects_unenforced_sqlite_durability(
    tmp_path,
    monkeypatch,
    journal_mode,
    foreign_keys,
    synchronous,
):
    class Result:
        def __init__(self, value):
            self.value = value

        def fetchone(self):
            return (self.value,)

    class Connection:
        def __init__(self):
            self.row_factory = None
            self.closed = False

        def execute(self, sql):
            if sql == "PRAGMA journal_mode=WAL":
                return Result(journal_mode)
            if sql == "PRAGMA foreign_keys":
                return Result(int(foreign_keys))
            if sql == "PRAGMA synchronous":
                return Result(synchronous)
            return Result(None)

        def close(self):
            self.closed = True

    connection = Connection()
    monkeypatch.setattr(
        runstore_module.sqlite3,
        "connect",
        lambda *_args, **_kwargs: connection,
    )

    with pytest.raises(RunStoreError, match="durability"):
        RunStore._connect(tmp_path / "ledger")

    assert connection.closed is True


def test_missing_projection_metadata_and_closed_store_are_detected(tmp_path):
    store = RunStore.create(tmp_path / "generation", "run", _run_spec(b""))
    store._connection.execute("DELETE FROM projection_state")
    with pytest.raises(LedgerIntegrityError, match="projection state"):
        _ = store.projection_state
    store.close()

    with pytest.raises(RunStoreError, match="closed"):
        _ = store.status
    store.close()


def test_missing_metadata_is_detected_by_read_and_update(tmp_path):
    store = RunStore.create(tmp_path / "generation", "run", _run_spec(b""))
    try:
        store._connection.execute("DELETE FROM metadata WHERE key = 'workers_closed'")
        with pytest.raises(LedgerIntegrityError, match="workers_closed"):
            store._metadata("workers_closed")
        with pytest.raises(LedgerIntegrityError, match="workers_closed"):
            RunStore._set_metadata(store._connection, "workers_closed", "1")
    finally:
        store.close()


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("status", "unknown"),
        ("epoch", "NaN"),
        ("resume_status", "unknown"),
        ("resume_status", None),
    ],
)
def test_lifecycle_rejects_corrupt_persisted_state(tmp_path, key, value):
    store = RunStore.create(tmp_path / "generation", "run", _run_spec(b""))
    try:
        if value is None:
            store._connection.execute("DELETE FROM metadata WHERE key = ?", (key,))
        else:
            _set_metadata(store, key, value)
        with pytest.raises(LedgerIntegrityError, match="lifecycle"):
            RunStore._lifecycle(store._connection)
    finally:
        store.close()


def test_failure_event_round_trips_failure_metadata(tmp_path):
    store = RunStore.create(tmp_path / "generation", "run", _run_spec(b""))
    failure = Failure(FailureCode.OUTPUT_FAILURE, FailureDisposition.RECOVERABLE)
    lifecycle = RunLifecycle(
        status=RunStatus.FAILED_RECOVERABLE,
        epoch=3,
        resume_status=RunStatus.PROJECTING,
        failure=failure,
    )
    try:
        with runstore_module._transaction(store._connection):
            RunStore._insert_event(store._connection, EventKind.RUN_FAILURE, lifecycle)

        event = list(store.iter_events())[-1]
        assert event.kind is EventKind.RUN_FAILURE
        assert event.failure == failure
        assert event.epoch == 3
    finally:
        store.close()


def test_ingest_rejects_missing_and_nonregular_sources(tmp_path):
    store = RunStore.create(tmp_path / "generation", "run", _run_spec(b""))
    try:
        with pytest.raises(SourceChangedError, match="cannot open"):
            store.ingest(tmp_path / "missing")
        with pytest.raises(SourceChangedError, match="regular file"):
            store.ingest("/dev/null")
        assert store.counts.occurrences == 0
    finally:
        store.close()


def test_ingest_rolls_back_if_lifecycle_changes_inside_transaction(tmp_path, monkeypatch):
    raw = b"192.0.2.10:80\n"
    source = tmp_path / "targets"
    source.write_bytes(raw)
    store = RunStore.create(tmp_path / "generation", "run", _run_spec(raw))
    original_transaction = runstore_module._transaction
    raced = False

    @contextmanager
    def raced_transaction(connection):
        nonlocal raced
        if connection is store._connection and not raced:
            raced = True
            RunStore._set_metadata(connection, "ingested", "1")
        with original_transaction(connection):
            yield

    monkeypatch.setattr(runstore_module, "_transaction", raced_transaction)
    try:
        with pytest.raises(IngestionStateError, match="already"):
            store.ingest(source)

        assert store.counts.occurrences == 0
        assert store._metadata("ingested") == "1"
    finally:
        store.close()


def test_ingest_rolls_back_if_source_disappears_during_parse(tmp_path, monkeypatch):
    raw = b"192.0.2.10:80\n"
    source = tmp_path / "targets"
    source.write_bytes(raw)
    store = RunStore.create(tmp_path / "generation", "run", _run_spec(raw))
    original_ingest = runstore_module.ingest_targets

    def disappearing_ingest(stream, callback):
        summary = original_ingest(stream, callback)
        source.unlink()
        return summary

    monkeypatch.setattr(runstore_module, "ingest_targets", disappearing_ingest)
    try:
        with pytest.raises(SourceChangedError, match="disappeared"):
            store.ingest(source)
        assert store.counts.occurrences == 0
    finally:
        store.close()


def test_ingest_rolls_back_if_source_changes_during_parse(tmp_path, monkeypatch):
    raw = b"192.0.2.10:80\n"
    source = tmp_path / "targets"
    source.write_bytes(raw)
    store = RunStore.create(tmp_path / "generation", "run", _run_spec(raw))
    original_ingest = runstore_module.ingest_targets

    def mutating_ingest(stream, callback):
        summary = original_ingest(stream, callback)
        source.write_bytes(b"192.0.2.11:80\n")
        return summary

    monkeypatch.setattr(runstore_module, "ingest_targets", mutating_ingest)
    try:
        with pytest.raises(SourceChangedError, match="changed"):
            store.ingest(source)
        assert store.counts.occurrences == 0
    finally:
        store.close()


def test_ingest_rejects_source_that_disagrees_with_run_spec(tmp_path):
    raw = b"192.0.2.10:80\n"
    source = tmp_path / "targets"
    source.write_bytes(raw)
    store = RunStore.create(tmp_path / "generation", "run", _run_spec(b"different"))
    try:
        with pytest.raises(SourceChangedError, match="changed"):
            store.ingest(source)
        assert store.counts.occurrences == 0
    finally:
        store.close()


def test_ingest_detects_endpoint_insert_that_did_not_persist(tmp_path):
    raw = b"192.0.2.10:80\n"
    source = tmp_path / "targets"
    source.write_bytes(raw)
    store = RunStore.create(tmp_path / "generation", "run", _run_spec(raw))
    store._connection.execute(
        """
        CREATE TRIGGER ignore_endpoint_insert
        BEFORE INSERT ON endpoint_work
        BEGIN
            SELECT RAISE(IGNORE);
        END
        """
    )
    try:
        with pytest.raises(LedgerIntegrityError, match="identity"):
            store.ingest(source)
        assert store.counts.occurrences == 0
    finally:
        store.close()


def test_verify_source_validates_phase_and_reopen_failure(tmp_path):
    raw = b"192.0.2.10:80\n"
    source = tmp_path / "targets"
    source.write_bytes(raw)
    store = RunStore.create(tmp_path / "generation", "run", _run_spec(raw))
    try:
        with pytest.raises(IngestionStateError, match="awaiting"):
            store.verify_source(source)
        store.ingest(source)
        source.unlink()
        with pytest.raises(SourceChangedError, match="cannot reopen"):
            store.verify_source(source)
    finally:
        store.close()


def test_verify_source_detects_disappearance_after_hash(tmp_path, monkeypatch):
    raw = b"192.0.2.10:80\n"
    source = tmp_path / "targets"
    source.write_bytes(raw)
    store = RunStore.create(tmp_path / "generation", "run", _run_spec(raw))
    store.ingest(source)
    original_hash = runstore_module._stream_sha256

    def hash_then_unlink(stream):
        result = original_hash(stream)
        source.unlink()
        return result

    monkeypatch.setattr(runstore_module, "_stream_sha256", hash_then_unlink)
    try:
        with pytest.raises(SourceChangedError, match="disappeared during verification"):
            store.verify_source(source)
        assert store.status is RunStatus.INGESTING
    finally:
        store.close()


def test_verify_source_detects_concurrent_verifier_before_ready_commit(
    tmp_path,
    monkeypatch,
):
    raw = b"192.0.2.10:80\n"
    source = tmp_path / "targets"
    source.write_bytes(raw)
    store = RunStore.create(tmp_path / "generation", "run", _run_spec(raw))
    store.ingest(source)
    original_hash = runstore_module._stream_sha256

    def hash_then_mark_verified(stream):
        result = original_hash(stream)
        _set_metadata(store, "source_verified", "1")
        return result

    monkeypatch.setattr(runstore_module, "_stream_sha256", hash_then_mark_verified)
    try:
        with pytest.raises(IngestionStateError, match="awaiting"):
            store.verify_source(source)
        assert store.status is RunStatus.INGESTING
    finally:
        store.close()


@pytest.mark.parametrize("mutation", ["disappear", "change"])
def test_verify_source_rechecks_path_inside_ready_transaction(
    tmp_path,
    monkeypatch,
    mutation,
):
    raw = b"192.0.2.10:80\n"
    source = tmp_path / "targets"
    source.write_bytes(raw)
    store = RunStore.create(tmp_path / "generation", "run", _run_spec(raw))
    store.ingest(source)
    original_stat = Path.stat
    source_stats = 0

    def changing_stat(path, *args, **kwargs):
        nonlocal source_stats
        if path == source:
            source_stats += 1
            if source_stats == 2:
                if mutation == "disappear":
                    source.unlink()
                    raise FileNotFoundError(str(source))
                source.write_bytes(b"192.0.2.11:80\n")
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", changing_stat)
    try:
        message = "disappeared during ready commit" if mutation == "disappear" else "changed"
        with pytest.raises(SourceChangedError, match=message):
            store.verify_source(source)
        assert store.status is RunStatus.INGESTING
    finally:
        store.close()


def test_frontier_cache_rebuilds_and_detects_missing_state(tmp_path):
    raw = b"invalid\n"
    source = tmp_path / "targets"
    source.write_bytes(raw)
    store = RunStore.create(tmp_path / "generation", "run", _run_spec(raw))
    store.ingest(source)
    try:
        store._outbox_cache = None
        cache = store._frontier_hash_cache(store._connection)
        assert cache.next_sequence == 1
        assert cache.byte_offset > 0

        store._connection.execute("DELETE FROM outbox_frontier")
        store._outbox_cache = None
        with pytest.raises(LedgerIntegrityError, match="frontier is missing"):
            store._frontier_hash_cache(store._connection)
    finally:
        store.close()


@pytest.mark.parametrize(
    ("assignment", "value", "message"),
    [
        ("byte_length", 1, "prefix metadata"),
        ("payload_sha256", "0" * 64, "prefix metadata"),
        ("output_offset", 1, "prefix metadata"),
        ("prefix_sha256", "0" * 64, "prefix digest"),
    ],
)
def test_frontier_cache_rejects_corrupt_committed_prefix(
    tmp_path,
    assignment,
    value,
    message,
):
    raw = b"invalid\n"
    source = tmp_path / "targets"
    source.write_bytes(raw)
    store = RunStore.create(tmp_path / "generation", "run", _run_spec(raw))
    store.ingest(source)
    try:
        store._connection.execute(
            f"UPDATE occurrence_outbox SET {assignment} = ? WHERE occurrence_sequence = 0",
            (value,),
        )
        store._outbox_cache = None
        with pytest.raises(LedgerIntegrityError, match=message):
            store._frontier_hash_cache(store._connection)
    finally:
        store.close()


def test_frontier_cache_rejects_sequence_gap_and_frontier_mismatch(tmp_path):
    raw = b"192.0.2.10:80\ninvalid\n"
    source = tmp_path / "targets"
    source.write_bytes(raw)
    store = RunStore.create(tmp_path / "generation", "run", _run_spec(raw))
    store.ingest(source)
    try:
        entry = list(store.iter_occurrence_outbox())[0]
        store._connection.execute(
            """
            UPDATE occurrence_outbox
            SET output_offset = 0, prefix_sha256 = ?
            WHERE occurrence_sequence = 1
            """,
            (_sha256(entry.payload + b"\n"),),
        )
        store._connection.execute(
            """
            UPDATE outbox_frontier
            SET next_sequence = 2, byte_offset = ?, prefix_sha256 = ?
            """,
            (entry.byte_length + 1, _sha256(entry.payload + b"\n")),
        )
        store._outbox_cache = None
        with pytest.raises(LedgerIntegrityError, match="prefix metadata"):
            store._frontier_hash_cache(store._connection)

        store._connection.execute(
            "UPDATE occurrence_outbox SET occurrence_sequence = 0 WHERE occurrence_sequence = 1"
        )
        store._connection.execute(
            "UPDATE outbox_frontier SET next_sequence = 1, byte_offset = byte_offset + 1"
        )
        with pytest.raises(LedgerIntegrityError, match="frontier does not match"):
            store._frontier_hash_cache(store._connection)
    finally:
        store.close()


@pytest.mark.parametrize("corruption", ["payload", "committed_metadata", "update_race"])
def test_outbox_frontier_advance_rolls_back_corrupt_or_raced_prefix(
    tmp_path,
    corruption,
):
    raw = b"192.0.2.10:80\ninvalid\n"
    source = tmp_path / "targets"
    source.write_bytes(raw)
    store = RunStore.create(tmp_path / "generation", "run", _run_spec(raw))
    store.ingest(source)
    store.verify_source(source)
    store.transition(RunStatus.EXECUTING)
    claim = store.claim_endpoint()
    assert claim is not None
    if corruption == "payload":
        store._connection.execute(
            "UPDATE occurrence_outbox SET byte_length = 1 WHERE occurrence_sequence = 1"
        )
    elif corruption == "committed_metadata":
        store._connection.execute(
            """
            UPDATE occurrence_outbox
            SET output_offset = 0, prefix_sha256 = ?
            WHERE occurrence_sequence = 1
            """,
            ("0" * 64,),
        )
    else:
        store._connection.execute(
            """
            CREATE TRIGGER ignore_prefix_update
            BEFORE UPDATE OF output_offset, prefix_sha256 ON occurrence_outbox
            BEGIN
                SELECT RAISE(IGNORE);
            END
            """
        )
    try:
        message = {
            "payload": "payload metadata",
            "committed_metadata": "uncommitted",
            "update_race": "not exclusive",
        }[corruption]
        with pytest.raises(LedgerIntegrityError, match=message):
            store.commit_endpoint(claim, (_success_empty(claim.endpoint),))

        assert store.counts.terminal_occurrences == 1
        assert store.counts.active_claims == 1
    finally:
        store.close()


def test_contiguous_outbox_validates_arguments_frontier_and_gap(tmp_path):
    store = _executing_store(tmp_path, b"invalid\n")
    try:
        with pytest.raises(ValueError, match="start_sequence"):
            store.contiguous_outbox(True)
        with pytest.raises(ValueError, match="max_records"):
            store.contiguous_outbox(0, max_records=0)
        assert store.contiguous_outbox(1) == ()
        assert len(store.contiguous_outbox(0, max_records=1)) == 1

        store._connection.execute("UPDATE outbox_frontier SET next_sequence = 2")
        with pytest.raises(LedgerIntegrityError, match="sequence gap"):
            store.contiguous_outbox(0)
        store._connection.execute("DELETE FROM outbox_frontier")
        with pytest.raises(LedgerIntegrityError, match="frontier is missing"):
            store.contiguous_outbox(0)
    finally:
        store.close()


def test_claim_detects_nonexclusive_pending_update(tmp_path):
    store = _executing_store(tmp_path, b"192.0.2.10:80\n")
    store._connection.execute(
        """
        CREATE TRIGGER ignore_claim_update
        BEFORE UPDATE OF state ON endpoint_work
        WHEN NEW.state = 'claimed'
        BEGIN
            SELECT RAISE(IGNORE);
        END
        """
    )
    try:
        with pytest.raises(RunStateError, match="raced"):
            store.claim_endpoint()
        assert store.counts.pending_endpoints == 1
    finally:
        store.close()


def test_commit_endpoint_validates_claim_results_and_lifecycle(tmp_path):
    store = _executing_store(tmp_path, b"192.0.2.10:80\n")
    claim = store.claim_endpoint()
    assert claim is not None
    result = _success_empty(claim.endpoint)
    try:
        with pytest.raises(TypeError, match="EndpointClaim"):
            store.commit_endpoint(object(), ())
        with pytest.raises(TypeError, match="ProtocolResult"):
            store.commit_endpoint(claim, (object(),))
        with pytest.raises(ValueError, match="one result"):
            store.commit_endpoint(claim, (result, result))

        store.interrupt()
        with pytest.raises(RunStateError, match="executing"):
            store.commit_endpoint(claim, (result,))
    finally:
        store.close()


@pytest.mark.parametrize("race", ["occurrence", "endpoint"])
def test_commit_endpoint_rolls_back_terminalization_races(tmp_path, race):
    store = _executing_store(tmp_path, b"192.0.2.10:80\n")
    claim = store.claim_endpoint()
    assert claim is not None
    if race == "occurrence":
        store._connection.execute(
            """
            CREATE TRIGGER ignore_occurrence_terminal
            BEFORE UPDATE OF terminal ON occurrences
            BEGIN
                SELECT RAISE(IGNORE);
            END
            """
        )
    else:
        store._connection.execute(
            """
            CREATE TRIGGER ignore_endpoint_terminal
            BEFORE UPDATE OF state ON endpoint_work
            WHEN NEW.state = 'terminal'
            BEGIN
                SELECT RAISE(IGNORE);
            END
            """
        )
    try:
        error = LedgerIntegrityError if race == "occurrence" else StaleClaimError
        with pytest.raises(error):
            store.commit_endpoint(claim, (_success_empty(claim.endpoint),))

        assert store.counts.terminal_occurrences == 0
        assert store.counts.occurrence_outbox == 0
        assert store.counts.active_claims == 1
    finally:
        store.close()


def test_endpoint_results_detect_missing_digest_and_payload_corruption(tmp_path):
    store = _executing_store(tmp_path, b"192.0.2.10:80\n")
    claim = store.claim_endpoint()
    assert claim is not None
    store.commit_endpoint(claim, (_rich_result(claim.endpoint),))
    try:
        assert store.endpoint_protocol_results(9999) == ()
        store._connection.execute(
            "UPDATE endpoint_results SET payload_sha256 = ? WHERE endpoint_id = ?",
            ("0" * 64, claim.endpoint_id),
        )
        with pytest.raises(LedgerIntegrityError, match="digest"):
            store.endpoint_protocol_results(claim.endpoint_id)

        payload = b"{}"
        store._connection.execute(
            """
            UPDATE endpoint_results
            SET payload = ?, payload_sha256 = ?
            WHERE endpoint_id = ?
            """,
            (payload, _sha256(payload), claim.endpoint_id),
        )
        with pytest.raises(LedgerIntegrityError, match="not an array"):
            store.endpoint_protocol_results(claim.endpoint_id)
    finally:
        store.close()


def test_transitions_enforce_types_source_verification_and_fallthrough(tmp_path):
    raw = b""
    source = tmp_path / "targets"
    source.write_bytes(raw)
    store = RunStore.create(tmp_path / "generation", "run", _run_spec(raw))
    try:
        with pytest.raises(TypeError, match="RunStatus"):
            store.transition("ready")
        with pytest.raises(CompletionPreconditionError, match="verified"):
            store.transition(RunStatus.READY)

        store.ingest(source)
        store.verify_source(source)
        _set_metadata(store, "source_verified", "0")
        with pytest.raises(CompletionPreconditionError, match="verified"):
            store.transition(RunStatus.EXECUTING)
        _set_metadata(store, "source_verified", "1")

        with pytest.raises(Exception, match="cannot transition"):
            store.transition(RunStatus.READY)
    finally:
        store.close()


def test_execution_completion_requires_outbox_frontier(tmp_path):
    store = _executing_store(tmp_path, b"invalid\n")
    try:
        store._connection.execute("DELETE FROM outbox_frontier")
        with pytest.raises(CompletionPreconditionError, match="execution"):
            store.transition(RunStatus.PROJECTING)
    finally:
        store.close()


def test_publish_ready_requires_safe_matching_canonical_file(tmp_path):
    store = _terminal_store(tmp_path, b"")
    try:
        store.mark_workers_closed()
        store.reconcile_counts()
        with pytest.raises(CompletionPreconditionError, match="missing or unsafe"):
            store.transition(RunStatus.PUBLISH_READY)

        canonical = store.generation_path / store.CANONICAL_FILENAME
        canonical.write_bytes(b"corrupt")
        with pytest.raises(CompletionPreconditionError, match="does not match"):
            store.transition(RunStatus.PUBLISH_READY)

        canonical.unlink()
        victim = tmp_path / "victim"
        victim.write_bytes(b"")
        os.link(victim, canonical)
        with pytest.raises(CompletionPreconditionError, match="missing or unsafe"):
            store.transition(RunStatus.PUBLISH_READY)
        assert victim.read_bytes() == b""
    finally:
        store.close()


def test_completion_requires_recorded_existing_matching_manifest(tmp_path):
    store = _publish_ready_store(tmp_path)
    try:
        with pytest.raises(CompletionPreconditionError, match="not been published"):
            store.transition(RunStatus.COMPLETE)

        expected = b"manifest\n"
        _set_metadata(store, "manifest_byte_count", len(expected))
        _set_metadata(store, "manifest_sha256", _sha256(expected))
        with pytest.raises(CompletionPreconditionError, match="missing or unsafe"):
            store.transition(RunStatus.COMPLETE)

        path = store.generation_path / store.MANIFEST_FILENAME
        path.write_bytes(b"different")
        with pytest.raises(CompletionPreconditionError, match="does not match"):
            store.transition(RunStatus.COMPLETE)
    finally:
        store.close()


def test_resume_rejects_interrupted_ledger_that_retained_claim(tmp_path):
    store = _executing_store(tmp_path, b"192.0.2.10:80\n")
    claim = store.claim_endpoint()
    assert claim is not None
    interrupted = RunLifecycle(
        status=RunStatus.INTERRUPTED,
        epoch=claim.token.epoch,
        resume_status=RunStatus.EXECUTING,
    )
    RunStore._persist_lifecycle(store._connection, interrupted)
    try:
        with pytest.raises(LedgerIntegrityError, match="active claim"):
            store.resume()
        assert store.status is RunStatus.INTERRUPTED
    finally:
        store.close()


def test_workers_can_only_close_while_projecting(tmp_path):
    store = RunStore.create(tmp_path / "generation", "run", _run_spec(b""))
    try:
        with pytest.raises(RunStateError, match="projecting"):
            store.mark_workers_closed()
    finally:
        store.close()


def test_reconcile_detects_foreign_key_and_terminal_fact_corruption(tmp_path):
    foreign = _executing_store(tmp_path, b"192.0.2.10:80\n", "foreign")
    try:
        foreign._connection.execute("PRAGMA foreign_keys=OFF")
        foreign._connection.execute(
            """
            INSERT INTO endpoint_results(endpoint_id, payload, payload_sha256)
            VALUES (999, ?, ?)
            """,
            (b"[]", _sha256(b"[]")),
        )
        foreign._connection.execute("PRAGMA foreign_keys=ON")
        with pytest.raises(LedgerIntegrityError, match="foreign-key"):
            foreign.reconcile_counts()
    finally:
        foreign.close()

    occurrence = _executing_store(tmp_path, b"invalid\n", "occurrence")
    try:
        occurrence._connection.execute("DELETE FROM occurrence_outbox")
        with pytest.raises(LedgerIntegrityError, match="terminal facts"):
            occurrence.reconcile_counts()
    finally:
        occurrence.close()

    endpoint = _executing_store(tmp_path, b"192.0.2.10:80\n", "endpoint")
    try:
        endpoint._connection.execute(
            "UPDATE endpoint_work SET state = 'terminal' WHERE endpoint_id = 1"
        )
        with pytest.raises(LedgerIntegrityError, match="terminal facts"):
            endpoint.reconcile_counts()
    finally:
        endpoint.close()


def test_verify_outbox_accepts_uncommitted_gap_and_cached_endpoint_results(tmp_path):
    gap = _executing_store(tmp_path, b"192.0.2.10:80\ninvalid\n", "gap")
    try:
        gap._verify_outbox()
    finally:
        gap.close()

    duplicate = _executing_store(
        tmp_path,
        b"192.0.2.10:80\n192.0.2.10:80\n",
        "duplicate",
    )
    claim = duplicate.claim_endpoint()
    assert claim is not None
    duplicate.commit_endpoint(claim, (_success_empty(claim.endpoint),))
    try:
        duplicate._verify_outbox()
    finally:
        duplicate.close()


@pytest.mark.parametrize(
    ("corruption", "message"),
    [
        ("frontier_missing", "frontier is missing"),
        ("payload_length", "payload metadata"),
        ("nonterminal_occurrence", "no terminal occurrence"),
        ("result_missing", "no endpoint result"),
        ("result_digest", "result digest"),
        ("canonical_payload", "not the canonical"),
        ("output_offset", "output offset"),
        ("prefix_digest", "prefix digest"),
        ("sequence_metadata", "sequence metadata"),
        ("frontier_mismatch", "frontier is inconsistent"),
    ],
)
def test_verify_outbox_rejects_corruption(tmp_path, corruption, message):
    if corruption in {"result_missing", "result_digest"}:
        raw = b"192.0.2.10:80\n"
    elif corruption == "sequence_metadata":
        raw = b"192.0.2.10:80\ninvalid\n"
    else:
        raw = b"invalid\n"
    store = _executing_store(tmp_path, raw)
    if raw.startswith(b"192") and corruption != "sequence_metadata":
        claim = store.claim_endpoint()
        assert claim is not None
        store.commit_endpoint(claim, (_success_empty(claim.endpoint),))
    try:
        if corruption == "frontier_missing":
            store._connection.execute("DELETE FROM outbox_frontier")
        elif corruption == "payload_length":
            store._connection.execute("UPDATE occurrence_outbox SET byte_length = 1")
        elif corruption == "nonterminal_occurrence":
            store._connection.execute(
                "UPDATE occurrences SET terminal = 0, status = NULL"
            )
        elif corruption == "result_missing":
            store._connection.execute("DELETE FROM endpoint_results")
        elif corruption == "result_digest":
            store._connection.execute(
                "UPDATE endpoint_results SET payload_sha256 = ?",
                ("0" * 64,),
            )
        elif corruption == "canonical_payload":
            payload = canonical_json_bytes(
                CanonicalRecord(
                    run_id="wrong-run",
                    occurrence=list(store.iter_occurrences())[0],
                    status=OccurrenceStatus.INVALID_INPUT,
                    error_codes=(FailureCode.INVALID_INPUT,),
                )
            )
            store._connection.execute(
                """
                UPDATE occurrence_outbox
                SET payload = ?, byte_length = ?, payload_sha256 = ?
                """,
                (payload, len(payload), _sha256(payload)),
            )
        elif corruption == "output_offset":
            store._connection.execute("UPDATE occurrence_outbox SET output_offset = 1")
        elif corruption == "prefix_digest":
            store._connection.execute(
                "UPDATE occurrence_outbox SET prefix_sha256 = ?",
                ("0" * 64,),
            )
        elif corruption == "sequence_metadata":
            store._connection.execute(
                """
                UPDATE occurrence_outbox
                SET output_offset = 0, prefix_sha256 = ?
                WHERE occurrence_sequence = 1
                """,
                ("0" * 64,),
            )
        else:
            store._connection.execute(
                "UPDATE outbox_frontier SET byte_offset = byte_offset + 1"
            )

        with pytest.raises(LedgerIntegrityError, match=message):
            store._verify_outbox()
    finally:
        store.close()


def test_advance_projection_validates_types_order_fencing_and_outbox_bounds(tmp_path):
    store = _executing_store(tmp_path, b"invalid\n")
    initial = store.projection_state
    entry = store.contiguous_outbox(0)[0]
    valid = ProjectionState(1, entry.byte_length + 1, entry.prefix_sha256)
    try:
        with pytest.raises(TypeError, match="ProjectionState"):
            store.advance_projection(object(), initial)
        with pytest.raises(ValueError, match="backwards"):
            store.advance_projection(
                ProjectionState(1, 1, "a" * 64),
                initial,
            )
        with pytest.raises(RunStateError, match="concurrently"):
            store.advance_projection(ProjectionState(0, 0, "0" * 64), valid)
        with pytest.raises(LedgerIntegrityError, match="exceeds"):
            store.advance_projection(initial, ProjectionState(2, 2, "a" * 64))
        with pytest.raises(LedgerIntegrityError, match="empty"):
            store.advance_projection(initial, ProjectionState(0, 1, "a" * 64))
        store.advance_projection(initial, valid)
        assert store.projection_state == valid
    finally:
        store.close()


@pytest.mark.parametrize(
    ("byte_count", "digest", "message"),
    [
        (True, "a" * 64, "byte_count"),
        (-1, "a" * 64, "byte_count"),
        (0, object(), "sha256"),
        (0, "A" * 64, "sha256"),
    ],
)
def test_record_manifest_validates_publication_metadata(
    tmp_path,
    byte_count,
    digest,
    message,
):
    store = RunStore.create(tmp_path / "generation", "run", _run_spec(b""))
    try:
        with pytest.raises(ValueError, match=message):
            store.record_manifest(byte_count, digest)
    finally:
        store.close()


def test_record_manifest_enforces_lifecycle_single_record_and_file_digest(tmp_path):
    store = RunStore.create(tmp_path / "generation", "run", _run_spec(b""))
    try:
        with pytest.raises(RunStateError, match="publish-ready"):
            store.record_manifest(0, _sha256(b""))
    finally:
        store.close()

    store = _publish_ready_store(tmp_path, name="publish")
    path = store.generation_path / store.MANIFEST_FILENAME
    path.write_bytes(b"manifest")
    try:
        with pytest.raises(LedgerIntegrityError, match="does not match"):
            store.record_manifest(1, _sha256(b"x"))
        payload = path.read_bytes()
        store.record_manifest(len(payload), _sha256(payload))
        with pytest.raises(RunStateError, match="already"):
            store.record_manifest(len(payload), _sha256(payload))
    finally:
        store.close()


def test_source_summary_requires_completed_ingestion(tmp_path):
    store = RunStore.create(tmp_path / "generation", "run", _run_spec(b""))
    try:
        with pytest.raises(RunStateError, match="not been ingested"):
            _ = store.source_summary
    finally:
        store.close()


def test_generation_lock_guards_platform_alias_contention_and_fsync(
    tmp_path,
    monkeypatch,
):
    lock = tmp_path / "generation.lock"
    monkeypatch.delattr(runstore_module.os, "O_NOFOLLOW")
    descriptor = runstore_module._open_generation_lock(lock)
    try:
        assert lock.read_text().startswith(f"pid={os.getpid()}")
        with pytest.raises(GenerationLockedError, match="locked"):
            runstore_module._open_generation_lock(lock)
    finally:
        runstore_module._close_generation_lock(descriptor)
    lock.unlink()

    victim = tmp_path / "victim"
    victim.write_bytes(b"safe")
    os.link(victim, lock)
    with pytest.raises(ArtifactSafetyError, match="unalias"):
        runstore_module._open_generation_lock(lock)
    lock.unlink()
    assert victim.read_bytes() == b"safe"

    def fail_sync(_descriptor):
        raise OSError("injected lock fsync failure")

    monkeypatch.setattr(runstore_module.os, "fsync", fail_sync)
    with pytest.raises(OSError, match="fsync"):
        runstore_module._open_generation_lock(lock)


@pytest.mark.parametrize("error_number", [errno.ELOOP, errno.EIO])
def test_generation_lock_maps_alias_error_and_preserves_storage_error(
    tmp_path,
    monkeypatch,
    error_number,
):
    def fail_open(_path, _flags, _mode):
        raise OSError(error_number, "open failure")

    monkeypatch.setattr(runstore_module.os, "open", fail_open)
    expected = ArtifactSafetyError if error_number == errno.ELOOP else OSError
    with pytest.raises(expected):
        runstore_module._open_generation_lock(tmp_path / "lock")


def test_generation_lock_reports_missing_fcntl_and_close_still_releases_fd(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(runstore_module, "fcntl", None)
    with pytest.raises(ArtifactSafetyError, match="locking is unavailable"):
        runstore_module._open_generation_lock(tmp_path / "lock")

    descriptor = os.open(tmp_path / "plain", os.O_CREAT | os.O_RDWR, 0o600)
    runstore_module._close_generation_lock(descriptor)
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_acquired_generation_closes_lock_even_if_store_close_fails(monkeypatch, tmp_path):
    released = []

    class FailingStore:
        def close(self):
            raise OSError("injected close failure")

    monkeypatch.setattr(
        runstore_module,
        "_close_generation_lock",
        lambda descriptor: released.append(descriptor),
    )
    acquired = AcquiredGeneration(tmp_path, FailingStore(), 42, resumed=False)

    with pytest.raises(OSError, match="close failure"):
        acquired.close()

    assert released == [42]


def test_acquired_generation_rejects_enter_after_close(tmp_path):
    store = RunStore.create(tmp_path / "generation", "run", _run_spec(b""))
    descriptor = runstore_module._open_generation_lock(
        tmp_path / "generation" / RunStore.LOCK_FILENAME
    )
    acquired = AcquiredGeneration(tmp_path / "generation", store, descriptor, False)
    acquired.close()
    acquired.close()

    with pytest.raises(RunStoreError, match="lease is closed"):
        acquired.__enter__()


def test_repository_rejects_unsafe_generation_entry(tmp_path):
    root = tmp_path / "artifacts"
    root.mkdir()
    (root / "generation-not-a-directory").write_bytes(b"unsafe")

    with pytest.raises(ArtifactSafetyError, match="real directory"):
        GenerationRepository(root).acquire(_run_spec(b""))


def test_repository_releases_lock_when_existing_generation_is_corrupt(tmp_path):
    repository = GenerationRepository(tmp_path / "artifacts")
    spec = _run_spec(b"")
    acquired = repository.acquire(spec)
    generation = acquired.path
    acquired.close()
    connection = sqlite3.connect(str(generation / RunStore.LEDGER_FILENAME))
    connection.execute("UPDATE metadata SET value = '' WHERE key = 'run_id'")
    connection.commit()
    connection.close()

    with pytest.raises(LedgerIntegrityError, match="run ID"):
        repository.acquire(spec)

    descriptor = runstore_module._open_generation_lock(
        generation / RunStore.LOCK_FILENAME
    )
    runstore_module._close_generation_lock(descriptor)


def test_repository_resumes_interrupted_and_abandoned_claim_generations(tmp_path):
    raw = b"192.0.2.10:80\n"
    spec = _run_spec(raw)
    interrupted_repository = GenerationRepository(tmp_path / "interrupted")
    acquired = interrupted_repository.acquire(spec)
    acquired.store.interrupt()
    interrupted_path = acquired.path
    acquired.close()

    with interrupted_repository.acquire(spec) as resumed:
        assert resumed.path == interrupted_path
        assert resumed.resumed is True
        assert resumed.store.status is RunStatus.INGESTING

    source = tmp_path / "targets"
    source.write_bytes(raw)
    claimed_repository = GenerationRepository(tmp_path / "claimed")
    acquired = claimed_repository.acquire(spec)
    acquired.store.ingest(source)
    acquired.store.verify_source(source)
    acquired.store.transition(RunStatus.EXECUTING)
    stale = acquired.store.claim_endpoint()
    assert stale is not None
    claimed_path = acquired.path
    acquired.close()

    with claimed_repository.acquire(spec) as resumed:
        assert resumed.path == claimed_path
        current = resumed.store.claim_endpoint()
        assert current is not None
        assert current.endpoint_id == stale.endpoint_id
        assert current.token == ClaimToken(
            epoch=stale.token.epoch + 1,
            attempt=stale.token.attempt + 1,
        )


def test_repository_rejects_nonresumable_failed_generation(tmp_path):
    repository = GenerationRepository(tmp_path / "artifacts")
    spec = _run_spec(b"")
    acquired = repository.acquire(spec)
    path = acquired.path
    _set_metadata(acquired.store, "status", RunStatus.FAILED_FATAL.value)
    acquired.close()

    with pytest.raises(RunStateError, match="cannot be resumed"):
        repository.acquire(spec)

    descriptor = runstore_module._open_generation_lock(path / RunStore.LOCK_FILENAME)
    runstore_module._close_generation_lock(descriptor)


def test_repository_releases_new_generation_lock_if_store_creation_fails(
    tmp_path,
    monkeypatch,
):
    repository = GenerationRepository(tmp_path / "artifacts")

    def fail_create(*_args, **_kwargs):
        raise sqlite3.OperationalError("injected creation failure")

    monkeypatch.setattr(RunStore, "create", fail_create)
    with pytest.raises(sqlite3.OperationalError, match="creation failure"):
        repository.acquire(_run_spec(b""))

    generations = list(repository.root.glob("generation-*"))
    assert len(generations) == 1
    descriptor = runstore_module._open_generation_lock(
        generations[0] / RunStore.LOCK_FILENAME
    )
    runstore_module._close_generation_lock(descriptor)


def test_generation_directory_retries_collision_and_caps_attempts(tmp_path, monkeypatch):
    root = tmp_path / "artifacts"
    root.mkdir()
    repository = GenerationRepository(root)
    original_mkdir = Path.mkdir
    calls = 0

    def collide_once(path, *args, **kwargs):
        nonlocal calls
        if path.parent == root:
            calls += 1
            if calls == 1:
                raise FileExistsError(str(path))
        return original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", collide_once)
    generation = repository._create_generation_directory()
    assert generation.is_dir()
    assert calls == 2

    def always_collide(path, *args, **kwargs):
        if path.parent == root:
            raise FileExistsError(str(path))
        return original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", always_collide)
    with pytest.raises(RunStoreError, match="allocate"):
        repository._create_generation_directory()
