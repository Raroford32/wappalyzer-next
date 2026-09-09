import hashlib
import json
import stat

import pytest

from wappalyzer.models import (
    CANONICAL_SCHEMA_VERSION,
    Protocol,
    ProtocolResult,
    ProtocolStatus,
    RunSpec,
    RunStatus,
    StageName,
    StageResult,
    StageStatus,
    TLSMetadata,
    TLSTrust,
)
from wappalyzer.output import (
    ArtifactExistsError,
    CanonicalProjector,
    ProjectionIntegrityError,
    build_manifest_bytes,
    publish_manifest,
)
from wappalyzer.runstore import (
    LEDGER_SCHEMA_VERSION,
    CompletionPreconditionError,
    GenerationRepository,
    RunStore,
)


def _sha256(value):
    return hashlib.sha256(value).hexdigest()


def _run_spec(input_bytes):
    return RunSpec(
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


def _success_empty(endpoint):
    requested_url = f"http://{endpoint.authority}/"
    return ProtocolResult(
        protocol=Protocol.HTTP,
        status=ProtocolStatus.SUCCESS_EMPTY,
        requested_url=requested_url,
        effective_url=requested_url,
        http_status=200,
        tls=TLSMetadata(present=False, trust=TLSTrust.NOT_APPLICABLE),
        stages=(
            StageResult(name=StageName.STATIC, status=StageStatus.SUCCESS_EMPTY),
            StageResult(name=StageName.BROWSER, status=StageStatus.SUCCESS_EMPTY),
        ),
    )


def _executing_store(tmp_path, raw, name="generation"):
    source = tmp_path / f"{name}.txt"
    source.write_bytes(raw)
    store = RunStore.create(
        tmp_path / name,
        run_id=f"run-{name}",
        spec=_run_spec(raw),
    )
    store.ingest(source)
    store.verify_source(source)
    store.transition(RunStatus.EXECUTING)
    return store


def _terminal_store(tmp_path, raw, name="generation"):
    store = _executing_store(tmp_path, raw, name)
    while True:
        claim = store.claim_endpoint()
        if claim is None:
            break
        store.commit_endpoint(claim, (_success_empty(claim.endpoint),))
    store.transition(RunStatus.PROJECTING)
    return store


def test_projector_waits_for_contiguous_outbox_and_writes_canonical_order(tmp_path):
    raw = b"192.0.2.10:80\n192.0.2.20:80\n"
    store = _executing_store(tmp_path, raw)
    try:
        first = store.claim_endpoint()
        second = store.claim_endpoint()
        assert first is not None
        assert second is not None
        store.commit_endpoint(second, (_success_empty(second.endpoint),))

        projector = CanonicalProjector(store)
        assert projector.project() == 0
        assert projector.path.read_bytes() == b""
        assert store.projection_state.next_sequence == 0

        store.commit_endpoint(first, (_success_empty(first.endpoint),))
        store.transition(RunStatus.PROJECTING)
        entries = list(store.iter_occurrence_outbox())
        expected = b"".join(entry.payload + b"\n" for entry in entries)

        assert projector.project() == 2
        assert projector.path.read_bytes() == expected
        assert stat.S_IMODE(projector.path.stat().st_mode) == 0o600
        assert store.projection_state.next_sequence == 2
        assert store.projection_state.byte_offset == len(expected)
        assert store.projection_state.prefix_sha256 == _sha256(expected)
    finally:
        store.close()


def test_zero_records_create_a_zero_byte_projection(tmp_path):
    store = _terminal_store(tmp_path, b"")
    try:
        projector = CanonicalProjector(store)

        assert projector.project() == 0
        assert projector.path.exists()
        assert projector.path.read_bytes() == b""
        assert store.projection_state.next_sequence == 0
        assert store.projection_state.byte_offset == 0
    finally:
        store.close()


def test_projector_truncates_torn_tail_but_rejects_corrupt_durable_middle(tmp_path):
    raw = b"192.0.2.10:80\n192.0.2.20:80\n"
    store = _terminal_store(tmp_path, raw)
    try:
        entries = list(store.iter_occurrence_outbox())
        projector = CanonicalProjector(store)

        assert projector.project(max_records=1) == 1
        durable_prefix = entries[0].payload + b"\n"
        assert projector.path.read_bytes() == durable_prefix
        with projector.path.open("ab") as stream:
            stream.write(entries[1].payload[: len(entries[1].payload) // 2])

        resumed = CanonicalProjector(store)
        assert resumed.project() == 1
        expected = b"".join(entry.payload + b"\n" for entry in entries)
        assert resumed.path.read_bytes() == expected
        durable_state = store.projection_state

        with resumed.path.open("r+b") as stream:
            stream.seek(0)
            assert stream.read(1) == b"{"
            stream.seek(0)
            stream.write(b"[")
        corrupted = resumed.path.read_bytes()

        with pytest.raises(ProjectionIntegrityError):
            CanonicalProjector(store).project()

        assert resumed.path.read_bytes() == corrupted
        assert store.projection_state == durable_state
    finally:
        store.close()


def test_projection_cursor_advances_only_after_file_sync(tmp_path):
    raw = b"192.0.2.10:80\n"
    store = _terminal_store(tmp_path, raw)

    def fail_sync(_file_descriptor):
        raise OSError("injected sync failure")

    try:
        initial_state = store.projection_state
        projector = CanonicalProjector(store, sync_file=fail_sync)

        with pytest.raises(OSError, match="injected sync failure"):
            projector.project()

        assert store.projection_state == initial_state

        recovered = CanonicalProjector(store)
        assert recovered.project() == 1
        entry = list(store.iter_occurrence_outbox())[0]
        expected = entry.payload + b"\n"
        assert recovered.path.read_bytes() == expected
        assert store.projection_state.next_sequence == 1
        assert store.projection_state.byte_offset == len(expected)
    finally:
        store.close()


def test_completion_requires_projection_reconciliation_workers_and_manifest(tmp_path):
    raw = b"192.0.2.10:80\n"
    store = _terminal_store(tmp_path, raw)
    try:
        with pytest.raises(CompletionPreconditionError):
            store.transition(RunStatus.PUBLISH_READY)

        projector = CanonicalProjector(store)
        projector.project()
        with pytest.raises(CompletionPreconditionError):
            store.transition(RunStatus.PUBLISH_READY)

        store.mark_workers_closed()
        with pytest.raises(CompletionPreconditionError):
            store.transition(RunStatus.PUBLISH_READY)

        counts = store.reconcile_counts()
        assert counts.terminal_occurrences == counts.occurrences == 1
        assert store.projection_state.next_sequence == counts.occurrences
        store.transition(RunStatus.PUBLISH_READY)

        first_manifest = build_manifest_bytes(store)
        assert first_manifest == build_manifest_bytes(store)
        manifest = json.loads(first_manifest)
        output_bytes = projector.path.read_bytes()
        assert manifest["schema_version"] == CANONICAL_SCHEMA_VERSION
        assert manifest["ledger_schema_version"] == LEDGER_SCHEMA_VERSION
        assert manifest["run_id"] == store.run_id
        assert manifest["counts"]["occurrences"] == 1
        assert manifest["counts"]["terminal_occurrences"] == 1
        assert manifest["canonical_output"] == {
            "record_count": 1,
            "byte_count": len(output_bytes),
            "sha256": _sha256(output_bytes),
        }
        assert "timestamp" not in first_manifest.decode("utf-8")

        manifest_path = publish_manifest(store)
        assert manifest_path.read_bytes() == first_manifest
        assert stat.S_IMODE(manifest_path.stat().st_mode) == 0o600
        store.transition(RunStatus.COMPLETE)
        completed_bytes = manifest_path.read_bytes()

        with pytest.raises(ArtifactExistsError):
            publish_manifest(store)
        assert manifest_path.read_bytes() == completed_bytes
    finally:
        store.close()


def test_completed_generation_is_preserved_and_next_acquire_creates_new(tmp_path):
    raw = b""
    source = tmp_path / "targets.txt"
    source.write_bytes(raw)
    repository = GenerationRepository(tmp_path / "artifacts")
    spec = _run_spec(raw)

    with repository.acquire(spec) as generation:
        completed_path = generation.path
        store = generation.store
        store.ingest(source)
        store.verify_source(source)
        store.transition(RunStatus.EXECUTING)
        store.transition(RunStatus.PROJECTING)
        projector = CanonicalProjector(store)
        assert projector.project() == 0
        store.mark_workers_closed()
        store.reconcile_counts()
        store.transition(RunStatus.PUBLISH_READY)
        manifest_path = publish_manifest(store)
        store.transition(RunStatus.COMPLETE)
        completed_manifest = manifest_path.read_bytes()
        completed_output = projector.path.read_bytes()

    with repository.acquire(spec) as next_generation:
        assert next_generation.resumed is False
        assert next_generation.path != completed_path
        assert completed_path.exists()
        assert manifest_path.read_bytes() == completed_manifest
        assert projector.path.read_bytes() == completed_output
