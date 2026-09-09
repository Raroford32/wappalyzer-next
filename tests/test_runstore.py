import hashlib
import os
import stat
from dataclasses import replace

import pytest

from wappalyzer.models import (
    CANONICAL_SCHEMA_VERSION,
    CanonicalRecord,
    Endpoint,
    FailureCode,
    OccurrenceStatus,
    Protocol,
    ProtocolResult,
    ProtocolStatus,
    RunEvent,
    RunSpec,
    RunStatus,
    StageName,
    StageResult,
    StageStatus,
    StaleClaimError,
    TLSMetadata,
    TLSTrust,
    canonical_json_bytes,
)
from wappalyzer.runstore import (
    LEDGER_SCHEMA_VERSION,
    ArtifactSafetyError,
    CompletionPreconditionError,
    GenerationLockedError,
    GenerationRepository,
    IngestionStateError,
    RunStateError,
    RunStore,
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


def _ingest_and_verify(store, source):
    summary = store.ingest(source)
    store.verify_source(source)
    return summary


def _modify_same_size(path, original):
    path.write_bytes(original.replace(b"10", b"11", 1))


def _truncate(path, original):
    path.write_bytes(original[:-1])


def _append(path, original):
    path.write_bytes(original + b"192.0.2.99:80\n")


def _replace_same_content(path, original):
    replacement = path.with_name("replacement.txt")
    replacement.write_bytes(original)
    os.replace(str(replacement), str(path))


def test_create_and_reopen_private_versioned_wal_ledger(tmp_path):
    source_bytes = b"192.0.2.10:80\n"
    generation = tmp_path / "generation"
    spec = _run_spec(source_bytes)

    with RunStore.create(generation, run_id="run-01", spec=spec) as store:
        assert store.schema_version == LEDGER_SCHEMA_VERSION
        assert store.run_id == "run-01"
        assert store.run_spec == spec
        assert store.status is RunStatus.INGESTING
        assert store.sqlite_settings.journal_mode == "wal"
        assert store.sqlite_settings.foreign_keys is True
        assert store.sqlite_settings.synchronous == "full"
        assert stat.S_IMODE(generation.stat().st_mode) == 0o700
        assert stat.S_IMODE(store.ledger_path.stat().st_mode) == 0o600

    with RunStore.open(generation, expected_spec=spec) as reopened:
        assert reopened.schema_version == LEDGER_SCHEMA_VERSION
        assert reopened.run_id == "run-01"
        assert reopened.run_spec == spec
        assert reopened.sqlite_settings.journal_mode == "wal"
        assert reopened.sqlite_settings.foreign_keys is True
        assert reopened.sqlite_settings.synchronous == "full"


def test_ingest_preserves_occurrences_deduplicates_endpoint_work_and_outboxes_invalid(
    tmp_path,
):
    lines = [
        b"192.0.2.10:80\n",
        b" # ignored\n",
        b"192.0.2.10:80\n",
        b"not-an-endpoint\n",
    ]
    raw = b"".join(lines)
    source = tmp_path / "targets.txt"
    source.write_bytes(raw)

    with RunStore.create(
        tmp_path / "generation",
        run_id="run-duplicates",
        spec=_run_spec(raw),
    ) as store:
        summary = store.ingest(source)

        assert summary.occurrence_count == 3
        assert summary.valid_occurrence_count == 2
        assert summary.invalid_occurrence_count == 1
        occurrences = list(store.iter_occurrences())
        assert [item.sequence for item in occurrences] == [0, 1, 2]
        assert [item.line_number for item in occurrences] == [1, 3, 4]
        assert (
            len({(item.sequence, item.line_number, item.byte_offset) for item in occurrences}) == 3
        )
        assert occurrences[0].endpoint == occurrences[1].endpoint

        counts = store.counts
        assert counts.occurrences == 3
        assert counts.endpoint_work == 1
        assert counts.terminal_occurrences == 1
        assert counts.pending_endpoints == 1
        assert counts.occurrence_outbox == 1

        entry = list(store.iter_occurrence_outbox())[0]
        expected = canonical_json_bytes(
            CanonicalRecord(
                run_id="run-duplicates",
                occurrence=occurrences[2],
                status=OccurrenceStatus.INVALID_INPUT,
                error_codes=(FailureCode.INVALID_INPUT,),
            )
        )
        assert entry.occurrence_sequence == 2
        assert entry.payload == expected
        assert entry.byte_length == len(expected)
        assert entry.payload_sha256 == _sha256(expected)

        with pytest.raises(IngestionStateError):
            store.ingest(source)
        assert store.counts == counts

        verified = store.verify_source(source)
        assert verified == summary
        assert store.status is RunStatus.READY


@pytest.mark.parametrize(
    "mutation",
    [_modify_same_size, _truncate, _append, _replace_same_content],
    ids=["modified", "truncated", "appended", "replaced"],
)
def test_second_pass_rejects_changed_source_before_ready(tmp_path, mutation):
    raw = b"192.0.2.10:80\n192.0.2.20:443\n"
    source = tmp_path / "targets.txt"
    source.write_bytes(raw)

    with RunStore.create(
        tmp_path / "generation",
        run_id="run-source-check",
        spec=_run_spec(raw),
    ) as store:
        store.ingest(source)
        original_counts = store.counts
        mutation(source, raw)

        with pytest.raises(SourceChangedError):
            store.verify_source(source)

        assert store.status is RunStatus.INGESTING
        assert store.counts == original_counts
        with pytest.raises(RunStateError):
            store.claim_endpoint()


def test_claim_epoch_attempt_fencing_resets_interrupted_work_and_fans_out_once(tmp_path):
    raw = b"192.0.2.10:80\n192.0.2.10:80\n"
    source = tmp_path / "targets.txt"
    source.write_bytes(raw)

    with RunStore.create(
        tmp_path / "generation",
        run_id="run-claims",
        spec=_run_spec(raw),
    ) as store:
        _ingest_and_verify(store, source)
        store.transition(RunStatus.EXECUTING)

        stale = store.claim_endpoint()
        assert stale is not None
        assert stale.endpoint == Endpoint(address="192.0.2.10", port=80)
        assert stale.token.epoch == 0
        assert stale.token.attempt == 1
        assert store.counts.active_claims == 1

        store.interrupt()
        assert store.status is RunStatus.INTERRUPTED
        assert store.counts.active_claims == 0
        assert store.counts.pending_endpoints == 1

        store.resume()
        current = store.claim_endpoint()
        assert current is not None
        assert current.endpoint_id == stale.endpoint_id
        assert current.token.epoch == stale.token.epoch + 1
        assert current.token.attempt == stale.token.attempt + 1

        with pytest.raises(StaleClaimError):
            store.commit_endpoint(stale, (_success_empty(stale.endpoint),))
        assert store.counts.terminal_occurrences == 0

        assert store.commit_endpoint(current, (_success_empty(current.endpoint),)) == 2
        assert store.endpoint_protocol_results(current.endpoint_id) == (
            _success_empty(current.endpoint),
        )
        assert store.counts.terminal_occurrences == 2
        assert store.counts.occurrence_outbox == 2
        assert store.counts.active_claims == 0

        with pytest.raises(StaleClaimError):
            store.commit_endpoint(current, (_success_empty(current.endpoint),))
        assert store.counts.occurrence_outbox == 2

        expected = [
            canonical_json_bytes(
                CanonicalRecord(
                    run_id="run-claims",
                    occurrence=occurrence,
                    status=OccurrenceStatus.SUCCESS_EMPTY,
                    protocols=(_success_empty(current.endpoint),),
                )
            )
            for occurrence in store.iter_occurrences()
        ]
        entries = list(store.iter_occurrence_outbox())
        assert [entry.occurrence_sequence for entry in entries] == [0, 1]
        assert [entry.payload for entry in entries] == expected
        assert all(entry.payload_sha256 == _sha256(entry.payload) for entry in entries)
        prefix = b""
        for entry in entries:
            assert entry.output_offset == len(prefix)
            prefix += entry.payload + b"\n"
            assert entry.prefix_sha256 == _sha256(prefix)


def test_persisted_transitions_reconcile_derived_counts_and_keep_events_separate(tmp_path):
    raw = b"192.0.2.10:80\n192.0.2.20:80\n"
    source = tmp_path / "targets.txt"
    source.write_bytes(raw)

    with RunStore.create(
        tmp_path / "generation",
        run_id="run-lifecycle",
        spec=_run_spec(raw),
    ) as store:
        _ingest_and_verify(store, source)
        store.transition(RunStatus.EXECUTING)
        claim = store.claim_endpoint()
        assert claim is not None

        with pytest.raises(CompletionPreconditionError):
            store.transition(RunStatus.PROJECTING)

        store.interrupt()
        store.resume()
        while True:
            claim = store.claim_endpoint()
            if claim is None:
                break
            store.commit_endpoint(claim, (_success_empty(claim.endpoint),))

        counts = store.reconcile_counts()
        assert counts.occurrences == 2
        assert counts.endpoint_work == 2
        assert counts.terminal_occurrences == 2
        assert counts.pending_endpoints == 0
        assert counts.active_claims == 0
        assert counts.occurrence_outbox == 2

        events = list(store.iter_events())
        assert events
        assert all(isinstance(event, RunEvent) for event in events)
        assert [event.sequence for event in events] == list(range(len(events)))
        assert RunStatus.INTERRUPTED in {event.status for event in events}
        assert counts.operational_events == len(events)
        assert all(b"timestamp_ns" not in entry.payload for entry in store.iter_occurrence_outbox())

        store.transition(RunStatus.PROJECTING)
        store.mark_workers_closed()
        with pytest.raises(CompletionPreconditionError):
            store.transition(RunStatus.PUBLISH_READY)


def test_generation_selection_resumes_only_compatible_incomplete_and_locks_live_owner(
    tmp_path,
):
    repository = GenerationRepository(tmp_path / "artifacts")
    spec = _run_spec(b"")

    first = repository.acquire(spec)
    try:
        first_path = first.path
        assert first.resumed is False
        assert first.store.run_spec == spec
        with pytest.raises(GenerationLockedError):
            repository.acquire(spec)
    finally:
        first.close()

    with repository.acquire(spec) as resumed:
        assert resumed.resumed is True
        assert resumed.path == first_path

    incompatible_spec = replace(spec, engine_version="complete-v2")
    with repository.acquire(incompatible_spec) as incompatible:
        assert incompatible.resumed is False
        assert incompatible.path != first_path
        assert first_path.exists()


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks are unavailable")
def test_symlinked_ledger_artifact_is_rejected_without_touching_target(tmp_path):
    generation = tmp_path / "generation"
    generation.mkdir()
    victim = tmp_path / "victim.sqlite3"
    victim.write_bytes(b"do-not-touch")
    (generation / RunStore.LEDGER_FILENAME).symlink_to(victim)

    with pytest.raises(ArtifactSafetyError):
        RunStore.create(generation, run_id="run-unsafe", spec=_run_spec(b""))

    assert victim.read_bytes() == b"do-not-touch"
