import asyncio
import hashlib
import json

import pytest

from wappalyzer.models import (
    CANONICAL_SCHEMA_VERSION,
    Endpoint,
    FailureCode,
    Protocol,
    ProtocolResult,
    ProtocolStatus,
    RunSpec,
    RunStatus,
    TLSMetadata,
    TLSTrust,
)
from wappalyzer.output import CanonicalProjector
from wappalyzer.pipeline import BoundedScanPipeline, PipelineStats, _normalize_results
from wappalyzer.runstore import RunStateError, RunStore


def run_spec(input_bytes):
    digest = hashlib.sha256(input_bytes).hexdigest()
    return RunSpec(
        input_sha256=digest,
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


def protocol_results(endpoint):
    results = []
    for protocol in Protocol:
        url = f"{protocol.value}://{endpoint.authority}/"
        results.append(
            ProtocolResult(
                protocol=protocol,
                status=ProtocolStatus.SUCCESS_EMPTY,
                requested_url=url,
                effective_url=url,
                http_status=200,
                tls=TLSMetadata(
                    present=protocol is Protocol.HTTPS,
                    trust=(
                        TLSTrust.TRUSTED if protocol is Protocol.HTTPS else TLSTrust.NOT_APPLICABLE
                    ),
                ),
            )
        )
    return tuple(results)


def prepared_store(tmp_path, count):
    tmp_path.mkdir(parents=True, exist_ok=True)
    raw = b"".join(f"192.0.2.{index + 1}:8080\n".encode() for index in range(count))
    source = tmp_path / "targets.txt"
    source.write_bytes(raw)
    store = RunStore.create(tmp_path / "generation", "run-pipeline", run_spec(raw))
    store.ingest(source)
    store.verify_source(source)
    return store


def prepare_projecting_store(store):
    store.transition(RunStatus.EXECUTING)
    while True:
        claim = store.claim_endpoint()
        if claim is None:
            break
        store.commit_endpoint(claim, protocol_results(claim.endpoint))
    store.transition(RunStatus.PROJECTING)


def test_pipeline_validates_constructor_contract(tmp_path):
    store = prepared_store(tmp_path / "primary", 1)
    other_store = prepared_store(tmp_path / "other", 1)
    projector = CanonicalProjector(store)

    async def scan(endpoint):
        return protocol_results(endpoint)

    with pytest.raises(TypeError, match="RunStore"):
        BoundedScanPipeline(
            store=object(),
            scan_endpoint=scan,
            projector=projector,
            max_inflight=1,
        )
    with pytest.raises(TypeError, match="scan_endpoint"):
        BoundedScanPipeline(
            store=store,
            scan_endpoint=None,
            projector=projector,
            max_inflight=1,
        )
    with pytest.raises(TypeError, match="CanonicalProjector"):
        BoundedScanPipeline(
            store=store,
            scan_endpoint=scan,
            projector=object(),
            max_inflight=1,
        )
    with pytest.raises(ValueError, match="same run store"):
        BoundedScanPipeline(
            store=store,
            scan_endpoint=scan,
            projector=CanonicalProjector(other_store),
            max_inflight=1,
        )
    for invalid_inflight in (True, "1", 0):
        with pytest.raises(ValueError, match="max_inflight"):
            BoundedScanPipeline(
                store=store,
                scan_endpoint=scan,
                projector=projector,
                max_inflight=invalid_inflight,
            )
    with pytest.raises(TypeError, match="close_workers"):
        BoundedScanPipeline(
            store=store,
            scan_endpoint=scan,
            projector=projector,
            max_inflight=1,
            close_workers=object(),
        )
    for invalid_batch in (True, "1", 0):
        with pytest.raises(ValueError, match="projection_batch_records"):
            BoundedScanPipeline(
                store=store,
                scan_endpoint=scan,
                projector=projector,
                max_inflight=1,
                projection_batch_records=invalid_batch,
            )

    store.close()
    other_store.close()


@pytest.mark.parametrize("invalid_value", [None, "results", b"results", bytearray(b"results")])
def test_pipeline_normalization_fails_closed_on_non_result_collections(invalid_value):
    endpoint = Endpoint("192.0.2.1", 8080)
    results = _normalize_results(endpoint, invalid_value)

    assert [result.protocol for result in results] == list(Protocol)
    assert all(result.error_codes == (FailureCode.WORKER_FAILURE,) for result in results)


def test_pipeline_normalization_fails_closed_on_invalid_or_duplicate_members():
    endpoint = Endpoint("192.0.2.1", 8080)
    http_result = protocol_results(endpoint)[0]

    for invalid_value in ([object()], (http_result, http_result)):
        results = _normalize_results(endpoint, invalid_value)
        assert [result.protocol for result in results] == list(Protocol)
        assert all(result.error_codes == (FailureCode.WORKER_FAILURE,) for result in results)


def test_pipeline_normalization_preserves_partial_results_and_fills_missing_protocol():
    endpoint = Endpoint("192.0.2.1", 8080)
    http_result = protocol_results(endpoint)[0]

    results = _normalize_results(endpoint, (http_result,))

    assert results[0] is http_result
    assert results[1].protocol is Protocol.HTTPS
    assert results[1].error_codes == (FailureCode.WORKER_FAILURE,)


def test_pipeline_bounds_claims_keeps_workers_busy_and_projects_in_input_order(tmp_path):
    store = prepared_store(tmp_path, 20)
    active = 0
    maximum_active = 0
    fast_completed_before_first = 0
    first_complete = False

    async def scan(endpoint):
        nonlocal active
        nonlocal fast_completed_before_first
        nonlocal first_complete
        nonlocal maximum_active
        active += 1
        maximum_active = max(maximum_active, active)
        try:
            if endpoint.address == "192.0.2.1":
                await asyncio.sleep(0.15)
                first_complete = True
            else:
                await asyncio.sleep(0.005)
                if not first_complete:
                    fast_completed_before_first += 1
            return protocol_results(endpoint)
        finally:
            active -= 1

    pipeline = BoundedScanPipeline(
        store=store,
        scan_endpoint=scan,
        projector=CanonicalProjector(store),
        max_inflight=4,
    )
    stats = asyncio.run(pipeline.run())

    assert maximum_active == 4
    assert stats.max_inflight_observed == 4
    assert fast_completed_before_first >= 8
    assert store.status is RunStatus.PUBLISH_READY
    documents = [
        json.loads(line)
        for line in (store.generation_path / store.CANONICAL_FILENAME)
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert [document["occurrence"]["sequence"] for document in documents] == list(range(20))
    store.close()


def test_pipeline_converts_worker_exceptions_to_terminal_protocol_outcomes(tmp_path):
    store = prepared_store(tmp_path, 2)

    async def scan(endpoint):
        if endpoint.address == "192.0.2.1":
            raise RuntimeError("sentinel secret must not be persisted")
        return protocol_results(endpoint)

    pipeline = BoundedScanPipeline(
        store=store,
        scan_endpoint=scan,
        projector=CanonicalProjector(store),
        max_inflight=2,
    )
    asyncio.run(pipeline.run())

    failed = store.endpoint_protocol_results(1)
    assert {result.protocol for result in failed} == set(Protocol)
    assert all(result.status is ProtocolStatus.INDETERMINATE for result in failed)
    assert all(result.error_codes == (FailureCode.WORKER_FAILURE,) for result in failed)
    assert b"sentinel secret" not in store.ledger_path.read_bytes()
    assert store.counts.terminal_occurrences == 2
    store.close()


def test_pipeline_cancellation_interrupts_and_releases_every_claim(tmp_path):
    store = prepared_store(tmp_path, 8)
    started = asyncio.Event()

    async def scan(_endpoint):
        started.set()
        await asyncio.sleep(30)
        raise AssertionError("cancelled worker continued")

    pipeline = BoundedScanPipeline(
        store=store,
        scan_endpoint=scan,
        projector=CanonicalProjector(store),
        max_inflight=3,
    )

    async def cancel_run():
        task = asyncio.create_task(pipeline.run())
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(cancel_run())

    assert store.status is RunStatus.INTERRUPTED
    assert store.counts.active_claims == 0
    assert store.counts.pending_endpoints == 8

    async def resumed_scan(endpoint):
        return protocol_results(endpoint)

    resumed_pipeline = BoundedScanPipeline(
        store=store,
        scan_endpoint=resumed_scan,
        projector=CanonicalProjector(store),
        max_inflight=3,
    )
    stats = asyncio.run(resumed_pipeline.run())

    assert stats.endpoints_committed == 8
    assert store.status is RunStatus.PUBLISH_READY
    assert store.counts.pending_endpoints == 0
    store.close()


def test_pipeline_propagates_self_cancelling_worker_and_interrupts_run(tmp_path):
    store = prepared_store(tmp_path, 1)

    async def scan(_endpoint):
        raise asyncio.CancelledError

    pipeline = BoundedScanPipeline(
        store=store,
        scan_endpoint=scan,
        projector=CanonicalProjector(store),
        max_inflight=1,
    )

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(pipeline.run())

    assert store.status is RunStatus.INTERRUPTED
    assert store.counts.active_claims == 0
    store.close()


def test_pipeline_empty_run_closes_async_workers_and_reaches_publish_ready(tmp_path):
    store = prepared_store(tmp_path, 0)
    close_calls = 0

    async def scan(_endpoint):
        raise AssertionError("empty run claimed endpoint work")

    async def close_workers():
        nonlocal close_calls
        close_calls += 1

    pipeline = BoundedScanPipeline(
        store=store,
        scan_endpoint=scan,
        projector=CanonicalProjector(store),
        max_inflight=1,
        close_workers=close_workers,
    )
    stats = asyncio.run(pipeline.run())

    assert stats == PipelineStats(0, 0, 0)
    assert close_calls == 1
    assert store.status is RunStatus.PUBLISH_READY
    store.close()


def test_pipeline_finishes_projection_when_resumed_after_execution(tmp_path):
    store = prepared_store(tmp_path, 2)
    prepare_projecting_store(store)
    close_called = False

    def close_workers():
        nonlocal close_called
        close_called = True

    pipeline = BoundedScanPipeline(
        store=store,
        scan_endpoint=lambda _endpoint: pytest.fail("projecting run restarted execution"),
        projector=CanonicalProjector(store),
        max_inflight=1,
        close_workers=close_workers,
    )
    stats = asyncio.run(pipeline.run())

    assert stats.endpoints_committed == 0
    assert stats.projected_records == 2
    assert not close_called
    assert store.status is RunStatus.PUBLISH_READY
    store.close()


def test_pipeline_publish_ready_rerun_is_idempotent(tmp_path):
    store = prepared_store(tmp_path, 1)

    async def scan(endpoint):
        return protocol_results(endpoint)

    pipeline = BoundedScanPipeline(
        store=store,
        scan_endpoint=scan,
        projector=CanonicalProjector(store),
        max_inflight=1,
    )
    asyncio.run(pipeline.run())

    assert asyncio.run(pipeline.run()) == PipelineStats(0, 0, 0)
    assert store.status is RunStatus.PUBLISH_READY
    store.close()


def test_pipeline_rejects_store_before_ingestion_is_ready(tmp_path):
    store = RunStore.create(tmp_path / "generation", "run-pipeline", run_spec(b""))

    async def scan(endpoint):
        return protocol_results(endpoint)

    pipeline = BoundedScanPipeline(
        store=store,
        scan_endpoint=scan,
        projector=CanonicalProjector(store),
        max_inflight=1,
    )

    with pytest.raises(RunStateError, match="ingesting"):
        asyncio.run(pipeline.run())
    store.close()


def test_pipeline_cleanup_failure_interrupts_after_releasing_claims(tmp_path):
    store = prepared_store(tmp_path, 1)
    close_calls = 0

    async def scan(endpoint):
        return protocol_results(endpoint)

    def close_workers():
        nonlocal close_calls
        close_calls += 1
        raise RuntimeError("cleanup failed")

    pipeline = BoundedScanPipeline(
        store=store,
        scan_endpoint=scan,
        projector=CanonicalProjector(store),
        max_inflight=1,
        close_workers=close_workers,
    )

    with pytest.raises(RuntimeError, match="cleanup failed"):
        asyncio.run(pipeline.run())

    assert close_calls == 2
    assert store.status is RunStatus.INTERRUPTED
    assert store.counts.active_claims == 0
    store.close()


def test_pipeline_does_not_overwrite_interrupt_recorded_by_failing_projector(tmp_path):
    store = prepared_store(tmp_path, 1)

    async def scan(endpoint):
        return protocol_results(endpoint)

    class InterruptingProjector(CanonicalProjector):
        def project(self, max_records=None):
            self.store.interrupt()
            raise OSError("projection failed after durable interrupt")

    pipeline = BoundedScanPipeline(
        store=store,
        scan_endpoint=scan,
        projector=InterruptingProjector(store),
        max_inflight=1,
    )

    with pytest.raises(OSError, match="durable interrupt"):
        asyncio.run(pipeline.run())

    assert store.status is RunStatus.INTERRUPTED
    assert store.counts.active_claims == 0
    store.close()


def test_pipeline_rejects_unbounded_or_zero_admission(tmp_path):
    store = prepared_store(tmp_path, 1)

    async def scan(endpoint):
        return protocol_results(endpoint)

    with pytest.raises(ValueError):
        BoundedScanPipeline(
            store=store,
            scan_endpoint=scan,
            projector=CanonicalProjector(store),
            max_inflight=0,
        )
    store.close()
