import asyncio
import hashlib
import json

import pytest

from wappalyzer.models import (
    CANONICAL_SCHEMA_VERSION,
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
from wappalyzer.pipeline import BoundedScanPipeline
from wappalyzer.runstore import RunStore


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
    raw = b"".join(f"192.0.2.{index + 1}:8080\n".encode() for index in range(count))
    source = tmp_path / "targets.txt"
    source.write_bytes(raw)
    store = RunStore.create(tmp_path / "generation", "run-pipeline", run_spec(raw))
    store.ingest(source)
    store.verify_source(source)
    return store


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
