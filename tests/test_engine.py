import asyncio

from wappalyzer.discovery import DiscoveryResult, DiscoveryState
from wappalyzer.engine import DirectScanRuntime, ExhaustiveEndpointScanner
from wappalyzer.models import (
    Endpoint,
    FailureCode,
    Protocol,
    ProtocolResult,
    ProtocolStatus,
    TLSMetadata,
    TLSTrust,
)
from wappalyzer.resources import ResourceSnapshot


def discovery(protocol, state, failure_code=None, trust=None):
    url = f"{protocol.value}://192.0.2.1:8443/"
    return DiscoveryResult(
        protocol=protocol,
        state=state,
        requested_url=url,
        http_status=200 if state is DiscoveryState.LIVE else None,
        tls=TLSMetadata(
            present=protocol is Protocol.HTTPS,
            trust=trust
            or (TLSTrust.TRUSTED if protocol is Protocol.HTTPS else TLSTrust.NOT_APPLICABLE),
        ),
        failure_code=failure_code,
    )


def completed(result):
    return ProtocolResult(
        protocol=result.protocol,
        status=ProtocolStatus.SUCCESS_EMPTY,
        requested_url=result.requested_url,
        effective_url=result.requested_url,
        http_status=200,
        tls=result.tls,
    )


def test_endpoint_scanner_runs_complete_profile_for_every_live_protocol():
    discoveries = (
        discovery(Protocol.HTTP, DiscoveryState.LIVE),
        discovery(
            Protocol.HTTPS,
            DiscoveryState.LIVE,
            FailureCode.TLS_UNTRUSTED,
            TLSTrust.UNTRUSTED,
        ),
    )
    completed_protocols = []

    async def complete_runner(result):
        completed_protocols.append((result.protocol, result.tls.trust))
        return completed(result)

    scanner = ExhaustiveEndpointScanner(
        discovery_runner=lambda _endpoint: discoveries,
        complete_runner=complete_runner,
        discovery_workers=2,
    )
    try:
        results = asyncio.run(scanner.scan(Endpoint("192.0.2.1", 8443)))
    finally:
        scanner.close()

    assert [result.protocol for result in results] == [Protocol.HTTP, Protocol.HTTPS]
    assert completed_protocols == [
        (Protocol.HTTP, TLSTrust.NOT_APPLICABLE),
        (Protocol.HTTPS, TLSTrust.UNTRUSTED),
    ]
    assert all(result.status is ProtocolStatus.SUCCESS_EMPTY for result in results)


def test_endpoint_scanner_preserves_nonlive_discovery_outcomes_without_suppression():
    discoveries = (
        discovery(
            Protocol.HTTP,
            DiscoveryState.UNAVAILABLE,
            FailureCode.UNREACHABLE,
        ),
        discovery(
            Protocol.HTTPS,
            DiscoveryState.INDETERMINATE,
            FailureCode.DISCOVERY_TIMEOUT,
            TLSTrust.INDETERMINATE,
        ),
    )

    async def forbidden_complete(_result):
        raise AssertionError("non-live protocol reached complete execution")

    scanner = ExhaustiveEndpointScanner(
        discovery_runner=lambda _endpoint: discoveries,
        complete_runner=forbidden_complete,
        discovery_workers=1,
    )
    try:
        results = asyncio.run(scanner.scan(Endpoint("192.0.2.1", 8443)))
    finally:
        scanner.close()

    assert [result.status for result in results] == [
        ProtocolStatus.UNAVAILABLE,
        ProtocolStatus.INDETERMINATE,
    ]
    assert [result.error_codes for result in results] == [
        (FailureCode.UNREACHABLE,),
        (FailureCode.DISCOVERY_TIMEOUT,),
    ]


def test_endpoint_scanner_fails_closed_on_duplicate_or_missing_discovery_results():
    duplicate = discovery(
        Protocol.HTTP,
        DiscoveryState.UNAVAILABLE,
        FailureCode.UNREACHABLE,
    )

    async def complete_runner(result):
        return completed(result)

    for malformed in ((duplicate,), (duplicate, duplicate)):
        scanner = ExhaustiveEndpointScanner(
            discovery_runner=lambda _endpoint, value=malformed: value,
            complete_runner=complete_runner,
            discovery_workers=1,
        )
        try:
            results = asyncio.run(scanner.scan(Endpoint("192.0.2.1", 8443)))
        finally:
            scanner.close()

        assert len(results) == 2
        assert all(result.status is ProtocolStatus.INDETERMINATE for result in results)
        assert all(result.error_codes == (FailureCode.WORKER_FAILURE,) for result in results)


def test_direct_runtime_derives_bounded_pipeline_admission_from_resource_plan():
    runtime = DirectScanRuntime(
        workers=20,
        resource_snapshot=ResourceSnapshot(
            cpu_count=4,
            memory_bytes=4 * 1024**3,
            file_descriptors=512,
            sockets=256,
            processes=128,
            shared_memory_bytes=2 * 1024**3,
            temp_bytes=8 * 1024**3,
            artifact_bytes=16 * 1024**3,
        ),
    )
    try:
        selected = runtime.resource_plan.selected
        assert runtime.max_inflight == (selected.discovery + selected.static + selected.browser)
        assert selected.discovery >= 1
        assert selected.static >= 1
        assert selected.browser >= 1
        assert runtime.browser_backend.blocked_resource_types == ()
    finally:
        asyncio.run(runtime.aclose())
