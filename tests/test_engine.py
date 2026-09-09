import asyncio
import threading

import pytest

import wappalyzer.engine as engine_module
from wappalyzer.core.transport import TransportLimits
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
from wappalyzer.resources import (
    ResourcePlan,
    ResourceProfile,
    ResourceRequest,
    ResourceSnapshot,
    WorkerCounts,
)


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


def resource_snapshot(**overrides):
    values = {
        "cpu_count": 4,
        "memory_bytes": 4 * 1024**3,
        "file_descriptors": 512,
        "sockets": 256,
        "processes": 128,
        "shared_memory_bytes": 2 * 1024**3,
        "temp_bytes": 8 * 1024**3,
        "artifact_bytes": 16 * 1024**3,
    }
    values.update(overrides)
    return ResourceSnapshot(**values)


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


def test_endpoint_scanner_validates_constructor_and_scan_contracts():
    async def complete_runner(result):
        return completed(result)

    with pytest.raises(TypeError, match="discovery_runner"):
        ExhaustiveEndpointScanner(
            discovery_runner=None,
            complete_runner=complete_runner,
            discovery_workers=1,
        )
    with pytest.raises(TypeError, match="complete_runner"):
        ExhaustiveEndpointScanner(
            discovery_runner=lambda _endpoint: (),
            complete_runner=None,
            discovery_workers=1,
        )
    for invalid_workers in (True, "1", 0):
        with pytest.raises(ValueError, match="positive integer"):
            ExhaustiveEndpointScanner(
                discovery_runner=lambda _endpoint: (),
                complete_runner=complete_runner,
                discovery_workers=invalid_workers,
            )

    scanner = ExhaustiveEndpointScanner(
        discovery_runner=lambda _endpoint: (),
        complete_runner=complete_runner,
        discovery_workers=1,
    )
    with pytest.raises(TypeError, match="Endpoint"):
        asyncio.run(scanner.scan("192.0.2.1:8443"))
    scanner.close()
    with pytest.raises(RuntimeError, match="closed"):
        asyncio.run(scanner.scan(Endpoint("192.0.2.1", 8443)))


@pytest.mark.parametrize("invalid_result", [object(), "wrong protocol"])
def test_endpoint_scanner_fails_closed_on_invalid_complete_results(invalid_result):
    discoveries = (
        discovery(Protocol.HTTP, DiscoveryState.LIVE),
        discovery(Protocol.HTTPS, DiscoveryState.UNAVAILABLE, FailureCode.UNREACHABLE),
    )

    async def complete_runner(result):
        if invalid_result == "wrong protocol":
            return completed(discovery(Protocol.HTTPS, DiscoveryState.LIVE))
        return invalid_result

    scanner = ExhaustiveEndpointScanner(
        discovery_runner=lambda _endpoint: discoveries,
        complete_runner=complete_runner,
        discovery_workers=1,
    )
    try:
        result = asyncio.run(scanner.scan(Endpoint("192.0.2.1", 8443)))[0]
    finally:
        scanner.close()

    assert result.protocol is Protocol.HTTP
    assert result.status is ProtocolStatus.INDETERMINATE
    assert result.error_codes == (FailureCode.WORKER_FAILURE,)


def test_endpoint_scanner_converts_complete_exception_to_worker_failure():
    discoveries = (
        discovery(Protocol.HTTP, DiscoveryState.LIVE),
        discovery(Protocol.HTTPS, DiscoveryState.UNAVAILABLE, FailureCode.UNREACHABLE),
    )

    async def complete_runner(_result):
        raise RuntimeError("backend details must not escape")

    scanner = ExhaustiveEndpointScanner(
        discovery_runner=lambda _endpoint: discoveries,
        complete_runner=complete_runner,
        discovery_workers=1,
    )
    try:
        result = asyncio.run(scanner.scan(Endpoint("192.0.2.1", 8443)))[0]
    finally:
        scanner.close()

    assert result.error_codes == (FailureCode.WORKER_FAILURE,)


def test_endpoint_scanner_cancellation_during_complete_cleans_up_siblings():
    discoveries = tuple(discovery(protocol, DiscoveryState.LIVE) for protocol in Protocol)
    both_started = asyncio.Event()
    started = set()
    https_cleaned_up = False

    async def complete_runner(result):
        nonlocal https_cleaned_up
        started.add(result.protocol)
        if len(started) == len(Protocol):
            both_started.set()
        await both_started.wait()
        if result.protocol is Protocol.HTTP:
            raise asyncio.CancelledError
        try:
            await asyncio.sleep(30)
        finally:
            https_cleaned_up = True

    scanner = ExhaustiveEndpointScanner(
        discovery_runner=lambda _endpoint: discoveries,
        complete_runner=complete_runner,
        discovery_workers=1,
    )
    try:
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(scanner.scan(Endpoint("192.0.2.1", 8443)))
    finally:
        scanner.close()

    assert started == set(Protocol)
    assert https_cleaned_up


def test_endpoint_scanner_cancellation_during_discovery_is_propagated():
    entered = threading.Event()
    release = threading.Event()

    def discovery_runner(_endpoint):
        entered.set()
        release.wait(timeout=5)
        return ()

    async def complete_runner(result):
        return completed(result)

    scanner = ExhaustiveEndpointScanner(
        discovery_runner=discovery_runner,
        complete_runner=complete_runner,
        discovery_workers=1,
    )

    async def cancel_discovery():
        task = asyncio.create_task(scanner.scan(Endpoint("192.0.2.1", 8443)))
        while not entered.is_set():
            await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    try:
        asyncio.run(cancel_discovery())
    finally:
        release.set()
        scanner.close()


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


def test_endpoint_scanner_defaults_missing_nonlive_failure_to_worker_failure():
    discoveries = (
        discovery(Protocol.HTTP, DiscoveryState.UNAVAILABLE),
        discovery(Protocol.HTTPS, DiscoveryState.UNAVAILABLE, FailureCode.UNREACHABLE),
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

    assert results[0].error_codes == (FailureCode.WORKER_FAILURE,)


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


def test_endpoint_scanner_fails_closed_on_invalid_discovery_member_or_runner_failure():
    endpoint = Endpoint("192.0.2.1", 8443)

    async def complete_runner(result):
        return completed(result)

    def raises(_endpoint):
        raise RuntimeError("discovery implementation failed")

    for discovery_runner in (
        lambda _endpoint: (object(), object()),
        raises,
    ):
        scanner = ExhaustiveEndpointScanner(
            discovery_runner=discovery_runner,
            complete_runner=complete_runner,
            discovery_workers=1,
        )
        try:
            results = asyncio.run(scanner.scan(endpoint))
        finally:
            scanner.close()

        assert [result.protocol for result in results] == list(Protocol)
        assert all(result.error_codes == (FailureCode.WORKER_FAILURE,) for result in results)


def test_endpoint_scanner_context_manager_closes_once_and_cannot_be_reentered():
    async def complete_runner(result):
        return completed(result)

    scanner = ExhaustiveEndpointScanner(
        discovery_runner=lambda _endpoint: (),
        complete_runner=complete_runner,
        discovery_workers=1,
    )
    with scanner as entered:
        assert entered is scanner

    scanner.close()
    with pytest.raises(RuntimeError, match="closed"):
        scanner.__enter__()


def test_direct_runtime_derives_bounded_pipeline_admission_from_resource_plan():
    runtime = DirectScanRuntime(
        workers=20,
        resource_snapshot=resource_snapshot(),
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


def test_direct_runtime_validates_public_configuration_before_starting_workers(monkeypatch):
    def forbidden_backend(**_kwargs):
        raise AssertionError("worker backend started during validation")

    monkeypatch.setattr(engine_module, "_FullScanBackend", forbidden_backend)

    for invalid_workers in (True, "1", 0):
        with pytest.raises(ValueError, match="workers"):
            DirectScanRuntime(workers=invalid_workers)
    for invalid_timeout in (True, "1", 0.5):
        with pytest.raises(ValueError, match="timeout"):
            DirectScanRuntime(timeout=invalid_timeout)
    with pytest.raises(TypeError, match="resource_snapshot"):
        DirectScanRuntime(resource_snapshot=object())
    with pytest.raises(TypeError, match="resource_profile"):
        DirectScanRuntime(
            resource_snapshot=resource_snapshot(),
            resource_profile=object(),
        )
    with pytest.raises(TypeError, match="transport_limits"):
        DirectScanRuntime(
            resource_snapshot=resource_snapshot(),
            transport_limits=object(),
        )


def test_direct_runtime_resource_preflight_rejects_insufficient_capacity(monkeypatch):
    def forbidden_backend(**_kwargs):
        raise AssertionError("worker backend started without resource capacity")

    monkeypatch.setattr(engine_module, "_FullScanBackend", forbidden_backend)
    constrained = resource_snapshot(
        memory_bytes=0,
        file_descriptors=0,
        sockets=0,
        processes=0,
        shared_memory_bytes=0,
        temp_bytes=0,
        artifact_bytes=0,
    )

    with pytest.raises(RuntimeError, match="insufficient resources: memory"):
        DirectScanRuntime(resource_snapshot=constrained)


@pytest.mark.parametrize(
    "selected",
    [
        WorkerCounts(0, 1, 1),
        WorkerCounts(1, 0, 1),
        WorkerCounts(1, 1, 0),
    ],
)
def test_direct_runtime_rejects_resource_plan_with_zero_stage_capacity(monkeypatch, selected):
    snapshot = resource_snapshot()
    plan = ResourcePlan(
        snapshot=snapshot,
        profile=engine_module.DEFAULT_RESOURCE_PROFILE,
        requested=WorkerCounts(1, 1, 1),
        selected=selected,
    )
    monkeypatch.setattr(engine_module, "autosize", lambda *_args, **_kwargs: plan)
    monkeypatch.setattr(
        engine_module,
        "_FullScanBackend",
        lambda **_kwargs: pytest.fail("worker backend started with zero stage capacity"),
    )

    with pytest.raises(RuntimeError, match="complete worker capacity"):
        DirectScanRuntime(resource_snapshot=snapshot)


def test_direct_runtime_delegates_transport_scan_and_cleanup(monkeypatch):
    snapshot = resource_snapshot()
    profile = ResourceProfile(
        discovery_worker=ResourceRequest(memory_bytes=1),
        static_worker=ResourceRequest(cpu=1),
        browser_active_page=ResourceRequest(memory_bytes=1),
        browser_replacement=ResourceRequest(memory_bytes=1),
    )
    limits = TransportLimits()
    events = []

    class FakeBrowserBackend:
        def __init__(self, **kwargs):
            events.append(("browser_init", kwargs))

        async def analyze_evidence(self, *_args):
            raise AssertionError("browser runner should be delegated by the complete executor")

        async def close(self):
            events.append(("browser_close",))

    class FakeCompleteExecutor:
        def __init__(self, **kwargs):
            events.append(("complete_init", kwargs))

        async def analyze_protocol(self, requested_url, protocol, tls):
            events.append(("complete", requested_url, protocol, tls))
            return "complete-result"

        def close(self):
            events.append(("complete_close",))

    class FakeEndpointScanner:
        def __init__(self, **kwargs):
            events.append(("scanner_init", kwargs))

        async def scan(self, endpoint):
            events.append(("scan", endpoint))
            return ("scan-result",)

        def close(self):
            events.append(("scanner_close",))

    class FakeTransport:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            events.append(("transport_init", kwargs))

        def __enter__(self):
            events.append(("transport_enter",))
            return self

        def __exit__(self, _exc_type, _exc, _traceback):
            events.append(("transport_exit",))

    def fake_discover(endpoint, transport):
        events.append(("discover", endpoint, transport))
        return ("discovery-result",)

    monkeypatch.setattr(engine_module, "capture_snapshot", lambda: snapshot)
    monkeypatch.setattr(engine_module, "_FullScanBackend", FakeBrowserBackend)
    monkeypatch.setattr(engine_module, "CompleteScanExecutor", FakeCompleteExecutor)
    monkeypatch.setattr(engine_module, "ExhaustiveEndpointScanner", FakeEndpointScanner)
    monkeypatch.setattr(engine_module, "DirectTransport", FakeTransport)
    monkeypatch.setattr(engine_module, "discover_protocols", fake_discover)

    runtime = DirectScanRuntime(
        resource_profile=profile,
        transport_limits=limits,
        timeout=5,
    )
    endpoint = Endpoint("192.0.2.1", 8443)
    assert runtime._discover(endpoint) == ("discovery-result",)
    assert events[-2][0] == "discover"
    transport_kwargs = next(event[1] for event in events if event[0] == "transport_init")
    assert transport_kwargs["limits"] is limits
    assert transport_kwargs["policy"].supplied_endpoints == (endpoint,)

    async def exercise_runtime():
        assert await runtime.scan(endpoint) == ("scan-result",)
        tls = discovery(Protocol.HTTPS, DiscoveryState.LIVE).tls
        assert (
            await runtime._complete(discovery(Protocol.HTTPS, DiscoveryState.LIVE))
            == "complete-result"
        )
        assert events[-1] == (
            "complete",
            "https://192.0.2.1:8443/",
            Protocol.HTTPS,
            tls,
        )
        await runtime.aclose()
        await runtime.aclose()
        with pytest.raises(RuntimeError, match="closed"):
            await runtime.scan(endpoint)

    asyncio.run(exercise_runtime())

    cleanup_events = [
        event[0]
        for event in events
        if event[0] in {"scanner_close", "complete_close", "browser_close"}
    ]
    assert cleanup_events == ["scanner_close", "complete_close", "browser_close"]
