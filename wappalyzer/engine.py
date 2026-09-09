import asyncio
import concurrent.futures
from typing import Dict

from wappalyzer.core.transport import DirectTransport, EgressPolicy, TransportLimits
from wappalyzer.discovery import DiscoveryResult, DiscoveryState, discover_protocols
from wappalyzer.models import (
    PROTOCOL_ORDER,
    Endpoint,
    FailureCode,
    Protocol,
    ProtocolResult,
    ProtocolStatus,
    worker_failure_protocol,
)
from wappalyzer.resources import (
    DEFAULT_RESOURCE_PROFILE,
    ResourceProfile,
    ResourceSnapshot,
    WorkerCounts,
    autosize,
    capture_snapshot,
)
from wappalyzer.scanner import CompleteScanExecutor, _FullScanBackend


def _nonlive_result(discovery):
    status = (
        ProtocolStatus.INDETERMINATE
        if discovery.state is DiscoveryState.INDETERMINATE
        else ProtocolStatus.UNAVAILABLE
    )
    failure_code = discovery.failure_code or FailureCode.WORKER_FAILURE
    return ProtocolResult(
        protocol=discovery.protocol,
        status=status,
        requested_url=discovery.requested_url,
        effective_url=discovery.requested_url,
        http_status=None,
        tls=discovery.tls,
        error_codes=(failure_code,),
    )


class ExhaustiveEndpointScanner:
    def __init__(
        self,
        *,
        discovery_runner,
        complete_runner,
        discovery_workers,
    ):
        if not callable(discovery_runner):
            raise TypeError("discovery_runner must be callable")
        if not callable(complete_runner):
            raise TypeError("complete_runner must be callable")
        if (
            isinstance(discovery_workers, bool)
            or not isinstance(discovery_workers, int)
            or discovery_workers < 1
        ):
            raise ValueError("discovery_workers must be a positive integer")
        self.discovery_runner = discovery_runner
        self.complete_runner = complete_runner
        self._discovery_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=discovery_workers,
        )
        self._closed = False

    async def _complete(self, endpoint, discovery):
        try:
            result = await self.complete_runner(discovery)
        except asyncio.CancelledError:
            raise
        except Exception:
            return worker_failure_protocol(endpoint, discovery.protocol)
        if not isinstance(result, ProtocolResult) or result.protocol is not discovery.protocol:
            return worker_failure_protocol(endpoint, discovery.protocol)
        return result

    async def scan(self, endpoint):
        if self._closed:
            raise RuntimeError("endpoint scanner is closed")
        if not isinstance(endpoint, Endpoint):
            raise TypeError("endpoint must be an Endpoint")

        loop = asyncio.get_running_loop()
        try:
            discoveries = await loop.run_in_executor(
                self._discovery_executor,
                self.discovery_runner,
                endpoint,
            )
            discoveries = tuple(discoveries)
        except asyncio.CancelledError:
            raise
        except Exception:
            return tuple(worker_failure_protocol(endpoint, protocol) for protocol in PROTOCOL_ORDER)

        if (
            any(not isinstance(result, DiscoveryResult) for result in discoveries)
            or len(discoveries) != len(PROTOCOL_ORDER)
            or {result.protocol for result in discoveries} != set(PROTOCOL_ORDER)
        ):
            return tuple(worker_failure_protocol(endpoint, protocol) for protocol in PROTOCOL_ORDER)

        by_protocol: Dict[Protocol, ProtocolResult] = {}
        tasks = {}
        for discovery in discoveries:
            if discovery.state is DiscoveryState.LIVE:
                task = asyncio.create_task(self._complete(endpoint, discovery))
                tasks[task] = discovery.protocol
            else:
                by_protocol[discovery.protocol] = _nonlive_result(discovery)

        try:
            if tasks:
                completed = await asyncio.gather(*tasks)
                for result in completed:
                    by_protocol[result.protocol] = result
        except BaseException:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise

        return tuple(by_protocol[protocol] for protocol in PROTOCOL_ORDER)

    def close(self):
        if self._closed:
            return
        self._closed = True
        self._discovery_executor.shutdown(wait=True, cancel_futures=True)

    def __enter__(self):
        if self._closed:
            raise RuntimeError("endpoint scanner is closed")
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()


class DirectScanRuntime:
    def __init__(
        self,
        *,
        workers=None,
        timeout=30,
        resource_snapshot=None,
        resource_profile=None,
        transport_limits=None,
        artifact_required_bytes=0,
    ):
        if workers is not None and (
            isinstance(workers, bool) or not isinstance(workers, int) or workers < 1
        ):
            raise ValueError("workers must be a positive integer or None")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout < 1:
            raise ValueError("timeout must be at least one second")
        snapshot = resource_snapshot or capture_snapshot()
        profile = resource_profile or DEFAULT_RESOURCE_PROFILE
        if not isinstance(snapshot, ResourceSnapshot):
            raise TypeError("resource_snapshot must be a ResourceSnapshot or None")
        if not isinstance(profile, ResourceProfile):
            raise TypeError("resource_profile must be a ResourceProfile or None")
        requested = WorkerCounts(workers, workers, workers) if workers is not None else None
        plan = autosize(
            snapshot,
            profile,
            requested=requested,
            artifact_required_bytes=artifact_required_bytes,
        )
        if (
            not plan.can_run
            or plan.selected.discovery < 1
            or plan.selected.static < 1
            or plan.selected.browser < 1
        ):
            reasons = ", ".join(plan.insufficiency_reasons) or "complete worker capacity"
            raise RuntimeError(f"insufficient resources: {reasons}")
        if transport_limits is not None and not isinstance(
            transport_limits,
            TransportLimits,
        ):
            raise TypeError("transport_limits must be TransportLimits or None")

        self.resource_plan = plan
        self.transport_limits = transport_limits or TransportLimits()
        self.browser_backend = _FullScanBackend(
            workers=plan.selected.browser,
            timeout=timeout,
            strict_tls=True,
            blocked_resource_types=(),
        )
        self.complete_executor = CompleteScanExecutor(
            browser_runner=self.browser_backend.analyze_evidence,
            timeout=timeout,
            static_workers=plan.selected.static,
            asset_workers=1,
        )
        self.endpoint_scanner = ExhaustiveEndpointScanner(
            discovery_runner=self._discover,
            complete_runner=self._complete,
            discovery_workers=plan.selected.discovery,
        )
        self.max_inflight = sum(
            (
                plan.selected.discovery,
                plan.selected.static,
                plan.selected.browser,
            )
        )
        self._closed = False

    def _discover(self, endpoint):
        with DirectTransport(
            policy=EgressPolicy((endpoint,)),
            limits=self.transport_limits,
        ) as transport:
            return discover_protocols(endpoint, transport)

    async def _complete(self, discovery):
        return await self.complete_executor.analyze_protocol(
            discovery.requested_url,
            discovery.protocol,
            discovery.tls,
        )

    async def scan(self, endpoint):
        if self._closed:
            raise RuntimeError("direct scan runtime is closed")
        return await self.endpoint_scanner.scan(endpoint)

    async def aclose(self):
        if self._closed:
            return
        self._closed = True
        self.endpoint_scanner.close()
        self.complete_executor.close()
        await self.browser_backend.close()


__all__ = ["DirectScanRuntime", "ExhaustiveEndpointScanner"]
