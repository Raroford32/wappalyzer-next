import asyncio
import concurrent.futures
from typing import Dict

from wappalyzer.discovery import DiscoveryResult, DiscoveryState
from wappalyzer.models import (
    PROTOCOL_ORDER,
    Endpoint,
    FailureCode,
    Protocol,
    ProtocolResult,
    ProtocolStatus,
    TLSMetadata,
    TLSTrust,
)


def _failed_protocol(endpoint, protocol, failure_code=FailureCode.WORKER_FAILURE):
    requested_url = f"{protocol.value}://{endpoint.authority}/"
    return ProtocolResult(
        protocol=protocol,
        status=ProtocolStatus.INDETERMINATE,
        requested_url=requested_url,
        effective_url=requested_url,
        http_status=None,
        tls=TLSMetadata(
            present=protocol is Protocol.HTTPS,
            trust=(
                TLSTrust.INDETERMINATE if protocol is Protocol.HTTPS else TLSTrust.NOT_APPLICABLE
            ),
        ),
        error_codes=(failure_code,),
    )


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
            return _failed_protocol(endpoint, discovery.protocol)
        if not isinstance(result, ProtocolResult) or result.protocol is not discovery.protocol:
            return _failed_protocol(endpoint, discovery.protocol)
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
            return tuple(_failed_protocol(endpoint, protocol) for protocol in PROTOCOL_ORDER)

        if (
            any(not isinstance(result, DiscoveryResult) for result in discoveries)
            or len(discoveries) != len(PROTOCOL_ORDER)
            or {result.protocol for result in discoveries} != set(PROTOCOL_ORDER)
        ):
            return tuple(_failed_protocol(endpoint, protocol) for protocol in PROTOCOL_ORDER)

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


__all__ = ["ExhaustiveEndpointScanner"]
