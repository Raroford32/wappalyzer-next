from dataclasses import dataclass
from typing import Optional, Tuple

from wappalyzer.core.transport import (
    Diagnostic,
    DirectTransport,
    RequestPurpose,
    TransportResult,
    TransportState,
)
from wappalyzer.models import (
    Endpoint,
    FailureCode,
    Protocol,
    StringEnum,
    TLSMetadata,
    TLSTrust,
)


class DiscoveryState(StringEnum):
    LIVE = "live"
    UNAVAILABLE = "unavailable"
    INDETERMINATE = "indeterminate"
    MALFORMED_TLS = "malformed_tls"


@dataclass(frozen=True)
class DiscoveryResult:
    protocol: Protocol
    state: DiscoveryState
    requested_url: str
    http_status: Optional[int]
    tls: TLSMetadata
    failure_code: Optional[FailureCode] = None
    diagnostic: Optional[Diagnostic] = None

    def __post_init__(self) -> None:
        if not isinstance(self.protocol, Protocol):
            raise TypeError("protocol must be a Protocol")
        if not isinstance(self.state, DiscoveryState):
            raise TypeError("state must be a DiscoveryState")
        if not isinstance(self.requested_url, str) or not self.requested_url:
            raise ValueError("requested_url must be a non-empty string")
        if self.http_status is not None and (
            isinstance(self.http_status, bool)
            or not isinstance(self.http_status, int)
            or not 100 <= self.http_status <= 599
        ):
            raise ValueError("http_status must be between 100 and 599 or None")
        if not isinstance(self.tls, TLSMetadata):
            raise TypeError("tls must be TLSMetadata")
        if self.failure_code is not None and not isinstance(self.failure_code, FailureCode):
            raise TypeError("failure_code must be a FailureCode or None")
        if self.diagnostic is not None and not isinstance(self.diagnostic, Diagnostic):
            raise TypeError("diagnostic must be a Diagnostic or None")
        if self.state is DiscoveryState.LIVE and self.http_status is None:
            raise ValueError("live discovery results require an HTTP status")
        if self.state is not DiscoveryState.LIVE and self.http_status is not None:
            raise ValueError("non-live discovery results cannot carry an HTTP status")


ProtocolDiscoveryResult = DiscoveryResult


def _tls_metadata(protocol: Protocol, trust: TLSTrust) -> TLSMetadata:
    return TLSMetadata(
        present=protocol is Protocol.HTTPS,
        trust=trust,
    )


def _non_response_state(result: TransportResult) -> DiscoveryState:
    if result.state is TransportState.UNAVAILABLE:
        return DiscoveryState.UNAVAILABLE
    if result.state is TransportState.TIMEOUT:
        return DiscoveryState.INDETERMINATE
    if result.state is TransportState.TLS_UNTRUSTED:
        return DiscoveryState.INDETERMINATE
    if result.state is TransportState.MALFORMED_TLS:
        return DiscoveryState.MALFORMED_TLS
    if result.state is TransportState.RESPONSE:
        raise ValueError("response transport state is not a failure")
    raise ValueError(f"unsupported transport state: {result.state!r}")


def _ordinary_result(
    protocol: Protocol,
    requested_url: str,
    transport_result: TransportResult,
) -> DiscoveryResult:
    if transport_result.state is TransportState.RESPONSE:
        trust = TLSTrust.TRUSTED if protocol is Protocol.HTTPS else TLSTrust.NOT_APPLICABLE
        return DiscoveryResult(
            protocol=protocol,
            state=DiscoveryState.LIVE,
            requested_url=requested_url,
            http_status=transport_result.status_code,
            tls=_tls_metadata(protocol, trust),
        )

    trust = TLSTrust.INDETERMINATE if protocol is Protocol.HTTPS else TLSTrust.NOT_APPLICABLE
    return DiscoveryResult(
        protocol=protocol,
        state=_non_response_state(transport_result),
        requested_url=requested_url,
        http_status=None,
        tls=_tls_metadata(protocol, trust),
        failure_code=transport_result.failure_code,
        diagnostic=transport_result.diagnostic,
    )


def _confirmed_untrusted_result(
    requested_url: str,
    verified_result: TransportResult,
    confirmation: TransportResult,
) -> DiscoveryResult:
    if confirmation.state is TransportState.RESPONSE:
        return DiscoveryResult(
            protocol=Protocol.HTTPS,
            state=DiscoveryState.LIVE,
            requested_url=requested_url,
            http_status=confirmation.status_code,
            tls=_tls_metadata(Protocol.HTTPS, TLSTrust.UNTRUSTED),
            failure_code=FailureCode.TLS_UNTRUSTED,
            diagnostic=verified_result.diagnostic,
        )

    if confirmation.state is TransportState.MALFORMED_TLS:
        return _ordinary_result(Protocol.HTTPS, requested_url, confirmation)

    return DiscoveryResult(
        protocol=Protocol.HTTPS,
        state=_non_response_state(confirmation),
        requested_url=requested_url,
        http_status=None,
        tls=_tls_metadata(Protocol.HTTPS, TLSTrust.UNTRUSTED),
        failure_code=FailureCode.TLS_UNTRUSTED,
        diagnostic=verified_result.diagnostic,
    )


def discover_protocols(
    endpoint: Endpoint,
    transport: DirectTransport,
) -> Tuple[DiscoveryResult, DiscoveryResult]:
    if not isinstance(endpoint, Endpoint):
        raise TypeError("endpoint must be an Endpoint")
    if not callable(getattr(transport, "probe", None)):
        raise TypeError("transport must provide a callable probe method")

    http_url = f"http://{endpoint.authority}/"
    https_url = f"https://{endpoint.authority}/"

    http_transport_result = transport.probe(
        http_url,
        verify_tls=True,
        purpose=RequestPurpose.DIRECT,
    )
    http_result = _ordinary_result(Protocol.HTTP, http_url, http_transport_result)

    verified_https_result = transport.probe(
        https_url,
        verify_tls=True,
        purpose=RequestPurpose.DIRECT,
    )
    if verified_https_result.state is TransportState.TLS_UNTRUSTED:
        insecure_confirmation = transport.probe(
            https_url,
            verify_tls=False,
            purpose=RequestPurpose.DIRECT,
        )
        https_result = _confirmed_untrusted_result(
            https_url,
            verified_https_result,
            insecure_confirmation,
        )
    else:
        https_result = _ordinary_result(
            Protocol.HTTPS,
            https_url,
            verified_https_result,
        )

    return http_result, https_result


__all__ = [
    "DiscoveryResult",
    "DiscoveryState",
    "ProtocolDiscoveryResult",
    "discover_protocols",
]
