import hashlib
import ipaddress
import math
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Optional, Tuple, Union
from urllib.parse import SplitResult, urlsplit, urlunsplit

import requests
from urllib3.util import Timeout

from wappalyzer.models import Endpoint, FailureCode, StringEnum

_BODY_CHUNK_BYTES = 64 * 1024
_DIAGNOSTIC_VERSION = b"transport-diagnostic-v1"
_DEFAULT_CONNECT_TIMEOUT = 5.0
_DEFAULT_OVERALL_TIMEOUT = 10.0
_DEFAULT_MAX_BODY_BYTES = 64 * 1024
_METADATA_ADDRESSES = frozenset(
    {
        ipaddress.ip_address("100.100.100.200"),
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("fd00:ec2::254"),
    }
)
_METADATA_HOST_ALIASES = frozenset(
    {
        "instance-data",
        "instance-data.ec2.internal",
        "metadata",
        "metadata.aws.internal",
        "metadata.azure.internal",
        "metadata.google",
        "metadata.google.internal",
        "metadata.goog",
        "metadata.packet.net",
    }
)
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


class RequestPurpose(StringEnum):
    DIRECT = "direct"
    REDIRECT = "redirect"
    SUBRESOURCE = "subresource"


class TransportState(StringEnum):
    RESPONSE = "response"
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    TLS_UNTRUSTED = "tls_untrusted"
    MALFORMED_TLS = "malformed_tls"


@dataclass(frozen=True)
class TransportLimits:
    connect_timeout: float = _DEFAULT_CONNECT_TIMEOUT
    overall_timeout: float = _DEFAULT_OVERALL_TIMEOUT
    max_body_bytes: int = _DEFAULT_MAX_BODY_BYTES

    def __post_init__(self) -> None:
        for name in ("connect_timeout", "overall_timeout"):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError(f"{name} must be a finite positive number")
            object.__setattr__(self, name, float(value))

        if (
            isinstance(self.max_body_bytes, bool)
            or not isinstance(self.max_body_bytes, int)
            or self.max_body_bytes < 0
        ):
            raise ValueError("max_body_bytes must be a non-negative integer")


@dataclass(frozen=True)
class Diagnostic:
    code: FailureCode
    url: str
    message: str
    digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.code, FailureCode):
            raise TypeError("code must be a FailureCode")
        if not isinstance(self.url, str):
            raise TypeError("url must be a string")
        if not isinstance(self.message, str):
            raise TypeError("message must be a string")
        if (
            not isinstance(self.digest, str)
            or len(self.digest) != 64
            or any(character not in "0123456789abcdef" for character in self.digest)
        ):
            raise ValueError("digest must be a lowercase SHA-256 digest")


TransportDiagnostic = Diagnostic
SanitizedDiagnostic = Diagnostic


@dataclass(frozen=True)
class TransportResult:
    state: TransportState
    status_code: Optional[int] = None
    body: bytes = b""
    failure_code: Optional[FailureCode] = None
    diagnostic: Optional[Diagnostic] = None

    def __post_init__(self) -> None:
        if not isinstance(self.state, TransportState):
            raise TypeError("state must be a TransportState")
        if not isinstance(self.body, bytes):
            raise TypeError("body must be bytes")
        if self.failure_code is not None and not isinstance(self.failure_code, FailureCode):
            raise TypeError("failure_code must be a FailureCode or None")
        if self.diagnostic is not None and not isinstance(self.diagnostic, Diagnostic):
            raise TypeError("diagnostic must be a Diagnostic or None")
        if self.diagnostic is not None and self.diagnostic.code is not self.failure_code:
            raise ValueError("diagnostic code must match failure_code")

        if self.state is TransportState.RESPONSE:
            if (
                isinstance(self.status_code, bool)
                or not isinstance(self.status_code, int)
                or not 100 <= self.status_code <= 599
            ):
                raise ValueError("response status_code must be between 100 and 599")
            if self.failure_code is not None or self.diagnostic is not None:
                raise ValueError("a response cannot carry a transport failure")
            return

        if self.status_code is not None:
            raise ValueError("failed transports cannot carry an HTTP status")
        if self.body:
            raise ValueError("failed transports cannot carry a response body")
        if self.failure_code is None:
            raise ValueError("failed transports require a failure_code")


class DestinationBlocked(RuntimeError):
    failure_code = FailureCode.UNREACHABLE

    def __init__(self) -> None:
        super().__init__("destination rejected by egress policy")


def _default_resolver(host: str) -> Tuple[str, ...]:
    records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    addresses = []
    for record in records:
        address = record[4][0]
        addresses.append(str(ipaddress.ip_address(address)))
    return tuple(dict.fromkeys(addresses))


def http_origin(url):
    parsed = urlsplit(url)
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
        return None
    try:
        port = parsed.port or (443 if parsed.scheme.casefold() == "https" else 80)
    except ValueError:
        return None
    return parsed.scheme.casefold(), parsed.hostname.casefold(), port


def _parse_http_url(url: str) -> Tuple[SplitResult, str, int, Optional[IPAddress]]:
    if not isinstance(url, str) or not url:
        raise DestinationBlocked()
    if "\\" in url or any(ord(character) <= 32 or ord(character) == 127 for character in url):
        raise DestinationBlocked()

    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        host = parsed.hostname
        port = parsed.port
    except (TypeError, ValueError):
        raise DestinationBlocked() from None

    if scheme not in {"http", "https"} or not parsed.netloc or not host:
        raise DestinationBlocked()
    if "%" in host:
        raise DestinationBlocked()

    effective_port = (80 if scheme == "http" else 443) if port is None else port
    if not 1 <= effective_port <= 65535:
        raise DestinationBlocked()

    try:
        literal_address = ipaddress.ip_address(host)
    except ValueError:
        literal_address = None

    return parsed, host, effective_port, literal_address


@dataclass(frozen=True)
class EgressPolicy:
    supplied_endpoints: Tuple[Endpoint, ...]
    resolver: Callable[[str], Iterable[str]] = field(default=_default_resolver)

    def __post_init__(self) -> None:
        endpoints = tuple(self.supplied_endpoints)
        if any(not isinstance(endpoint, Endpoint) for endpoint in endpoints):
            raise TypeError("supplied_endpoints must contain only Endpoint values")
        if not callable(self.resolver):
            raise TypeError("resolver must be callable")
        object.__setattr__(self, "supplied_endpoints", endpoints)

    def _is_supplied(self, address: IPAddress, port: int) -> bool:
        normalized = str(address)
        return any(
            endpoint.address == normalized and endpoint.port == port
            for endpoint in self.supplied_endpoints
        )

    def _is_allowed(self, address: IPAddress, port: int) -> bool:
        if self._is_supplied(address, port):
            return True
        if address in _METADATA_ADDRESSES:
            return False
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            return self._is_allowed(address.ipv4_mapped, port)
        return address.is_global and not any(
            (
                address.is_link_local,
                address.is_loopback,
                address.is_multicast,
                address.is_private,
                address.is_reserved,
                address.is_unspecified,
            )
        )

    def authorize(self, url: str, purpose: RequestPurpose) -> Tuple[str, ...]:
        if not isinstance(purpose, RequestPurpose):
            raise TypeError("purpose must be a RequestPurpose")

        _parsed, host, port, literal_address = _parse_http_url(url)
        if literal_address is not None:
            if not self._is_allowed(literal_address, port):
                raise DestinationBlocked()
            return (str(literal_address),)

        normalized_host = host.rstrip(".").lower()
        if not normalized_host or normalized_host in _METADATA_HOST_ALIASES:
            raise DestinationBlocked()

        try:
            answers = tuple(self.resolver(host))
            resolved = tuple(ipaddress.ip_address(address) for address in answers)
        except Exception:
            raise DestinationBlocked() from None

        if not resolved or any(not self._is_allowed(address, port) for address in resolved):
            raise DestinationBlocked()
        return tuple(str(address) for address in resolved)


def sanitize_url(url: str) -> str:
    if not isinstance(url, str):
        return "<invalid-url>"

    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
    except (TypeError, ValueError):
        return "<invalid-url>"

    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc or not host:
        return "<invalid-url>"

    authority = f"[{host}]" if ":" in host else host
    if port is not None:
        authority = f"{authority}:{port}"
    return urlunsplit((parsed.scheme.lower(), authority, parsed.path, "", ""))


def _request_url(url: str) -> str:
    parsed = urlsplit(url)
    host = parsed.hostname
    authority = f"[{host}]" if ":" in host else host
    if parsed.port is not None:
        authority = f"{authority}:{parsed.port}"
    return urlunsplit((parsed.scheme.lower(), authority, parsed.path, parsed.query, ""))


def _digest_part(digest: Any, value: bytes) -> None:
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def _safe_text(value: object) -> str:
    try:
        return str(value)
    except BaseException:
        return f"<{type(value).__module__}.{type(value).__qualname__}>"


def sanitize_diagnostic(
    *,
    code: FailureCode,
    url: str,
    exception: Optional[BaseException] = None,
    headers: Optional[Mapping[str, object]] = None,
    body: bytes = b"",
    max_length: int = 160,
) -> Diagnostic:
    if not isinstance(code, FailureCode):
        raise TypeError("code must be a FailureCode")
    if isinstance(max_length, bool) or not isinstance(max_length, int) or max_length < 0:
        raise ValueError("max_length must be a non-negative integer")

    safe_url = sanitize_url(url)
    digest = hashlib.sha256()
    _digest_part(digest, _DIAGNOSTIC_VERSION)
    _digest_part(digest, code.value.encode("utf-8"))
    _digest_part(digest, _safe_text(url).encode("utf-8", "surrogatepass"))
    if exception is not None:
        exception_type = f"{type(exception).__module__}.{type(exception).__qualname__}"
        _digest_part(digest, exception_type.encode("utf-8"))
        _digest_part(digest, _safe_text(exception).encode("utf-8", "backslashreplace"))
    if headers:
        normalized_headers = sorted(
            (
                _safe_text(name).casefold(),
                _safe_text(name),
                _safe_text(value),
            )
            for name, value in headers.items()
        )
        for folded_name, original_name, value in normalized_headers:
            _digest_part(digest, folded_name.encode("utf-8", "backslashreplace"))
            _digest_part(digest, original_name.encode("utf-8", "backslashreplace"))
            _digest_part(digest, value.encode("utf-8", "backslashreplace"))
    if isinstance(body, bytes):
        _digest_part(digest, body)
    else:
        _digest_part(digest, _safe_text(body).encode("utf-8", "backslashreplace"))

    message = code.value.replace("_", " ")[:max_length]
    return Diagnostic(
        code=code,
        url=safe_url,
        message=message,
        digest=digest.hexdigest(),
    )


def _walk_exceptions(error: BaseException) -> Iterable[BaseException]:
    pending = [error]
    visited = set()
    while pending:
        current = pending.pop()
        identity = id(current)
        if identity in visited:
            continue
        visited.add(identity)
        yield current

        for related in (
            current.__cause__,
            current.__context__,
            getattr(current, "reason", None),
            getattr(current, "original_error", None),
        ):
            if isinstance(related, BaseException):
                pending.append(related)
        pending.extend(argument for argument in current.args if isinstance(argument, BaseException))


def _is_certificate_verification_error(error: BaseException) -> bool:
    for current in _walk_exceptions(error):
        if isinstance(current, (ssl.SSLCertVerificationError, ssl.CertificateError)):
            return True
        text = _safe_text(current).lower()
        if (
            "certificate_verify_failed" in text
            or "certificate verify failed" in text
            or ("hostname" in text and "match" in text)
        ):
            return True
    return False


def _close_response(response: object) -> None:
    close = getattr(response, "close", None)
    if not callable(close):
        return
    try:
        close()
    except Exception:
        pass


def _failure_result(
    *,
    state: TransportState,
    code: FailureCode,
    url: str,
    exception: Optional[BaseException] = None,
) -> TransportResult:
    if exception is not None:
        error_response = getattr(exception, "response", None)
        if error_response is not None:
            _close_response(error_response)
    return TransportResult(
        state=state,
        failure_code=code,
        diagnostic=sanitize_diagnostic(code=code, url=url, exception=exception),
    )


class DirectTransport:
    def __init__(
        self,
        *,
        policy: EgressPolicy,
        limits: TransportLimits = TransportLimits(),
        session_factory: Callable[[], requests.Session] = requests.Session,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if not isinstance(policy, EgressPolicy):
            raise TypeError("policy must be an EgressPolicy")
        if not isinstance(limits, TransportLimits):
            raise TypeError("limits must be TransportLimits")
        if not callable(session_factory):
            raise TypeError("session_factory must be callable")
        if not callable(monotonic):
            raise TypeError("monotonic must be callable")

        self._policy = policy
        self._limits = limits
        self._monotonic = monotonic
        self._session = session_factory()
        self._harden_session()

    def _harden_session(self) -> None:
        self._session.trust_env = False
        self._session.auth = None
        self._session.cert = None
        self._session.verify = True
        self._session.cookies.clear()
        self._session.headers.clear()

        params = getattr(self._session, "params", None)
        if params is not None:
            params.clear()
        proxies = getattr(self._session, "proxies", None)
        if proxies is not None:
            proxies.clear()

    def _read_body(self, response: requests.Response, started_at: float) -> bytes:
        remaining = self._limits.max_body_bytes
        if remaining == 0:
            return b""

        content = bytearray()
        chunks = response.iter_content(chunk_size=min(_BODY_CHUNK_BYTES, remaining))
        while remaining:
            if self._monotonic() - started_at >= self._limits.overall_timeout:
                break
            try:
                chunk = next(chunks)
            except StopIteration:
                break
            except requests.exceptions.RequestException:
                break

            if not chunk:
                continue
            accepted = chunk[:remaining]
            content.extend(accepted)
            remaining -= len(accepted)
            if len(accepted) < len(chunk):
                break
        return bytes(content)

    def probe(
        self,
        url: str,
        *,
        verify_tls: bool = True,
        purpose: RequestPurpose = RequestPurpose.DIRECT,
    ) -> TransportResult:
        if not isinstance(verify_tls, bool):
            raise TypeError("verify_tls must be a boolean")

        try:
            self._policy.authorize(url, purpose)
        except DestinationBlocked as error:
            return _failure_result(
                state=TransportState.UNAVAILABLE,
                code=error.failure_code,
                url=url,
                exception=error,
            )

        request_url = _request_url(url)
        started_at = self._monotonic()
        response = None
        try:
            response = self._session.request(
                "GET",
                request_url,
                allow_redirects=False,
                stream=True,
                timeout=Timeout(
                    connect=self._limits.connect_timeout,
                    total=self._limits.overall_timeout,
                ),
                verify=verify_tls,
                auth=None,
                cookies=None,
                headers={},
            )
        except requests.exceptions.Timeout as error:
            return _failure_result(
                state=TransportState.TIMEOUT,
                code=FailureCode.DISCOVERY_TIMEOUT,
                url=url,
                exception=error,
            )
        except requests.exceptions.SSLError as error:
            if _is_certificate_verification_error(error):
                return _failure_result(
                    state=TransportState.TLS_UNTRUSTED,
                    code=FailureCode.TLS_UNTRUSTED,
                    url=url,
                    exception=error,
                )
            return _failure_result(
                state=TransportState.MALFORMED_TLS,
                code=FailureCode.UNREACHABLE,
                url=url,
                exception=error,
            )
        except requests.exceptions.ConnectionError as error:
            return _failure_result(
                state=TransportState.UNAVAILABLE,
                code=FailureCode.UNREACHABLE,
                url=url,
                exception=error,
            )
        except requests.exceptions.RequestException as error:
            return _failure_result(
                state=TransportState.UNAVAILABLE,
                code=FailureCode.UNREACHABLE,
                url=url,
                exception=error,
            )

        try:
            status_code = response.status_code
            body = self._read_body(response, started_at)
            return TransportResult(
                state=TransportState.RESPONSE,
                status_code=status_code,
                body=body,
            )
        finally:
            _close_response(response)

    def close(self) -> None:
        _close_response(self._session)

    def __enter__(self) -> "DirectTransport":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


__all__ = [
    "DestinationBlocked",
    "Diagnostic",
    "DirectTransport",
    "EgressPolicy",
    "RequestPurpose",
    "SanitizedDiagnostic",
    "TransportDiagnostic",
    "TransportLimits",
    "TransportResult",
    "TransportState",
    "http_origin",
    "sanitize_diagnostic",
    "sanitize_url",
]
