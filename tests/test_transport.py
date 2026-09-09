import json
import ssl
from dataclasses import asdict

import pytest
import requests

from wappalyzer.core.transport import (
    DestinationBlocked,
    DirectTransport,
    EgressPolicy,
    RequestPurpose,
    TransportLimits,
    TransportResult,
    TransportState,
    sanitize_diagnostic,
    sanitize_url,
)
from wappalyzer.models import Endpoint, FailureCode


class FakeResponse:
    def __init__(self, status_code, chunks=()):
        self.status_code = status_code
        self.chunks = list(chunks)
        self.chunk_reads = 0
        self.closed = False

    def iter_content(self, chunk_size):
        assert chunk_size > 0
        for chunk in self.chunks:
            self.chunk_reads += 1
            if isinstance(chunk, BaseException):
                raise chunk
            yield chunk

    def close(self):
        self.closed = True


class RecordingSession:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []
        self.trust_env = True
        self.auth = ("ambient-user", "ambient-password")
        self.cookies = requests.cookies.cookiejar_from_dict({"ambient-cookie": "secret-cookie"})
        self.headers = {
            "Authorization": "Bearer secret-authorization",
            "Cookie": "ambient-cookie=secret-cookie",
            "User-Agent": "ambient-agent",
        }

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        result = next(self.responses)
        if isinstance(result, BaseException):
            raise result
        return result

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)


def explicit_policy(address="127.0.0.1", port=8443):
    return EgressPolicy(
        supplied_endpoints=(Endpoint(address=address, port=port),),
        resolver=lambda _host: (),
    )


def direct_transport(session, limits=None, policy=None, monotonic=None):
    kwargs = {
        "policy": policy or explicit_policy(),
        "limits": limits
        or TransportLimits(
            connect_timeout=1.25,
            overall_timeout=3.5,
            max_body_bytes=16,
        ),
        "session_factory": lambda: session,
    }
    if monotonic is not None:
        kwargs["monotonic"] = monotonic
    return DirectTransport(**kwargs)


@pytest.mark.parametrize("status_code", [100, 199, 200, 302, 404, 599])
def test_every_valid_http_status_is_a_reachable_response(status_code):
    response = FakeResponse(status_code, (b"ok",))
    session = RecordingSession((response,))

    result = direct_transport(session).probe("http://127.0.0.1:8443/status")

    assert result == TransportResult(
        state=TransportState.RESPONSE,
        status_code=status_code,
        body=b"ok",
    )
    assert result.failure_code is None
    assert response.closed


def test_probe_is_no_redirect_streamed_bounded_and_has_connect_and_overall_timeouts():
    response = FakeResponse(302, (b"1234", b"5678", AssertionError("read past bound")))
    session = RecordingSession((response,))
    limits = TransportLimits(
        connect_timeout=1.25,
        overall_timeout=3.5,
        max_body_bytes=6,
    )

    result = direct_transport(
        session,
        limits=limits,
        monotonic=lambda: 0.0,
    ).probe("http://127.0.0.1:8443/redirect")

    assert result.state is TransportState.RESPONSE
    assert result.status_code == 302
    assert result.body == b"123456"
    assert response.chunk_reads == 2
    assert response.closed

    call = session.calls[0]
    assert call["method"] == "GET"
    assert call["allow_redirects"] is False
    assert call["stream"] is True
    assert call["timeout"].connect_timeout == 1.25
    assert call["timeout"].total == 3.5


def test_overall_timeout_stops_body_read_without_erasing_a_reachable_status():
    class Clock:
        def __init__(self):
            self.calls = 0

        def __call__(self):
            self.calls += 1
            return 10.0 if self.calls == 1 else 14.0

    response = FakeResponse(200, (b"late",))
    session = RecordingSession((response,))

    result = direct_transport(
        session,
        monotonic=Clock(),
    ).probe("http://127.0.0.1:8443/slow")

    assert result.state is TransportState.RESPONSE
    assert result.failure_code is None
    assert result.status_code == 200
    assert result.body == b""
    assert response.closed


def test_stream_reset_after_status_remains_reachable_and_closes_stream():
    response = FakeResponse(
        503,
        (
            b"part",
            requests.exceptions.ConnectionError("raw-stream-reset-secret"),
        ),
    )
    session = RecordingSession((response,))

    result = direct_transport(session).probe("http://127.0.0.1:8443/reset")

    assert result.state is TransportState.RESPONSE
    assert result.status_code == 503
    assert result.body == b"part"
    assert result.failure_code is None
    assert response.closed
    assert "raw-stream-reset-secret" not in repr(result)


def test_direct_transport_ignores_proxies_netrc_credentials_and_cookies(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://proxy-user:proxy-secret@proxy.invalid")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy-user:proxy-secret@proxy.invalid")
    monkeypatch.setenv("NETRC", "/tmp/netrc-containing-secret")
    response = FakeResponse(200)
    session = RecordingSession((response,))

    direct_transport(session).probe("http://127.0.0.1:8443/")

    assert session.trust_env is False
    assert session.auth is None
    assert not session.cookies
    assert {"authorization", "proxy-authorization", "cookie"}.isdisjoint(
        {name.lower() for name in session.headers}
    )

    call = session.calls[0]
    assert call.get("auth") is None
    assert call.get("cookies") is None
    assert call["allow_redirects"] is False
    assert call["verify"] is True
    assert {"authorization", "proxy-authorization", "cookie"}.isdisjoint(
        {name.lower() for name in call.get("headers", {})}
    )


def test_insecure_verification_setting_is_request_scoped():
    session = RecordingSession((FakeResponse(200), FakeResponse(200)))
    transport = direct_transport(session)

    transport.probe("https://127.0.0.1:8443/", verify_tls=False)
    transport.probe("https://127.0.0.1:8443/")

    assert [call["verify"] for call in session.calls] == [False, True]


@pytest.mark.parametrize(
    ("error", "expected_state", "expected_code"),
    [
        (
            requests.exceptions.ConnectionError(
                ConnectionRefusedError("raw-connect-refused-secret")
            ),
            TransportState.UNAVAILABLE,
            FailureCode.UNREACHABLE,
        ),
        (
            requests.exceptions.ConnectionError(ConnectionResetError("raw-reset-secret")),
            TransportState.UNAVAILABLE,
            FailureCode.UNREACHABLE,
        ),
        (
            requests.exceptions.Timeout("raw-timeout-secret"),
            TransportState.TIMEOUT,
            FailureCode.DISCOVERY_TIMEOUT,
        ),
        (
            requests.exceptions.SSLError(ssl.SSLCertVerificationError(1, "raw-self-signed-secret")),
            TransportState.TLS_UNTRUSTED,
            FailureCode.TLS_UNTRUSTED,
        ),
        (
            requests.exceptions.SSLError(
                ssl.SSLCertVerificationError(1, "raw-hostname-mismatch-secret")
            ),
            TransportState.TLS_UNTRUSTED,
            FailureCode.TLS_UNTRUSTED,
        ),
        (
            requests.exceptions.SSLError(ssl.SSLError(1, "raw-malformed-tls-secret")),
            TransportState.MALFORMED_TLS,
            FailureCode.UNREACHABLE,
        ),
    ],
)
def test_network_failures_are_typed_sanitized_and_never_return_exceptions(
    error,
    expected_state,
    expected_code,
):
    session = RecordingSession((error,))

    result = direct_transport(session).probe(
        "https://user:password@127.0.0.1:8443/path?token=query-secret#fragment-secret"
    )

    assert result.state is expected_state
    assert result.failure_code is expected_code
    assert result.status_code is None
    assert result.body == b""
    assert result.diagnostic.code is expected_code
    assert not hasattr(result, "exception")

    serialized = json.dumps(asdict(result), default=str)
    for secret in (
        "raw-",
        "user",
        "password",
        "query-secret",
        "fragment-secret",
    ):
        assert secret not in serialized


@pytest.mark.parametrize(
    ("raw_url", "expected"),
    [
        (
            "https://alice:password@example.test:9443/a?token=query-secret#fragment-secret",
            "https://example.test:9443/a",
        ),
        (
            "https://alice:password@[2001:db8::1]:9443/a?token=query-secret#fragment",
            "https://[2001:db8::1]:9443/a",
        ),
    ],
)
def test_url_sanitizer_removes_userinfo_query_and_fragment(raw_url, expected):
    assert sanitize_url(raw_url) == expected


def test_diagnostic_sanitizer_omits_sensitive_inputs_and_is_bounded_and_deterministic():
    kwargs = {
        "code": FailureCode.UNREACHABLE,
        "url": (
            "https://alice:password@example.test/path?authorization=query-secret#fragment-secret"
        ),
        "exception": RuntimeError("raw-exception-secret"),
        "headers": {
            "Authorization": "Bearer header-secret",
            "Cookie": "session=header-cookie-secret",
        },
        "body": b"body-secret",
        "max_length": 48,
    }

    diagnostic = sanitize_diagnostic(**kwargs)

    assert diagnostic == sanitize_diagnostic(**kwargs)
    assert diagnostic.code is FailureCode.UNREACHABLE
    assert diagnostic.url == "https://example.test/path"
    assert len(diagnostic.message) <= 48
    assert len(diagnostic.digest) == 64
    assert set(diagnostic.digest) <= set("0123456789abcdef")
    assert not hasattr(diagnostic, "exception")
    assert not hasattr(diagnostic, "headers")
    assert not hasattr(diagnostic, "body")

    serialized = json.dumps(asdict(diagnostic), default=str)
    for secret in (
        "alice",
        "password",
        "query-secret",
        "fragment-secret",
        "raw-exception-secret",
        "header-secret",
        "header-cookie-secret",
        "body-secret",
        "Authorization",
        "Cookie",
    ):
        assert secret not in serialized


@pytest.mark.parametrize(
    "purpose",
    [RequestPurpose.DIRECT, RequestPurpose.REDIRECT, RequestPurpose.SUBRESOURCE],
)
def test_explicitly_supplied_ipv4_and_ipv6_endpoints_are_always_allowed(purpose):
    resolver_calls = []

    def resolver(host):
        resolver_calls.append(host)
        raise AssertionError("literal supplied endpoints must not require ambient DNS")

    policy = EgressPolicy(
        supplied_endpoints=(
            Endpoint(address="127.0.0.1", port=8080),
            Endpoint(address="::1", port=8443),
        ),
        resolver=resolver,
    )

    assert policy.authorize("http://127.0.0.1:8080/", purpose) == ("127.0.0.1",)
    assert policy.authorize("https://[::1]:8443/", purpose) == ("::1",)
    assert resolver_calls == []


def test_public_destinations_are_allowed_after_every_address_is_resolved():
    policy = EgressPolicy(
        supplied_endpoints=(),
        resolver=lambda host: {
            "public-v4.test": ("8.8.8.8",),
            "public-v6.test": ("2606:4700:4700::1111",),
        }[host],
    )

    assert policy.authorize(
        "https://public-v4.test/resource",
        RequestPurpose.REDIRECT,
    ) == ("8.8.8.8",)
    assert policy.authorize(
        "https://public-v6.test/resource",
        RequestPurpose.SUBRESOURCE,
    ) == ("2606:4700:4700::1111",)


def test_public_literal_destinations_do_not_require_dns():
    def resolver(_host):
        raise AssertionError("literal public destinations must not require DNS")

    policy = EgressPolicy(supplied_endpoints=(), resolver=resolver)

    assert policy.authorize(
        "https://8.8.8.8/resource",
        RequestPurpose.REDIRECT,
    ) == ("8.8.8.8",)
    assert policy.authorize(
        "https://[2606:4700:4700::1111]/resource",
        RequestPurpose.SUBRESOURCE,
    ) == ("2606:4700:4700::1111",)


def test_private_endpoint_allowance_is_scoped_to_the_explicit_port():
    policy = EgressPolicy(
        supplied_endpoints=(Endpoint(address="127.0.0.1", port=8443),),
        resolver=lambda _host: ("127.0.0.1",),
    )

    with pytest.raises(DestinationBlocked):
        policy.authorize(
            "https://127.0.0.1:9443/",
            RequestPurpose.REDIRECT,
        )


@pytest.mark.parametrize(
    ("host", "resolved_address"),
    [
        ("loopback.test", "127.0.0.1"),
        ("ipv6-loopback.test", "::1"),
        ("link-local.test", "169.254.1.2"),
        ("ipv6-link-local.test", "fe80::1"),
        ("private.test", "10.20.30.40"),
        ("ipv6-ula.test", "fd12:3456:789a::1"),
        ("multicast.test", "224.0.0.1"),
        ("ipv6-multicast.test", "ff02::1"),
        ("unspecified.test", "0.0.0.0"),
        ("ipv6-unspecified.test", "::"),
        ("metadata.test", "169.254.169.254"),
        ("metadata-alias.test", "100.100.100.200"),
    ],
)
@pytest.mark.parametrize("purpose", [RequestPurpose.REDIRECT, RequestPurpose.SUBRESOURCE])
def test_non_supplied_non_public_destinations_are_blocked_after_resolution(
    host,
    resolved_address,
    purpose,
):
    def resolver(resolved_host):
        assert resolved_host == host
        return (resolved_address,)

    policy = EgressPolicy(
        supplied_endpoints=(Endpoint(address="127.0.0.1", port=8443),),
        resolver=resolver,
    )

    with pytest.raises(DestinationBlocked) as captured:
        policy.authorize(f"https://{host}/resource", purpose)

    assert captured.value.failure_code is FailureCode.UNREACHABLE


def test_one_blocked_address_rejects_a_mixed_dns_answer():
    policy = EgressPolicy(
        supplied_endpoints=(),
        resolver=lambda _host: ("8.8.8.8", "127.0.0.1"),
    )

    with pytest.raises(DestinationBlocked):
        policy.authorize("https://mixed-answer.test/", RequestPurpose.REDIRECT)


def test_dns_rebinding_is_rechecked_on_every_authorization():
    answers = iter((("8.8.8.8",), ("127.0.0.1",)))
    resolution_count = 0

    def resolver(_host):
        nonlocal resolution_count
        resolution_count += 1
        return next(answers)

    policy = EgressPolicy(supplied_endpoints=(), resolver=resolver)
    url = "https://rebinding.test/resource"

    assert policy.authorize(url, RequestPurpose.SUBRESOURCE) == ("8.8.8.8",)
    with pytest.raises(DestinationBlocked):
        policy.authorize(url, RequestPurpose.SUBRESOURCE)
    assert resolution_count == 2


def test_transport_applies_egress_policy_before_opening_a_connection():
    response = FakeResponse(200)
    session = RecordingSession((response,))
    policy = EgressPolicy(
        supplied_endpoints=(Endpoint(address="127.0.0.1", port=8443),),
        resolver=lambda _host: ("127.0.0.1",),
    )
    transport = direct_transport(session, policy=policy)

    allowed = transport.probe("https://127.0.0.1:8443/")
    blocked = transport.probe(
        "https://private-redirect.test/",
        purpose=RequestPurpose.REDIRECT,
    )

    assert allowed.state is TransportState.RESPONSE
    assert blocked.state is TransportState.UNAVAILABLE
    assert blocked.failure_code is FailureCode.UNREACHABLE
    assert len(session.calls) == 1
