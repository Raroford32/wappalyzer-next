import json
import ssl
from dataclasses import asdict
from types import SimpleNamespace

import pytest
import requests

import wappalyzer.core.transport as transport_module
from wappalyzer.core.transport import (
    Diagnostic,
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
        self.cert = "ambient-cert"
        self.verify = False
        self.cookies = requests.cookies.cookiejar_from_dict({"ambient-cookie": "secret-cookie"})
        self.headers = {
            "Authorization": "Bearer secret-authorization",
            "Cookie": "ambient-cookie=secret-cookie",
            "User-Agent": "ambient-agent",
        }
        self.params = {"ambient": "parameter"}
        self.proxies = {"https": "http://ambient-proxy.invalid"}
        self.closed = False

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        result = next(self.responses)
        if isinstance(result, BaseException):
            raise result
        return result

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def close(self):
        self.closed = True


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


@pytest.mark.parametrize(
    "kwargs",
    [
        {"connect_timeout": True},
        {"connect_timeout": "1"},
        {"connect_timeout": float("inf")},
        {"connect_timeout": 0},
        {"overall_timeout": False},
        {"overall_timeout": None},
        {"overall_timeout": float("nan")},
        {"overall_timeout": -1},
    ],
)
def test_transport_limits_reject_invalid_timeouts(kwargs):
    with pytest.raises(ValueError, match="must be a finite positive number"):
        TransportLimits(**kwargs)


@pytest.mark.parametrize("max_body_bytes", [True, 1.5, -1])
def test_transport_limits_reject_invalid_body_limits(max_body_bytes):
    with pytest.raises(ValueError, match="must be a non-negative integer"):
        TransportLimits(max_body_bytes=max_body_bytes)


def test_transport_limits_normalize_integer_timeouts():
    limits = TransportLimits(connect_timeout=1, overall_timeout=2, max_body_bytes=0)

    assert limits.connect_timeout == 1.0
    assert limits.overall_timeout == 2.0


@pytest.mark.parametrize(
    ("replacement", "exception_type"),
    [
        ({"code": "unreachable"}, TypeError),
        ({"url": 3}, TypeError),
        ({"message": object()}, TypeError),
        ({"digest": b"0" * 64}, ValueError),
        ({"digest": "0" * 63}, ValueError),
        ({"digest": "g" * 64}, ValueError),
    ],
)
def test_diagnostic_validates_every_field(replacement, exception_type):
    kwargs = {
        "code": FailureCode.UNREACHABLE,
        "url": "https://example.test/",
        "message": "unreachable",
        "digest": "0" * 64,
    }
    kwargs.update(replacement)

    with pytest.raises(exception_type):
        Diagnostic(**kwargs)


def test_transport_result_validates_types_and_failure_invariants():
    diagnostic = sanitize_diagnostic(
        code=FailureCode.DISCOVERY_TIMEOUT,
        url="https://example.test/",
    )
    invalid_results = [
        ({"state": "response", "status_code": 200}, TypeError),
        ({"state": TransportState.RESPONSE, "status_code": 200, "body": "body"}, TypeError),
        (
            {
                "state": TransportState.UNAVAILABLE,
                "failure_code": "unreachable",
            },
            TypeError,
        ),
        (
            {
                "state": TransportState.UNAVAILABLE,
                "failure_code": FailureCode.UNREACHABLE,
                "diagnostic": object(),
            },
            TypeError,
        ),
        (
            {
                "state": TransportState.TIMEOUT,
                "failure_code": FailureCode.UNREACHABLE,
                "diagnostic": diagnostic,
            },
            ValueError,
        ),
        ({"state": TransportState.RESPONSE, "status_code": True}, ValueError),
        ({"state": TransportState.RESPONSE, "status_code": 99}, ValueError),
        (
            {
                "state": TransportState.RESPONSE,
                "status_code": 200,
                "failure_code": FailureCode.UNREACHABLE,
            },
            ValueError,
        ),
        (
            {
                "state": TransportState.UNAVAILABLE,
                "status_code": 503,
                "failure_code": FailureCode.UNREACHABLE,
            },
            ValueError,
        ),
        (
            {
                "state": TransportState.UNAVAILABLE,
                "body": b"partial",
                "failure_code": FailureCode.UNREACHABLE,
            },
            ValueError,
        ),
        ({"state": TransportState.UNAVAILABLE}, ValueError),
    ]

    for kwargs, exception_type in invalid_results:
        with pytest.raises(exception_type):
            TransportResult(**kwargs)


def test_default_resolver_normalizes_and_deduplicates_dns_answers(monkeypatch):
    records = (
        (transport_module.socket.AF_INET, 0, 0, "", ("8.8.8.8", 0)),
        (transport_module.socket.AF_INET, 0, 0, "", ("8.8.8.8", 0)),
        (
            transport_module.socket.AF_INET6,
            0,
            0,
            "",
            ("2606:4700:4700:0:0:0:0:1111", 0, 0, 0),
        ),
    )

    def getaddrinfo(host, port, *, type):
        assert (host, port, type) == ("resolver.test", None, transport_module.socket.SOCK_STREAM)
        return records

    monkeypatch.setattr(transport_module.socket, "getaddrinfo", getaddrinfo)

    assert transport_module._default_resolver("resolver.test") == (
        "8.8.8.8",
        "2606:4700:4700::1111",
    )


@pytest.mark.parametrize(
    "url",
    [
        None,
        "",
        "https://example.test/\n",
        "https://example.test\\private",
        "https://example.test:invalid/",
        "ftp://example.test/",
        "https://percent%25.test/",
        "https://./",
        "http://127.0.0.1:0/",
    ],
)
def test_egress_policy_rejects_malformed_or_unsupported_destinations(url):
    policy = EgressPolicy((), resolver=lambda _host: ("8.8.8.8",))

    with pytest.raises(DestinationBlocked):
        policy.authorize(url, RequestPurpose.DIRECT)


def test_egress_policy_validates_configuration_and_purpose():
    with pytest.raises(TypeError, match="Endpoint"):
        EgressPolicy(("not-an-endpoint",))
    with pytest.raises(TypeError, match="resolver"):
        EgressPolicy((), resolver=None)

    policy = EgressPolicy(())
    with pytest.raises(TypeError, match="purpose"):
        policy.authorize("https://8.8.8.8/", "direct")


@pytest.mark.parametrize(
    "url",
    [
        "https://metadata.google.internal/",
        "https://[::ffff:127.0.0.1]/",
    ],
)
def test_egress_policy_blocks_metadata_aliases_and_ipv4_mapped_private_addresses(url):
    policy = EgressPolicy((), resolver=lambda _host: ("8.8.8.8",))

    with pytest.raises(DestinationBlocked):
        policy.authorize(url, RequestPurpose.SUBRESOURCE)


def test_egress_policy_allows_ipv4_mapped_public_addresses():
    policy = EgressPolicy(())

    assert policy.authorize(
        "https://[::ffff:8.8.8.8]/",
        RequestPurpose.REDIRECT,
    ) == ("::ffff:808:808",)


@pytest.mark.parametrize(
    "resolver",
    [
        lambda _host: (_ for _ in ()).throw(OSError("dns unavailable")),
        lambda _host: ("not-an-address",),
    ],
)
def test_egress_policy_converts_dns_failures_to_destination_blocked(resolver):
    policy = EgressPolicy((), resolver=resolver)

    with pytest.raises(DestinationBlocked) as captured:
        policy.authorize("https://dns-failure.test/", RequestPurpose.REDIRECT)

    assert captured.value.failure_code is FailureCode.UNREACHABLE


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (object(), "<invalid-url>"),
        ("https://example.test:invalid/", "<invalid-url>"),
        ("ftp://example.test/path", "<invalid-url>"),
    ],
)
def test_url_sanitizer_rejects_non_http_or_malformed_values(url, expected):
    assert sanitize_url(url) == expected


class ExplodingText:
    def __str__(self):
        raise RuntimeError("string conversion failed")


def test_diagnostic_sanitizer_handles_unprintable_values_and_non_byte_bodies():
    value = ExplodingText()

    assert transport_module._safe_text(value).endswith(".ExplodingText>")
    diagnostic = sanitize_diagnostic(
        code=FailureCode.UNREACHABLE,
        url="https://example.test/",
        headers={value: value},
        body=value,
    )

    assert diagnostic.url == "https://example.test/"
    assert len(diagnostic.digest) == 64


@pytest.mark.parametrize(
    "kwargs",
    [
        {"code": "unreachable"},
        {"max_length": True},
        {"max_length": -1},
    ],
)
def test_diagnostic_sanitizer_validates_inputs(kwargs):
    values = {
        "code": FailureCode.UNREACHABLE,
        "url": "https://example.test/",
    }
    values.update(kwargs)

    with pytest.raises((TypeError, ValueError)):
        sanitize_diagnostic(**values)


def test_exception_walker_handles_cycles_and_exception_arguments():
    child = ValueError("child")
    root = RuntimeError("root", child)
    root.reason = root

    walked = tuple(transport_module._walk_exceptions(root))

    assert walked[0] is root
    assert child in walked
    assert walked.count(root) == 1


def test_response_closer_tolerates_missing_or_failing_close_methods():
    class FailingClose:
        def close(self):
            raise OSError("close failed")

    transport_module._close_response(object())
    transport_module._close_response(FailingClose())


def test_failure_result_without_an_exception_is_still_sanitized():
    result = transport_module._failure_result(
        state=TransportState.UNAVAILABLE,
        code=FailureCode.UNREACHABLE,
        url="https://user:secret@example.test/?token=secret",
    )

    assert result.diagnostic.url == "https://example.test/"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"policy": object()},
        {"limits": object()},
        {"session_factory": None},
        {"monotonic": None},
    ],
)
def test_direct_transport_validates_dependencies(kwargs):
    values = {
        "policy": explicit_policy(),
        "limits": TransportLimits(),
        "session_factory": lambda: RecordingSession(()),
        "monotonic": lambda: 0.0,
    }
    values.update(kwargs)

    with pytest.raises(TypeError):
        DirectTransport(**values)


def test_session_hardening_handles_sessions_without_optional_mappings():
    session = RecordingSession(())
    del session.params
    del session.proxies

    direct_transport(session)

    assert session.trust_env is False
    assert session.auth is None
    assert session.cert is None
    assert session.verify is True


def test_zero_body_limit_avoids_stream_reads():
    response = FakeResponse(200, (AssertionError("body should not be read"),))
    session = RecordingSession((response,))
    limits = TransportLimits(connect_timeout=1, overall_timeout=1, max_body_bytes=0)

    result = direct_transport(session, limits=limits).probe("http://127.0.0.1:8443/")

    assert result.body == b""
    assert response.chunk_reads == 0


def test_empty_chunks_are_ignored_and_an_exact_limit_exits_cleanly():
    response = FakeResponse(200, (b"", b"1234", AssertionError("read past exact limit")))
    session = RecordingSession((response,))
    limits = TransportLimits(connect_timeout=1, overall_timeout=1, max_body_bytes=4)

    result = direct_transport(
        session,
        limits=limits,
        monotonic=lambda: 0.0,
    ).probe("http://127.0.0.1:8443/")

    assert result.body == b"1234"
    assert response.chunk_reads == 2


def test_probe_validates_tls_flag_before_network_access():
    session = RecordingSession(())

    with pytest.raises(TypeError, match="verify_tls"):
        direct_transport(session).probe("https://127.0.0.1:8443/", verify_tls=1)

    assert session.calls == []


def test_generic_request_failure_closes_attached_response_and_is_typed():
    attached_response = FakeResponse(500)
    error = requests.exceptions.RequestException("request failed")
    error.response = attached_response
    session = RecordingSession((error,))

    result = direct_transport(session).probe("https://127.0.0.1:8443/")

    assert result.state is TransportState.UNAVAILABLE
    assert result.failure_code is FailureCode.UNREACHABLE
    assert attached_response.closed


def test_request_url_preserves_query_but_removes_fragment_without_explicit_port():
    session = RecordingSession((FakeResponse(200),))
    policy = EgressPolicy(())

    result = direct_transport(session, policy=policy).probe(
        "https://8.8.8.8/path?token=value#fragment"
    )

    assert result.state is TransportState.RESPONSE
    assert session.calls[0]["url"] == "https://8.8.8.8/path?token=value"


def test_direct_transport_context_manager_closes_its_session():
    session = RecordingSession(())
    transport = direct_transport(session)

    with transport as entered:
        assert entered is transport

    assert session.closed
