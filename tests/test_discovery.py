import pytest

from wappalyzer.core.transport import RequestPurpose, TransportResult, TransportState
from wappalyzer.discovery import DiscoveryState, discover_protocols
from wappalyzer.models import Endpoint, FailureCode, Protocol, TLSMetadata, TLSTrust


class ScriptedTransport:
    def __init__(self, results):
        self.results = iter(results)
        self.calls = []

    def probe(
        self,
        url,
        *,
        verify_tls=True,
        purpose=RequestPurpose.DIRECT,
    ):
        self.calls.append(
            {
                "url": url,
                "verify_tls": verify_tls,
                "purpose": purpose,
            }
        )
        return next(self.results)


def response(status_code, body=b""):
    return TransportResult(
        state=TransportState.RESPONSE,
        status_code=status_code,
        body=body,
    )


def failure(state, code):
    return TransportResult(
        state=state,
        failure_code=code,
    )


@pytest.mark.parametrize("port", [80, 443, 31337])
@pytest.mark.parametrize(
    ("address", "http_url", "https_url"),
    [
        (
            "192.0.2.10",
            "http://192.0.2.10:{port}/",
            "https://192.0.2.10:{port}/",
        ),
        (
            "2001:db8::10",
            "http://[2001:db8::10]:{port}/",
            "https://[2001:db8::10]:{port}/",
        ),
    ],
)
def test_http_and_https_are_independent_ordered_attempts_on_the_supplied_port(
    port,
    address,
    http_url,
    https_url,
):
    transport = ScriptedTransport((response(204), response(299)))
    endpoint = Endpoint(address=address, port=port)
    expected_urls = [http_url.format(port=port), https_url.format(port=port)]

    results = discover_protocols(endpoint, transport)

    assert [call["url"] for call in transport.calls] == expected_urls
    assert [call["verify_tls"] for call in transport.calls] == [True, True]
    assert [call["purpose"] for call in transport.calls] == [
        RequestPurpose.DIRECT,
        RequestPurpose.DIRECT,
    ]
    assert [result.protocol for result in results] == [Protocol.HTTP, Protocol.HTTPS]
    assert [result.requested_url for result in results] == expected_urls
    assert [result.http_status for result in results] == [204, 299]
    assert [result.state for result in results] == [
        DiscoveryState.LIVE,
        DiscoveryState.LIVE,
    ]
    assert results[0].tls == TLSMetadata(
        present=False,
        trust=TLSTrust.NOT_APPLICABLE,
    )
    assert results[1].tls == TLSMetadata(
        present=True,
        trust=TLSTrust.TRUSTED,
    )


@pytest.mark.parametrize("status_code", [100, 199, 200, 302, 404, 599])
def test_any_valid_status_makes_each_protocol_live(status_code):
    transport = ScriptedTransport((response(status_code), response(status_code)))

    results = discover_protocols(Endpoint("192.0.2.10", 9443), transport)

    assert [result.state for result in results] == [
        DiscoveryState.LIVE,
        DiscoveryState.LIVE,
    ]
    assert [result.http_status for result in results] == [status_code, status_code]
    assert all(result.failure_code is None for result in results)


@pytest.mark.parametrize(
    ("http_result", "https_result", "expected_states"),
    [
        (
            response(200),
            failure(TransportState.UNAVAILABLE, FailureCode.UNREACHABLE),
            (DiscoveryState.LIVE, DiscoveryState.UNAVAILABLE),
        ),
        (
            failure(TransportState.UNAVAILABLE, FailureCode.UNREACHABLE),
            response(200),
            (DiscoveryState.UNAVAILABLE, DiscoveryState.LIVE),
        ),
        (
            response(200),
            response(200),
            (DiscoveryState.LIVE, DiscoveryState.LIVE),
        ),
    ],
)
def test_one_protocol_result_never_suppresses_the_other_attempt(
    http_result,
    https_result,
    expected_states,
):
    transport = ScriptedTransport((http_result, https_result))

    results = discover_protocols(Endpoint("192.0.2.10", 443), transport)

    assert len(transport.calls) == 2
    assert [call["url"].split(":", 1)[0] for call in transport.calls] == [
        "http",
        "https",
    ]
    assert tuple(result.state for result in results) == expected_states


def test_verified_handshake_failure_gets_one_insecure_probe_and_remains_untrusted():
    transport = ScriptedTransport(
        (
            failure(TransportState.UNAVAILABLE, FailureCode.UNREACHABLE),
            failure(TransportState.TLS_UNTRUSTED, FailureCode.TLS_UNTRUSTED),
            response(401, b"tiny"),
        )
    )

    http, https = discover_protocols(Endpoint("192.0.2.10", 8443), transport)

    assert http.state is DiscoveryState.UNAVAILABLE
    assert [(call["url"], call["verify_tls"]) for call in transport.calls] == [
        ("http://192.0.2.10:8443/", True),
        ("https://192.0.2.10:8443/", True),
        ("https://192.0.2.10:8443/", False),
    ]
    assert https.state is DiscoveryState.LIVE
    assert https.http_status == 401
    assert https.failure_code is FailureCode.TLS_UNTRUSTED
    assert https.tls == TLSMetadata(
        present=True,
        trust=TLSTrust.UNTRUSTED,
    )


def test_insecure_tls_probe_is_bounded_to_one_and_does_not_disable_future_verification():
    transport = ScriptedTransport(
        (
            failure(TransportState.UNAVAILABLE, FailureCode.UNREACHABLE),
            failure(TransportState.TLS_UNTRUSTED, FailureCode.TLS_UNTRUSTED),
            response(200),
            failure(TransportState.UNAVAILABLE, FailureCode.UNREACHABLE),
            response(204),
        )
    )

    first = discover_protocols(Endpoint("192.0.2.10", 8443), transport)
    second = discover_protocols(Endpoint("192.0.2.11", 8443), transport)

    assert first[1].tls.trust is TLSTrust.UNTRUSTED
    assert second[1].tls.trust is TLSTrust.TRUSTED
    assert [call["verify_tls"] for call in transport.calls] == [
        True,
        True,
        False,
        True,
        True,
    ]


def test_malformed_tls_does_not_trigger_an_insecure_certificate_retry():
    transport = ScriptedTransport(
        (
            failure(TransportState.UNAVAILABLE, FailureCode.UNREACHABLE),
            failure(TransportState.MALFORMED_TLS, FailureCode.UNREACHABLE),
        )
    )

    _http, https = discover_protocols(Endpoint("192.0.2.10", 8443), transport)

    assert len(transport.calls) == 2
    assert https.state is DiscoveryState.MALFORMED_TLS
    assert https.http_status is None
    assert https.failure_code is FailureCode.UNREACHABLE
    assert https.tls == TLSMetadata(
        present=True,
        trust=TLSTrust.INDETERMINATE,
    )


def test_failed_insecure_confirmation_is_malformed_tls_without_further_retries():
    transport = ScriptedTransport(
        (
            failure(TransportState.UNAVAILABLE, FailureCode.UNREACHABLE),
            failure(TransportState.TLS_UNTRUSTED, FailureCode.TLS_UNTRUSTED),
            failure(TransportState.MALFORMED_TLS, FailureCode.UNREACHABLE),
        )
    )

    _http, https = discover_protocols(Endpoint("192.0.2.10", 8443), transport)

    assert [call["verify_tls"] for call in transport.calls] == [True, True, False]
    assert https.state is DiscoveryState.MALFORMED_TLS
    assert https.failure_code is FailureCode.UNREACHABLE
    assert https.tls == TLSMetadata(
        present=True,
        trust=TLSTrust.INDETERMINATE,
    )


def test_unavailable_timeout_and_malformed_tls_are_distinct_typed_results():
    transport = ScriptedTransport(
        (
            failure(TransportState.TIMEOUT, FailureCode.DISCOVERY_TIMEOUT),
            failure(TransportState.MALFORMED_TLS, FailureCode.UNREACHABLE),
        )
    )

    http, https = discover_protocols(Endpoint("192.0.2.10", 8443), transport)

    assert (http.state, http.failure_code, http.http_status) == (
        DiscoveryState.INDETERMINATE,
        FailureCode.DISCOVERY_TIMEOUT,
        None,
    )
    assert http.tls == TLSMetadata(
        present=False,
        trust=TLSTrust.NOT_APPLICABLE,
    )
    assert (https.state, https.failure_code, https.http_status) == (
        DiscoveryState.MALFORMED_TLS,
        FailureCode.UNREACHABLE,
        None,
    )
    assert https.tls == TLSMetadata(
        present=True,
        trust=TLSTrust.INDETERMINATE,
    )


def test_connection_refusal_is_unavailable_not_timeout_or_success():
    transport = ScriptedTransport(
        (
            failure(TransportState.UNAVAILABLE, FailureCode.UNREACHABLE),
            failure(TransportState.UNAVAILABLE, FailureCode.UNREACHABLE),
        )
    )

    results = discover_protocols(Endpoint("192.0.2.10", 65535), transport)

    assert [result.state for result in results] == [
        DiscoveryState.UNAVAILABLE,
        DiscoveryState.UNAVAILABLE,
    ]
    assert [result.failure_code for result in results] == [
        FailureCode.UNREACHABLE,
        FailureCode.UNREACHABLE,
    ]
    assert all(result.http_status is None for result in results)
