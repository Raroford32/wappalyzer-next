import pytest
import requests

import wappalyzer.core.direct_requester as direct_requester_module
from wappalyzer.core.direct_requester import DirectResponseFetcher
from wappalyzer.core.transport import EgressPolicy, http_origin
from wappalyzer.models import Endpoint, EvidenceLimit, TLSMetadata, TLSTrust


def response(url, status=200, location=None, body=b"ok"):
    value = requests.Response()
    value.url = url
    value.status_code = status
    value._content = body
    value._content_consumed = True
    if location is not None:
        value.headers["Location"] = location
    return value


class Session:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []
        self.trust_env = True
        self.auth = ("ambient", "secret")
        self.cert = "ambient-cert"
        self.cookies = requests.cookies.cookiejar_from_dict({"ambient": "secret"})
        self.headers = {"Authorization": "secret"}
        self.params = {"secret": "value"}
        self.proxies = {"https": "http://secret"}
        self.closed = False

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return next(self.responses)

    def close(self):
        self.closed = True


def test_direct_fetcher_scopes_untrusted_tls_and_strips_ambient_credentials():
    endpoint = Endpoint("127.0.0.1", 8443)
    session = Session(
        (
            response("https://127.0.0.1:8443/", 302, "/next"),
            response("https://127.0.0.1:8443/next"),
        )
    )
    fetcher = DirectResponseFetcher(
        endpoint=endpoint,
        tls=TLSMetadata(True, TLSTrust.UNTRUSTED),
        timeout=5,
        session_factory=lambda: session,
    )

    outcome = fetcher.fetch("https://127.0.0.1:8443/")

    assert outcome.response.url.endswith("/next")
    assert [call[1]["verify"] for call in session.calls] == [False, False]
    assert all(call[1]["allow_redirects"] is False for call in session.calls)
    assert session.trust_env is False
    assert session.auth is None
    assert not session.cookies
    assert not session.headers
    assert not session.params
    assert not session.proxies
    assert session.closed


def test_direct_fetcher_blocks_private_redirect_and_reports_policy_limit():
    endpoint = Endpoint("192.0.2.1", 8080)
    session = Session(
        (
            response(
                "http://192.0.2.1:8080/",
                302,
                "http://169.254.169.254/latest/meta-data",
            ),
        )
    )
    fetcher = DirectResponseFetcher(
        endpoint=endpoint,
        tls=TLSMetadata(False, TLSTrust.NOT_APPLICABLE),
        timeout=5,
        session_factory=lambda: session,
    )

    outcome = fetcher.fetch("http://192.0.2.1:8080/")

    assert outcome.response.status_code == 302
    assert outcome.limits == (EvidenceLimit.POLICY,)
    assert len(session.calls) == 1


def test_untrusted_exception_does_not_cross_to_public_redirect_authority():
    endpoint = Endpoint("192.0.2.1", 8443)
    session = Session(
        (
            response("https://192.0.2.1:8443/", 302, "https://public.example/"),
            response("https://public.example/"),
        )
    )
    policy = EgressPolicy(
        (endpoint,),
        resolver=lambda host: ("93.184.216.34",) if host == "public.example" else (),
    )
    fetcher = DirectResponseFetcher(
        endpoint=endpoint,
        tls=TLSMetadata(True, TLSTrust.UNTRUSTED),
        timeout=5,
        policy=policy,
        session_factory=lambda: session,
    )

    outcome = fetcher.fetch("https://192.0.2.1:8443/")

    assert outcome.response.url == "https://public.example/"
    assert [call[1]["verify"] for call in session.calls] == [False, True]


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.test/",
        "https://example.test:invalid/",
        "/relative",
    ],
)
def test_origin_rejects_unsupported_or_malformed_urls(url):
    assert http_origin(url) is None


def test_origin_normalizes_default_ports_and_host_case():
    assert http_origin("HTTPS://EXAMPLE.TEST/path") == (
        "https",
        "example.test",
        443,
    )


@pytest.mark.parametrize(
    "replacement",
    [
        {"endpoint": object()},
        {"tls": object()},
        {"timeout": True},
        {"timeout": "5"},
        {"timeout": 0},
        {"max_redirects": True},
        {"max_redirects": "1"},
        {"max_redirects": -1},
        {"session_factory": None},
        {"monotonic": None},
        {"policy": object()},
    ],
)
def test_direct_fetcher_validates_configuration(replacement):
    values = {
        "endpoint": Endpoint("127.0.0.1", 8443),
        "tls": TLSMetadata(True, TLSTrust.TRUSTED),
        "timeout": 5,
    }
    values.update(replacement)

    with pytest.raises((TypeError, ValueError)):
        DirectResponseFetcher(**values)


def test_direct_fetcher_reports_timer_limit_before_requesting():
    clock = iter((10.0, 12.0))
    session = Session(())
    fetcher = DirectResponseFetcher(
        endpoint=Endpoint("127.0.0.1", 8443),
        tls=TLSMetadata(True, TLSTrust.TRUSTED),
        timeout=1,
        session_factory=lambda: session,
        monotonic=lambda: next(clock),
    )

    outcome = fetcher.fetch("https://127.0.0.1:8443/")

    assert outcome == direct_requester_module.DirectResponseOutcome(
        None,
        (EvidenceLimit.TIMER,),
    )
    assert session.calls == []
    assert session.closed


def test_direct_fetcher_returns_none_for_typed_request_failure(monkeypatch):
    session = Session(())
    fetcher = DirectResponseFetcher(
        endpoint=Endpoint("127.0.0.1", 8443),
        tls=TLSMetadata(True, TLSTrust.TRUSTED),
        timeout=1,
        session_factory=lambda: session,
        monotonic=lambda: 0.0,
    )
    monkeypatch.setattr(direct_requester_module, "get_response", lambda *args, **kwargs: None)

    outcome = fetcher.fetch("https://127.0.0.1:8443/")

    assert outcome.response is None
    assert outcome.limits == ()
    assert session.closed


def test_redirect_status_without_location_is_returned_without_following():
    missing_location = response("http://127.0.0.1:8080/", status=302)
    session = Session((missing_location,))
    fetcher = DirectResponseFetcher(
        endpoint=Endpoint("127.0.0.1", 8080),
        tls=TLSMetadata(False, TLSTrust.NOT_APPLICABLE),
        timeout=5,
        session_factory=lambda: session,
    )

    outcome = fetcher.fetch("http://127.0.0.1:8080/")

    assert outcome.response is missing_location
    assert outcome.limits == ()
    assert len(session.calls) == 1


def test_redirect_limit_returns_last_response_and_records_limit():
    redirect = response("http://127.0.0.1:8080/", status=301, location="/again")
    session = Session((redirect,))
    fetcher = DirectResponseFetcher(
        endpoint=Endpoint("127.0.0.1", 8080),
        tls=TLSMetadata(False, TLSTrust.NOT_APPLICABLE),
        timeout=5,
        max_redirects=0,
        session_factory=lambda: session,
    )

    outcome = fetcher.fetch("http://127.0.0.1:8080/")

    assert outcome.response is redirect
    assert outcome.limits == (EvidenceLimit.REDIRECT,)
    assert len(session.calls) == 1


def test_redirect_rechecks_dns_and_blocks_rebinding():
    answers = iter((("8.8.8.8",), ("127.0.0.1",)))
    session = Session(
        (
            response(
                "http://rebinding.test/",
                status=302,
                location="/next",
            ),
        )
    )
    fetcher = DirectResponseFetcher(
        endpoint=Endpoint("192.0.2.1", 80),
        tls=TLSMetadata(False, TLSTrust.NOT_APPLICABLE),
        timeout=5,
        policy=EgressPolicy((), resolver=lambda _host: next(answers)),
        session_factory=lambda: session,
    )

    outcome = fetcher.fetch("http://rebinding.test/")

    assert outcome.response.status_code == 302
    assert outcome.limits == (EvidenceLimit.POLICY,)
    assert len(session.calls) == 1


def test_call_forwards_bounded_request_options(monkeypatch):
    recorded = {}
    expected = response("https://127.0.0.1:8443/")
    session = Session(())
    fetcher = DirectResponseFetcher(
        endpoint=Endpoint("127.0.0.1", 8443),
        tls=TLSMetadata(True, TLSTrust.TRUSTED),
        timeout=5,
        session_factory=lambda: session,
        monotonic=lambda: 0.0,
    )

    def get_response(url, cookie, **kwargs):
        recorded.update({"url": url, "cookie": cookie, **kwargs})
        return expected

    monkeypatch.setattr(direct_requester_module, "get_response", get_response)

    result = fetcher(
        "https://127.0.0.1:8443/",
        cookie="session=value",
        timeout=2,
        max_bytes=1024,
        ignored="value",
    )

    assert result is expected
    assert recorded["cookie"] == "session=value"
    assert recorded["timeout"] == 2
    assert recorded["max_bytes"] == 1024
