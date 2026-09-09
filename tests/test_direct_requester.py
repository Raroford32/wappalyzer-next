import requests

from wappalyzer.core.direct_requester import DirectResponseFetcher
from wappalyzer.core.transport import EgressPolicy
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
