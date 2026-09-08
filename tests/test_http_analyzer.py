import pytest
from requests import Response
from requests.cookies import cookiejar_from_dict
from requests.structures import CaseInsensitiveDict

from wappalyzer.core import analyzer, utils

HTML = b"""
<!doctype html>
<html>
  <head>
    <meta http-equiv="X-Generator" content="MetaMarker">
    <style>.css-marker { color: red }</style>
    <script>const scriptMarker = "ScriptMarker";</script>
  </head>
  <body>
    <main ng-version="22.1.5">Visible Marker</main>
  </body>
</html>
"""


def response():
    value = Response()
    value.status_code = 200
    value.url = "https://example.test/path"
    value._content = HTML
    value.headers = CaseInsensitiveDict({"X-Powered-By": "HeaderMarker"})
    value.cookies = cookiejar_from_dict({"session_marker": "CookieMarker"})
    return value


def test_collects_all_single_request_evidence_channels():
    evidence = analyzer.collect_evidence(response(), "fast")

    assert any("ScriptMarker" in source for source in evidence["scripts"])
    assert any("css-marker" in source for source in evidence["css"])
    assert "Visible Marker" in evidence["text"]
    assert evidence["meta"]["x-generator"] == "MetaMarker"
    assert evidence["headers"]["x-powered-by"] == "HeaderMarker"
    assert evidence["cookies"]["session_marker"] == "CookieMarker"


def test_fast_analyzer_uses_compiled_channel_plan(monkeypatch):
    database = {
        "CookieTech": {"cats": [], "cookies": {"session_marker": "CookieMarker"}},
        "CssTech": {"cats": [], "css": r"\.css-marker"},
        "DomTech": {
            "cats": [],
            "dom": {
                "[ng-version]": {
                    "attributes": {
                        "ng-version": r"([\d.]+)\;version:\1",
                    },
                },
            },
        },
        "HeaderTech": {"cats": [], "headers": {"x-powered-by": "HeaderMarker"}},
        "HtmlTech": {"cats": [], "html": "Visible Marker"},
        "MetaTech": {"cats": [], "meta": {"x-generator": "MetaMarker"}},
        "ScriptTech": {"cats": [], "scripts": "ScriptMarker"},
        "TextTech": {"cats": [], "text": "Visible Marker"},
        "UrlTech": {"cats": [], "url": r"example\.test/path"},
    }
    monkeypatch.setattr(analyzer, "tech_db", database)
    monkeypatch.setattr(analyzer, "DETECTOR_PLAN", analyzer.build_detector_plan(database))
    monkeypatch.setattr(utils, "tech_db", database)
    analyzer.prepare_matchers.cache_clear()

    result = analyzer.analyze_from_response(response(), "fast")

    assert list(result) == sorted(database)
    assert result["DomTech"]["version"] == "22.1.5"


def test_asset_credentials_never_cross_origins(monkeypatch):
    seen = {}

    def fake_fetch(url, timeout, cookie):
        seen[url] = cookie
        return url, "ok"

    monkeypatch.setattr(analyzer, "_fetch_asset", fake_fetch)
    analyzer._fetch_assets(
        [
            "https://app.example.test/app.js",
            "https://cdn.example.test/library.js",
        ],
        timeout=5,
        cookie="session=secret",
        credential_origin="https://app.example.test/page",
        budget=analyzer.AssetBudget(2),
    )

    assert seen["https://app.example.test/app.js"] == "session=secret"
    assert seen["https://cdn.example.test/library.js"] is None


def test_asset_budget_is_shared_across_resource_classes(monkeypatch):
    monkeypatch.setattr(
        analyzer,
        "_fetch_asset",
        lambda url, timeout, cookie: (url, "ok"),
    )
    budget = analyzer.AssetBudget(2)

    scripts = analyzer._fetch_assets(
        ["https://example.test/a.js", "https://example.test/b.js"],
        5,
        None,
        "https://example.test",
        budget,
    )
    styles = analyzer._fetch_assets(
        ["https://example.test/a.css"],
        5,
        None,
        "https://example.test",
        budget,
    )

    assert len(scripts) == 2
    assert styles == {}


def test_primary_request_failure_is_not_reported_as_empty_success(monkeypatch):
    monkeypatch.setattr(analyzer, "get_response", lambda *args, **kwargs: None)

    with pytest.raises(analyzer.ScanRequestError, match="Unable to fetch"):
        analyzer.http_scan("https://unreachable.example", "fast")


def test_versions_from_multiple_channels_merge_deterministically():
    forward = {}
    reverse = {}

    analyzer._add_candidate(forward, "VersionedTech", (True, "10", 50))
    analyzer._add_candidate(forward, "VersionedTech", (True, "9", 50))
    analyzer._add_candidate(reverse, "VersionedTech", (True, "9", 50))
    analyzer._add_candidate(reverse, "VersionedTech", (True, "10", 50))

    assert forward == reverse
    assert forward["VersionedTech"] == {
        "version": "10",
        "confidence": 100,
    }


def test_expired_url_budget_skips_secondary_requests(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("secondary request exceeded the URL budget")

    monkeypatch.setattr(analyzer, "get_dns", forbidden)
    monkeypatch.setattr(analyzer, "get_robots", forbidden)
    monkeypatch.setattr(analyzer, "get_certIssuer", forbidden)
    monkeypatch.setattr(analyzer, "_probe_responses", forbidden)

    evidence = analyzer.collect_evidence(
        response(),
        "balanced",
        timeout=1,
        deadline=0,
    )

    assert evidence["dns"] == {}
    assert evidence["robots"] == ""
    assert evidence["certIssuer"] == ""
    assert evidence["probes"] == {}
