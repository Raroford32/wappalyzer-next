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
