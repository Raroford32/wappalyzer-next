import asyncio
import zipfile

import pytest

from wappalyzer.browser import analyzer
from wappalyzer.models import ChannelOwner, EvidenceLimit, StageStatus


def test_extension_bridge_requests_raw_channel_tagged_detections():
    assert (
        "func: raw ? 'getRawDetectionsForTab' : 'getDetectionsForTab'"
        in analyzer.GET_DETECTIONS_FOR_TAB_SCRIPT
    )
    assert "type: pattern.type" in analyzer.GET_DETECTIONS_FOR_TAB_SCRIPT
    assert "match: pattern.match" in analyzer.GET_DETECTIONS_FOR_TAB_SCRIPT


class FakePage:
    def __init__(self):
        self.url = "about:blank"
        self.closed = False

    async def goto(self, url, **kwargs):
        self.url = url

    async def evaluate(self, _script, *_args):
        return {
            "htmlCharacters": 0,
            "textCharacters": 0,
            "inlineScriptCount": 0,
            "inlineScriptCharacters": 0,
        }

    async def close(self):
        self.closed = True


class FakeContext:
    def __init__(self):
        self.pages_created = []

    async def new_page(self):
        page = FakePage()
        self.pages_created.append(page)
        return page


class FakeDriver:
    def __init__(self):
        self.context = FakeContext()
        self.page = None
        self.timeout_ms = 1_000
        self.extension_id = "example"

    async def apply_pending_cookies(self, url):
        return None


def test_detection_polling_keeps_last_success_after_transient_error(monkeypatch):
    detections = [{"technology": "React"}]

    class Popup:
        url = "chrome-extension://example/html/popup.html"

        def __init__(self):
            self.poll = 0

        def is_closed(self):
            return False

        async def evaluate(self, script, _arguments):
            if script == analyzer.SELECT_TARGET_TAB_SCRIPT:
                return {"id": 1, "url": "https://example.test"}

            self.poll += 1

            if self.poll == 1:
                return {"__error": "service worker restarted"}

            return detections

    driver = FakeDriver()
    driver.timeout_ms = 10_000
    driver.popup = Popup()

    async def activity(_page):
        return {
            "readyState": "complete",
            "scannerState": "complete",
            "lastRelevantAge": 2_000,
            "lastMutationAge": 2_000,
        }

    monkeypatch.setattr(analyzer, "_page_activity", activity)

    result = asyncio.run(analyzer._get_detections(driver, "https://example.test"))

    assert result == detections


def test_page_quiet_requires_complete_and_inactive_page():
    assert analyzer._page_quiet(
        {
            "readyState": "complete",
            "lastRelevantAge": 1_500,
            "lastMutationAge": 1_500,
        }
    )
    assert not analyzer._page_quiet(
        {
            "readyState": "complete",
            "lastRelevantAge": 10,
            "lastMutationAge": 1_500,
        }
    )


def test_process_url_uses_and_closes_a_fresh_page(monkeypatch):
    driver = FakeDriver()

    async def no_stimulation(page):
        return None

    async def detections(current_driver, url):
        assert current_driver.page is driver.context.pages_created[0]
        return [{"technology": "Example"}]

    async def clear_state(current_driver, page):
        return None

    monkeypatch.setattr(analyzer, "_stimulate_page", no_stimulation)
    monkeypatch.setattr(analyzer, "_get_detections", detections)
    monkeypatch.setattr(analyzer, "_clear_target_state", clear_state)

    result = asyncio.run(analyzer.process_url(driver, "https://example.test"))

    assert result == (
        "https://example.test",
        [{"technology": "Example"}],
    )
    assert driver.context.pages_created[0].closed
    assert driver.page is None


def test_complete_browser_stage_returns_raw_evidence_and_response_identity(monkeypatch):
    class Response:
        status = 202

    driver = FakeDriver()
    page = FakePage()

    async def new_page():
        return page

    async def goto(url, **kwargs):
        page.url = f"{url}/redirected"
        return Response()

    async def content():
        return "<html><script>window.React = {}</script></html>"

    async def no_stimulation(current_page):
        return None

    async def detections(current_driver, url, raw=False):
        assert raw is True
        return [
            {
                "technology": "React",
                "version": "19.1.0",
                "pattern": {
                    "type": "js",
                    "regex": "React",
                    "confidence": 100,
                    "match": "window.React",
                },
            }
        ]

    async def clear_state(current_driver, current_page):
        return None

    driver.context.new_page = new_page
    page.goto = goto
    page.content = content
    monkeypatch.setattr(analyzer, "_stimulate_page", no_stimulation)
    monkeypatch.setattr(analyzer, "_get_detections", detections)
    monkeypatch.setattr(analyzer, "_clear_target_state", clear_state)

    stage = asyncio.run(analyzer.process_url_evidence(driver, "https://example.test"))

    assert stage.name.value == "browser"
    assert stage.status.value == "success"
    assert stage.response_identity.effective_url.endswith("/redirected")
    assert stage.response_identity.http_status == 202
    assert len(stage.response_identity.content_sha256) == 64
    assert [(item.technology, item.channel) for item in stage.detections] == [("React", "js")]
    assert page.closed


def test_browser_stage_reports_every_configured_collection_limit(monkeypatch):
    class Response:
        status = 200

        async def body(self):
            return b"response"

    driver = FakeDriver()
    page = FakePage()

    async def new_page():
        return page

    async def goto(url, **kwargs):
        page.url = url
        return Response()

    async def no_stimulation(_page):
        return None

    async def detections(_driver, _url, raw=False):
        assert raw
        return [
            {
                "technology": "DenseDom",
                "pattern": {
                    "type": "dom.exists",
                    "regex": "selector",
                    "confidence": 100,
                },
            }
            for _index in range(analyzer.BROWSER_DOM_DETECTIONS_PER_TECH_LIMIT)
        ]

    async def metrics(_page):
        return {
            "htmlCharacters": analyzer.BROWSER_HTML_CHARACTER_LIMIT + 1,
            "textCharacters": analyzer.BROWSER_DOM_TEXT_CHARACTER_LIMIT + 1,
            "inlineScriptCount": analyzer.BROWSER_INLINE_SCRIPT_COUNT_LIMIT + 1,
            "inlineScriptCharacters": analyzer.BROWSER_INLINE_SCRIPT_CHARACTER_LIMIT + 1,
        }

    async def clear_state(_driver, _page):
        return None

    driver.context.new_page = new_page
    page.goto = goto
    monkeypatch.setattr(analyzer, "_stimulate_page", no_stimulation)
    monkeypatch.setattr(analyzer, "_get_detections", detections)
    monkeypatch.setattr(analyzer, "_get_evidence_metrics", metrics)
    monkeypatch.setattr(analyzer, "_clear_target_state", clear_state)

    stage = asyncio.run(analyzer.process_url_evidence(driver, "https://example.test"))
    truncations = {item.channel: set(item.limits) for item in stage.truncations}

    assert stage.status is StageStatus.PARTIAL
    assert truncations == {
        "dom": {EvidenceLimit.BYTES, EvidenceLimit.COUNT},
        "html": {EvidenceLimit.BYTES},
        "scripts": {EvidenceLimit.BYTES, EvidenceLimit.COUNT},
        "text": {EvidenceLimit.BYTES},
    }


def test_cleanup_failure_retires_driver_without_discarding_result(monkeypatch):
    driver = FakeDriver()

    async def no_stimulation(page):
        return None

    async def detections(current_driver, url):
        return []

    async def failed_cleanup(current_driver, page):
        raise RuntimeError("storage remained")

    monkeypatch.setattr(analyzer, "_stimulate_page", no_stimulation)
    monkeypatch.setattr(analyzer, "_get_detections", detections)
    monkeypatch.setattr(analyzer, "_clear_target_state", failed_cleanup)

    result = asyncio.run(analyzer.process_url(driver, "https://example.test"))

    assert result == ("https://example.test", [])
    assert not driver.healthy
    assert driver.context.pages_created[0].closed
    assert driver.page is None


def test_browser_detection_versions_merge_deterministically():
    detections = [
        {
            "technology": "React",
            "version": "10",
            "pattern": {"confidence": 50},
        },
        {
            "technology": "React",
            "version": "9",
            "pattern": {"confidence": 50},
        },
    ]

    forward = analyzer.merge_technologies(detections)
    reverse = analyzer.merge_technologies(reversed(detections))

    assert forward == reverse
    assert forward["React"]["version"] == "10"
    assert forward["React"]["confidence"] == 100


def test_browser_raw_detections_require_channel_provenance_and_filter_ownership():
    detections = [
        {
            "technology": "React",
            "version": "19.1.0",
            "pattern": {
                "type": "js",
                "regex": r"^React$",
                "confidence": 50,
                "match": "window.React",
            },
        },
        {
            "technology": "RobotsTech",
            "pattern": {
                "type": "robots",
                "regex": "private",
                "confidence": 100,
                "match": "Disallow: /private",
            },
        },
        {"technology": "MissingChannel", "pattern": {"confidence": 100}},
    ]

    raw = analyzer.raw_browser_detections(detections)

    assert [(item.technology, item.channel) for item in raw] == [("React", "js")]
    assert raw[0].version == "19.1.0"
    assert raw[0].confidence == 50
    assert len(raw[0].source_key) == 64
    assert len(raw[0].evidence_sha256) == 64
    assert analyzer.CHANNEL_REGISTRY["js"].owner is ChannelOwner.BROWSER


def test_extension_archive_rejects_path_traversal(tmp_path):
    archive_path = tmp_path / "extension.zip"

    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../outside.txt", "unsafe")

    with pytest.raises(RuntimeError, match="Unsafe extension archive path"):
        analyzer._prepare_extension_dir(archive_path)


def test_browser_pool_growth_is_incremental_to_avoid_startup_spikes(monkeypatch):
    pool = analyzer.DriverPool(size=0)
    active = 0
    peak = 0

    async def create_driver():
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0)
        active -= 1
        return object()

    monkeypatch.setattr(pool, "_create_driver", create_driver)

    asyncio.run(pool.grow_to(4))

    assert pool.size == 4
    assert peak == 1
