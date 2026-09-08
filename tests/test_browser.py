import asyncio
import zipfile

import pytest

from wappalyzer.browser import analyzer


class FakePage:
    def __init__(self):
        self.url = "about:blank"
        self.closed = False

    async def goto(self, url, **kwargs):
        self.url = url

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

    async def apply_pending_cookies(self, url):
        return None


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


def test_cleanup_failure_invalidates_browser_driver(monkeypatch):
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

    with pytest.raises(RuntimeError, match="storage remained"):
        asyncio.run(analyzer.process_url(driver, "https://example.test"))

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


def test_extension_archive_rejects_path_traversal(tmp_path):
    archive_path = tmp_path / "extension.zip"

    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../outside.txt", "unsafe")

    with pytest.raises(RuntimeError, match="Unsafe extension archive path"):
        analyzer._prepare_extension_dir(archive_path)
