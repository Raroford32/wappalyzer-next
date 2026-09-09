import asyncio
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from wappalyzer.browser import analyzer as browser_analyzer
from wappalyzer.scanner import Wappalyzer

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_BROWSER_TESTS") != "1",
    reason="set RUN_BROWSER_TESTS=1 to run Chromium integration tests",
)


class HonoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        fixture = self.path.strip("/").split("/", 1)[0]
        bodies = {
            "hono": b"<!doctype html><main>Hono integration fixture</main>",
            "plain": b"<!doctype html><main>Plain integration fixture</main>",
            "delayed-js": (
                b"<script>setTimeout(() => { window.React = { version: '19.1.0' } }, 3500)</script>"
            ),
            "html": b"<span data-avatar='gravatar.com/avatar/example'></span>",
            "dom-src": b"<img src='https://cdn.getyourguide.com/example.png'>",
            "repaired-dom": (
                b"<a href='https://www.influxmarketing.com'>"
                b"<svg class='influx-footer-logo'></svg></a>"
            ),
        }
        body = bodies.get(fixture, bodies["plain"])
        self.send_response(200)
        self.send_header("Content-Type", "text/html")

        if fixture == "hono":
            self.send_header("X-Powered-By", "hOnO")

        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


def test_every_warmed_browser_detects_complete_isolated_schema(monkeypatch):
    monkeypatch.setattr(
        browser_analyzer,
        "BLOCKED_RESOURCE_TYPES",
        frozenset({"font", "image", "media"}),
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), HonoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    worker_count = int(os.getenv("BROWSER_TEST_WORKERS", "4"))
    urls = [
        f"http://127.0.0.1:{port}/{fixture}/{index}"
        for fixture in ("hono", "plain")
        for index in range(worker_count)
    ]
    urls.extend(
        f"http://127.0.0.1:{port}/{fixture}/0"
        for fixture in ("delayed-js", "html", "dom-src", "repaired-dom")
    )
    errors = {}

    try:
        with Wappalyzer(scan_type="full", workers=worker_count, timeout=12) as scanner:
            results = scanner.analyze_many(
                urls,
                on_error=lambda url, error: errors.setdefault(url, repr(error)),
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()

    assert list(results) == urls
    assert not errors
    assert all(
        ("Hono" in technologies) == ("/hono/" in url) for url, technologies in results.items()
    )
    expected = {
        "delayed-js": "React",
        "html": "Gravatar",
        "dom-src": "GetYourGuide",
        "repaired-dom": "Influx CMS",
    }

    for fixture, technology in expected.items():
        url = next(url for url in urls if f"/{fixture}/" in url)
        assert technology in results[url]


def test_complete_browser_stage_preserves_raw_runtime_channel_provenance():
    server = ThreadingHTTPServer(("127.0.0.1", 0), HonoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    url = f"http://127.0.0.1:{port}/delayed-js/raw"

    async def scan():
        pool = browser_analyzer.DriverPool(size=1, timeout=12)
        try:
            await pool.start()
            async with pool.get_driver() as driver:
                return await browser_analyzer.process_url_evidence(driver, url)
        finally:
            await pool.cleanup()

    try:
        stage = asyncio.run(scan())
    finally:
        server.shutdown()
        server.server_close()
        thread.join()

    react = [item for item in stage.detections if item.technology == "React"]
    assert [(item.channel, item.version) for item in react] == [("js", "19.1.0")]
    assert stage.response_identity.effective_url == url
