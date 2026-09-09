import asyncio
import json
import os
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from wappalyzer.browser import analyzer as browser_analyzer
from wappalyzer.scanner import Wappalyzer

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_BROWSER_TESTS") != "1",
    reason="set RUN_BROWSER_TESTS=1 to run Chromium integration tests",
)

BROWSER_CHANNEL_PATTERNS = {
    "cookies": {"cookies": {"matrix_cookie": "matrix-cookie-positive"}},
    "css": {"css": "matrix-css-positive"},
    "dom": {"dom": "[data-matrix-dom-positive]"},
    "headers": {"headers": {"x-matrix-header": "matrix-header-positive"}},
    "html": {"html": "data-matrix-html=.matrix-html-positive."},
    "js": {"js": {"matrixRuntime.value": "^matrix-js-positive$"}},
    "meta": {"meta": {"matrix-meta": "matrix-meta-positive"}},
    "scriptSrc": {"scriptSrc": "matrix-script-src-positive"},
    "scripts": {"scripts": "matrix-scripts-positive"},
    "text": {"text": "matrix-text-positive"},
    "url": {"url": "/matrix-positive"},
    "xhr": {"xhr": "matrix-xhr-positive"},
}


def matrix_technologies():
    return {
        f"Matrix {channel}": {"cats": [1], **pattern}
        for channel, pattern in BROWSER_CHANNEL_PATTERNS.items()
    }


def build_matrix_extension(tmp_path):
    source = Path(browser_analyzer.extension_path)
    destination = tmp_path / "matrix-extension.zip"
    with zipfile.ZipFile(source) as archive:
        members = {
            item.filename: archive.read(item) for item in archive.infolist() if not item.is_dir()
        }
    for name in tuple(members):
        if name.startswith("technologies/") and name.endswith(".json"):
            members[name] = b"{}"
    members["technologies/m.json"] = json.dumps(
        matrix_technologies(),
        separators=(",", ":"),
    ).encode()
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in sorted(members.items()):
            archive.writestr(name, content)
    return destination


class HonoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        fixture = self.path.strip("/").split("/", 1)[0]
        if fixture == "matrix-script-src-positive.js":
            body = b"/* matrix-scripts-positive */"
            self.send_response(200)
            self.send_header("Content-Type", "text/javascript")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if fixture in {"matrix-xhr-positive", "matrix-image"}:
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
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
            "matrix-positive": b"""<!doctype html>
                <meta name="matrix-meta" content="matrix-meta-positive">
                <style>.matrix-css-positive { color: rgb(1, 2, 3) }</style>
                <main
                  data-matrix-dom-positive
                  data-matrix-html="matrix-html-positive"
                >matrix-text-positive</main>
                <script src="/matrix-script-src-positive.js"></script>
                <script>
                  window.matrixRuntime = { value: 'matrix-js-positive' };
                  fetch('/matrix-xhr-positive');
                </script>
            """,
            "matrix-negative": b"""<!doctype html>
                <main
                  data-note="matrix-text-positive"
                >
                  matrix-cookie-positive matrix-css-positive
                  matrix-header-positive matrix-meta-positive
                  matrix-scripts-positive
                  <a href="/matrix-positive">URL lookalike</a>
                  <img src="/matrix-xhr-positive">
                </main>
                <script>
                  const matrixRuntime = { value: 'matrix-js-positive' };
                  const scriptUrl = '/matrix-script-src-positive.js';
                  const domSelector = 'data-' + 'matrix-dom-positive';
                  const htmlMarker = 'matrix-html-' + 'positive';
                </script>
            """,
        }
        body = bodies.get(fixture, bodies["plain"])
        self.send_response(200)
        self.send_header("Content-Type", "text/html")

        if fixture == "hono":
            self.send_header("X-Powered-By", "hOnO")
        if fixture == "matrix-positive":
            self.send_header("X-Matrix-Header", "matrix-header-positive")
            self.send_header("Set-Cookie", "matrix_cookie=matrix-cookie-positive; Path=/")

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


def test_generated_extension_executes_every_browser_channel_without_lookalikes(
    tmp_path,
    monkeypatch,
):
    extension = build_matrix_extension(tmp_path)
    monkeypatch.setattr(browser_analyzer, "extension_path", str(extension))
    monkeypatch.setattr(browser_analyzer, "BLOCKED_RESOURCE_TYPES", frozenset())
    server = ThreadingHTTPServer(("127.0.0.1", 0), HonoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    positive_url = f"http://127.0.0.1:{port}/matrix-positive"
    negative_url = f"http://127.0.0.1:{port}/matrix-negative"

    async def scan():
        pool = browser_analyzer.DriverPool(size=1, timeout=12)
        try:
            await pool.start()
            stages = []
            for url in (positive_url, negative_url):
                async with pool.get_driver() as driver:
                    stages.append(await browser_analyzer.process_url_evidence(driver, url))
            return stages
        finally:
            await pool.cleanup()

    try:
        positive, negative = asyncio.run(scan())
    finally:
        server.shutdown()
        server.server_close()
        thread.join()

    expected = {(f"Matrix {channel}", channel) for channel in BROWSER_CHANNEL_PATTERNS}
    assert {(item.technology, item.channel) for item in positive.detections} == expected
    assert not {
        item.technology for item in negative.detections if item.technology.startswith("Matrix ")
    }
