import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from wappalyzer.scanner import Wappalyzer

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_BROWSER_TESTS") != "1",
    reason="set RUN_BROWSER_TESTS=1 to run Chromium integration tests",
)


class HonoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        is_hono = self.path.startswith("/hono/")
        body = (
            b"<!doctype html><main>Hono integration fixture</main>"
            if is_hono
            else b"<!doctype html><main>Plain integration fixture</main>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html")

        if is_hono:
            self.send_header("X-Powered-By", "Hono")

        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


def test_every_warmed_browser_detects_first_navigation():
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
        ("Hono" in technologies) == ("/hono/" in url)
        for url, technologies in results.items()
    )
