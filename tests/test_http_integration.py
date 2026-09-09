import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from wappalyzer.scanner import Wappalyzer


class TechnologyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"""
        <!doctype html>
        <main ng-version="22.1.5">Angular</main>
        """
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("X-Powered-By", "Hono")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


def test_process_workers_are_deterministic_and_complete():
    server = ThreadingHTTPServer(("127.0.0.1", 0), TechnologyHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    urls = [f"http://127.0.0.1:{port}/{index}" for index in range(8)]

    try:
        with Wappalyzer(scan_type="fast", workers=4, timeout=5) as scanner:
            results = scanner.analyze_many(urls)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()

    assert list(results) == urls
    assert all("Angular" in technologies for technologies in results.values())
    assert all("Hono" in technologies for technologies in results.values())
    assert len({tuple(technologies) for technologies in results.values()}) == 1
