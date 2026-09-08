#!/usr/bin/env python3

import argparse
import json
import random
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from wappalyzer.scanner import Wappalyzer, automatic_worker_count

FIXTURES = {
    "angular": ({}, '<main ng-version="22.1.5">Angular</main>'),
    "drupal": ({}, '<meta name="generator" content="Drupal 11.4.6">'),
    "hono": ({"X-Powered-By": "Hono"}, "<main>Hono</main>"),
    "next": ({"X-Powered-By": "Next.js 16.3.4"}, "<main>Next.js</main>"),
    "react": ({}, '<meta name="description" content="Web site created using create-react-app">'),
    "shopify": ({"X-Shopify-Stage": "production"}, "<main>Shopify</main>"),
    "vue": ({}, '<script src="/assets/vue-3.5.42.js"></script>'),
    "wordpress": ({}, '<meta name="generator" content="WordPress 7.1">'),
}
EXPECTED_TECHNOLOGIES = {
    "angular": "Angular",
    "drupal": "Drupal",
    "hono": "Hono",
    "next": "Next.js",
    "react": "React",
    "shopify": "Shopify",
    "vue": "Vue.js",
    "wordpress": "WordPress",
}


class FixtureHandler(BaseHTTPRequestHandler):
    server_version = "Fixture"
    sys_version = ""

    def do_GET(self):
        path = urlparse(self.path).path

        if path.startswith("/assets/"):
            body = b"window.Vue = { version: '3.5.42' };"
            self.send_response(200)
            self.send_header("Content-Type", "text/javascript")
        else:
            fixture = path.strip("/").split("/")[0]
            headers, marker = FIXTURES.get(fixture, ({}, "<main>Unknown</main>"))
            body = (
                f"<!doctype html><html><head>{marker}</head><body><h1>{fixture}</h1></body></html>"
            ).encode()
            self.send_response(200)

            for name, value in headers.items():
                self.send_header(name, value)

            self.send_header("Content-Type", "text/html")

        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


def normalized(results):
    return {urlparse(url).path: sorted(technologies) for url, technologies in results.items()}


def run(mode, workers, urls):
    started = time.perf_counter()

    with Wappalyzer(scan_type=mode, workers=workers, timeout=12) as scanner:
        results = scanner.analyze_many(urls)

    elapsed = time.perf_counter() - started
    return {
        "elapsed_seconds": round(elapsed, 3),
        "results": normalized(results),
        "url_count": len(urls),
        "urls_per_second": round(len(urls) / elapsed, 3),
        "workers": workers,
    }


def verify_expected(results):
    missing = {}

    for path, technologies in results.items():
        fixture = path.strip("/").split("/")[0]
        expected = EXPECTED_TECHNOLOGIES[fixture]

        if expected not in technologies:
            missing[path] = expected

    if missing:
        raise RuntimeError(f"Missing expected detections: {missing}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("fast", "balanced", "full"), required=True)
    parser.add_argument("--repeats", type=int, default=8)
    parser.add_argument("--workers", type=int, nargs="*")
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    urls = [
        f"http://127.0.0.1:{port}/{fixture}/{index}"
        for index in range(args.repeats)
        for fixture in FIXTURES
    ]
    worker_counts = args.workers or [
        1,
        automatic_worker_count(args.mode),
    ]
    baseline = None

    try:
        for workers in dict.fromkeys(worker_counts):
            ordered_urls = list(urls)
            random.Random(10_000 + workers).shuffle(ordered_urls)
            measurement = run(args.mode, workers, ordered_urls)
            results = measurement.pop("results")
            verify_expected(results)

            if baseline is None:
                baseline = results

            measurement["same_as_worker_1"] = results == baseline

            if results != baseline:
                raise RuntimeError(
                    f"Detection drift at {workers} workers"
                )

            print(json.dumps(measurement, sort_keys=True), flush=True)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == "__main__":
    main()
