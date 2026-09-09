import concurrent.futures
import functools
import os
import time
from urllib.parse import urljoin, urlparse

import tldextract
from bs4 import BeautifulSoup

from wappalyzer.analyzers.dom import compile_selector, match_dom
from wappalyzer.analyzers.js import match_js
from wappalyzer.core.config import tech_db
from wappalyzer.core.matcher import (
    better_version,
    compile_pattern,
    match,
    match_dict,
    parse_pattern,
)
from wappalyzer.core.requester import get_response
from wappalyzer.core.utils import create_result
from wappalyzer.parsers.certIssuer import get_certIssuer
from wappalyzer.parsers.css import get_css
from wappalyzer.parsers.dns import get_dns
from wappalyzer.parsers.js import get_js
from wappalyzer.parsers.meta import get_meta
from wappalyzer.parsers.robots import get_robots
from wappalyzer.parsers.scriptSrc import get_scriptSrc

PATTERN_FIELDS = {
    "certIssuer",
    "css",
    "html",
    "robots",
    "scriptSrc",
    "scripts",
    "text",
    "url",
    "xhr",
}
DICT_PATTERN_FIELDS = {"cookies", "dns", "headers", "js", "meta"}
ASSET_LIMIT = max(0, int(os.getenv("WAPPALYZER_ASSET_LIMIT", "64")))
ASSET_DEPTH = max(0, int(os.getenv("WAPPALYZER_ASSET_DEPTH", "2")))
ASSET_MAX_BYTES = max(
    1,
    int(os.getenv("WAPPALYZER_MAX_ASSET_BYTES", str(2 * 1024 * 1024))),
)
PROBES = {name: data["probe"] for name, data in tech_db.items() if "probe" in data}
DETECTION_FIELDS = PATTERN_FIELDS | DICT_PATTERN_FIELDS | {"dom", "probe"}


def build_detector_plan(database=None):
    database = tech_db if database is None else database
    return {
        field: tuple(
            (name, technology[field])
            for name, technology in sorted(database.items())
            if field in technology
        )
        for field in DETECTION_FIELDS
    }


DETECTOR_PLAN = build_detector_plan()


class ScanRequestError(RuntimeError):
    pass


def asset_worker_count(cpu_budget=None):
    override = os.getenv("WAPPALYZER_ASSET_WORKERS")

    if override:
        return max(1, int(override))

    return max(1, cpu_budget or os.cpu_count() or 1)


def _remaining_seconds(deadline):
    return max(0.0, deadline - time.monotonic())


def _compile_value(value):
    values = value if isinstance(value, list) else [value]

    for pattern in values:
        compile_pattern(pattern)


@functools.cache
def prepare_matchers():
    for technology in tech_db.values():
        for field in PATTERN_FIELDS:
            if field in technology:
                _compile_value(technology[field])

        for field in DICT_PATTERN_FIELDS:
            patterns = technology.get(field, {})

            if isinstance(patterns, dict):
                for pattern in patterns.values():
                    _compile_value(pattern)

        dom = technology.get("dom")

        if isinstance(dom, str):
            compile_selector(parse_pattern(dom)[0])
        elif isinstance(dom, list):
            for selector in dom:
                compile_selector(parse_pattern(selector)[0])
        elif isinstance(dom, dict):
            for selector, rule in dom.items():
                compile_selector(parse_pattern(selector)[0])

                if not isinstance(rule, dict):
                    _compile_value(rule)
                    continue

                for key in ("exists", "src", "text"):
                    if rule.get(key):
                        _compile_value(rule[key])

                for key in ("attributes", "properties"):
                    patterns = rule.get(key, {})

                    if not isinstance(patterns, dict):
                        continue

                    for pattern in patterns.values():
                        if pattern:
                            _compile_value(pattern)


def _js_evidence(source):
    js_dict, low_dict, js_classes = get_js(source)

    if not js_dict and not low_dict:
        return None

    return {
        "dict": js_dict,
        "low_dict": low_dict,
        "classes": js_classes,
    }


class AssetBudget:
    def __init__(self, limit):
        self.remaining = max(0, limit)

    def claim(self, urls):
        claimed = list(dict.fromkeys(urls))[: self.remaining]
        self.remaining -= len(claimed)
        return claimed


def _origin(url):
    parsed = urlparse(url)
    default_port = 443 if parsed.scheme.casefold() == "https" else 80
    return (
        parsed.scheme.casefold(),
        (parsed.hostname or "").casefold(),
        parsed.port or default_port,
    )


def _same_origin(first_url, second_url):
    return _origin(first_url) == _origin(second_url)


def _fetch_asset(url, timeout, cookie):
    response = get_response(
        url,
        cookie=cookie,
        timeout=timeout,
        max_bytes=ASSET_MAX_BYTES,
    )

    if response is None:
        return url, ""

    return response.url, response.text


def _fetch_assets(
    urls,
    timeout,
    cookie,
    credential_origin,
    budget,
    asset_workers=None,
):
    ordered_urls = budget.claim(urls)

    if not ordered_urls:
        return {}

    responses = {}
    worker_count = min(len(ordered_urls), asset_worker_count(asset_workers))

    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(
                _fetch_asset,
                url,
                timeout,
                cookie if _same_origin(credential_origin, url) else None,
            ): url
            for url in ordered_urls
        }

        for future in concurrent.futures.as_completed(futures):
            requested_url = futures[future]

            try:
                result_url, text = future.result()
                responses[requested_url] = text
                responses.setdefault(result_url, text)
            except Exception:
                responses[requested_url] = ""

    return responses


def _looks_like_script(url):
    path = urlparse(url).path.casefold()
    return path.endswith((".js", ".mjs", ".cjs"))


def _stylesheet_urls(base_url, soup):
    urls = []

    for link in soup.find_all("link"):
        relationship = link.get("rel", [])
        relationship = relationship if isinstance(relationship, list) else [relationship]

        if "stylesheet" in [item.casefold() for item in relationship]:
            href = link.get("href")

            if href:
                urls.append(urljoin(base_url, href))

    return urls


def _probe_responses(
    base_url,
    timeout,
    cookie,
    budget,
    asset_workers=None,
):
    urls = {path: urljoin(base_url, path) for probes in PROBES.values() for path in probes}
    responses = {}
    claimed_urls = set(budget.claim(urls.values()))
    urls = {path: url for path, url in urls.items() if url in claimed_urls}

    if not urls:
        return responses

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(len(urls), asset_worker_count(asset_workers))
    ) as executor:
        futures = {
            executor.submit(
                get_response,
                url,
                cookie,
                timeout=timeout,
                max_bytes=ASSET_MAX_BYTES,
            ): path
            for path, url in urls.items()
        }

        for future in concurrent.futures.as_completed(futures):
            path = futures[future]

            try:
                response = future.result()
            except Exception:
                response = None

            responses[path] = (
                bool(response and response.ok),
                response.text if response else "",
            )

    return responses


def collect_evidence(
    response,
    scan_type,
    cookie=None,
    timeout=30,
    deadline=None,
    asset_workers=None,
):
    if deadline is None:
        deadline = time.monotonic() + timeout
    asset_workers = asset_worker_count(asset_workers)
    soup = BeautifulSoup(response.text, "html.parser")
    r = tldextract.extract(response.url)
    parsed_url = urlparse(response.url)
    domain = ".".join(part for part in (r.domain, r.suffix) if part)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    js = []
    scripts = []
    xhr_candidates = []
    asset_budget = AssetBudget(ASSET_LIMIT)

    for script in soup.find_all("script"):
        if not script.get("src"):
            source = script.string or script.get_text()
            scripts.append(source)
            xhr_candidates.extend(get_scriptSrc(response.url, source))
            parsed_js = _js_evidence(source)

            if parsed_js:
                js.append(parsed_js)

    script_sources = get_scriptSrc(response.url, soup)
    css_sources = get_css(soup)

    if scan_type != "fast":
        pending_scripts = list(script_sources)
        fetched_scripts = {}

        for _ in range(ASSET_DEPTH):
            new_urls = [url for url in pending_scripts if url not in fetched_scripts]
            remaining = _remaining_seconds(deadline)

            if not new_urls or remaining <= 0:
                break

            batch = _fetch_assets(
                new_urls,
                remaining,
                cookie,
                response.url,
                asset_budget,
                asset_workers,
            )
            fetched_scripts.update((url, batch.get(url, "")) for url in new_urls if url in batch)
            pending_scripts = []

            for url in new_urls:
                if url not in fetched_scripts:
                    continue

                source = fetched_scripts[url]

                if not source:
                    continue

                scripts.append(source)
                parsed_js = _js_evidence(source)

                if parsed_js:
                    js.append(parsed_js)

                discovered = get_scriptSrc(url, source)
                xhr_candidates.extend(discovered)
                pending_scripts.extend(item for item in discovered if _looks_like_script(item))

        script_sources = list(dict.fromkeys(script_sources + list(fetched_scripts)))
        css_urls = _stylesheet_urls(response.url, soup)
        remaining = _remaining_seconds(deadline)

        if remaining > 0:
            css_sources.extend(
                _fetch_assets(
                    css_urls,
                    remaining,
                    cookie,
                    response.url,
                    asset_budget,
                    asset_workers,
                ).values()
            )

    dns = {}
    meta = get_meta(soup)
    cookies = response.cookies.get_dict()
    robots = ""
    cert_issuer = ""
    probes = {}
    remaining = _remaining_seconds(deadline)

    if scan_type != "fast" and remaining > 0:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            future_to_field = {
                executor.submit(
                    get_robots,
                    response.url,
                    timeout=remaining,
                ): "robots",
                executor.submit(
                    get_certIssuer,
                    response,
                    timeout=min(remaining, 5),
                ): "certIssuer",
                executor.submit(
                    _probe_responses,
                    base_url,
                    remaining,
                    cookie,
                    asset_budget,
                    asset_workers,
                ): "probes",
            }

            if domain:
                future_to_field[
                    executor.submit(
                        get_dns,
                        domain,
                        timeout=min(remaining, 5),
                    )
                ] = "dns"

            for future in concurrent.futures.as_completed(future_to_field):
                field = future_to_field[future]

                try:
                    value = future.result()
                except Exception:
                    value = {} if field in {"dns", "probes"} else ""

                if field == "dns":
                    dns = value
                elif field == "robots":
                    robots = value
                elif field == "certIssuer":
                    cert_issuer = value
                elif field == "probes":
                    probes = value

    return {
        "certIssuer": cert_issuer,
        "cookies": cookies,
        "css": css_sources,
        "dns": dns,
        "dom": soup,
        "headers": response.headers,
        "html": response.text,
        "js": js,
        "meta": meta,
        "probes": probes,
        "robots": robots,
        "scriptSrc": script_sources,
        "scripts": scripts,
        "text": soup.get_text(" ", strip=True),
        "url": response.url,
        "xhr": list(dict.fromkeys(xhr_candidates)),
    }


def _add_candidate(result, tech_name, candidate):
    matched, version, confidence = candidate

    if not matched:
        return

    if tech_name not in result:
        result[tech_name] = {
            "version": version or "",
            "confidence": confidence,
        }
        return

    current = result[tech_name]
    current["confidence"] = min(current["confidence"] + confidence, 100)

    current["version"] = better_version(version, current["version"])


def analyze_from_response(
    response,
    scan_type,
    cookie=None,
    timeout=30,
    deadline=None,
    asset_workers=None,
):
    prepare_matchers()
    evidence = collect_evidence(
        response,
        scan_type,
        cookie=cookie,
        timeout=timeout,
        deadline=deadline,
        asset_workers=asset_workers,
    )

    result = {}

    if evidence["certIssuer"]:
        for tech_name, pattern in DETECTOR_PLAN["certIssuer"]:
            _add_candidate(
                result,
                tech_name,
                match(pattern, evidence["certIssuer"]),
            )

    for field in ("css", "html", "robots", "scriptSrc", "scripts", "text", "url", "xhr"):
        if evidence[field]:
            for tech_name, pattern in DETECTOR_PLAN[field]:
                _add_candidate(
                    result,
                    tech_name,
                    match(pattern, evidence[field]),
                )

    for tech_name, pattern in DETECTOR_PLAN["dom"]:
        _add_candidate(
            result,
            tech_name,
            match_dom(pattern, evidence["dom"]),
        )

    if evidence["js"]:
        for tech_name, pattern in DETECTOR_PLAN["js"]:
            _add_candidate(
                result,
                tech_name,
                match_js(pattern, evidence["js"]),
            )

    for field in ("cookies", "dns", "headers", "meta"):
        if evidence[field]:
            for tech_name, pattern in DETECTOR_PLAN[field]:
                _add_candidate(
                    result,
                    tech_name,
                    match_dict(
                        pattern,
                        evidence[field],
                        case_insensitive_keys=field in {"headers", "meta"},
                    ),
                )

    if evidence["probes"]:
        for tech_name, probes in DETECTOR_PLAN["probe"]:
            for path, pattern in probes.items():
                probe_ok, probe_text = evidence["probes"].get(
                    path,
                    (False, ""),
                )

                if probe_ok and (probe_text or pattern == ""):
                    _add_candidate(
                        result,
                        tech_name,
                        (True, "", 100)
                        if pattern == "" and probe_text
                        else match(pattern, probe_text),
                    )

    return create_result(result)


def http_scan(
    url,
    scan_type,
    cookie=None,
    timeout=30,
    asset_workers=None,
):
    deadline = time.monotonic() + timeout
    response = get_response(url, cookie, timeout=timeout)
    if response is not None:
        return analyze_from_response(
            response,
            scan_type,
            cookie=cookie,
            timeout=timeout,
            deadline=deadline,
            asset_workers=asset_workers,
        )

    raise ScanRequestError(f"Unable to fetch {url}")
