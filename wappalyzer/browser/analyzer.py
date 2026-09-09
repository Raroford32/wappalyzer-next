import asyncio
import hashlib
import json
import logging
import os
import shutil
import stat
import tempfile
import zipfile
from contextlib import asynccontextmanager
from http.cookies import SimpleCookie
from pathlib import Path

from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from playwright.async_api import async_playwright

from wappalyzer.core.config import extension_path
from wappalyzer.core.matcher import better_version
from wappalyzer.core.requester import VERIFY_TLS
from wappalyzer.core.utils import enrich_result
from wappalyzer.evidence import RawDetection, StageEvidence
from wappalyzer.evidence_limits import (
    BROWSER_DOM_TEXT_CHARACTER_LIMIT,
    BROWSER_HTML_CHARACTER_LIMIT,
    BROWSER_INLINE_SCRIPT_CHARACTER_LIMIT,
    BROWSER_INLINE_SCRIPT_COUNT_LIMIT,
    BROWSER_TEXT_CHARACTER_LIMIT,
)
from wappalyzer.models import (
    CHANNEL_REGISTRY,
    ChannelOwner,
    EvidenceLimit,
    EvidenceTruncation,
    ResponseIdentity,
    StageName,
    StageStatus,
)

logger = logging.getLogger(__name__)

WAPPALYZER_POPUP_PATH = "html/popup.html"
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
BLOCKED_RESOURCE_TYPES = frozenset(
    item.strip()
    for item in os.getenv("WAPPALYZER_BLOCK_RESOURCE_TYPES", "").split(",")
    if item.strip()
)
MAX_EXTENSION_UNCOMPRESSED_BYTES = 512 * 1024 * 1024

SELECT_TARGET_TAB_SCRIPT = """
async ({ targetUrl, timeoutMs }) => {
  const parseUrl = (value) => {
    try {
      return new URL(value)
    } catch (_) {
      return null
    }
  }

  const queryTabs = () => {
    if (typeof browser !== 'undefined' && browser.tabs?.query) {
      return browser.tabs.query({})
    }

    return new Promise((resolve, reject) => {
      chrome.tabs.query({}, (tabs) => {
        const error = chrome.runtime.lastError

        if (error) {
          reject(new Error(error.message))

          return
        }

        resolve(tabs || [])
      })
    })
  }

  const target = parseUrl(targetUrl)

  if (!target || !/^https?:$/.test(target.protocol)) {
    return null
  }

  const tabs = await Promise.race([
    queryTabs(),
    new Promise((resolve) =>
      setTimeout(() => resolve({ __error: 'Tab query timed out' }), timeoutMs)
    ),
  ])

  if (tabs?.__error) {
    return tabs
  }

  const isTargetTab = (tab) => {
    if (!tab || !tab.url) {
      return false
    }

    const parsed = parseUrl(tab.url)

    if (!parsed || !/^https?:$/.test(parsed.protocol)) {
      return false
    }

    return parsed.href === target.href
  }

  return tabs.find((tab) => isTargetTab(tab)) || null
}
"""

GET_DETECTIONS_FOR_TAB_SCRIPT = """
async ({ selectedTab, timeoutMs, raw }) => {
  const sendMessage = (message) => {
    if (typeof browser !== 'undefined' && browser.runtime?.sendMessage) {
      return browser.runtime
        .sendMessage(message)
        .catch((error) => ({ __error: error.message || String(error) }))
    }

    return new Promise((resolve) => {
      chrome.runtime.sendMessage(message, (response) => {
        const error = chrome.runtime.lastError

        if (error) {
          resolve({ __error: error.message || String(error) })

          return
        }

        resolve(response)
      })
    })
  }

  const normaliseDetection = (detection) => {
    const technology = detection.technology
    const pattern = detection.pattern || {}
    const confidence = Number(
      pattern.confidence ?? detection.confidence
    )
    const technologyName =
      technology && typeof technology === 'object'
        ? technology.name
        : technology || detection.name || detection.slug

    return {
      technology: technologyName,
      pattern: {
        type: pattern.type ? String(pattern.type) : '',
        regex: pattern.regex
          ? String(pattern.regex.source || pattern.regex)
          : '',
        confidence: Number.isFinite(confidence) ? confidence : 100,
        match: pattern.match ? String(pattern.match) : '',
      },
      version: detection.version || '',
      rootPath: detection.rootPath || '',
      lastUrl: detection.lastUrl || '',
    }
  }

  if (!selectedTab) {
    return []
  }

  const getTab = () => {
    if (typeof browser !== 'undefined' && browser.tabs?.get) {
      return browser.tabs
        .get(selectedTab.id)
        .catch((error) => ({ __error: error.message || String(error) }))
    }

    return new Promise((resolve) => {
      chrome.tabs.get(selectedTab.id, (tab) => {
        const error = chrome.runtime.lastError
        resolve(error ? { __error: error.message || String(error) } : tab)
      })
    })
  }
  const currentTab = await Promise.race([
    getTab(),
    new Promise((resolve) =>
      setTimeout(() => resolve({ __error: 'Tab refresh timed out' }), timeoutMs)
    ),
  ])

  if (currentTab?.__error) {
    return currentTab
  }

  const response = await Promise.race([
    sendMessage({
      source: 'popup.js',
      func: raw ? 'getRawDetectionsForTab' : 'getDetectionsForTab',
      args: [{ id: currentTab.id, url: currentTab.url }],
    }),
    new Promise((resolve) =>
      setTimeout(
        () => resolve({ __error: 'Extension detection request timed out' }),
        timeoutMs
      )
    ),
  ])

  if (response?.__error) {
    return response
  }

  const detections = Array.isArray(response)
    ? response
    : Array.isArray(response?.detections)
      ? response.detections
      : []

  return detections
    .filter(
      (detection) =>
        detection?.technology || detection?.name || detection?.slug
    )
    .map(normaliseDetection)
}
"""

PAGE_ACTIVITY_SCRIPT = """
() => {
  const now = performance.now()

  if (!window.__wappalyzerActivityStarted) {
    window.__wappalyzerActivityStarted = true
    window.__wappalyzerLastMutationAt = now
    window.__wappalyzerMutationCount = 0

    try {
      new MutationObserver(() => {
        window.__wappalyzerLastMutationAt = performance.now()
        window.__wappalyzerMutationCount += 1
      }).observe(document.documentElement, {
        childList: true,
        subtree: true,
        attributes: true,
      })
    } catch (_) {}
  }

  const relevantTypes = new Set(['script', 'fetch', 'xmlhttprequest', 'beacon', 'css'])
  const isRelevantResource = (entry) =>
    relevantTypes.has(entry.initiatorType) ||
    (
      entry.initiatorType === 'link' &&
      /\\.css(?:[?#]|$)/i.test(entry.name || '')
    )
  let relevantCount = 0
  let lastRelevantAt = 0

  try {
    for (const entry of performance.getEntriesByType('resource')) {
      if (!isRelevantResource(entry)) {
        continue
      }

      relevantCount += 1
      lastRelevantAt = Math.max(
        lastRelevantAt,
        entry.responseEnd || entry.startTime || 0
      )
    }
  } catch (_) {}

  return {
    readyState: document.readyState,
    scannerState: document.documentElement.getAttribute(
      'data-wappalyzer-scanner-state'
    ),
    relevantCount,
    lastRelevantAge: lastRelevantAt ? now - lastRelevantAt : null,
    lastMutationAge: window.__wappalyzerLastMutationAt
      ? now - window.__wappalyzerLastMutationAt
      : null,
    mutationCount: window.__wappalyzerMutationCount || 0,
  }
}
"""

EVIDENCE_METRICS_SCRIPT = """
() => {
  const root = document.documentElement
  const body = document.body
  const inlineScripts = Array.from(document.querySelectorAll('script:not([src])'))
    .map((script) => (script.textContent || '').trim())
    .filter(Boolean)

  return {
    htmlCharacters: root?.outerHTML?.length || 0,
    textCharacters: body?.innerText?.length || 0,
    inlineScriptCount: inlineScripts.length,
    inlineScriptCharacters: inlineScripts.reduce(
      (total, script) => total + script.length,
      0
    ),
    domDetectionTruncated:
      root?.getAttribute('data-wappalyzer-dom-truncated') === 'count',
  }
}
"""

STIMULATE_SCRIPT = """
(maxDuration) => {
  if (!window.__wappalyzerStimulusUntil || Date.now() > window.__wappalyzerStimulusUntil) {
    window.__wappalyzerStimulusUntil = Date.now() + maxDuration + 100

    ;(async () => {
      if (maxDuration <= 0) {
        return
      }

      const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
      const startedAt = Date.now()
      const height = Math.max(
        document.body?.scrollHeight || 0,
        document.documentElement?.scrollHeight || 0
      )
      const width = Math.max(
        document.documentElement?.clientWidth || window.innerWidth || 1,
        1
      )
      const steps = [0.25, 0.5, 0.75, 1, 0]

      for (const step of steps) {
        const elapsed = Date.now() - startedAt

        if (elapsed >= maxDuration) {
          break
        }

        window.scrollTo(0, Math.max(0, height * step - window.innerHeight))
        document.dispatchEvent(
          new MouseEvent('mousemove', {
            view: window,
            bubbles: true,
            cancelable: true,
            clientX: Math.max(1, Math.floor(width * 0.5)),
            clientY: Math.max(1, Math.floor(window.innerHeight * 0.5)),
          })
        )

        if (document.body?.focus) {
          document.body.focus()
        }

        window.dispatchEvent(new Event('focus'))
        await sleep(Math.min(250, Math.max(0, maxDuration - elapsed)))
      }
    })().catch(() => {})
  }
}
"""


def _validate_extension_dir(extension_dir):
    required_files = (
        "manifest.json",
        "html/popup.html",
        "js/background.js",
        "js/index.js",
        "js/content.js",
    )

    for relative_path in required_files:
        if not (extension_dir / relative_path).is_file():
            raise RuntimeError(f"Missing extension file: {relative_path}")

    manifest = json.loads((extension_dir / "manifest.json").read_text(encoding="utf-8"))
    errors = []

    if manifest.get("manifest_version") != 3:
        errors.append("manifest_version must be 3")

    if manifest.get("action", {}).get("default_popup") != WAPPALYZER_POPUP_PATH:
        errors.append(f"action.default_popup must be {WAPPALYZER_POPUP_PATH}")

    if not manifest.get("background", {}).get("service_worker"):
        errors.append("background.service_worker is required")

    if "scripts" in manifest.get("background", {}):
        errors.append("background.scripts must be absent for Chromium MV3")

    if "browser_specific_settings" in manifest:
        errors.append("browser_specific_settings must be absent")

    if errors:
        raise RuntimeError("Invalid bundled Chromium extension: " + "; ".join(errors))


def _prepare_extension_dir(extension_archive_path):
    extension_dir = Path(tempfile.mkdtemp(prefix="wappalyzer-extension-"))

    try:
        with zipfile.ZipFile(extension_archive_path) as archive:
            destination = extension_dir.resolve()
            seen = set()
            total_size = 0

            for member in archive.infolist():
                member_path = (destination / member.filename).resolve()
                normalized_name = member.filename.casefold()
                mode = member.external_attr >> 16

                if destination not in member_path.parents and member_path != destination:
                    raise RuntimeError(f"Unsafe extension archive path: {member.filename}")

                if normalized_name in seen:
                    raise RuntimeError(f"Duplicate extension archive path: {member.filename}")

                if stat.S_ISLNK(mode):
                    raise RuntimeError(f"Extension archive contains a symlink: {member.filename}")

                seen.add(normalized_name)
                total_size += member.file_size

                if total_size > MAX_EXTENSION_UNCOMPRESSED_BYTES:
                    raise RuntimeError("Extension archive exceeds the extraction size limit")

            archive.extractall(extension_dir)

        _validate_extension_dir(extension_dir)
    except Exception:
        shutil.rmtree(extension_dir, ignore_errors=True)
        raise

    return extension_dir


def _detection_signature(detections):
    parts = []

    for detection in detections or ():
        technology = detection.get("technology") or detection.get("name") or detection.get("slug")

        if not technology:
            continue

        pattern = detection.get("pattern") or {}
        confidence = pattern.get("confidence", detection.get("confidence", ""))
        parts.append(f"{technology}:{detection.get('version', '')}:{confidence}")

    return "|".join(sorted(parts))


def _activity_signature(activity):
    return ":".join(
        str(activity.get(key, ""))
        for key in ("readyState", "scannerState", "relevantCount", "mutationCount")
    )


def _page_quiet(activity, quiet_ms=1000):
    if activity.get("unavailable"):
        return True

    recent_resource = (
        activity.get("lastRelevantAge") is not None and activity["lastRelevantAge"] < quiet_ms
    )
    recent_mutation = (
        activity.get("lastMutationAge") is not None and activity["lastMutationAge"] < quiet_ms
    )

    return activity.get("readyState") == "complete" and not recent_resource and not recent_mutation


class BrowserDriver:
    def __init__(self, context, page, user_data_dir, extension_id, timeout_ms):
        self.context = context
        self.page = page
        self.user_data_dir = Path(user_data_dir)
        self.extension_id = extension_id
        self.timeout_ms = timeout_ms
        self.popup = None
        self.pending_cookies = []
        self.healthy = True

    def add_cookie(self, cookie):
        self.pending_cookies.append(cookie)

    async def apply_pending_cookies(self, url):
        if not self.pending_cookies:
            return

        cookies = []

        for cookie in self.pending_cookies:
            cookies.append(
                {
                    "name": cookie["name"],
                    "value": cookie["value"],
                    "url": url,
                }
            )

        self.pending_cookies = []
        await self.context.add_cookies(cookies)

    async def reset(self):
        if not self.healthy:
            raise RuntimeError("Browser driver is unhealthy")

        failures = []

        try:
            await asyncio.wait_for(self.context.clear_cookies(), timeout=2)
        except Exception as error:
            failures.append(f"cookies: {error}")

        for worker in tuple(self.context.service_workers):
            if worker.url.startswith("chrome-extension://"):
                continue

            try:
                await asyncio.wait_for(
                    worker.evaluate("() => self.registration && self.registration.unregister()"),
                    timeout=2,
                )
            except Exception as error:
                failures.append(f"service worker: {error}")

        for page in tuple(self.context.pages):
            if page is self.popup or page.is_closed():
                continue

            try:
                await asyncio.wait_for(page.close(), timeout=2)
            except Exception as error:
                failures.append(f"page close: {error}")

        self.page = None

        if failures:
            raise RuntimeError("Browser cleanup failed: " + "; ".join(failures))

    async def close(self):
        try:
            await asyncio.wait_for(self.context.close(), timeout=5)
        except Exception:
            pass

        shutil.rmtree(self.user_data_dir, ignore_errors=True)


class DriverPool:
    def __init__(self, size=3, max_retries=3, timeout=30):
        self.target_size = size
        self.max_retries = max_retries
        self.timeout = timeout
        self.queue = asyncio.Queue()
        self.closed = False
        self.playwright = None
        self.extension_dir = None
        self.drivers = []

    @property
    def size(self):
        return len(self.drivers)

    async def start(self):
        self.playwright = await async_playwright().start()
        self.extension_dir = _prepare_extension_dir(os.path.abspath(extension_path))

        for _index in range(self.target_size):
            driver = await self._create_driver()
            if driver:
                self.drivers.append(driver)
                await self.queue.put(driver)

        if self.queue.empty():
            raise RuntimeError("Failed to initialize Chromium browser contexts")

    async def grow_to(self, size):
        if self.closed or size <= self.size:
            return

        additional = size - len(self.drivers)
        for _index in range(additional):
            driver = await self._create_driver()
            if driver:
                self.drivers.append(driver)
                await self.queue.put(driver)

    async def _create_driver(self):
        for attempt in range(self.max_retries):
            user_data_dir = tempfile.mkdtemp(prefix="wappalyzer-chromium-")
            context = None
            timeout_ms = self.timeout * 1000

            try:
                context = await self.playwright.chromium.launch_persistent_context(
                    user_data_dir,
                    channel="chromium",
                    headless=True,
                    timeout=timeout_ms,
                    viewport={"width": 1366, "height": 900},
                    user_agent=USER_AGENT,
                    timezone_id="UTC",
                    reduced_motion="reduce",
                    ignore_https_errors=not VERIFY_TLS,
                    args=[
                        f"--disable-extensions-except={self.extension_dir}",
                        f"--load-extension={self.extension_dir}",
                        "--disable-background-networking",
                        "--disable-breakpad",
                        "--disable-client-side-phishing-detection",
                        "--disable-component-update",
                        "--disable-crash-reporter",
                        "--disable-default-apps",
                        "--disable-dev-shm-usage",
                        "--disable-domain-reliability",
                        "--disable-features=Translate,MediaRouter",
                        "--disable-notifications",
                        "--disable-speech-api",
                        "--disable-sync",
                        "--metrics-recording-only",
                        "--mute-audio",
                        "--no-first-run",
                        "--no-default-browser-check",
                    ],
                )
                context.on(
                    "console",
                    lambda message: (
                        logger.debug("Chromium console: %s", message.text)
                        if message.type == "error"
                        else None
                    ),
                )
                context.on(
                    "weberror",
                    lambda error: logger.warning("Chromium page error: %s", error),
                )

                context.set_default_timeout(timeout_ms)
                context.set_default_navigation_timeout(timeout_ms)

                async def route_handler(route):
                    if route.request.resource_type in BLOCKED_RESOURCE_TYPES:
                        await route.abort()
                    else:
                        await route.continue_()

                await context.route("**/*", route_handler)

                extension_id = await self._get_extension_id(context)
                await self._wait_for_extension_ready(context)
                pages = context.pages
                page = pages[0] if pages else await context.new_page()

                driver = BrowserDriver(
                    context,
                    page,
                    user_data_dir,
                    extension_id,
                    timeout_ms,
                )
                await _ensure_popup(driver)

                if page is not driver.popup and not page.is_closed():
                    await page.close()

                driver.page = None
                return driver
            except Exception as e:
                if context:
                    try:
                        await asyncio.wait_for(context.close(), timeout=5)
                    except Exception:
                        pass

                shutil.rmtree(user_data_dir, ignore_errors=True)
                logger.warning("Browser attempt %s failed: %s", attempt + 1, e)
                await asyncio.sleep(1)

        return None

    async def _get_extension_id(self, context):
        service_worker = await self._get_service_worker(context)

        return service_worker.url.split("/")[2]

    async def _get_service_worker(self, context):
        service_workers = context.service_workers
        service_worker = service_workers[0] if service_workers else None

        if service_worker is None:
            service_worker = await context.wait_for_event("serviceworker", timeout=10000)

        return service_worker

    async def _wait_for_extension_ready(self, context):
        service_worker = await self._get_service_worker(context)
        deadline = asyncio.get_running_loop().time() + self.timeout
        last_state = None

        while asyncio.get_running_loop().time() < deadline:
            try:
                last_state = await asyncio.wait_for(
                    service_worker.evaluate(
                        """
                        () => {
                          return {
                            count:
                              globalThis.__WAPPALYZER_TECHNOLOGY_COUNT__ || 0,
                            ready:
                              globalThis.__WAPPALYZER_SCANNER_READY__ === true,
                          }
                        }
                        """
                    ),
                    timeout=2,
                )
            except Exception:
                last_state = None

            if last_state and last_state.get("ready") and last_state.get("count", 0) > 0:
                return

            await asyncio.sleep(0.1)

        raise RuntimeError(f"Wappalyzer extension did not become ready: {last_state!r}")

    @asynccontextmanager
    async def get_driver(self):
        try:
            driver = await asyncio.wait_for(
                self.queue.get(),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError as error:
            raise RuntimeError("No healthy browser driver is available") from error

        try:
            yield driver
        except asyncio.CancelledError:
            await asyncio.shield(self._retire_and_replace(driver))
            raise
        except Exception:
            await self._retire_and_replace(driver)
            raise
        else:
            if self.closed:
                if driver in self.drivers:
                    self.drivers.remove(driver)
                await driver.close()
                return

            if not driver.healthy:
                await self._retire_and_replace(driver)
                return

            try:
                await driver.reset()
            except Exception:
                await self._retire_and_replace(driver)
                raise

            await self.queue.put(driver)

    async def _retire_and_replace(self, driver):
        if driver in self.drivers:
            self.drivers.remove(driver)

        await driver.close()

        if self.closed:
            return

        replacement = await self._create_driver()

        if replacement:
            self.drivers.append(replacement)
            await self.queue.put(replacement)

    async def cleanup(self):
        if self.closed:
            return

        self.closed = True
        drivers = list(self.drivers)
        self.drivers = []

        await asyncio.gather(
            *(driver.close() for driver in drivers),
            return_exceptions=True,
        )

        if self.playwright:
            try:
                await asyncio.wait_for(self.playwright.stop(), timeout=5)
            except Exception:
                pass

        if self.extension_dir:
            shutil.rmtree(self.extension_dir, ignore_errors=True)


async def _ensure_popup(driver):
    popup_url = f"chrome-extension://{driver.extension_id}/{WAPPALYZER_POPUP_PATH}"

    if driver.popup and not driver.popup.is_closed():
        if driver.popup.url != popup_url:
            await driver.popup.goto(popup_url, wait_until="domcontentloaded")

        return driver.popup

    driver.popup = await driver.context.new_page()
    await driver.popup.goto(popup_url, wait_until="domcontentloaded")

    return driver.popup


async def _stimulate_page(page, max_duration_ms=1250):
    try:
        await page.evaluate(STIMULATE_SCRIPT, max_duration_ms)
    except Exception:
        pass


async def _page_activity(page):
    try:
        return await page.evaluate(PAGE_ACTIVITY_SCRIPT)
    except Exception:
        return {"unavailable": True}


async def _get_detections(driver, target_url, raw=False):
    popup = await _ensure_popup(driver)
    extension_timeout_ms = max(1_000, min(driver.timeout_ms, 15_000))
    selected_tab = await popup.evaluate(
        SELECT_TARGET_TAB_SCRIPT,
        {
            "targetUrl": target_url,
            "timeoutMs": extension_timeout_ms,
        },
    )

    if isinstance(selected_tab, dict) and selected_tab.get("__error"):
        raise RuntimeError(selected_tab["__error"])

    if not selected_tab:
        raise RuntimeError(f"Unable to identify browser tab for {target_url}")

    last_successful_detections = None
    last_signature = None
    last_activity_signature = None
    stable_polls = 0
    completion_seen = False
    started_at = asyncio.get_running_loop().time()
    min_wait = 0.5
    hard_max = max(1.0, driver.timeout_ms / 1000 - 1)

    while True:
        response = await popup.evaluate(
            GET_DETECTIONS_FOR_TAB_SCRIPT,
            {
                "selectedTab": selected_tab,
                "timeoutMs": extension_timeout_ms,
                "raw": raw,
            },
        )

        response_failed = isinstance(response, dict) and response.get("__error")

        if response_failed:
            logger.warning("Wappalyzer extension error: %s", response["__error"])
            stable_polls = 0
        elif isinstance(response, list):
            last_successful_detections = response

        detections = last_successful_detections if last_successful_detections is not None else []
        signature = _detection_signature(detections)
        activity = await _page_activity(driver.page)
        activity_signature = _activity_signature(activity)
        scanner_state = activity.get("scannerState")

        if scanner_state == "error":
            raise RuntimeError("Wappalyzer content analysis failed")

        if scanner_state == "complete" and not completion_seen:
            completion_seen = True
            stable_polls = 0
            last_signature = signature
            last_activity_signature = activity_signature
            await asyncio.sleep(0.5)
            continue

        if response_failed:
            stable_polls = 0
        elif signature == last_signature and activity_signature == last_activity_signature:
            stable_polls += 1
        else:
            stable_polls = 0
            last_signature = signature
            last_activity_signature = activity_signature

        elapsed = asyncio.get_running_loop().time() - started_at
        page_quiet = _page_quiet(activity)
        stable_enough = stable_polls >= 2 and elapsed >= min_wait

        if completion_seen and stable_enough and page_quiet:
            break

        if elapsed >= hard_max:
            if not completion_seen:
                raise RuntimeError("Wappalyzer content analysis timed out")

            if last_successful_detections is None:
                raise RuntimeError("Wappalyzer extension returned no successful response")

            break

        await asyncio.sleep(0.5)

    if last_successful_detections is None:
        raise RuntimeError("Wappalyzer extension returned no successful response")

    return last_successful_detections


async def _clear_target_state(driver, page):
    failures = []

    try:
        await asyncio.wait_for(
            page.evaluate("() => { localStorage.clear(); sessionStorage.clear(); }"),
            timeout=2,
        )
    except Exception as error:
        failures.append(f"web storage: {error}")

    try:
        origin = await asyncio.wait_for(
            page.evaluate("() => location.origin"),
            timeout=2,
        )
        session = await asyncio.wait_for(
            driver.context.new_cdp_session(page),
            timeout=2,
        )

        try:
            await asyncio.wait_for(
                session.send("Network.clearBrowserCache"),
                timeout=2,
            )

            if origin and origin != "null":
                await asyncio.wait_for(
                    session.send(
                        "Storage.clearDataForOrigin",
                        {
                            "origin": origin,
                            "storageTypes": "all",
                        },
                    ),
                    timeout=2,
                )
        finally:
            try:
                await asyncio.wait_for(session.detach(), timeout=2)
            except Exception as error:
                failures.append(f"CDP detach: {error}")
    except Exception as error:
        failures.append(f"origin storage: {error}")

    if failures:
        raise RuntimeError("Target cleanup failed: " + "; ".join(failures))


async def _get_evidence_metrics(page):
    try:
        metrics = await asyncio.wait_for(
            page.evaluate(EVIDENCE_METRICS_SCRIPT),
            timeout=2,
        )
    except Exception:
        return None
    if not isinstance(metrics, dict):
        return None
    names = (
        "htmlCharacters",
        "textCharacters",
        "inlineScriptCount",
        "inlineScriptCharacters",
    )
    if any(
        isinstance(metrics.get(name), bool)
        or not isinstance(metrics.get(name), (int, float))
        or metrics[name] < 0
        for name in names
    ):
        return None
    dom_detection_truncated = metrics.get("domDetectionTruncated")
    if not isinstance(dom_detection_truncated, bool):
        return None
    return {
        **{name: int(metrics[name]) for name in names},
        "domDetectionTruncated": dom_detection_truncated,
    }


async def _process_page(driver, url, *, raw):
    page = await driver.context.new_page()
    driver.page = page
    response = None
    navigation_timed_out = False

    try:
        await driver.apply_pending_cookies(url)

        try:
            response = await page.goto(
                url,
                wait_until="load",
                timeout=driver.timeout_ms,
            )
        except PlaywrightTimeoutError:
            navigation_timed_out = True
            try:
                await page.evaluate("() => window.stop()")
            except Exception:
                pass

        await _stimulate_page(page)
        detections = (
            await _get_detections(driver, page.url, raw=True)
            if raw
            else await _get_detections(driver, page.url)
        )
        content = b""
        evidence_metrics = None
        if raw:
            evidence_metrics = await _get_evidence_metrics(page)
            body = getattr(response, "body", None)
            if callable(body):
                try:
                    content = await body()
                except Exception:
                    content = b""
            if not content:
                content = (await page.content()).encode("utf-8")
        return (
            detections,
            page.url,
            response.status if response is not None else None,
            content,
            navigation_timed_out,
            evidence_metrics,
        )
    finally:
        cleanup_failures = []

        try:
            await _clear_target_state(driver, page)
        except Exception as error:
            cleanup_failures.append(str(error))

        try:
            await asyncio.wait_for(page.close(), timeout=2)
        except Exception as error:
            cleanup_failures.append(f"page close: {error}")

        if driver.page is page:
            driver.page = None

        if cleanup_failures:
            driver.healthy = False
            logger.warning(
                "Retiring browser driver after cleanup failure: %s",
                "; ".join(cleanup_failures),
            )


async def process_url(driver, url):
    detections, _effective_url, _status, _content, _timed_out, _metrics = await _process_page(
        driver,
        url,
        raw=False,
    )
    return url, detections


def browser_evidence_truncations(detections, metrics, timed_out):
    limits_by_channel = {}

    def add(channel, limit):
        limits_by_channel.setdefault(channel, set()).add(limit)

    if timed_out:
        for channel, registration in CHANNEL_REGISTRY.items():
            if registration.owner is ChannelOwner.BROWSER:
                add(channel, EvidenceLimit.TIMER)

    limited_channels = ("dom", "html", "scripts", "text")
    if metrics is None:
        for channel in limited_channels:
            add(channel, EvidenceLimit.WORKER)
    else:
        if metrics["htmlCharacters"] > BROWSER_HTML_CHARACTER_LIMIT:
            add("html", EvidenceLimit.BYTES)
        if metrics["textCharacters"] > BROWSER_TEXT_CHARACTER_LIMIT:
            add("text", EvidenceLimit.BYTES)
        if metrics["textCharacters"] > BROWSER_DOM_TEXT_CHARACTER_LIMIT:
            add("dom", EvidenceLimit.BYTES)
        if metrics["inlineScriptCount"] > BROWSER_INLINE_SCRIPT_COUNT_LIMIT:
            add("scripts", EvidenceLimit.COUNT)
        if metrics["inlineScriptCharacters"] > BROWSER_INLINE_SCRIPT_CHARACTER_LIMIT:
            add("scripts", EvidenceLimit.BYTES)

    if metrics is not None and metrics["domDetectionTruncated"]:
        add("dom", EvidenceLimit.COUNT)

    limit_order = {limit: index for index, limit in enumerate(EvidenceLimit)}
    return tuple(
        EvidenceTruncation(
            channel=channel,
            limits=tuple(sorted(limits_by_channel[channel], key=lambda item: limit_order[item])),
        )
        for channel in CHANNEL_REGISTRY
        if channel in limits_by_channel
    )


async def process_url_evidence(driver, url):
    detections, effective_url, http_status, content, timed_out, metrics = await _process_page(
        driver,
        url,
        raw=True,
    )
    raw = raw_browser_detections(detections)
    truncations = browser_evidence_truncations(detections, metrics, timed_out)
    status = (
        StageStatus.PARTIAL
        if truncations
        else StageStatus.SUCCESS
        if raw
        else StageStatus.SUCCESS_EMPTY
    )
    identity = (
        ResponseIdentity(
            effective_url=effective_url,
            http_status=http_status,
            content_sha256=hashlib.sha256(content).hexdigest(),
        )
        if http_status is not None
        else None
    )
    return StageEvidence(
        name=StageName.BROWSER,
        status=status,
        response_identity=identity,
        detections=raw,
        truncations=truncations,
    )


def cookie_to_cookies(cookie):
    cookie_dict = SimpleCookie()
    cookie_dict.load(cookie)
    cookies = []

    for key, value in cookie_dict.items():
        cookies.append(
            {
                "name": key,
                "value": value.value,
            }
        )

    return cookies


def merge_technologies(detections):
    """wappalyzer produces duplicate results, we are merging them"""
    tech_map = {}

    for detection in detections:
        tech_name = detection.get("technology")

        if not tech_name:
            continue

        pattern = detection.get("pattern") or {}
        confidence = pattern.get("confidence", detection.get("confidence", 100))

        if tech_name not in tech_map:
            tech_map[tech_name] = {
                "version": detection.get("version", ""),
                "confidence": confidence,
            }
        else:
            existing = tech_map[tech_name]
            existing["version"] = better_version(
                detection.get("version", ""),
                existing["version"],
            )

            existing["confidence"] = min(
                existing["confidence"] + confidence,
                100,
            )

    return enrich_result(tech_map)


def _browser_detection_digest(value):
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def raw_browser_detections(detections):
    raw = []
    for detection in detections:
        technology = detection.get("technology")
        pattern = detection.get("pattern") or {}
        channel = pattern.get("type", "").split(".", 1)[0]
        registration = CHANNEL_REGISTRY.get(channel)
        if not technology or registration is None or registration.owner is not ChannelOwner.BROWSER:
            continue
        confidence = pattern.get("confidence", detection.get("confidence", 100))
        if isinstance(confidence, bool):
            continue
        try:
            confidence = max(0, min(int(confidence), 100))
        except (TypeError, ValueError):
            continue
        source = {
            "channel": channel,
            "confidence": confidence,
            "regex": pattern.get("regex", ""),
        }
        evidence = {
            "lastUrl": detection.get("lastUrl", ""),
            "match": pattern.get("match", ""),
        }
        raw.append(
            RawDetection(
                technology=technology,
                channel=channel,
                source_key=_browser_detection_digest(source),
                evidence_sha256=_browser_detection_digest(evidence),
                version=detection.get("version", ""),
                confidence=confidence,
            )
        )
    return tuple(
        sorted(
            raw,
            key=lambda item: (
                item.technology,
                item.channel,
                item.source_key,
                item.evidence_sha256,
            ),
        )
    )
