import asyncio
import concurrent.futures
import ipaddress
import multiprocessing
import os
import sys
import threading
import time
from concurrent.futures.process import BrokenProcessPool
from pathlib import Path
from urllib.parse import urlsplit

from wappalyzer.browser.analyzer import (
    DriverPool,
    cookie_to_cookies,
    merge_technologies,
    process_url,
    process_url_evidence,
)
from wappalyzer.core.analyzer import (
    ScanRequestError,
    analyze_static_stage,
    asset_worker_count,
    http_scan,
)
from wappalyzer.core.direct_requester import DirectResponseFetcher
from wappalyzer.core.regex_workers import RegexWorkerPool
from wappalyzer.core.requester import DEFAULT_READ_TIMEOUT
from wappalyzer.evidence import StageEvidence, merge_stage_evidence
from wappalyzer.models import (
    Endpoint,
    FailureCode,
    Protocol,
    StageName,
    StageStatus,
    TLSMetadata,
    TLSTrust,
)
from wappalyzer.resources import (
    DEFAULT_RESOURCE_PROFILE,
    ResourceBroker,
    WorkerCounts,
    autosize,
    capture_snapshot,
)


def _available_memory_bytes():
    cgroup_limit = Path("/sys/fs/cgroup/memory.max")
    cgroup_usage = Path("/sys/fs/cgroup/memory.current")

    try:
        value = cgroup_limit.read_text(encoding="utf-8").strip()

        if value != "max":
            limit = int(value)
            usage = int(cgroup_usage.read_text(encoding="utf-8").strip())
            return max(0, limit - usage)
    except (OSError, ValueError):
        pass

    try:
        return os.sysconf("SC_AVPHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError):
        return None


def _available_cpu_count():
    counts = []

    try:
        counts.append(len(os.sched_getaffinity(0)))
    except AttributeError:
        pass

    try:
        quota, period = Path("/sys/fs/cgroup/cpu.max").read_text(encoding="utf-8").split()

        if quota != "max":
            quota_value = int(quota)
            period_value = int(period)
            counts.append(max(1, (quota_value + period_value - 1) // period_value))
    except (OSError, ValueError):
        pass

    counts.append(max(1, os.cpu_count() or 1))
    return min(counts)


def automatic_worker_count(scan_type):
    override = os.getenv("WAPPALYZER_WORKERS")

    if override:
        return max(1, int(override))

    cpu_count = _available_cpu_count()

    if scan_type != "full":
        return cpu_count

    available_memory = _available_memory_bytes()
    memory_bound = (
        max(1, available_memory // (512 * 1024 * 1024))
        if available_memory is not None
        else cpu_count * 2
    )
    return max(1, min(cpu_count * 2, memory_bound))


def _process_pool_supported():
    main_module = sys.modules.get("__main__")
    main_file = getattr(main_module, "__file__", None)
    return bool(
        main_file
        and not str(main_file).startswith("<")
        and Path(main_file).is_file()
        and "ipykernel" not in sys.modules
    )


def _http_scan_job(url, scan_type, cookie, timeout, asset_workers):
    return url, http_scan(
        url,
        scan_type,
        cookie=cookie,
        timeout=timeout,
        asset_workers=asset_workers,
    )


def _static_stage_job(url, cookie, timeout, asset_workers, tls, regex_pool=None):
    deadline = time.monotonic() + timeout
    parsed = urlsplit(url)
    address = str(ipaddress.ip_address(parsed.hostname or ""))
    endpoint = Endpoint(
        address=address,
        port=parsed.port or (443 if parsed.scheme.casefold() == "https" else 80),
    )
    response_fetcher = DirectResponseFetcher(
        endpoint=endpoint,
        tls=tls,
        timeout=timeout,
    )
    response = response_fetcher(url, cookie=cookie, timeout=timeout)
    if response is None:
        raise ScanRequestError(f"Unable to fetch {url}")
    return analyze_static_stage(
        response,
        cookie=cookie,
        timeout=timeout,
        deadline=deadline,
        asset_workers=asset_workers,
        regex_pool=regex_pool,
        regex_timeout=timeout,
        response_fetcher=response_fetcher,
    )


class _LoopRunner:
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def run(self, coro):
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)

        try:
            return future.result()
        except KeyboardInterrupt:
            future.cancel()
            raise

    def close(self):
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join()


class _FullScanBackend:
    def __init__(
        self,
        workers=1,
        timeout=30,
        strict_tls=False,
        blocked_resource_types=None,
    ):
        self.workers = workers
        self.timeout = timeout
        self.strict_tls = strict_tls
        self.blocked_resource_types = blocked_resource_types
        self.pool = None
        self._pool_lock = None

    async def ensure_pool(self, size):
        if self._pool_lock is None:
            self._pool_lock = asyncio.Lock()

        async with self._pool_lock:
            if self.pool:
                if size > self.pool.size:
                    await self.pool.grow_to(size)

                if self.pool.size == 0:
                    raise RuntimeError("No healthy browser driver is available")

                return

            pool = DriverPool(
                size=size,
                timeout=self.timeout,
                strict_tls=self.strict_tls,
                blocked_resource_types=self.blocked_resource_types,
            )

            try:
                await pool.start()
            except Exception:
                await pool.cleanup()
                raise

            self.pool = pool

    async def analyze_url(self, url, cookie=None):
        async def scan():
            await self.ensure_pool(1)

            async with self.pool.get_driver() as driver:
                if cookie:
                    for cookie_dict in cookie_to_cookies(cookie):
                        driver.add_cookie(cookie_dict)

                result_url, detections = await process_url(driver, url)

            return result_url, merge_technologies(detections)

        return await asyncio.wait_for(scan(), timeout=self.timeout)

    async def analyze_evidence(self, url, cookie=None, tls=None):
        await self.ensure_pool(self.workers)
        async with self.pool.get_driver() as driver:
            if cookie:
                for cookie_dict in cookie_to_cookies(cookie):
                    driver.add_cookie(cookie_dict)
            return await asyncio.wait_for(
                process_url_evidence(
                    driver,
                    url,
                    tls_trust=tls.trust if tls is not None else TLSTrust.TRUSTED,
                ),
                timeout=self.timeout,
            )

    async def analyze_many(self, urls, cookie=None, on_result=None, on_error=None):
        urls = [url for url in urls if url]

        if not urls:
            return {}

        worker_count = min(self.workers, len(urls))
        await self.ensure_pool(worker_count)
        worker_count = min(worker_count, len(self.pool.drivers))

        queue = asyncio.Queue()
        indexed_results = {}
        indexed_errors = {}

        for index, url in enumerate(urls):
            queue.put_nowait((index, url))

        async def worker():
            while True:
                try:
                    index, url = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break

                result_url = url
                technologies = {}
                error = None

                try:
                    result_url, technologies = await self.analyze_url(url, cookie)
                except Exception as exc:
                    error = exc

                indexed_results[index] = (result_url, technologies)

                if error:
                    indexed_errors[index] = error

                if error and on_error:
                    on_error(url, error)

                if on_result:
                    on_result(url, technologies)

                queue.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(worker_count)]

        try:
            await asyncio.gather(*workers)
        except asyncio.CancelledError:
            for worker_task in workers:
                worker_task.cancel()

            raise

        results = {}

        for index in range(len(urls)):
            _result_url, technologies = indexed_results.get(
                index,
                (urls[index], {}),
            )
            input_url = urls[index]
            results[input_url] = technologies

        return results

    async def close(self):
        if self.pool:
            await self.pool.cleanup()
            self.pool = None


class CompleteScanExecutor:
    def __init__(
        self,
        *,
        browser_runner,
        static_runner=_static_stage_job,
        timeout=DEFAULT_READ_TIMEOUT,
        static_workers=1,
        asset_workers=1,
        regex_pool=None,
    ):
        if not callable(static_runner):
            raise TypeError("static_runner must be callable")
        if not callable(browser_runner):
            raise TypeError("browser_runner must be callable")
        if timeout < 1:
            raise ValueError("timeout must be at least 1 second")
        if static_workers < 1:
            raise ValueError("static_workers must be at least one")
        if asset_workers < 1:
            raise ValueError("asset_workers must be at least one")
        self.static_runner = static_runner
        self.browser_runner = browser_runner
        self.timeout = timeout
        self.asset_workers = asset_workers
        self._default_static_runner = static_runner is _static_stage_job
        if regex_pool is not None:
            self._regex_pool = regex_pool
        elif self._default_static_runner:
            self._regex_pool = RegexWorkerPool(
                workers=static_workers,
                wall_timeout=timeout,
                cpu_seconds=max(1, int(timeout)),
            )
        else:
            self._regex_pool = None
        self._owns_regex_pool = regex_pool is None and self._regex_pool is not None
        self._static_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=static_workers,
        )
        self._closed = False

    def _run_static(self, url, cookie, tls):
        if self._default_static_runner:
            return self.static_runner(
                url,
                cookie,
                self.timeout,
                self.asset_workers,
                tls,
                self._regex_pool,
            )
        return self.static_runner(
            url,
            cookie,
            self.timeout,
            self.asset_workers,
            tls,
        )

    @staticmethod
    def _failed_stage(name, error):
        failure_code = (
            FailureCode.SCAN_TIMEOUT
            if isinstance(error, (TimeoutError, asyncio.TimeoutError))
            else FailureCode.WORKER_FAILURE
        )
        return StageEvidence(
            name=name,
            status=StageStatus.INDETERMINATE,
            response_identity=None,
            error_codes=(failure_code,),
        )

    @classmethod
    def _stage_or_failure(cls, expected_name, value):
        if isinstance(value, asyncio.CancelledError):
            raise value
        if isinstance(value, BaseException):
            return cls._failed_stage(expected_name, value)
        if not isinstance(value, StageEvidence) or value.name is not expected_name:
            return cls._failed_stage(
                expected_name,
                TypeError(f"{expected_name.value} runner returned invalid evidence"),
            )
        return value

    async def analyze_protocol(self, url, protocol, tls, cookie=None):
        if self._closed:
            raise RuntimeError("complete scan executor is closed")
        if not isinstance(protocol, Protocol):
            raise TypeError("protocol must be a Protocol")
        if not isinstance(tls, TLSMetadata):
            raise TypeError("tls must be TLSMetadata")

        loop = asyncio.get_running_loop()
        static_future = loop.run_in_executor(
            self._static_executor,
            self._run_static,
            url,
            cookie,
            tls,
        )
        browser_future = asyncio.ensure_future(self.browser_runner(url, cookie, tls))
        static_value, browser_value = await asyncio.gather(
            static_future,
            browser_future,
            return_exceptions=True,
        )
        stages = (
            self._stage_or_failure(StageName.STATIC, static_value),
            self._stage_or_failure(StageName.BROWSER, browser_value),
        )
        return merge_stage_evidence(
            protocol=protocol,
            requested_url=url,
            tls=tls,
            stages=stages,
        )

    def close(self):
        if self._closed:
            return
        self._closed = True
        self._static_executor.shutdown(wait=True, cancel_futures=True)
        if self._owns_regex_pool:
            self._regex_pool.close()

    def __enter__(self):
        if self._closed:
            raise RuntimeError("complete scan executor is closed")
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()


class Wappalyzer:
    SUPPORTED_SCAN_TYPES = {"fast", "balanced", "full"}

    def __init__(
        self,
        scan_type="full",
        workers=None,
        cookie=None,
        timeout=None,
        resource_snapshot=None,
        resource_profile=None,
    ):
        scan_type = scan_type.lower()

        if scan_type not in self.SUPPORTED_SCAN_TYPES:
            raise ValueError(
                f"Unsupported scan_type {scan_type!r}. "
                f"Expected one of: {', '.join(sorted(self.SUPPORTED_SCAN_TYPES))}"
            )

        snapshot = resource_snapshot or capture_snapshot()
        profile = resource_profile or DEFAULT_RESOURCE_PROFILE
        if workers is None:
            workers = automatic_worker_count(scan_type)

        if timeout is None:
            timeout = DEFAULT_READ_TIMEOUT

        if workers < 1:
            raise ValueError("workers must be at least 1")

        if timeout < 1:
            raise ValueError("timeout must be at least 1 second")

        requested = (
            WorkerCounts(discovery=0, static=0, browser=workers)
            if scan_type == "full"
            else WorkerCounts(discovery=workers, static=workers, browser=0)
        )
        resource_plan = autosize(snapshot, profile, requested=requested)
        selected_workers = (
            resource_plan.selected.browser
            if scan_type == "full"
            else min(
                resource_plan.selected.discovery,
                resource_plan.selected.static,
            )
        )
        if selected_workers < 1:
            reasons = ", ".join(resource_plan.insufficiency_reasons) or "worker capacity"
            raise RuntimeError(f"Insufficient resources for one complete worker: {reasons}")

        self.scan_type = scan_type
        self.workers = selected_workers
        self.requested_workers = workers
        self.cookie = cookie
        self.timeout = timeout
        self.resource_plan = resource_plan
        self.resource_broker = ResourceBroker(snapshot.broker_capacity())
        self._closed = False
        self._runner = None
        self._full_backend = None
        self._http_executor = None
        self._lock = threading.RLock()

    def __enter__(self):
        self._check_open()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def close(self):
        with self._lock:
            if self._closed:
                return

            self._closed = True
            runner = self._runner
            backend = self._full_backend
            http_executor = self._http_executor
            self._runner = None
            self._full_backend = None
            self._http_executor = None

        if runner and backend:
            try:
                runner.run(backend.close())
            finally:
                runner.close()
        elif runner:
            runner.close()

        if http_executor:
            http_executor.shutdown(wait=True, cancel_futures=True)

    def analyze(self, url, cookie=None):
        result_url, technologies = self._analyze_url(url, cookie)

        return {result_url: technologies}

    def analyze_many(self, urls, cookie=None, on_result=None, on_error=None):
        urls = [url for url in urls if url]

        if not urls:
            return {}

        self._check_open()

        if self.scan_type == "full":
            return self._full_runner().run(
                self._full_backend.analyze_many(
                    urls,
                    cookie=self._effective_cookie(cookie),
                    on_result=on_result,
                    on_error=on_error,
                )
            )

        return self._analyze_many_http(
            urls,
            cookie=self._effective_cookie(cookie),
            on_result=on_result,
            on_error=on_error,
        )

    def _check_open(self):
        if self._closed:
            raise RuntimeError("Wappalyzer scanner is closed")

    def _effective_cookie(self, cookie):
        return self.cookie if cookie is None else cookie

    def _full_runner(self):
        with self._lock:
            self._check_open()

            if not self._runner:
                self._runner = _LoopRunner()
                self._full_backend = _FullScanBackend(
                    workers=self.workers,
                    timeout=self.timeout,
                )

            return self._runner

    def _analyze_url(self, url, cookie=None):
        self._check_open()
        cookie = self._effective_cookie(cookie)

        if self.scan_type == "full":
            return self._full_runner().run(self._full_backend.analyze_url(url, cookie=cookie))

        return url, http_scan(
            url,
            self.scan_type,
            cookie,
            timeout=self.timeout,
            asset_workers=asset_worker_count(_available_cpu_count()),
        )

    def _analyze_many_http(self, urls, cookie=None, on_result=None, on_error=None):
        worker_count = min(self.workers, len(urls))
        asset_workers = asset_worker_count(max(1, _available_cpu_count() // worker_count))
        indexed_results = {}
        indexed_errors = {}
        emitted = set()

        def emit(index, url):
            if index in emitted:
                return

            emitted.add(index)
            technologies = indexed_results[index][1]

            if index in indexed_errors and on_error:
                on_error(url, indexed_errors[index])

            if on_result:
                on_result(url, technologies)

        if worker_count == 1:
            for index, url in enumerate(urls):
                try:
                    indexed_results[index] = _http_scan_job(
                        url,
                        self.scan_type,
                        cookie,
                        self.timeout,
                        asset_workers,
                    )
                except Exception as exc:
                    indexed_results[index] = (url, {})
                    indexed_errors[index] = exc

                emit(index, url)
        else:
            with self._lock:
                if not self._http_executor:
                    if _process_pool_supported():
                        self._http_executor = concurrent.futures.ProcessPoolExecutor(
                            max_workers=self.workers,
                            mp_context=multiprocessing.get_context("spawn"),
                        )
                    else:
                        self._http_executor = concurrent.futures.ThreadPoolExecutor(
                            max_workers=self.workers,
                        )

                executor = self._http_executor

            items = list(enumerate(urls))
            future_to_item = {}
            fallback_items = []

            for item_position, (index, url) in enumerate(items):
                try:
                    future = executor.submit(
                        _http_scan_job,
                        url,
                        self.scan_type,
                        cookie,
                        self.timeout,
                        asset_workers,
                    )
                except BrokenProcessPool:
                    fallback_items.extend(items[item_position:])
                    break
                else:
                    future_to_item[future] = (index, url)

            for future in concurrent.futures.as_completed(future_to_item):
                index, url = future_to_item[future]

                try:
                    indexed_results[index] = future.result()
                except BrokenProcessPool:
                    fallback_items.append((index, url))
                except Exception as exc:
                    indexed_results[index] = (url, {})
                    indexed_errors[index] = exc

                if index in indexed_results:
                    emit(index, url)

            if fallback_items:
                with self._lock:
                    if self._http_executor is executor:
                        executor.shutdown(wait=True, cancel_futures=True)
                        self._http_executor = None

                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=min(worker_count, len(fallback_items))
                ) as fallback:
                    fallback_futures = {
                        fallback.submit(
                            _http_scan_job,
                            url,
                            self.scan_type,
                            cookie,
                            self.timeout,
                            asset_workers,
                        ): (index, url)
                        for index, url in fallback_items
                    }

                    for future in concurrent.futures.as_completed(fallback_futures):
                        index, url = fallback_futures[future]

                        try:
                            indexed_results[index] = future.result()
                        except Exception as exc:
                            indexed_results[index] = (url, {})
                            indexed_errors[index] = exc

                        emit(index, url)

        results = {}

        for index, url in enumerate(urls):
            _result_url, technologies = indexed_results[index]
            results[url] = technologies

        return results


Scanner = Wappalyzer


def analyze(url, scan_type="full", workers=None, cookie=None, timeout=None):
    with Wappalyzer(
        scan_type=scan_type,
        workers=workers,
        cookie=cookie,
        timeout=timeout,
    ) as scanner:
        return scanner.analyze(url)
