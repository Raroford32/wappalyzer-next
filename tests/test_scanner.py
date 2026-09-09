import asyncio

import pytest

from wappalyzer import scanner
from wappalyzer.resources import GIB, ResourceSnapshot


def test_automatic_http_workers_follow_cpu_allocation(monkeypatch):
    monkeypatch.delenv("WAPPALYZER_WORKERS", raising=False)
    monkeypatch.setattr(scanner, "_available_cpu_count", lambda: 12)

    assert scanner.automatic_worker_count("fast") == 12


def test_worker_environment_override(monkeypatch):
    monkeypatch.setenv("WAPPALYZER_WORKERS", "19")

    assert scanner.automatic_worker_count("full") == 19


def test_zero_available_memory_selects_minimum_browser_worker(monkeypatch):
    monkeypatch.delenv("WAPPALYZER_WORKERS", raising=False)
    monkeypatch.setattr(scanner, "_available_cpu_count", lambda: 12)
    monkeypatch.setattr(scanner, "_available_memory_bytes", lambda: 0)

    assert scanner.automatic_worker_count("full") == 1


def test_interactive_callers_use_thread_fallback(monkeypatch):
    monkeypatch.setitem(scanner.sys.modules, "ipykernel", object())
    monkeypatch.setattr(
        scanner,
        "_http_scan_job",
        lambda url, scan_type, cookie, timeout, asset_workers: (url, {}),
    )

    with scanner.Wappalyzer(scan_type="fast", workers=2) as instance:
        result = instance.analyze_many(["https://a.test", "https://b.test"])

    assert list(result) == ["https://a.test", "https://b.test"]


def test_http_executor_has_fixed_capacity_and_is_reused(monkeypatch):
    monkeypatch.setitem(scanner.sys.modules, "ipykernel", object())
    monkeypatch.setattr(
        scanner,
        "_http_scan_job",
        lambda url, scan_type, cookie, timeout, asset_workers: (url, {}),
    )

    with scanner.Wappalyzer(scan_type="fast", workers=4) as instance:
        instance.analyze_many(["https://a.test", "https://b.test"])
        executor = instance._http_executor
        instance.analyze_many(
            [
                "https://a.test",
                "https://b.test",
                "https://c.test",
                "https://d.test",
            ]
        )

        assert instance._http_executor is executor
        assert executor._max_workers == 4


def test_asset_worker_override_is_passed_without_global_mutation(monkeypatch):
    seen_asset_workers = []

    def fake_job(url, scan_type, cookie, timeout, asset_workers):
        seen_asset_workers.append(asset_workers)
        return url, {}

    monkeypatch.setenv("WAPPALYZER_ASSET_WORKERS", "7")
    monkeypatch.setattr(scanner, "_available_cpu_count", lambda: 2)
    monkeypatch.setattr(scanner, "_http_scan_job", fake_job)

    with scanner.Wappalyzer(scan_type="fast", workers=1) as instance:
        instance.analyze_many(["https://a.test"])

    assert seen_asset_workers == [2]


def test_manual_workers_are_clamped_to_the_resource_snapshot():
    snapshot = ResourceSnapshot(
        cpu_count=2,
        memory_bytes=4 * GIB,
        file_descriptors=256,
        sockets=128,
        processes=64,
        shared_memory_bytes=2 * GIB,
        temp_bytes=2 * GIB,
        artifact_bytes=None,
    )

    with scanner.Wappalyzer(
        scan_type="fast",
        workers=20,
        resource_snapshot=snapshot,
    ) as instance:
        assert instance.workers == 2
        assert instance.resource_plan.requested.static == 20
        assert instance.resource_plan.selected.static == 2


def test_http_results_and_callbacks_follow_input_order(monkeypatch):
    def fake_job(url, scan_type, cookie, timeout, asset_workers):
        return url, {
            url: {
                "version": "",
                "confidence": 100,
                "categories": [],
                "groups": [],
            },
        }

    monkeypatch.setattr(scanner, "_http_scan_job", fake_job)
    callback_order = []

    with scanner.Wappalyzer(scan_type="fast", workers=1) as instance:
        result = instance.analyze_many(
            ["https://b.test", "https://a.test"],
            on_result=lambda url, technologies: callback_order.append(url),
        )

    assert list(result) == ["https://b.test", "https://a.test"]
    assert callback_order == ["https://b.test", "https://a.test"]


def test_batch_request_failures_reach_error_callback(monkeypatch):
    def failed_job(url, scan_type, cookie, timeout, asset_workers):
        raise RuntimeError("network down")

    monkeypatch.setattr(scanner, "_http_scan_job", failed_job)
    errors = {}

    with scanner.Wappalyzer(scan_type="fast", workers=1) as instance:
        result = instance.analyze_many(
            ["https://offline.test"],
            on_error=lambda url, error: errors.setdefault(url, str(error)),
        )

    assert result == {"https://offline.test": {}}
    assert errors == {"https://offline.test": "network down"}


def test_empty_browser_pool_fails_instead_of_returning_empty_success():
    class EmptyPool:
        size = 0

        async def grow_to(self, size):
            return None

    backend = scanner._FullScanBackend()
    assert backend._pool_lock is None
    backend.pool = EmptyPool()

    with pytest.raises(RuntimeError, match="No healthy browser driver"):
        asyncio.run(backend.ensure_pool(1))
    assert backend._pool_lock is not None
