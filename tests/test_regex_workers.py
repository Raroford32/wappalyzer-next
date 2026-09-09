import os
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

import wappalyzer.core.regex_workers as regex_workers_module
from wappalyzer.core.regex_workers import RegexTimeoutError, RegexWorkerError, RegexWorkerPool


def worker_pid():
    return os.getpid()


def sleep_then_value(delay, value):
    time.sleep(delay)
    return value


def crash_worker():
    os._exit(17)


def crash_once_then_pid(marker):
    try:
        descriptor = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        return os.getpid()
    os.close(descriptor)
    os._exit(17)


def test_regex_workers_execute_in_spawned_processes_and_reuse_capacity():
    pool = RegexWorkerPool(workers=2, wall_timeout=2)
    try:
        parent_pid = os.getpid()
        worker_pids = {pool.run(worker_pid) for _ in range(4)}
    finally:
        pool.close()

    assert parent_pid not in worker_pids
    assert 1 <= len(worker_pids) <= 2


def test_worker_resource_limits_are_configured_independently(monkeypatch):
    calls = []
    monkeypatch.setattr(
        regex_workers_module.resource,
        "setrlimit",
        lambda resource_type, limits: calls.append((resource_type, limits)),
    )

    regex_workers_module._configure_worker(None, None)
    regex_workers_module._configure_worker(2, None)
    regex_workers_module._configure_worker(None, 4096)

    assert calls == [
        (regex_workers_module.resource.RLIMIT_CPU, (2, 3)),
        (regex_workers_module.resource.RLIMIT_AS, (4096, 4096)),
    ]
    assert regex_workers_module._worker_ready() is True


class ScriptedProcess:
    def __init__(self, alive):
        self._alive = iter(alive)
        self.terminated = False
        self.killed = False
        self.joins = []

    def is_alive(self):
        return next(self._alive)

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True

    def join(self, timeout):
        self.joins.append(timeout)


class RecordingExecutor:
    def __init__(self, processes=None, startup_error=None):
        self._processes = processes
        self.startup_error = startup_error
        self.shutdown_calls = []

    def submit(self, _function):
        return self

    def result(self, timeout):
        raise self.startup_error

    def shutdown(self, **kwargs):
        self.shutdown_calls.append(kwargs)


def test_executor_termination_escalates_only_live_processes(monkeypatch):
    clock = iter((10.0, 10.25, 10.5))
    dead = ScriptedProcess((False, False))
    stubborn = ScriptedProcess((True, True))
    executor = RecordingExecutor({"dead": dead, "stubborn": stubborn})
    monkeypatch.setattr(regex_workers_module.time, "monotonic", lambda: next(clock))

    regex_workers_module._terminate_executor(executor)

    assert not dead.terminated
    assert not dead.killed
    assert stubborn.terminated
    assert stubborn.killed
    assert len(dead.joins) == 2
    assert len(stubborn.joins) == 2
    assert executor.shutdown_calls == [{"wait": False, "cancel_futures": True}]


@pytest.mark.parametrize(
    "replacement",
    [
        {"workers": True},
        {"workers": 0},
        {"wall_timeout": True},
        {"wall_timeout": 0},
        {"cpu_seconds": True},
        {"cpu_seconds": 0},
        {"memory_bytes": True},
        {"memory_bytes": 0},
        {"startup_timeout": True},
        {"startup_timeout": 0},
    ],
)
def test_regex_worker_pool_validates_resource_configuration(replacement):
    values = {"workers": 1, "wall_timeout": 1}
    values.update(replacement)

    with pytest.raises(ValueError):
        RegexWorkerPool(**values)


def test_worker_startup_failure_terminates_executor_and_is_typed(monkeypatch):
    executor = RecordingExecutor({}, TimeoutError("worker startup timed out"))
    monkeypatch.setattr(
        regex_workers_module.concurrent.futures,
        "ProcessPoolExecutor",
        lambda **_kwargs: executor,
    )
    pool = RegexWorkerPool(workers=1, wall_timeout=1, startup_timeout=0.1)

    with pytest.raises(RegexWorkerError, match="failed to start") as captured:
        pool._new_executor()

    assert isinstance(captured.value.__cause__, TimeoutError)
    assert executor.shutdown_calls == [{"wait": False, "cancel_futures": True}]
    pool.close()
    pool.close()


def test_closed_pool_rejects_executor_access_and_waiting_callers():
    pool = RegexWorkerPool(workers=1, wall_timeout=1)
    assert pool._slots.acquire()
    pool.close()
    try:
        with pytest.raises(RuntimeError, match="closed"):
            pool._acquire_slot()
        with pytest.raises(RuntimeError, match="closed"):
            pool._current_executor()
    finally:
        pool._slots.release()


def test_invalidating_stale_executor_does_not_terminate_current_generation(monkeypatch):
    current = object()
    stale = object()
    terminated = []
    pool = RegexWorkerPool(workers=1, wall_timeout=1)
    pool._executor = current
    monkeypatch.setattr(regex_workers_module, "_terminate_executor", terminated.append)

    pool._invalidate(stale)

    assert pool._executor is current
    assert terminated == []
    pool._executor = None
    pool.close()


@pytest.mark.parametrize(
    ("function", "timeout", "exception_type"),
    [
        (None, None, TypeError),
        (worker_pid, True, ValueError),
        (worker_pid, 0, ValueError),
        (worker_pid, "1", ValueError),
    ],
)
def test_run_validates_function_and_timeout(function, timeout, exception_type):
    pool = RegexWorkerPool(workers=1, wall_timeout=1)
    try:
        with pytest.raises(exception_type):
            pool.run(function, timeout=timeout)
    finally:
        pool.close()


def test_process_crash_replaces_generation_and_retries_once(tmp_path):
    marker = str(tmp_path / "crashed")
    pool = RegexWorkerPool(workers=1, wall_timeout=2)
    try:
        replacement_pid = pool.run(crash_once_then_pid, marker)
        reused_pid = pool.run(worker_pid)
    finally:
        pool.close()

    assert replacement_pid == reused_pid


def test_second_process_crash_raises_typed_worker_failure():
    pool = RegexWorkerPool(workers=1, wall_timeout=2)
    try:
        with pytest.raises(RegexWorkerError, match="failed after replacement"):
            pool.run(crash_worker)
    finally:
        pool.close()


def test_context_manager_closes_pool_and_rejects_reentry():
    pool = RegexWorkerPool(workers=1, wall_timeout=2)

    with pool as entered:
        assert entered is pool
        assert pool.run(worker_pid) != os.getpid()

    with pytest.raises(RuntimeError, match="closed"):
        pool.__enter__()


def test_regex_timeout_terminates_generation_and_replaces_workers():
    pool = RegexWorkerPool(workers=1, wall_timeout=0.1)
    try:
        first_pid = pool.run(worker_pid)
        with pytest.raises(RegexTimeoutError):
            pool.run(sleep_then_value, 5, "late")
        replacement_pid = pool.run(worker_pid, timeout=2)
    finally:
        pool.close()

    assert replacement_pid != first_pid


def test_queue_wait_does_not_consume_regex_service_timeout():
    pool = RegexWorkerPool(workers=1, wall_timeout=0.1)
    try:
        with ThreadPoolExecutor(max_workers=1) as callers:
            occupied = callers.submit(pool.run, sleep_then_value, 0.25, "first", timeout=1)
            time.sleep(0.05)
            assert pool.run(sleep_then_value, 0, "second") == "second"
            assert occupied.result() == "first"
    finally:
        pool.close()
