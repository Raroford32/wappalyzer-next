import os
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from wappalyzer.core.regex_workers import RegexTimeoutError, RegexWorkerPool


def worker_pid():
    return os.getpid()


def sleep_then_value(delay, value):
    time.sleep(delay)
    return value


def test_regex_workers_execute_in_spawned_processes_and_reuse_capacity():
    pool = RegexWorkerPool(workers=2, wall_timeout=2)
    try:
        parent_pid = os.getpid()
        worker_pids = {pool.run(worker_pid) for _ in range(4)}
    finally:
        pool.close()

    assert parent_pid not in worker_pids
    assert 1 <= len(worker_pids) <= 2


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
