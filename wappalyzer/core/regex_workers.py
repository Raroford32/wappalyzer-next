import concurrent.futures
import multiprocessing
import resource
import threading
import time
from concurrent.futures.process import BrokenProcessPool


class RegexTimeoutError(TimeoutError):
    pass


class RegexWorkerError(RuntimeError):
    pass


def _configure_worker(cpu_seconds, memory_bytes):
    if cpu_seconds is not None:
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
    if memory_bytes is not None:
        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))


def _terminate_executor(executor):
    processes = tuple((getattr(executor, "_processes", None) or {}).values())
    for process in processes:
        if process.is_alive():
            process.terminate()

    deadline = time.monotonic() + 1
    for process in processes:
        process.join(timeout=max(0, deadline - time.monotonic()))
    for process in processes:
        if process.is_alive():
            process.kill()
    for process in processes:
        process.join(timeout=0.1)
    executor.shutdown(wait=False, cancel_futures=True)


class RegexWorkerPool:
    def __init__(
        self,
        *,
        workers,
        wall_timeout,
        cpu_seconds=None,
        memory_bytes=None,
    ):
        if isinstance(workers, bool) or not isinstance(workers, int) or workers < 1:
            raise ValueError("workers must be a positive integer")
        if (
            isinstance(wall_timeout, bool)
            or not isinstance(wall_timeout, (int, float))
            or wall_timeout <= 0
        ):
            raise ValueError("wall_timeout must be positive")
        if cpu_seconds is not None and (
            isinstance(cpu_seconds, bool) or not isinstance(cpu_seconds, int) or cpu_seconds < 1
        ):
            raise ValueError("cpu_seconds must be a positive integer or None")
        if memory_bytes is not None and (
            isinstance(memory_bytes, bool) or not isinstance(memory_bytes, int) or memory_bytes < 1
        ):
            raise ValueError("memory_bytes must be a positive integer or None")

        self.workers = workers
        self.wall_timeout = float(wall_timeout)
        self.cpu_seconds = cpu_seconds
        self.memory_bytes = memory_bytes
        self._slots = threading.BoundedSemaphore(workers)
        self._lock = threading.RLock()
        self._executor = None
        self._closed = False

    def _new_executor(self):
        return concurrent.futures.ProcessPoolExecutor(
            max_workers=self.workers,
            mp_context=multiprocessing.get_context("spawn"),
            initializer=_configure_worker,
            initargs=(self.cpu_seconds, self.memory_bytes),
        )

    def _current_executor(self):
        with self._lock:
            if self._closed:
                raise RuntimeError("regex worker pool is closed")
            if self._executor is None:
                self._executor = self._new_executor()
            return self._executor

    def _invalidate(self, executor):
        with self._lock:
            if self._executor is not executor:
                return
            self._executor = None
        _terminate_executor(executor)

    def _acquire_slot(self):
        while not self._slots.acquire(timeout=0.05):
            with self._lock:
                if self._closed:
                    raise RuntimeError("regex worker pool is closed")

    def run(self, function, *args, timeout=None):
        if not callable(function):
            raise TypeError("function must be callable")
        effective_timeout = self.wall_timeout if timeout is None else timeout
        if (
            isinstance(effective_timeout, bool)
            or not isinstance(effective_timeout, (int, float))
            or effective_timeout <= 0
        ):
            raise ValueError("timeout must be positive")

        self._acquire_slot()
        try:
            for attempt in range(2):
                executor = self._current_executor()
                try:
                    future = executor.submit(function, *args)
                    return future.result(timeout=effective_timeout)
                except concurrent.futures.TimeoutError as error:
                    self._invalidate(executor)
                    raise RegexTimeoutError(
                        f"regex worker exceeded {effective_timeout:g}s wall timeout"
                    ) from error
                except BrokenProcessPool as error:
                    self._invalidate(executor)
                    if attempt:
                        raise RegexWorkerError(
                            "regex worker pool failed after replacement"
                        ) from error
            raise RegexWorkerError("regex worker pool retry exhausted")
        finally:
            self._slots.release()

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            executor = self._executor
            self._executor = None
        if executor is not None:
            _terminate_executor(executor)

    def __enter__(self):
        with self._lock:
            if self._closed:
                raise RuntimeError("regex worker pool is closed")
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()


__all__ = ["RegexTimeoutError", "RegexWorkerError", "RegexWorkerPool"]
