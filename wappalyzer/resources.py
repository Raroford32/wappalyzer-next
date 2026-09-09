import math
import os
import resource
import threading
from concurrent.futures import CancelledError
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

MIB = 1024**2
GIB = 1024**3
_RESOURCE_FIELDS = (
    "cpu",
    "memory_bytes",
    "file_descriptors",
    "sockets",
    "processes",
    "temp_bytes",
)
_SNAPSHOT_FIELDS = {
    "cpu": "cpu_count",
    "memory_bytes": "memory_bytes",
    "file_descriptors": "file_descriptors",
    "sockets": "sockets",
    "processes": "processes",
    "temp_bytes": "temp_bytes",
}


def _require_nonnegative_integer(name, value, *, optional=False):
    if optional and value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        qualifier = " or None" if optional else ""
        raise ValueError(f"{name} must be a nonnegative integer{qualifier}")


@dataclass(frozen=True)
class ResourceRequest:
    cpu: int = 0
    memory_bytes: int = 0
    file_descriptors: int = 0
    sockets: int = 0
    processes: int = 0
    temp_bytes: int = 0

    def __post_init__(self):
        for name in _RESOURCE_FIELDS:
            _require_nonnegative_integer(name, getattr(self, name))

    def __add__(self, other):
        if not isinstance(other, ResourceRequest):
            return NotImplemented
        return ResourceRequest(
            *(getattr(self, name) + getattr(other, name) for name in _RESOURCE_FIELDS)
        )

    def __sub__(self, other):
        if not isinstance(other, ResourceRequest):
            return NotImplemented
        values = tuple(getattr(self, name) - getattr(other, name) for name in _RESOURCE_FIELDS)
        if any(value < 0 for value in values):
            raise ValueError("resource subtraction would produce a negative value")
        return ResourceRequest(*values)

    def fits_within(self, capacity):
        return all(getattr(self, name) <= getattr(capacity, name) for name in _RESOURCE_FIELDS)

    def scale(self, count):
        _require_nonnegative_integer("count", count)
        return ResourceRequest(*(getattr(self, name) * count for name in _RESOURCE_FIELDS))


@dataclass(frozen=True)
class ResourceSnapshot:
    cpu_count: int
    memory_bytes: Optional[int]
    file_descriptors: Optional[int]
    sockets: Optional[int]
    processes: Optional[int]
    shared_memory_bytes: Optional[int]
    temp_bytes: Optional[int]
    artifact_bytes: Optional[int]
    file_descriptors_used: int = 0
    sockets_used: int = 0
    processes_used: int = 0
    reasons: tuple[str, ...] = ()

    def __post_init__(self):
        _require_nonnegative_integer("cpu_count", self.cpu_count)
        if self.cpu_count < 1:
            raise ValueError("cpu_count must be at least one")
        for name in (
            "memory_bytes",
            "file_descriptors",
            "sockets",
            "processes",
            "shared_memory_bytes",
            "temp_bytes",
            "artifact_bytes",
        ):
            _require_nonnegative_integer(name, getattr(self, name), optional=True)
        for name in (
            "file_descriptors_used",
            "sockets_used",
            "processes_used",
        ):
            _require_nonnegative_integer(name, getattr(self, name))
        object.__setattr__(self, "reasons", tuple(self.reasons))

    def broker_capacity(self):
        return ResourceRequest(
            cpu=self.cpu_count,
            memory_bytes=self.memory_bytes or 0,
            file_descriptors=self.file_descriptors or 0,
            sockets=self.sockets or 0,
            processes=self.processes or 0,
            temp_bytes=self.temp_bytes or 0,
        )


@dataclass(frozen=True)
class ResourceProfile:
    discovery_worker: ResourceRequest
    static_worker: ResourceRequest
    browser_active_page: ResourceRequest
    browser_replacement: ResourceRequest

    def __post_init__(self):
        for name in (
            "discovery_worker",
            "static_worker",
            "browser_active_page",
            "browser_replacement",
        ):
            if not isinstance(getattr(self, name), ResourceRequest):
                raise TypeError(f"{name} must be a ResourceRequest")


@dataclass(frozen=True)
class WorkerCounts:
    discovery: int
    static: int
    browser: int

    def __post_init__(self):
        for name in ("discovery", "static", "browser"):
            _require_nonnegative_integer(name, getattr(self, name))


@dataclass(frozen=True)
class ResourcePlan:
    snapshot: ResourceSnapshot
    profile: ResourceProfile
    requested: WorkerCounts
    selected: WorkerCounts
    insufficiency_reasons: tuple[str, ...] = ()

    @property
    def can_run(self):
        return not self.insufficiency_reasons


DEFAULT_RESOURCE_PROFILE = ResourceProfile(
    discovery_worker=ResourceRequest(
        memory_bytes=64 * MIB,
        file_descriptors=8,
        sockets=4,
    ),
    static_worker=ResourceRequest(
        cpu=1,
        memory_bytes=128 * MIB,
        file_descriptors=4,
        processes=1,
        temp_bytes=32 * MIB,
    ),
    browser_active_page=ResourceRequest(
        memory_bytes=512 * MIB,
        file_descriptors=32,
        sockets=16,
        processes=4,
        temp_bytes=128 * MIB,
    ),
    browser_replacement=ResourceRequest(
        memory_bytes=512 * MIB,
        file_descriptors=16,
        sockets=4,
        processes=4,
        temp_bytes=128 * MIB,
    ),
)


def parse_cpu_set(value):
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None

    intervals = []
    try:
        for item in value.split(","):
            item = item.strip()
            if not item:
                return None
            if "-" in item:
                if item.count("-") != 1:
                    return None
                start_text, end_text = item.split("-")
                start = int(start_text)
                end = int(end_text)
            else:
                start = end = int(item)
            if start < 0 or end < start:
                return None
            intervals.append((start, end))
    except ValueError:
        return None

    intervals.sort()
    merged = []
    for start, end in intervals:
        if not merged or start > merged[-1][1] + 1:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)
    return sum(end - start + 1 for start, end in merged)


def _quota_cpu_count(cpu_max):
    if cpu_max is None:
        return None
    parts = cpu_max.split()
    if len(parts) != 2 or parts[0] == "max":
        return None
    try:
        quota, period = (int(part) for part in parts)
    except ValueError:
        return None
    if quota <= 0 or period <= 0:
        return None
    return max(1, math.ceil(quota / period))


def effective_cpu_count(host_count, affinity_count, cpuset, cpu_max):
    candidates = []
    for value in (host_count, affinity_count):
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            candidates.append(value)

    cpuset_count = parse_cpu_set(cpuset)
    if cpuset_count:
        candidates.append(cpuset_count)

    quota_count = _quota_cpu_count(cpu_max)
    if quota_count:
        candidates.append(quota_count)

    return min(candidates) if candidates else 1


def _parse_controller_integer(value):
    if value is None:
        return None
    value = value.strip()
    if not value or value == "max":
        return None
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def effective_available_memory(host_available, memory_max, memory_current):
    candidates = []
    if (
        isinstance(host_available, int)
        and not isinstance(host_available, bool)
        and host_available >= 0
    ):
        candidates.append(host_available)

    limit = _parse_controller_integer(memory_max)
    current = _parse_controller_integer(memory_current)
    if limit is not None and current is not None:
        candidates.append(max(0, limit - current))

    if not candidates:
        return None

    effective = min(candidates)
    reserve = max((effective + 4) // 5, 512 * MIB)
    return max(0, effective - reserve)


class SystemResourceProbe:
    def host_cpu_count(self):
        return os.cpu_count()

    def affinity_cpu_count(self):
        try:
            return len(os.sched_getaffinity(0))
        except (AttributeError, OSError):
            return None

    def host_available_memory_bytes(self):
        try:
            return os.sysconf("SC_AVPHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
        except (OSError, ValueError):
            return None

    def nofile_soft_limit(self):
        try:
            value, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        except (OSError, ValueError):
            return None
        return None if value == resource.RLIM_INFINITY else value

    def open_file_descriptor_count(self):
        try:
            with os.scandir("/proc/self/fd") as entries:
                return sum(1 for _entry in entries)
        except OSError:
            return 0

    def open_socket_count(self):
        count = 0
        try:
            with os.scandir("/proc/self/fd") as entries:
                for entry in entries:
                    try:
                        if os.readlink(entry.path).startswith("socket:["):
                            count += 1
                    except OSError:
                        continue
        except OSError:
            return 0
        return count

    def temp_directory(self):
        return Path(os.getenv("TMPDIR", "/tmp"))

    def read_text(self, path):
        return Path(path).read_text(encoding="utf-8").strip()

    def filesystem_free_bytes(self, path):
        statistics = os.statvfs(path)
        return statistics.f_bavail * statistics.f_frsize


def _safe_call(reasons, label, function, *args):
    try:
        return function(*args)
    except (OSError, ValueError) as exc:
        reasons.append(f"{label}: {type(exc).__name__}")
        return None


def _read_text(probe, path, reasons):
    return _safe_call(reasons, str(path), probe.read_text, path)


def _valid_cpu_max(value):
    if value is None:
        return False
    parts = value.split()
    if len(parts) != 2:
        return False
    if parts[0] == "max":
        try:
            return int(parts[1]) > 0
        except ValueError:
            return False
    return _quota_cpu_count(value) is not None


def capture_snapshot(probe=None, *, artifact_path=None):
    probe = probe or SystemResourceProbe()
    reasons = []

    host_cpus = _safe_call(reasons, "host CPU count", probe.host_cpu_count)
    affinity_cpus = _safe_call(
        reasons,
        "CPU affinity",
        probe.affinity_cpu_count,
    )
    cpuset_path = Path("/sys/fs/cgroup/cpuset.cpus.effective")
    cpu_max_path = Path("/sys/fs/cgroup/cpu.max")
    cpuset = _read_text(probe, cpuset_path, reasons)
    cpu_max = _read_text(probe, cpu_max_path, reasons)
    if cpuset is not None and parse_cpu_set(cpuset) is None:
        reasons.append(f"{cpuset_path}: malformed")
    if cpu_max is not None and not _valid_cpu_max(cpu_max):
        reasons.append(f"{cpu_max_path}: malformed")

    host_memory = _safe_call(
        reasons,
        "host available memory",
        probe.host_available_memory_bytes,
    )
    memory_max_path = Path("/sys/fs/cgroup/memory.max")
    memory_current_path = Path("/sys/fs/cgroup/memory.current")
    memory_max = _read_text(probe, memory_max_path, reasons)
    memory_current = _read_text(probe, memory_current_path, reasons)
    if memory_max not in (None, "max") and _parse_controller_integer(memory_max) is None:
        reasons.append(f"{memory_max_path}: malformed")
    if memory_max not in (None, "max") and _parse_controller_integer(memory_current) is None:
        reasons.append(f"{memory_current_path}: malformed")
    available_memory = effective_available_memory(
        host_memory,
        memory_max,
        memory_current,
    )

    open_files = _safe_call(
        reasons,
        "open file descriptors",
        probe.open_file_descriptor_count,
    )
    open_files = open_files if open_files is not None else 0
    open_sockets = _safe_call(reasons, "open sockets", probe.open_socket_count)
    open_sockets = open_sockets if open_sockets is not None else 0
    nofile_limit = _safe_call(
        reasons,
        "RLIMIT_NOFILE",
        probe.nofile_soft_limit,
    )
    if not isinstance(nofile_limit, int) or nofile_limit < 0:
        file_descriptors = None
    else:
        file_descriptors = max(0, nofile_limit - open_files)

    pids_max_path = Path("/sys/fs/cgroup/pids.max")
    pids_current_path = Path("/sys/fs/cgroup/pids.current")
    pids_max_text = _read_text(probe, pids_max_path, reasons)
    pids_current_text = _read_text(probe, pids_current_path, reasons)
    pids_max = _parse_controller_integer(pids_max_text)
    pids_current = _parse_controller_integer(pids_current_text)
    if pids_max_text not in (None, "max") and pids_max is None:
        reasons.append(f"{pids_max_path}: malformed")
    if pids_max is not None and pids_current is None:
        reasons.append(f"{pids_current_path}: malformed")
    processes = (
        max(0, pids_max - pids_current)
        if pids_max is not None and pids_current is not None
        else None
    )

    shared_memory = _safe_call(
        reasons,
        "/dev/shm",
        probe.filesystem_free_bytes,
        Path("/dev/shm"),
    )
    temp_directory = _safe_call(
        reasons,
        "temporary directory",
        probe.temp_directory,
    )
    temporary = (
        _safe_call(
            reasons,
            str(temp_directory),
            probe.filesystem_free_bytes,
            temp_directory,
        )
        if temp_directory is not None
        else None
    )
    artifact = (
        _safe_call(
            reasons,
            str(artifact_path),
            probe.filesystem_free_bytes,
            artifact_path,
        )
        if artifact_path is not None
        else None
    )

    return ResourceSnapshot(
        cpu_count=effective_cpu_count(
            host_cpus,
            affinity_cpus,
            cpuset,
            cpu_max,
        ),
        memory_bytes=available_memory,
        file_descriptors=file_descriptors,
        sockets=file_descriptors,
        processes=processes,
        shared_memory_bytes=shared_memory,
        temp_bytes=temporary,
        artifact_bytes=artifact,
        file_descriptors_used=open_files,
        sockets_used=open_sockets,
        processes_used=pids_current or 0,
        reasons=tuple(reasons),
    )


def _capacity_for(snapshot, request, *, reserve=None):
    reserve = reserve or ResourceRequest()
    capacity = None
    for request_name, snapshot_name in _SNAPSHOT_FIELDS.items():
        per_worker = getattr(request, request_name)
        if per_worker == 0:
            continue
        available = getattr(snapshot, snapshot_name)
        if available is None:
            continue
        remaining = available - getattr(reserve, request_name)
        dimension_capacity = max(0, remaining // per_worker)
        capacity = dimension_capacity if capacity is None else min(capacity, dimension_capacity)
    return capacity


def _insufficient_dimensions(snapshot, request):
    reasons = []
    for request_name, snapshot_name in _SNAPSHOT_FIELDS.items():
        available = getattr(snapshot, snapshot_name)
        needed = getattr(request, request_name)
        if available is not None and available < needed:
            reasons.append(
                {
                    "cpu": "cpu",
                    "memory_bytes": "memory",
                    "file_descriptors": "file_descriptors",
                    "sockets": "sockets",
                    "processes": "processes",
                    "temp_bytes": "temp",
                }[request_name]
            )
    return reasons


def _selected_count(requested, snapshot, request, *, reserve=None):
    if requested == 0:
        return 0
    capacity = _capacity_for(snapshot, request, reserve=reserve)
    return requested if capacity is None else min(requested, capacity)


def autosize(
    snapshot,
    profile=DEFAULT_RESOURCE_PROFILE,
    *,
    requested=None,
    artifact_required_bytes=0,
):
    if not isinstance(snapshot, ResourceSnapshot):
        raise TypeError("snapshot must be a ResourceSnapshot")
    if not isinstance(profile, ResourceProfile):
        raise TypeError("profile must be a ResourceProfile")
    requested = requested or WorkerCounts(
        discovery=max(1, snapshot.cpu_count * 4),
        static=snapshot.cpu_count,
        browser=max(1, snapshot.cpu_count),
    )
    if not isinstance(requested, WorkerCounts):
        raise TypeError("requested must be WorkerCounts")
    _require_nonnegative_integer("artifact_required_bytes", artifact_required_bytes)

    minimum = ResourceRequest()
    if requested.discovery:
        minimum += profile.discovery_worker
    if requested.static:
        minimum += profile.static_worker
    if requested.browser:
        minimum += profile.browser_active_page
        minimum += profile.browser_replacement

    insufficiency_reasons = _insufficient_dimensions(snapshot, minimum)
    if artifact_required_bytes and snapshot.artifact_bytes is not None:
        artifact_reserve = (snapshot.artifact_bytes + 4) // 5 + GIB
        artifact_usable = max(0, snapshot.artifact_bytes - artifact_reserve)
        if artifact_required_bytes > artifact_usable:
            insufficiency_reasons.append("artifact_disk")

    if insufficiency_reasons:
        return ResourcePlan(
            snapshot=snapshot,
            profile=profile,
            requested=requested,
            selected=WorkerCounts(0, 0, 0),
            insufficiency_reasons=tuple(dict.fromkeys(insufficiency_reasons)),
        )

    selected = WorkerCounts(
        discovery=_selected_count(
            requested.discovery,
            snapshot,
            profile.discovery_worker,
        ),
        static=_selected_count(
            requested.static,
            snapshot,
            profile.static_worker,
        ),
        browser=_selected_count(
            requested.browser,
            snapshot,
            profile.browser_active_page,
            reserve=profile.browser_replacement,
        ),
    )
    return ResourcePlan(
        snapshot=snapshot,
        profile=profile,
        requested=requested,
        selected=selected,
    )


class ResourceLease:
    def __init__(self, broker, request):
        self._broker = broker
        self.request = request
        self._active = True
        self._lock = threading.Lock()

    @property
    def active(self):
        with self._lock:
            return self._active

    def release(self):
        with self._lock:
            if not self._active:
                return
            self._active = False
        self._broker._release(self.request)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.release()


@dataclass
class _Waiter:
    request: ResourceRequest
    cancel_event: Optional[object] = None
    marker: object = field(default_factory=object)


class ResourceBroker:
    def __init__(self, capacity):
        if not isinstance(capacity, ResourceRequest):
            raise TypeError("capacity must be a ResourceRequest")
        self._capacity = capacity
        self._in_use = ResourceRequest()
        self._condition = threading.Condition(threading.RLock())
        self._waiters = []

    @property
    def capacity(self):
        with self._condition:
            return self._capacity

    @property
    def in_use(self):
        with self._condition:
            return self._in_use

    @property
    def available(self):
        with self._condition:
            return self._capacity - self._in_use

    @property
    def waiting_count(self):
        with self._condition:
            return len(self._waiters)

    def _validate_request(self, request):
        if not isinstance(request, ResourceRequest):
            raise TypeError("request must be a ResourceRequest")
        if not request.fits_within(self._capacity):
            raise ValueError("request exceeds broker capacity")

    def try_acquire(self, request):
        with self._condition:
            self._validate_request(request)
            if self._waiters or not request.fits_within(self._capacity - self._in_use):
                return None
            self._in_use += request
            return ResourceLease(self, request)

    def acquire(self, request, *, cancel_event=None):
        with self._condition:
            self._validate_request(request)
            waiter = _Waiter(request=request, cancel_event=cancel_event)
            self._waiters.append(waiter)
            try:
                while True:
                    if cancel_event is not None and cancel_event.is_set():
                        raise CancelledError()
                    is_first = self._waiters[0] is waiter
                    available = self._capacity - self._in_use
                    if is_first and request.fits_within(available):
                        self._waiters.pop(0)
                        self._in_use += request
                        self._condition.notify_all()
                        return ResourceLease(self, request)
                    self._condition.wait(timeout=0.05 if cancel_event is not None else None)
            except BaseException:
                if waiter in self._waiters:
                    self._waiters.remove(waiter)
                    self._condition.notify_all()
                raise

    def _release(self, request):
        with self._condition:
            if not request.fits_within(self._in_use):
                raise RuntimeError("resource lease accounting underflow")
            self._in_use -= request
            self._condition.notify_all()

    def adapt_capacity(self, capacity):
        if not isinstance(capacity, ResourceRequest):
            raise TypeError("capacity must be a ResourceRequest")
        with self._condition:
            if self._in_use != ResourceRequest() or self._waiters:
                return False
            self._capacity = capacity
            self._condition.notify_all()
            return True
