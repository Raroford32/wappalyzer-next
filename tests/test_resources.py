import threading
import time
from concurrent.futures import CancelledError
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path

import pytest

from wappalyzer.models import RunSpec
from wappalyzer.resources import (
    ResourceBroker,
    ResourceProfile,
    ResourceRequest,
    ResourceSnapshot,
    SystemResourceProbe,
    WorkerCounts,
    autosize,
    capture_snapshot,
    effective_available_memory,
    effective_cpu_count,
    parse_cpu_set,
    selected_resource_request,
)

MIB = 1024**2
GIB = 1024**3


class FakeProbe:
    def __init__(
        self,
        *,
        host_cpus=16,
        affinity_cpus=8,
        host_memory=8 * GIB,
        nofile_limit=1024,
        open_files=24,
        open_sockets=7,
        temp_directory="/tmp",
        files=None,
        free_space=None,
    ):
        self._host_cpus = host_cpus
        self._affinity_cpus = affinity_cpus
        self._host_memory = host_memory
        self._nofile_limit = nofile_limit
        self._open_files = open_files
        self._open_sockets = open_sockets
        self._temp_directory = Path(temp_directory)
        self._files = {
            "/sys/fs/cgroup/cpuset.cpus.effective": "0-5",
            "/sys/fs/cgroup/cpu.max": "250000 100000",
            "/sys/fs/cgroup/memory.max": str(6 * GIB),
            "/sys/fs/cgroup/memory.current": str(2 * GIB),
            "/sys/fs/cgroup/pids.max": "100",
            "/sys/fs/cgroup/pids.current": "10",
        }
        self._files.update(files or {})
        self._free_space = {
            "/dev/shm": 2 * GIB,
            "/tmp": 3 * GIB,
            "/artifacts": 20 * GIB,
        }
        self._free_space.update(free_space or {})

    def host_cpu_count(self):
        return self._host_cpus

    def affinity_cpu_count(self):
        return self._affinity_cpus

    def host_available_memory_bytes(self):
        return self._host_memory

    def nofile_soft_limit(self):
        return self._nofile_limit

    def open_file_descriptor_count(self):
        return self._open_files

    def open_socket_count(self):
        return self._open_sockets

    def temp_directory(self):
        return self._temp_directory

    def read_text(self, path):
        value = self._files.get(str(path))
        if value is None:
            raise FileNotFoundError(path)
        return value

    def filesystem_free_bytes(self, path):
        value = self._free_space.get(str(path))
        if value is None:
            raise FileNotFoundError(path)
        return value


def resource_snapshot(**changes):
    snapshot = ResourceSnapshot(
        cpu_count=4,
        memory_bytes=4 * GIB,
        file_descriptors=256,
        sockets=128,
        processes=64,
        shared_memory_bytes=2 * GIB,
        temp_bytes=2 * GIB,
        artifact_bytes=20 * GIB,
        file_descriptors_used=20,
        sockets_used=5,
        processes_used=10,
    )
    return replace(snapshot, **changes)


def resource_profile():
    return ResourceProfile(
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


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("0", 1),
        ("0-3", 4),
        ("0-3,8,10-11", 7),
        ("0-3,2-5", 6),
        (" 1, 3-4 ", 3),
        ("", None),
        ("0-", None),
        ("3-1", None),
        ("max", None),
    ],
)
def test_parse_cpu_set_ranges(value, expected):
    assert parse_cpu_set(value) == expected


def test_effective_cpu_is_the_minimum_positive_host_affinity_cpuset_and_quota():
    assert (
        effective_cpu_count(
            host_count=16,
            affinity_count=8,
            cpuset="0-5",
            cpu_max="250000 100000",
        )
        == 2
    )
    assert (
        effective_cpu_count(
            host_count=12,
            affinity_count=4,
            cpuset="",
            cpu_max="max 100000",
        )
        == 4
    )
    assert (
        effective_cpu_count(
            host_count=8,
            affinity_count=0,
            cpuset="malformed",
            cpu_max="malformed",
        )
        == 1
    )
    assert effective_cpu_count(8, 8, "0-7", "50000 100000") == 1
    assert effective_cpu_count(8, 8, "0-7", "100000 0") == 1
    assert effective_cpu_count(None, None, None, None) == 1


def test_effective_memory_uses_tightest_source_then_keeps_emergency_reserve():
    cgroup_limit = 6 * GIB
    cgroup_current = 2 * GIB
    assert (
        effective_available_memory(
            8 * GIB,
            str(cgroup_limit),
            str(cgroup_current),
        )
        == cgroup_limit - max((cgroup_limit + 4) // 5, 512 * MIB) - cgroup_current
    )

    assert effective_available_memory(2 * GIB, "max", "not-needed") == 1536 * MIB
    assert effective_available_memory(2 * GIB, "broken", "1") is None
    assert effective_available_memory(2 * GIB, str(GIB), str(2 * GIB)) == 0


def test_snapshot_captures_current_use_and_all_effective_budgets():
    snapshot = capture_snapshot(FakeProbe(), artifact_path=Path("/artifacts"))
    cgroup_limit = 6 * GIB
    cgroup_current = 2 * GIB

    assert snapshot == ResourceSnapshot(
        cpu_count=2,
        memory_bytes=(cgroup_limit - max((cgroup_limit + 4) // 5, 512 * MIB) - cgroup_current),
        file_descriptors=1000,
        sockets=1000,
        processes=90,
        shared_memory_bytes=2 * GIB,
        temp_bytes=3 * GIB,
        artifact_bytes=20 * GIB,
        file_descriptors_used=24,
        sockets_used=7,
        processes_used=10,
    )


def test_snapshot_falls_back_deterministically_for_missing_malformed_and_unlimited_data():
    probe = FakeProbe(
        host_cpus=12,
        affinity_cpus=4,
        host_memory=2 * GIB,
        nofile_limit=-1,
        files={
            "/sys/fs/cgroup/cpuset.cpus.effective": None,
            "/sys/fs/cgroup/cpu.max": "broken",
            "/sys/fs/cgroup/memory.max": "max",
            "/sys/fs/cgroup/memory.current": None,
            "/sys/fs/cgroup/pids.max": "max",
            "/sys/fs/cgroup/pids.current": "broken",
        },
        free_space={"/dev/shm": None},
    )

    snapshot = capture_snapshot(probe, artifact_path=Path("/artifacts"))

    assert snapshot.cpu_count == 1
    assert snapshot.memory_bytes == 1536 * MIB
    assert snapshot.file_descriptors is None
    assert snapshot.sockets is None
    assert snapshot.processes is None
    assert snapshot.shared_memory_bytes is None
    assert snapshot.temp_bytes == 3 * GIB
    assert snapshot.artifact_bytes == 20 * GIB
    assert "cpu.max" in " ".join(snapshot.reasons)
    assert "cpuset.cpus.effective" in " ".join(snapshot.reasons)
    assert "/dev/shm" in " ".join(snapshot.reasons)


def test_snapshot_records_malformed_finite_memory_and_process_controllers():
    probe = FakeProbe(
        host_memory=2 * GIB,
        files={
            "/sys/fs/cgroup/memory.max": "broken",
            "/sys/fs/cgroup/memory.current": "1",
            "/sys/fs/cgroup/pids.max": "100",
            "/sys/fs/cgroup/pids.current": "broken",
        },
    )

    snapshot = capture_snapshot(probe, artifact_path=Path("/artifacts"))

    assert snapshot.memory_bytes is None
    assert snapshot.processes is None
    assert "memory.max" in " ".join(snapshot.reasons)
    assert "pids.current" in " ".join(snapshot.reasons)


def test_system_probe_resolves_current_cgroup_and_all_ancestors(tmp_path):
    cgroup_root = tmp_path / "cgroup"
    leaf = cgroup_root / "system.slice" / "scanner.service"
    leaf.mkdir(parents=True)
    (leaf / "cpu.max").write_text("max 100000", encoding="utf-8")
    (leaf.parent / "cpu.max").write_text("150000 100000", encoding="utf-8")
    proc_cgroup = tmp_path / "self.cgroup"
    proc_cgroup.write_text("0::/system.slice/scanner.service\n", encoding="utf-8")

    probe = SystemResourceProbe(
        cgroup_root=cgroup_root,
        proc_cgroup_path=proc_cgroup,
    )

    assert probe.controller_values("cpu.max") == (
        "max 100000",
        "150000 100000",
    )


def test_system_probe_supports_cgroup_v1_controller_mounts(tmp_path):
    mounts = {}
    mount_lines = []
    for index, controller in enumerate(("cpu", "cpuset", "memory", "pids"), 30):
        mount = tmp_path / controller
        leaf = mount / "scanner"
        leaf.mkdir(parents=True)
        mounts[controller] = leaf
        options = "cpu,cpuacct" if controller == "cpu" else controller
        mount_lines.append(f"{index} 23 0:{index} / {mount} rw - cgroup cgroup rw,{options}")

    (mounts["cpu"] / "cpu.cfs_quota_us").write_text("150000", encoding="utf-8")
    (mounts["cpu"] / "cpu.cfs_period_us").write_text("100000", encoding="utf-8")
    (mounts["cpuset"] / "cpuset.cpus").write_text("0-3", encoding="utf-8")
    (mounts["memory"] / "memory.limit_in_bytes").write_text(
        str(3 * GIB),
        encoding="utf-8",
    )
    (mounts["memory"] / "memory.usage_in_bytes").write_text(
        str(GIB),
        encoding="utf-8",
    )
    (mounts["pids"] / "pids.max").write_text("20", encoding="utf-8")
    (mounts["pids"] / "pids.current").write_text("5", encoding="utf-8")
    proc_cgroup = tmp_path / "self.cgroup"
    proc_cgroup.write_text(
        "\n".join(
            (
                "2:cpu,cpuacct:/scanner",
                "3:cpuset:/scanner",
                "4:memory:/scanner",
                "5:pids:/scanner",
            )
        ),
        encoding="utf-8",
    )
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text("\n".join(mount_lines), encoding="utf-8")

    probe = SystemResourceProbe(
        cgroup_root=tmp_path / "unused-v2",
        proc_cgroup_path=proc_cgroup,
        proc_mountinfo_path=mountinfo,
    )

    assert probe.controller_values("cpu.max") == ("150000 100000",)
    assert probe.controller_values("cpuset.cpus.effective") == ("0-3",)
    assert probe.controller_pairs("memory.max", "memory.current") == ((str(3 * GIB), str(GIB)),)
    assert probe.controller_pairs("pids.max", "pids.current") == (("20", "5"),)


def test_snapshot_uses_tightest_limits_across_cgroup_ancestors():
    class HierarchyProbe(FakeProbe):
        def controller_values(self, name):
            return {
                "cpuset.cpus.effective": ("0-7",),
                "cpu.max": ("max 100000", "150000 100000"),
            }.get(name, ())

        def controller_pairs(self, maximum, current):
            return {
                ("memory.max", "memory.current"): (
                    ("max", str(GIB)),
                    (str(3 * GIB), str(GIB)),
                ),
                ("pids.max", "pids.current"): (
                    ("max", "10"),
                    ("20", "5"),
                ),
            }.get((maximum, current), ())

    snapshot = capture_snapshot(HierarchyProbe(), artifact_path=Path("/artifacts"))

    assert snapshot.cpu_count == 1
    assert snapshot.memory_bytes == 7 * GIB // 5
    assert snapshot.processes == 15
    assert snapshot.processes_used == 10


def test_requests_snapshots_and_plans_are_immutable_nonnegative_vectors():
    request = ResourceRequest(
        cpu=1,
        memory_bytes=2,
        file_descriptors=3,
        sockets=4,
        processes=5,
        temp_bytes=6,
    )
    snapshot = resource_snapshot()
    plan = autosize(
        snapshot,
        resource_profile(),
        requested=WorkerCounts(discovery=2, static=2, browser=2),
    )

    assert request == ResourceRequest(1, 2, 3, 4, 5, 6)
    with pytest.raises(FrozenInstanceError):
        request.cpu = 2
    with pytest.raises(FrozenInstanceError):
        snapshot.cpu_count = 8
    with pytest.raises(FrozenInstanceError):
        plan.selected = WorkerCounts(1, 1, 1)
    with pytest.raises(ValueError):
        ResourceRequest(cpu=-1)
    with pytest.raises(ValueError):
        WorkerCounts(discovery=-1, static=1, browser=1)


def test_autosize_limits_static_by_cpu_and_browser_by_active_page_plus_replacement():
    snapshot = resource_snapshot()
    requested = WorkerCounts(discovery=20, static=20, browser=20)
    plan = autosize(
        snapshot,
        resource_profile(),
        requested=requested,
        artifact_required_bytes=8 * GIB,
    )

    assert plan.snapshot is snapshot
    assert plan.requested == requested
    assert plan.selected == WorkerCounts(discovery=2, static=3, browser=6)
    assert plan.insufficiency_reasons == ()
    assert selected_resource_request(plan.selected, plan.profile).fits_within(
        snapshot.broker_capacity()
    )


def test_browser_active_page_growth_contracts_only_browser_capacity():
    profile = resource_profile()
    requested = WorkerCounts(discovery=20, static=20, browser=20)
    baseline = autosize(resource_snapshot(), profile, requested=requested)
    grown_page = replace(
        profile,
        browser_active_page=replace(
            profile.browser_active_page,
            memory_bytes=GIB,
        ),
    )
    adapted = autosize(resource_snapshot(), grown_page, requested=requested)

    assert baseline.selected == WorkerCounts(discovery=2, static=3, browser=6)
    assert adapted.selected == WorkerCounts(discovery=2, static=3, browser=3)
    assert adapted.selected.browser < baseline.selected.browser


def test_missing_shared_memory_mount_uses_the_explicit_temp_budget():
    plan = autosize(
        resource_snapshot(shared_memory_bytes=None),
        resource_profile(),
        requested=WorkerCounts(discovery=1, static=1, browser=2),
    )

    assert plan.selected == WorkerCounts(discovery=1, static=1, browser=2)


def test_unknown_memory_conservatively_selects_one_browser_worker():
    plan = autosize(
        resource_snapshot(memory_bytes=None),
        resource_profile(),
        requested=WorkerCounts(discovery=20, static=20, browser=20),
    )

    assert plan.selected == WorkerCounts(discovery=1, static=1, browser=1)


@pytest.mark.parametrize(
    ("snapshot_change", "expected_reason"),
    [
        ({"memory_bytes": 1216 * MIB - 1}, "memory"),
        ({"file_descriptors": 59}, "file_descriptors"),
        ({"sockets": 23}, "sockets"),
        ({"processes": 8}, "processes"),
        ({"temp_bytes": 288 * MIB - 1}, "temp"),
    ],
)
def test_autosize_fails_closed_when_one_complete_worker_cannot_fit(
    snapshot_change,
    expected_reason,
):
    plan = autosize(
        resource_snapshot(**snapshot_change),
        resource_profile(),
        requested=WorkerCounts(discovery=4, static=4, browser=4),
    )

    assert plan.selected == WorkerCounts(discovery=0, static=0, browser=0)
    assert expected_reason in plan.insufficiency_reasons


def test_artifact_disk_preserves_twenty_percent_plus_one_gibibyte():
    artifact_free = 11 * GIB
    exact_usable = artifact_free - (artifact_free + 4) // 5 - GIB
    snapshot = resource_snapshot(artifact_bytes=artifact_free)
    requested = WorkerCounts(discovery=1, static=1, browser=1)

    fitting = autosize(
        snapshot,
        resource_profile(),
        requested=requested,
        artifact_required_bytes=exact_usable,
    )
    insufficient = autosize(
        snapshot,
        resource_profile(),
        requested=requested,
        artifact_required_bytes=exact_usable + 1,
    )

    assert fitting.selected == requested
    assert insufficient.selected == WorkerCounts(0, 0, 0)
    assert "artifact_disk" in insufficient.insufficiency_reasons


def test_broker_try_acquire_release_and_context_never_overcommit_or_go_negative():
    capacity = ResourceRequest(
        cpu=2,
        memory_bytes=200,
        file_descriptors=20,
        sockets=10,
        processes=4,
        temp_bytes=100,
    )
    request = ResourceRequest(
        cpu=1,
        memory_bytes=100,
        file_descriptors=10,
        sockets=5,
        processes=2,
        temp_bytes=50,
    )
    broker = ResourceBroker(capacity)

    first = broker.try_acquire(request)
    second = broker.try_acquire(request)
    assert first is not None
    assert second is not None
    assert broker.try_acquire(ResourceRequest(cpu=1)) is None
    assert broker.available == ResourceRequest()

    first.release()
    first.release()
    assert broker.available == request
    second.release()
    assert broker.available == capacity

    with pytest.raises(RuntimeError, match="body failed"):
        with broker.acquire(capacity) as lease:
            assert lease.active
            raise RuntimeError("body failed")

    assert not lease.active
    assert broker.available == capacity
    assert broker.in_use == ResourceRequest()


def test_broker_try_acquire_is_thread_safe_under_contention():
    broker = ResourceBroker(ResourceRequest(cpu=4))
    start = threading.Barrier(17)
    attempted = threading.Barrier(17)
    release = threading.Event()
    outcomes = []
    outcomes_lock = threading.Lock()

    def contend():
        start.wait()
        lease = broker.try_acquire(ResourceRequest(cpu=1))
        with outcomes_lock:
            outcomes.append(lease is not None)
        attempted.wait()
        release.wait()
        if lease is not None:
            lease.release()

    threads = [threading.Thread(target=contend) for _ in range(16)]
    for thread in threads:
        thread.start()

    start.wait()
    attempted.wait()
    assert outcomes.count(True) == 4
    assert outcomes.count(False) == 12
    assert broker.in_use == ResourceRequest(cpu=4)

    release.set()
    for thread in threads:
        thread.join(timeout=1)
        assert not thread.is_alive()
    assert broker.available == ResourceRequest(cpu=4)


def wait_until(predicate, timeout=1):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.005)
    pytest.fail("condition was not reached before timeout")


def test_blocking_acquire_is_fifo_and_waiting_acquisition_can_be_cancelled():
    broker = ResourceBroker(ResourceRequest(cpu=1))
    held = broker.acquire(ResourceRequest(cpu=1))
    acquisition_order = []
    first_acquired = threading.Event()
    release_first = threading.Event()

    def waiter(name, acquired=None, release_after=None):
        with broker.acquire(ResourceRequest(cpu=1)):
            acquisition_order.append(name)
            if acquired is not None:
                acquired.set()
            if release_after is not None:
                release_after.wait()

    first = threading.Thread(
        target=waiter,
        args=("first", first_acquired, release_first),
    )
    second = threading.Thread(target=waiter, args=("second",))
    first.start()
    wait_until(lambda: broker.waiting_count == 1)
    second.start()
    wait_until(lambda: broker.waiting_count == 2)

    held.release()
    assert first_acquired.wait(1)
    assert acquisition_order == ["first"]
    release_first.set()
    first.join(timeout=1)
    second.join(timeout=1)
    assert acquisition_order == ["first", "second"]

    held = broker.acquire(ResourceRequest(cpu=1))
    cancel_event = threading.Event()
    cancellation = []

    def cancelled_waiter():
        try:
            broker.acquire(ResourceRequest(cpu=1), cancel_event=cancel_event)
        except CancelledError:
            cancellation.append(True)

    cancelled = threading.Thread(target=cancelled_waiter)
    cancelled.start()
    wait_until(lambda: broker.waiting_count == 1)
    cancel_event.set()
    cancelled.join(timeout=1)
    held.release()

    assert cancellation == [True]
    assert broker.waiting_count == 0
    assert broker.available == ResourceRequest(cpu=1)


def test_capacity_adaptation_preserves_active_leases_and_blocks_until_below_target():
    initial = ResourceRequest(cpu=2, memory_bytes=200)
    expanded = ResourceRequest(cpu=4, memory_bytes=400)
    broker = ResourceBroker(initial)
    lease = broker.acquire(ResourceRequest(cpu=1, memory_bytes=100))

    contracted = ResourceRequest(cpu=0, memory_bytes=50)
    assert broker.adapt_capacity(contracted) is True
    assert broker.capacity == contracted
    assert lease.active
    assert broker.in_use == ResourceRequest(cpu=1, memory_bytes=100)
    assert broker.available == ResourceRequest()
    assert broker.try_acquire(ResourceRequest()) is None

    assert broker.adapt_capacity(expanded) is True
    assert broker.capacity == expanded
    lease.release()
    assert broker.available == expanded


def test_worker_counts_and_resource_adaptation_are_not_run_spec_semantics():
    semantic_fields = {field.name for field in fields(RunSpec)}
    operational_fields = {
        "cpu_count",
        "memory_bytes",
        "file_descriptors",
        "sockets",
        "processes",
        "temp_bytes",
        "discovery_workers",
        "static_workers",
        "browser_workers",
    }

    assert semantic_fields.isdisjoint(operational_fields)
