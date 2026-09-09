import threading
import time
from concurrent.futures import CancelledError
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path

import pytest

from wappalyzer.models import RunSpec
from wappalyzer.resources import (
    UNBOUNDED_RESOURCE,
    ResourceBroker,
    ResourceProfile,
    ResourceRequest,
    ResourceSnapshot,
    SystemResourceProbe,
    WorkerCounts,
    _parse_controller_integer,
    _quota_cpu_count,
    _valid_cpu_max,
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


class FakeScandir:
    def __init__(self, paths):
        self._entries = [FakeDirectoryEntry(path) for path in paths]

    def __enter__(self):
        return iter(self._entries)

    def __exit__(self, exc_type, exc, traceback):
        return None


class FakeDirectoryEntry:
    def __init__(self, path):
        self.path = path


class FakeStatvfs:
    f_bavail = 7
    f_frsize = 4096


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


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        ("not-a-number 100000", None),
        ("100000 not-a-number", None),
        ("0 100000", None),
        ("100000 -1", None),
        ("99999 100000", 1),
    ],
)
def test_cpu_quota_parser_rejects_missing_malformed_and_nonpositive_values(value, expected):
    assert _quota_cpu_count(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, False),
        ("max nope", False),
        ("max 0", False),
        ("quota 100000", False),
        ("100000", False),
        ("100000 100000 extra", False),
        ("max 100000", True),
        ("100000 100000", True),
    ],
)
def test_cpu_max_validation_requires_a_positive_period_and_valid_quota(value, expected):
    assert _valid_cpu_max(value) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        ("", None),
        ("max", None),
        ("-1", None),
        ("broken", None),
        ("0", 0),
        ("42", 42),
    ],
)
def test_controller_integer_parser_accepts_only_nonnegative_finite_values(value, expected):
    assert _parse_controller_integer(value) == expected


@pytest.mark.parametrize("value", [None, "0,,2", "1-2-3", "-1", "1-two"])
def test_cpu_set_parser_rejects_missing_empty_and_ambiguous_intervals(value):
    assert parse_cpu_set(value) is None


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


def test_effective_memory_rejects_mismatched_or_malformed_controller_pairs():
    assert effective_available_memory(None, ("1024",), ()) is None
    assert effective_available_memory(None, ("1024",), ("broken",)) is None
    assert effective_available_memory(None, ("max",), ("ignored",)) is None
    assert effective_available_memory(True, (), ()) is None
    assert effective_available_memory(-1, (), ()) is None


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


def test_snapshot_records_each_malformed_controller_and_clamps_exhausted_nofile():
    snapshot = capture_snapshot(
        FakeProbe(
            nofile_limit=10,
            open_files=20,
            files={
                "/sys/fs/cgroup/cpuset.cpus.effective": "0,,2",
                "/sys/fs/cgroup/cpu.max": "max nope",
                "/sys/fs/cgroup/memory.max": "100",
                "/sys/fs/cgroup/memory.current": "broken",
                "/sys/fs/cgroup/pids.max": "broken",
                "/sys/fs/cgroup/pids.current": "3",
            },
        )
    )

    assert snapshot.cpu_count == 1
    assert snapshot.memory_bytes is None
    assert snapshot.file_descriptors == 0
    assert snapshot.processes is None
    assert snapshot.processes_used == 3
    assert "cpuset.cpus.effective" in " ".join(snapshot.reasons)
    assert "cpu.max" in " ".join(snapshot.reasons)
    assert "memory.current" in " ".join(snapshot.reasons)
    assert "pids.max" in " ".join(snapshot.reasons)


def test_snapshot_handles_fully_missing_memory_and_process_limits():
    snapshot = capture_snapshot(
        FakeProbe(
            host_memory=2 * GIB,
            files={
                "/sys/fs/cgroup/memory.max": None,
                "/sys/fs/cgroup/memory.current": None,
                "/sys/fs/cgroup/pids.max": None,
                "/sys/fs/cgroup/pids.current": None,
            },
        )
    )

    assert snapshot.memory_bytes == 1536 * MIB
    assert snapshot.processes is None
    assert snapshot.processes_used == 0
    assert "/sys/fs/cgroup/memory.max" in " ".join(snapshot.reasons)
    assert "/sys/fs/cgroup/pids.max" in " ".join(snapshot.reasons)


def test_snapshot_survives_platform_and_controller_probe_failures():
    class UnavailableProbe(FakeProbe):
        def host_cpu_count(self):
            raise OSError("cpu")

        def affinity_cpu_count(self):
            raise ValueError("affinity")

        def host_available_memory_bytes(self):
            raise OSError("memory")

        def controller_values(self, name):
            raise ValueError(name)

        def controller_pairs(self, maximum, current):
            raise OSError(maximum)

        def open_file_descriptor_count(self):
            raise OSError("files")

        def open_socket_count(self):
            raise ValueError("sockets")

        def nofile_soft_limit(self):
            raise OSError("nofile")

        def temp_directory(self):
            raise ValueError("temp")

        def filesystem_free_bytes(self, path):
            raise OSError(path)

    snapshot = capture_snapshot(UnavailableProbe(), artifact_path=Path("/artifacts"))

    assert snapshot == ResourceSnapshot(
        cpu_count=1,
        memory_bytes=None,
        file_descriptors=None,
        sockets=None,
        processes=None,
        shared_memory_bytes=None,
        temp_bytes=None,
        artifact_bytes=None,
        reasons=snapshot.reasons,
    )
    assert {
        "host CPU count: OSError",
        "CPU affinity: ValueError",
        "host available memory: OSError",
        "open file descriptors: OSError",
        "open sockets: ValueError",
        "RLIMIT_NOFILE: OSError",
        "temporary directory: ValueError",
    }.issubset(snapshot.reasons)
    assert "/sys/fs/cgroup/cpu.max: unavailable" in snapshot.reasons
    assert "/sys/fs/cgroup/memory.max: unavailable" in snapshot.reasons


def test_system_probe_platform_methods_and_fallbacks(tmp_path, monkeypatch):
    probe = SystemResourceProbe()
    text_path = tmp_path / "value"
    text_path.write_text(" value \n", encoding="utf-8")

    monkeypatch.setattr("wappalyzer.resources.os.cpu_count", lambda: 7)
    monkeypatch.setattr("wappalyzer.resources.os.sched_getaffinity", lambda _pid: {0, 2, 4})
    monkeypatch.setattr(
        "wappalyzer.resources.os.sysconf",
        lambda name: {"SC_AVPHYS_PAGES": 11, "SC_PAGE_SIZE": 4096}[name],
    )
    monkeypatch.setattr("wappalyzer.resources.resource.getrlimit", lambda _kind: (123, 456))
    monkeypatch.setattr(
        "wappalyzer.resources.os.scandir",
        lambda _path: FakeScandir(("/proc/self/fd/1", "/proc/self/fd/2")),
    )
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    monkeypatch.setattr("wappalyzer.resources.os.statvfs", lambda _path: FakeStatvfs())

    assert probe.host_cpu_count() == 7
    assert probe.affinity_cpu_count() == 3
    assert probe.host_available_memory_bytes() == 11 * 4096
    assert probe.nofile_soft_limit() == 123
    assert probe.open_file_descriptor_count() == 2
    assert probe.temp_directory() == tmp_path
    assert probe.read_text(text_path) == "value"
    assert probe.filesystem_free_bytes(tmp_path) == 7 * 4096

    def unavailable(*_args):
        raise OSError("unavailable")

    monkeypatch.setattr("wappalyzer.resources.os.sched_getaffinity", unavailable)
    monkeypatch.setattr("wappalyzer.resources.os.sysconf", unavailable)
    monkeypatch.setattr("wappalyzer.resources.resource.getrlimit", unavailable)
    monkeypatch.setattr("wappalyzer.resources.os.scandir", unavailable)

    assert probe.affinity_cpu_count() is None
    assert probe.host_available_memory_bytes() is None
    assert probe.nofile_soft_limit() is None
    assert probe.open_file_descriptor_count() == 0
    assert probe.open_socket_count() == 0

    monkeypatch.setattr(
        "wappalyzer.resources.resource.getrlimit",
        lambda _kind: ("infinity", "infinity"),
    )
    monkeypatch.setattr("wappalyzer.resources.resource.RLIM_INFINITY", "infinity")
    assert probe.nofile_soft_limit() is None


def test_system_probe_counts_only_readable_socket_descriptors(monkeypatch):
    probe = SystemResourceProbe()
    targets = {
        "/proc/self/fd/1": "socket:[10]",
        "/proc/self/fd/2": "/tmp/file",
    }

    def readlink(path):
        if path == "/proc/self/fd/3":
            raise OSError("descriptor closed")
        return targets[path]

    monkeypatch.setattr(
        "wappalyzer.resources.os.scandir",
        lambda _path: FakeScandir(
            ("/proc/self/fd/1", "/proc/self/fd/2", "/proc/self/fd/3")
        ),
    )
    monkeypatch.setattr("wappalyzer.resources.os.readlink", readlink)

    assert probe.open_socket_count() == 1


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


def test_system_probe_supports_hybrid_cgroups_and_mount_namespace_roots(tmp_path):
    unified_root = tmp_path / "unified"
    unified_leaf = unified_root / "service"
    unified_leaf.mkdir(parents=True)
    (unified_leaf / "cpu.max").write_text("200000 100000", encoding="utf-8")

    memory_mount = tmp_path / "memory"
    memory_leaf = memory_mount / "tenant"
    memory_leaf.mkdir(parents=True)
    (memory_leaf / "memory.limit_in_bytes").write_text(str(2 * GIB), encoding="utf-8")
    (memory_leaf / "memory.usage_in_bytes").write_text(str(GIB), encoding="utf-8")

    pids_mount = tmp_path / "pids"
    pids_mount.mkdir()
    (pids_mount / "pids.max").write_text("9", encoding="utf-8")
    (pids_mount / "pids.current").write_text("2", encoding="utf-8")

    proc_cgroup = tmp_path / "self.cgroup"
    proc_cgroup.write_text(
        "\n".join(
            (
                "0::/service",
                "4:memory:/namespace/tenant",
                "5:pids:/outside-mount-root",
            )
        ),
        encoding="utf-8",
    )
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(
        "\n".join(
            (
                f"30 23 0:30 /namespace {memory_mount} rw - cgroup cgroup rw,memory",
                f"31 23 0:31 /different-root {pids_mount} rw - cgroup cgroup rw,pids",
            )
        ),
        encoding="utf-8",
    )

    probe = SystemResourceProbe(
        cgroup_root=unified_root,
        proc_cgroup_path=proc_cgroup,
        proc_mountinfo_path=mountinfo,
    )

    assert probe.controller_values("cpu.max") == ("200000 100000",)
    assert probe.controller_pairs("memory.max", "memory.current") == (
        (str(2 * GIB), str(GIB)),
    )
    assert probe.controller_pairs("pids.max", "pids.current") == (("9", "2"),)


def test_system_probe_handles_missing_malformed_and_escaping_cgroup_metadata(tmp_path):
    cgroup_root = tmp_path / "cgroup"
    cgroup_root.mkdir()
    (cgroup_root / "cpu.max").write_text("100000 100000", encoding="utf-8")
    (cgroup_root / "io.max").write_text("8:0 rbps=1024", encoding="utf-8")

    proc_cgroup = tmp_path / "self.cgroup"
    proc_cgroup.write_text("malformed\n0::/../../outside\n", encoding="utf-8")
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(
        "\n".join(
            (
                "malformed mount line",
                "1 2 0:1 / /mnt rw -",
                "1 2 0:1 / /mnt rw - tmpfs tmpfs rw",
            )
        ),
        encoding="utf-8",
    )
    probe = SystemResourceProbe(
        cgroup_root=cgroup_root,
        proc_cgroup_path=proc_cgroup,
        proc_mountinfo_path=mountinfo,
    )

    assert probe.controller_values("cpu.max") == ("100000 100000",)
    assert probe.controller_values("io.max") == ("8:0 rbps=1024",)
    assert SystemResourceProbe._mountinfo_path(r"a\040b\011c\134d") == "a b\tc\\d"

    missing_probe = SystemResourceProbe(
        cgroup_root=cgroup_root,
        proc_cgroup_path=tmp_path / "missing-cgroup",
        proc_mountinfo_path=tmp_path / "missing-mountinfo",
    )
    assert missing_probe.controller_values("cpu.max") == ("100000 100000",)


def test_system_probe_normalizes_v1_unlimited_memory_and_missing_files(tmp_path):
    cpu_mount = tmp_path / "cpu"
    cpu_leaf = cpu_mount / "scanner"
    cpu_leaf.mkdir(parents=True)
    (cpu_leaf / "cpu.cfs_quota_us").write_text("100000", encoding="utf-8")

    memory_mount = tmp_path / "memory"
    memory_leaf = memory_mount / "scanner"
    memory_leaf.mkdir(parents=True)
    (memory_leaf / "memory.limit_in_bytes").write_text("-1", encoding="utf-8")
    (memory_mount / "memory.limit_in_bytes").write_text(str(1 << 60), encoding="utf-8")
    (memory_mount / "memory.usage_in_bytes").write_text("1", encoding="utf-8")

    proc_cgroup = tmp_path / "self.cgroup"
    proc_cgroup.write_text("2:cpu:/scanner\n4:memory:/scanner\n", encoding="utf-8")
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(
        "\n".join(
            (
                f"30 23 0:30 / {cpu_mount} rw - cgroup cgroup rw,cpu",
                f"31 23 0:31 / {memory_mount} rw - cgroup cgroup rw,memory",
            )
        ),
        encoding="utf-8",
    )
    probe = SystemResourceProbe(
        cgroup_root=tmp_path / "unused",
        proc_cgroup_path=proc_cgroup,
        proc_mountinfo_path=mountinfo,
    )

    assert probe.controller_values("cpu.max") == ()
    assert probe.controller_pairs("memory.max", "memory.current") == (
        ("max", None),
        ("max", "1"),
    )
    assert probe.controller_pairs("pids.max", "pids.current") == ()


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


def test_resource_value_objects_enforce_types_arithmetic_and_unbounded_capacity():
    request = ResourceRequest(cpu=1)
    assert request.__add__(object()) is NotImplemented
    assert request.__sub__(object()) is NotImplemented
    with pytest.raises(ValueError, match="negative"):
        ResourceRequest().__sub__(request)
    with pytest.raises(ValueError, match="cpu"):
        ResourceRequest(cpu=True)
    with pytest.raises(ValueError, match="static"):
        WorkerCounts(discovery=1, static="1", browser=1)
    with pytest.raises(ValueError, match="at least one"):
        replace(resource_snapshot(), cpu_count=0)
    with pytest.raises(ValueError, match="memory_bytes"):
        replace(resource_snapshot(), memory_bytes=True)
    with pytest.raises(TypeError, match="browser_replacement"):
        replace(resource_profile(), browser_replacement=object())

    snapshot = resource_snapshot(
        memory_bytes=None,
        file_descriptors=None,
        sockets=None,
        processes=None,
        temp_bytes=None,
        reasons=["limits unavailable"],
    )
    assert snapshot.reasons == ("limits unavailable",)
    assert snapshot.broker_capacity() == ResourceRequest(
        cpu=4,
        memory_bytes=UNBOUNDED_RESOURCE,
        file_descriptors=UNBOUNDED_RESOURCE,
        sockets=UNBOUNDED_RESOURCE,
        processes=UNBOUNDED_RESOURCE,
        temp_bytes=UNBOUNDED_RESOURCE,
    )


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


def test_autosize_defaults_zero_workers_and_unknown_artifact_capacity():
    profile = resource_profile()
    defaulted = autosize(resource_snapshot(), profile)
    assert defaulted.requested == WorkerCounts(discovery=16, static=4, browser=4)
    assert defaulted.can_run
    assert selected_resource_request(defaulted.selected, profile).fits_within(
        defaulted.snapshot.broker_capacity()
    )

    zero = autosize(
        resource_snapshot(artifact_bytes=None),
        profile,
        requested=WorkerCounts(0, 0, 0),
        artifact_required_bytes=100 * GIB,
    )
    assert zero.selected == WorkerCounts(0, 0, 0)
    assert zero.can_run
    assert selected_resource_request(zero.selected, profile) == ResourceRequest()


def test_autosize_handles_zero_cost_workers_and_cpu_minimum_failure():
    zero_request = ResourceRequest()
    zero_profile = ResourceProfile(
        discovery_worker=zero_request,
        static_worker=zero_request,
        browser_active_page=zero_request,
        browser_replacement=zero_request,
    )
    free_plan = autosize(
        resource_snapshot(),
        zero_profile,
        requested=WorkerCounts(discovery=3, static=0, browser=0),
    )
    assert free_plan.selected == WorkerCounts(discovery=3, static=0, browser=0)

    cpu_heavy = replace(
        resource_profile(),
        static_worker=replace(resource_profile().static_worker, cpu=5),
    )
    insufficient = autosize(
        resource_snapshot(cpu_count=4),
        cpu_heavy,
        requested=WorkerCounts(discovery=0, static=1, browser=0),
    )
    assert not insufficient.can_run
    assert insufficient.insufficiency_reasons == ("cpu",)


def test_resource_selection_autosize_and_broker_type_contracts():
    snapshot = resource_snapshot()
    profile = resource_profile()
    counts = WorkerCounts(1, 1, 0)

    assert selected_resource_request(counts, profile) == (
        profile.discovery_worker + profile.static_worker
    )
    with pytest.raises(TypeError, match="counts"):
        selected_resource_request(object(), profile)
    with pytest.raises(TypeError, match="profile"):
        selected_resource_request(counts, object())
    with pytest.raises(TypeError, match="snapshot"):
        autosize(object(), profile)
    with pytest.raises(TypeError, match="profile"):
        autosize(snapshot, object())
    with pytest.raises(TypeError, match="requested"):
        autosize(snapshot, profile, requested=object())
    with pytest.raises(ValueError, match="artifact_required_bytes"):
        autosize(snapshot, profile, artifact_required_bytes=True)
    with pytest.raises(TypeError, match="capacity"):
        ResourceBroker(object())


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


def test_capacity_adaptation_wakes_fifo_waiter_and_preserves_try_acquire_fairness():
    broker = ResourceBroker(ResourceRequest(cpu=1))
    held = broker.acquire(ResourceRequest(cpu=1))
    acquired = threading.Event()
    release = threading.Event()

    def wait_for_capacity():
        with broker.acquire(ResourceRequest(cpu=1)):
            acquired.set()
            release.wait()

    thread = threading.Thread(target=wait_for_capacity)
    thread.start()
    wait_until(lambda: broker.waiting_count == 1)

    assert broker.try_acquire(ResourceRequest()) is None
    assert broker.adapt_capacity(ResourceRequest(cpu=2)) is True
    assert acquired.wait(1)
    assert broker.in_use == ResourceRequest(cpu=2)

    release.set()
    thread.join(timeout=1)
    held.release()
    assert not thread.is_alive()
    assert broker.available == ResourceRequest(cpu=2)


def test_broker_rejects_invalid_requests_and_cleans_up_interrupted_waiters(monkeypatch):
    broker = ResourceBroker(ResourceRequest(cpu=1))
    with pytest.raises(TypeError, match="request"):
        broker.try_acquire(object())
    with pytest.raises(ValueError, match="exceeds"):
        broker.acquire(ResourceRequest(cpu=2))
    with pytest.raises(TypeError, match="capacity"):
        broker.adapt_capacity(object())
    with pytest.raises(RuntimeError, match="underflow"):
        broker._release(ResourceRequest(cpu=1))

    held = broker.acquire(ResourceRequest(cpu=1))

    def interrupted_wait(*_args, **_kwargs):
        raise RuntimeError("interrupted")

    monkeypatch.setattr(broker._condition, "wait", interrupted_wait)
    with pytest.raises(RuntimeError, match="interrupted"):
        broker.acquire(ResourceRequest(cpu=1))

    assert broker.waiting_count == 0
    held.release()
    assert broker.available == ResourceRequest(cpu=1)


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
