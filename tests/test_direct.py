import asyncio
import hashlib
import json
import os
import subprocess
from types import SimpleNamespace

import pytest

import wappalyzer.direct as direct_module
from wappalyzer.direct import (
    _regular_file_sha256,
    _runtime_identity,
    build_run_spec,
    default_output_root,
    run_direct_scan,
)
from wappalyzer.models import (
    Endpoint,
    Protocol,
    ProtocolResult,
    ProtocolStatus,
    RunStatus,
    TLSMetadata,
    TLSTrust,
)
from wappalyzer.runstore import GenerationRepository, RunStore


def success_empty(endpoint):
    results = []
    for protocol in Protocol:
        url = f"{protocol.value}://{endpoint.authority}/"
        results.append(
            ProtocolResult(
                protocol=protocol,
                status=ProtocolStatus.SUCCESS_EMPTY,
                requested_url=url,
                effective_url=url,
                http_status=200,
                tls=TLSMetadata(
                    present=protocol is Protocol.HTTPS,
                    trust=(
                        TLSTrust.TRUSTED if protocol is Protocol.HTTPS else TLSTrust.NOT_APPLICABLE
                    ),
                ),
            )
        )
    return tuple(results)


class FakeRuntime:
    instances = []

    def __init__(self, **_kwargs):
        self.max_inflight = 2
        self.scanned = []
        self.closed = False
        self.__class__.instances.append(self)

    async def scan(self, endpoint):
        self.scanned.append(endpoint)
        return success_empty(endpoint)

    async def aclose(self):
        self.closed = True


def test_direct_helpers_hash_regular_files_and_choose_default_output(tmp_path, monkeypatch):
    source = tmp_path / "targets.txt"
    source.write_bytes(b"192.0.2.1:8080\n")

    byte_count, digest = _regular_file_sha256(source)

    assert byte_count == len(source.read_bytes())
    assert digest == hashlib.sha256(source.read_bytes()).hexdigest()
    assert default_output_root(source) == tmp_path / "targets.txt.wappalyzer-runs"

    class WithoutNoFollow:
        def __getattr__(self, name):
            if name == "O_NOFOLLOW":
                raise AttributeError(name)
            return getattr(os, name)

    monkeypatch.setattr(direct_module, "os", WithoutNoFollow())
    assert _regular_file_sha256(source) == (byte_count, digest)


def test_direct_hash_rejects_aliases_nonfiles_and_changed_identity(tmp_path, monkeypatch):
    source = tmp_path / "targets.txt"
    source.write_bytes(b"192.0.2.1:8080\n")
    alias = tmp_path / "alias.txt"
    alias.symlink_to(source)

    for unsafe in (alias, tmp_path):
        with pytest.raises(ValueError, match="unalias"):
            _regular_file_sha256(unsafe)

    class ChangedIdentityOS:
        def __init__(self):
            self.fstat_calls = 0
            self.closed = False

        def __getattr__(self, name):
            return getattr(os, name)

        def fstat(self, descriptor):
            self.fstat_calls += 1
            value = os.fstat(descriptor)
            if self.fstat_calls == 2:
                return SimpleNamespace(
                    st_dev=value.st_dev,
                    st_ino=value.st_ino,
                    st_size=value.st_size,
                    st_mtime_ns=value.st_mtime_ns + 1,
                    st_ctime_ns=value.st_ctime_ns,
                )
            return value

        def close(self, descriptor):
            self.closed = True
            os.close(descriptor)

    changed_os = ChangedIdentityOS()
    monkeypatch.setattr(direct_module, "os", changed_os)

    with pytest.raises(ValueError, match="changed"):
        _regular_file_sha256(source)
    assert changed_os.closed


def test_runtime_identity_reports_available_and_missing_dependencies(monkeypatch):
    monkeypatch.setattr(direct_module.platform, "python_version", lambda: "3.9.19")
    monkeypatch.setattr(direct_module.platform, "system", lambda: "TestOS")
    monkeypatch.setattr(direct_module.platform, "machine", lambda: "test-machine")
    monkeypatch.setattr(direct_module.importlib.metadata, "version", lambda _name: "1.2.3")
    monkeypatch.setattr(
        direct_module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout="Chromium 123\n"),
    )

    assert _runtime_identity() == (
        "python-3.9.19|playwright-1.2.3|Chromium 123|TestOS|test-machine"
    )

    def missing_playwright(_name):
        raise direct_module.importlib.metadata.PackageNotFoundError

    def missing_chromium(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("chromium", 5)

    monkeypatch.setattr(direct_module.importlib.metadata, "version", missing_playwright)
    monkeypatch.setattr(direct_module.subprocess, "run", missing_chromium)

    assert _runtime_identity() == (
        "python-3.9.19|playwright-missing|unavailable|TestOS|test-machine"
    )


def test_direct_run_accepts_only_target_file_and_publishes_complete_artifacts(tmp_path):
    FakeRuntime.instances = []
    source = tmp_path / "targets.txt"
    source.write_bytes(b"192.0.2.1:8080\n192.0.2.1:8080\nnot-an-endpoint\n[2001:db8::1]:8443\n")
    root = tmp_path / "runs"

    result = asyncio.run(
        run_direct_scan(
            source,
            output_root=root,
            runtime_factory=FakeRuntime,
        )
    )

    assert result.status is RunStatus.COMPLETE
    assert result.accepted_endpoints == 2
    assert result.canonical_path.is_file()
    assert result.manifest_path.is_file()
    assert len(FakeRuntime.instances) == 1
    runtime = FakeRuntime.instances[0]
    assert runtime.closed
    assert runtime.scanned == [
        Endpoint("192.0.2.1", 8080),
        Endpoint("2001:db8::1", 8443),
    ]
    documents = [
        json.loads(line) for line in result.canonical_path.read_text(encoding="utf-8").splitlines()
    ]
    assert [document["occurrence"]["sequence"] for document in documents] == [0, 1, 2, 3]
    assert documents[2]["status"] == "invalid_input"
    assert documents[0]["protocols"] == documents[1]["protocols"]

    with RunStore.open(result.generation_path) as store:
        assert store.status is RunStatus.COMPLETE
        assert store.counts.occurrences == 4
        assert store.counts.endpoint_work == 2


def test_direct_run_creates_new_immutable_generation_after_completion(tmp_path):
    source = tmp_path / "targets.txt"
    source.write_bytes(b"192.0.2.1:8080\n")
    root = tmp_path / "runs"

    first = asyncio.run(run_direct_scan(source, output_root=root, runtime_factory=FakeRuntime))
    second = asyncio.run(run_direct_scan(source, output_root=root, runtime_factory=FakeRuntime))

    assert first.generation_path != second.generation_path
    assert first.canonical_path.read_bytes() != second.canonical_path.read_bytes()
    assert first.canonical_path.exists()
    assert first.manifest_path.exists()


def test_direct_run_skips_runtime_when_input_has_no_endpoint_work(tmp_path):
    source = tmp_path / "targets.txt"
    source.write_bytes(b"not-an-endpoint\n")

    def forbidden_runtime(**_kwargs):
        raise AssertionError("runtime started without endpoint work")

    result = asyncio.run(
        run_direct_scan(
            source,
            output_root=tmp_path / "runs",
            runtime_factory=forbidden_runtime,
        )
    )

    document = json.loads(result.canonical_path.read_text(encoding="utf-8"))
    assert document["status"] == "invalid_input"
    assert result.status is RunStatus.COMPLETE


def test_direct_run_resumes_ingested_generation_without_duplicate_ingestion(tmp_path):
    source = tmp_path / "targets.txt"
    source.write_bytes(b"192.0.2.1:8080\n")
    root = tmp_path / "runs"
    repository = GenerationRepository(root)

    with repository.acquire(build_run_spec(source)) as generation:
        generation.store.ingest(source)
        generation_path = generation.path

    result = asyncio.run(
        run_direct_scan(
            source,
            output_root=root,
            runtime_factory=FakeRuntime,
        )
    )

    assert result.resumed
    assert result.generation_path == generation_path
    assert result.status is RunStatus.COMPLETE


def test_direct_run_cancellation_closes_runtime_and_resumes_endpoint_work(tmp_path):
    source = tmp_path / "targets.txt"
    source.write_bytes(b"192.0.2.1:8080\n")
    root = tmp_path / "runs"
    instances = []

    class CancellingRuntime(FakeRuntime):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            instances.append(self)

        async def scan(self, endpoint):
            self.scanned.append(endpoint)
            if len(instances) == 1:
                raise asyncio.CancelledError
            return success_empty(endpoint)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(
            run_direct_scan(
                source,
                output_root=root,
                runtime_factory=CancellingRuntime,
            )
        )

    assert instances[0].closed
    with RunStore.open(next(root.glob("generation-*"))) as interrupted_store:
        assert interrupted_store.status is RunStatus.INTERRUPTED
        assert interrupted_store.counts.pending_endpoints == 1

    resumed = asyncio.run(
        run_direct_scan(
            source,
            output_root=root,
            runtime_factory=CancellingRuntime,
        )
    )

    assert resumed.resumed
    assert resumed.status is RunStatus.COMPLETE
    assert len(instances) == 2
    assert instances[1].closed
    assert instances[0].scanned == instances[1].scanned


def test_direct_run_resumes_after_manifest_was_recorded(tmp_path, monkeypatch):
    FakeRuntime.instances = []
    source = tmp_path / "targets.txt"
    source.write_bytes(b"192.0.2.1:8080\n")
    root = tmp_path / "runs"
    original_transition = RunStore.transition
    fail_complete_once = True

    def fail_after_manifest(self, next_status):
        nonlocal fail_complete_once
        if next_status is RunStatus.COMPLETE and fail_complete_once:
            fail_complete_once = False
            raise RuntimeError("crash after durable manifest")
        return original_transition(self, next_status)

    monkeypatch.setattr(RunStore, "transition", fail_after_manifest)
    with pytest.raises(RuntimeError, match="durable manifest"):
        asyncio.run(
            run_direct_scan(
                source,
                output_root=root,
                runtime_factory=FakeRuntime,
            )
        )

    generation_path = next(root.glob("generation-*"))
    with RunStore.open(generation_path) as publish_ready_store:
        assert publish_ready_store.status is RunStatus.PUBLISH_READY
        assert publish_ready_store.manifest_recorded

    monkeypatch.setattr(RunStore, "transition", original_transition)
    monkeypatch.setattr(
        direct_module,
        "publish_manifest",
        lambda _store: pytest.fail("recorded manifest was republished"),
    )
    resumed = asyncio.run(
        run_direct_scan(
            source,
            output_root=root,
            runtime_factory=FakeRuntime,
        )
    )

    assert resumed.resumed
    assert resumed.generation_path == generation_path
    assert resumed.status is RunStatus.COMPLETE
    assert len(FakeRuntime.instances) == 1
