import asyncio
import json

from wappalyzer.direct import run_direct_scan
from wappalyzer.models import (
    Endpoint,
    Protocol,
    ProtocolResult,
    ProtocolStatus,
    RunStatus,
    TLSMetadata,
    TLSTrust,
)
from wappalyzer.runstore import RunStore


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
