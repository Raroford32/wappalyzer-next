import hashlib
import importlib.metadata
import json
import os
import platform
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

from wappalyzer.core.config import data_dir, root_dir
from wappalyzer.engine import DirectScanRuntime
from wappalyzer.evidence_limits import EVIDENCE_LIMITS_SHA256
from wappalyzer.models import CANONICAL_SCHEMA_VERSION, RunSpec, RunStatus
from wappalyzer.output import CanonicalProjector, publish_manifest
from wappalyzer.pipeline import BoundedScanPipeline
from wappalyzer.resources import capture_snapshot
from wappalyzer.runstore import GenerationRepository, RunStateError

PARSER_VERSION = "endpoint-v1"
SERIALIZER_VERSION = "canonical-json-v1"
ENGINE_VERSION = "complete-v1"
REDIRECT_POLICY_VERSION = "redirect-v1"
TLS_POLICY_VERSION = "tls-scoped-v1"
RETRY_POLICY_VERSION = "retry-v1"
TIMEOUT_POLICY_VERSION = "independent-stage-v1"
ESTIMATED_ARTIFACT_BYTES_PER_OCCURRENCE = 4096
MINIMUM_ARTIFACT_BYTES = 64 * 1024 * 1024
_HASH_CHUNK_BYTES = 1024 * 1024


@dataclass(frozen=True)
class DirectRunResult:
    generation_path: Path
    canonical_path: Path
    manifest_path: Path
    status: RunStatus
    resumed: bool


def _regular_file_sha256(path):
    path = Path(path)
    value = path.lstat()
    if stat.S_ISLNK(value.st_mode) or not stat.S_ISREG(value.st_mode):
        raise ValueError("input must be an unaliased regular file")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(str(path), flags)
    try:
        before = os.fstat(descriptor)
        digest = hashlib.sha256()
        byte_count = 0
        while True:
            chunk = os.read(descriptor, _HASH_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
            byte_count += len(chunk)
        after = os.fstat(descriptor)
        current = path.stat()
    finally:
        os.close(descriptor)
    identities = {
        (
            item.st_dev,
            item.st_ino,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        for item in (before, after, current)
    }
    if len(identities) != 1:
        raise ValueError("input changed while its identity was computed")
    return byte_count, digest.hexdigest()


def _scanner_build_identity():
    digest = hashlib.sha256()
    package_root = Path(root_dir)
    files = sorted(package_root.rglob("*.py"))
    files.extend(sorted((package_root / "schemas").glob("*.json")))
    for path in files:
        relative = path.relative_to(package_root).as_posix().encode("utf-8")
        payload = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def _runtime_identity():
    try:
        playwright_version = importlib.metadata.version("playwright")
    except importlib.metadata.PackageNotFoundError:
        playwright_version = "missing"
    try:
        chromium = subprocess.run(
            ("chromium", "--version"),
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        chromium = "unavailable"
    return "|".join(
        (
            f"python-{platform.python_version()}",
            f"playwright-{playwright_version}",
            chromium,
            platform.system(),
            platform.machine(),
        )
    )


def build_run_spec(input_path):
    _byte_count, input_sha256 = _regular_file_sha256(input_path)
    lock = json.loads((Path(data_dir) / "fingerprints.lock.json").read_text(encoding="utf-8"))
    file_hashes = lock["files"]
    return RunSpec(
        input_sha256=input_sha256,
        parser_version=PARSER_VERSION,
        schema_version=CANONICAL_SCHEMA_VERSION,
        serializer_version=SERIALIZER_VERSION,
        engine_version=ENGINE_VERSION,
        redirect_policy_version=REDIRECT_POLICY_VERSION,
        tls_policy_version=TLS_POLICY_VERSION,
        retry_policy_version=RETRY_POLICY_VERSION,
        timeout_policy_version=TIMEOUT_POLICY_VERSION,
        evidence_limits_sha256=EVIDENCE_LIMITS_SHA256,
        fingerprint_sha256=file_hashes["technologies.json"],
        extension_sha256=file_hashes["wappalyzer-extension.zip"],
        runtime_identity=_runtime_identity(),
        scanner_build=_scanner_build_identity(),
    )


def default_output_root(input_path):
    source = Path(input_path)
    return source.parent / f"{source.name}.wappalyzer-runs"


async def run_direct_scan(
    input_path,
    *,
    output_root=None,
    workers=None,
    timeout=30,
    runtime_factory=DirectScanRuntime,
):
    source = Path(input_path)
    spec = build_run_spec(source)
    repository = GenerationRepository(
        Path(output_root) if output_root is not None else default_output_root(source)
    )

    with repository.acquire(spec) as generation:
        store = generation.store
        if store.status is RunStatus.INGESTING:
            try:
                store.source_summary
            except RunStateError:
                store.ingest(source)
            store.verify_source(source)

        if store.status is not RunStatus.PUBLISH_READY:
            runtime = None
            if store.counts.endpoint_work:
                artifact_required = max(
                    MINIMUM_ARTIFACT_BYTES,
                    store.source_summary.occurrence_count * ESTIMATED_ARTIFACT_BYTES_PER_OCCURRENCE,
                )
                runtime = runtime_factory(
                    workers=workers,
                    timeout=timeout,
                    resource_snapshot=capture_snapshot(
                        artifact_path=generation.path,
                    ),
                    artifact_required_bytes=artifact_required,
                )

            async def scan_endpoint(endpoint):
                return await runtime.scan(endpoint)

            pipeline = BoundedScanPipeline(
                store=store,
                scan_endpoint=scan_endpoint,
                projector=CanonicalProjector(store),
                max_inflight=runtime.max_inflight if runtime is not None else 1,
                close_workers=runtime.aclose if runtime is not None else None,
            )
            await pipeline.run()

        manifest_path = generation.path / store.MANIFEST_FILENAME
        if not store.manifest_recorded:
            manifest_path = publish_manifest(store)
        store.transition(RunStatus.COMPLETE)
        return DirectRunResult(
            generation_path=generation.path,
            canonical_path=generation.path / store.CANONICAL_FILENAME,
            manifest_path=manifest_path,
            status=store.status,
            resumed=generation.resumed,
        )


__all__ = [
    "DirectRunResult",
    "build_run_spec",
    "default_output_root",
    "run_direct_scan",
]
