#!/usr/bin/env python3

import argparse
import asyncio
import gc
import hashlib
import ipaddress
import json
import os
import shutil
import tempfile
import time
import tracemalloc
from pathlib import Path

from wappalyzer.models import (
    CANONICAL_SCHEMA_VERSION,
    Protocol,
    ProtocolResult,
    ProtocolStatus,
    RunSpec,
    RunStatus,
    TLSMetadata,
    TLSTrust,
)
from wappalyzer.output import CanonicalProjector
from wappalyzer.pipeline import BoundedScanPipeline
from wappalyzer.runstore import RunStore


def positive_int(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("value must be at least one")
    return number


def nonnegative_int(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("value must not be negative")
    return number


def nonnegative_float(value):
    number = float(value)
    if number < 0:
        raise argparse.ArgumentTypeError("value must not be negative")
    return number


def input_line(index):
    address = ipaddress.IPv4Address(index + 1)
    port = 1024 + index % (65535 - 1024)
    return f"{address}:{port}\n".encode()


def write_input(path, record_count):
    digest = hashlib.sha256()
    with Path(path).open("wb") as stream:
        for index in range(record_count):
            line = input_line(index)
            stream.write(line)
            digest.update(line)
    return digest.hexdigest()


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_spec(input_sha256):
    return RunSpec(
        input_sha256=input_sha256,
        parser_version="endpoint-v1",
        schema_version=CANONICAL_SCHEMA_VERSION,
        serializer_version="canonical-json-v1",
        engine_version="benchmark-complete-v1",
        redirect_policy_version="redirect-v1",
        tls_policy_version="tls-v1",
        retry_policy_version="retry-v1",
        timeout_policy_version="independent-stage-v1",
        evidence_limits_sha256="b" * 64,
        fingerprint_sha256="c" * 64,
        extension_sha256="d" * 64,
        runtime_identity="benchmark-replay",
        scanner_build="benchmark-build",
    )


def protocol_results(endpoint):
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


def resident_bytes():
    try:
        status = Path("/proc/self/status").read_text(encoding="utf-8")
    except OSError:
        return None
    for line in status.splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) * 1024
    return None


def tree_bytes(path):
    return sum(item.stat().st_size for item in Path(path).rglob("*") if item.is_file())


class ReplayScanner:
    def __init__(self, service_delay):
        self.service_delay = service_delay
        self.active = 0
        self.max_active = 0
        self.busy_seconds = 0.0

    async def __call__(self, endpoint):
        started = time.perf_counter()
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            if self.service_delay:
                await asyncio.sleep(self.service_delay)
            else:
                await asyncio.sleep(0)
            return protocol_results(endpoint)
        finally:
            self.active -= 1
            self.busy_seconds += time.perf_counter() - started


async def execute_pipeline(store, workers, service_delay, projection_batch_records):
    scanner = ReplayScanner(service_delay)
    pipeline = BoundedScanPipeline(
        store=store,
        scan_endpoint=scanner,
        projector=CanonicalProjector(store),
        max_inflight=workers,
        projection_batch_records=projection_batch_records,
    )
    started = time.perf_counter()
    stats = await pipeline.run()
    elapsed = time.perf_counter() - started
    return scanner, stats, elapsed


async def interrupt_pipeline(
    store,
    workers,
    service_delay,
    projection_batch_records,
    interrupt_after,
):
    scanner = ReplayScanner(max(service_delay, 0.001))
    pipeline = BoundedScanPipeline(
        store=store,
        scan_endpoint=scanner,
        projector=CanonicalProjector(store),
        max_inflight=workers,
        projection_batch_records=projection_batch_records,
    )
    task = asyncio.create_task(pipeline.run())
    while store.counts.terminal_occurrences < interrupt_after:
        if task.done():
            raise RuntimeError("pipeline completed before the interruption boundary")
        await asyncio.sleep(0.001)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    if store.status is not RunStatus.INTERRUPTED or store.counts.active_claims:
        raise RuntimeError("interrupted pipeline did not durably release every claim")


def measure_once(
    root,
    source,
    input_sha256,
    *,
    records,
    workers,
    service_delay,
    projection_batch_records,
):
    generation = Path(root) / f"workers-{workers}"
    if generation.exists():
        shutil.rmtree(generation)
    store = RunStore.create(generation, "benchmark-run", run_spec(input_sha256))
    try:
        store.ingest(source)
        store.verify_source(source)
        gc.collect()
        rss_before = resident_bytes()
        tracemalloc.start()
        scanner, stats, elapsed = asyncio.run(
            execute_pipeline(
                store,
                workers,
                service_delay,
                projection_batch_records,
            )
        )
        _current_heap, peak_heap = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        rss_after = resident_bytes()
        canonical_path = generation / store.CANONICAL_FILENAME
        utilization = scanner.busy_seconds / (elapsed * workers) if elapsed and workers else 0.0
        return {
            "canonical_sha256": file_sha256(canonical_path),
            "disk_bytes": tree_bytes(generation),
            "elapsed_seconds": round(elapsed, 6),
            "eligible_worker_utilization": round(min(utilization, 1.0), 6),
            "max_inflight_observed": stats.max_inflight_observed,
            "peak_python_heap_bytes": peak_heap,
            "projected_records": stats.projected_records,
            "records": records,
            "resident_delta_bytes": (
                None if rss_before is None or rss_after is None else rss_after - rss_before
            ),
            "records_per_second": round(records / elapsed, 3),
            "workers": workers,
        }
    finally:
        store.close()


def measure_recovery(
    root,
    source,
    input_sha256,
    *,
    records,
    workers,
    service_delay,
    projection_batch_records,
    interrupt_after,
):
    generation = Path(root) / "recovery"
    if generation.exists():
        shutil.rmtree(generation)
    store = RunStore.create(generation, "benchmark-run", run_spec(input_sha256))
    store.ingest(source)
    store.verify_source(source)
    asyncio.run(
        interrupt_pipeline(
            store,
            workers,
            service_delay,
            projection_batch_records,
            interrupt_after,
        )
    )
    committed_before_resume = store.counts.terminal_occurrences
    store.close()

    resumed_store = RunStore.open(generation)
    try:
        started = time.perf_counter()
        _scanner, stats, _elapsed = asyncio.run(
            execute_pipeline(
                resumed_store,
                workers,
                service_delay,
                projection_batch_records,
            )
        )
        resume_elapsed = time.perf_counter() - started
        return {
            "canonical_sha256": file_sha256(generation / resumed_store.CANONICAL_FILENAME),
            "committed_before_resume": committed_before_resume,
            "elapsed_seconds": round(resume_elapsed, 6),
            "interrupted_after": interrupt_after,
            "max_inflight_observed": stats.max_inflight_observed,
            "projected_records": resumed_store.projection_state.next_sequence,
            "records": records,
            "records_per_second_after_resume": round(
                (records - committed_before_resume) / resume_elapsed,
                3,
            ),
            "workers": workers,
        }
    finally:
        resumed_store.close()


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark the bounded durable pipeline with deterministic replay evidence."
    )
    parser.add_argument("--records", type=positive_int, default=10_000)
    parser.add_argument("--workers", type=positive_int, nargs="+", default=[1, os.cpu_count() or 1])
    parser.add_argument("--service-delay-ms", type=nonnegative_float, default=0.25)
    parser.add_argument("--projection-batch-records", type=positive_int, default=256)
    parser.add_argument("--output-dir")
    parser.add_argument("--minimum-utilization", type=nonnegative_float, default=0.0)
    parser.add_argument("--interrupt-after", type=nonnegative_int, default=0)
    arguments = parser.parse_args()

    temporary = None
    if arguments.output_dir is None:
        temporary = tempfile.TemporaryDirectory(prefix="wappalyzer-pipeline-benchmark-")
        root = Path(temporary.name)
    else:
        root = Path(arguments.output_dir)
        root.mkdir(parents=True, exist_ok=True)
    source = root / "targets.txt"
    input_sha256 = write_input(source, arguments.records)
    baseline_digest = None

    try:
        for workers in dict.fromkeys(arguments.workers):
            measurement = measure_once(
                root,
                source,
                input_sha256,
                records=arguments.records,
                workers=workers,
                service_delay=arguments.service_delay_ms / 1000,
                projection_batch_records=arguments.projection_batch_records,
            )
            digest = measurement["canonical_sha256"]
            if baseline_digest is None:
                baseline_digest = digest
            measurement["semantic_parity"] = digest == baseline_digest
            print(json.dumps(measurement, sort_keys=True), flush=True)
            if not measurement["semantic_parity"]:
                raise RuntimeError("canonical output changed with worker count")
            if measurement["eligible_worker_utilization"] < arguments.minimum_utilization:
                raise RuntimeError("eligible worker utilization is below the required floor")
        if arguments.interrupt_after:
            if arguments.interrupt_after >= arguments.records:
                raise RuntimeError("--interrupt-after must be smaller than --records")
            recovery = measure_recovery(
                root,
                source,
                input_sha256,
                records=arguments.records,
                workers=max(arguments.workers),
                service_delay=arguments.service_delay_ms / 1000,
                projection_batch_records=arguments.projection_batch_records,
                interrupt_after=arguments.interrupt_after,
            )
            recovery["semantic_parity"] = recovery["canonical_sha256"] == baseline_digest
            print(json.dumps(recovery, sort_keys=True), flush=True)
            if not recovery["semantic_parity"]:
                raise RuntimeError("resumed output differs from uninterrupted output")
    finally:
        if temporary is not None:
            temporary.cleanup()


if __name__ == "__main__":
    main()
