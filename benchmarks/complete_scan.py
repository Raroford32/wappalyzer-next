#!/usr/bin/env python3

import argparse
import asyncio
import hashlib
import json
import os
import time

from wappalyzer.evidence import RawDetection, StageEvidence
from wappalyzer.models import (
    CHANNEL_REGISTRY,
    CanonicalRecord,
    ChannelOwner,
    Endpoint,
    OccurrenceStatus,
    Protocol,
    ResponseIdentity,
    StageName,
    StageStatus,
    TargetOccurrence,
    TLSMetadata,
    TLSTrust,
    aggregate_occurrence_status,
    canonical_ndjson_bytes,
)
from wappalyzer.scanner import CompleteScanExecutor


def positive_int(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("value must be at least one")
    return number


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def raw_detection(channel, index):
    source = f"{channel}:{index}"
    return RawDetection(
        technology=f"Benchmark {channel}",
        channel=channel,
        source_key=digest(f"source:{source}"),
        evidence_sha256=digest(f"evidence:{source}"),
        version="1.0.0",
        confidence=100,
    )


def stage(name, url, index):
    owner = ChannelOwner.STATIC if name is StageName.STATIC else ChannelOwner.BROWSER
    return StageEvidence(
        name=name,
        status=StageStatus.SUCCESS,
        response_identity=ResponseIdentity(
            effective_url=url,
            http_status=200,
            content_sha256=digest(f"body:{index}"),
        ),
        detections=tuple(
            raw_detection(channel, index)
            for channel, registration in CHANNEL_REGISTRY.items()
            if registration.owner is owner
        ),
    )


def static_runner(url, _cookie, _timeout, _asset_workers, _tls):
    index = int(url.rsplit("/", 1)[-1])
    return stage(StageName.STATIC, url, index)


async def browser_runner(url, _cookie, _tls):
    index = int(url.rsplit("/", 1)[-1])
    await asyncio.sleep(0)
    return stage(StageName.BROWSER, url, index)


async def execute(repeats, workers):
    executor = CompleteScanExecutor(
        static_runner=static_runner,
        browser_runner=browser_runner,
        timeout=10,
        static_workers=workers,
    )
    results = [None] * repeats
    next_index = 0

    async def worker():
        nonlocal next_index
        while next_index < repeats:
            index = next_index
            next_index += 1
            url = f"http://192.0.2.1:8080/{index}"
            results[index] = await executor.analyze_protocol(
                url,
                Protocol.HTTP,
                TLSMetadata(False, TLSTrust.NOT_APPLICABLE),
            )

    try:
        await asyncio.gather(*(worker() for _ in range(min(workers, repeats))))
    finally:
        executor.close()
    return results


def semantic_bytes(results):
    records = []
    endpoint = Endpoint("192.0.2.1", 8080)
    for index, result in enumerate(results):
        occurrence = TargetOccurrence(
            sequence=index,
            line_number=index + 1,
            byte_offset=index * 32,
            line_digest=digest(f"line:{index}"),
            endpoint=endpoint,
        )
        protocols = (result,)
        status = aggregate_occurrence_status(endpoint, protocols)
        if status not in {OccurrenceStatus.SUCCESS, OccurrenceStatus.SUCCESS_EMPTY}:
            raise RuntimeError(f"benchmark scan was incomplete at index {index}")
        records.append(
            CanonicalRecord(
                run_id="benchmark-run",
                occurrence=occurrence,
                status=status,
                protocols=protocols,
            )
        )
    return canonical_ndjson_bytes(records)


def measure(repeats, workers):
    started = time.perf_counter()
    results = asyncio.run(execute(repeats, workers))
    elapsed = time.perf_counter() - started
    payload = semantic_bytes(results)
    return {
        "all_channel_scans_per_second": round(repeats / elapsed, 3),
        "channel_count": len(CHANNEL_REGISTRY),
        "elapsed_seconds": round(elapsed, 6),
        "records": repeats,
        "semantic_sha256": hashlib.sha256(payload).hexdigest(),
        "workers": workers,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark deterministic all-channel hybrid evidence resolution."
    )
    parser.add_argument("--repeats", type=positive_int, default=10_000)
    parser.add_argument(
        "--workers",
        type=positive_int,
        nargs="+",
        default=[1, os.cpu_count() or 1],
    )
    arguments = parser.parse_args()
    baseline_digest = None

    for workers in dict.fromkeys(arguments.workers):
        measurement = measure(arguments.repeats, workers)
        digest_value = measurement["semantic_sha256"]
        if baseline_digest is None:
            baseline_digest = digest_value
        measurement["semantic_parity"] = digest_value == baseline_digest
        print(json.dumps(measurement, sort_keys=True), flush=True)
        if not measurement["semantic_parity"]:
            raise RuntimeError("all-channel semantic output changed with worker count")


if __name__ == "__main__":
    main()
