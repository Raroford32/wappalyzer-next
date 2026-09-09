import asyncio
import hashlib

from wappalyzer.evidence import RawDetection, StageEvidence
from wappalyzer.models import (
    CHANNEL_REGISTRY,
    ChannelOwner,
    FailureCode,
    Protocol,
    ProtocolObservation,
    ProtocolStatus,
    ResponseIdentity,
    StageName,
    StageStatus,
    TLSMetadata,
    TLSTrust,
)
from wappalyzer.scanner import CompleteScanExecutor


def identity():
    return ResponseIdentity(
        effective_url="http://192.0.2.1:8080/",
        http_status=200,
        content_sha256=hashlib.sha256(b"same response").hexdigest(),
    )


def raw(technology, channel, source_key):
    return RawDetection(
        technology=technology,
        channel=channel,
        source_key=source_key,
        evidence_sha256=hashlib.sha256(source_key.encode()).hexdigest(),
        confidence=10,
    )


def stage(name, channels):
    owner = ChannelOwner.STATIC if name is StageName.STATIC else ChannelOwner.BROWSER
    assert all(CHANNEL_REGISTRY[channel].owner is owner for channel in channels)
    return StageEvidence(
        name=name,
        status=StageStatus.SUCCESS,
        response_identity=identity(),
        detections=tuple(raw(f"Tech-{channel}", channel, channel) for channel in channels),
    )


def test_complete_executor_unions_every_owned_channel_once():
    static_channels = tuple(
        channel
        for channel, registration in CHANNEL_REGISTRY.items()
        if registration.owner is ChannelOwner.STATIC
    )
    browser_channels = tuple(
        channel
        for channel, registration in CHANNEL_REGISTRY.items()
        if registration.owner is ChannelOwner.BROWSER
    )

    async def browser_runner(_url, _cookie, _tls):
        return stage(StageName.BROWSER, browser_channels)

    executor = CompleteScanExecutor(
        static_runner=lambda _url, _cookie, _timeout, _workers, _tls: stage(
            StageName.STATIC,
            static_channels,
        ),
        browser_runner=browser_runner,
        timeout=5,
    )
    result = asyncio.run(
        executor.analyze_protocol(
            "http://192.0.2.1:8080/",
            Protocol.HTTP,
            TLSMetadata(False, TLSTrust.NOT_APPLICABLE),
        )
    )
    executor.close()

    assert result.status is ProtocolStatus.SUCCESS
    assert result.observation is ProtocolObservation.SINGLE
    assert {technology.name for technology in result.technologies} == {
        f"Tech-{channel}" for channel in CHANNEL_REGISTRY
    }
    assert tuple(stage_result.name for stage_result in result.stages) == (
        StageName.STATIC,
        StageName.BROWSER,
    )


def test_complete_executor_preserves_completed_stage_when_peer_fails():
    static_stage = stage(StageName.STATIC, ("robots",))

    async def failing_browser(_url, _cookie, _tls):
        raise asyncio.TimeoutError()

    executor = CompleteScanExecutor(
        static_runner=lambda _url, _cookie, _timeout, _workers, _tls: static_stage,
        browser_runner=failing_browser,
        timeout=5,
    )
    result = asyncio.run(
        executor.analyze_protocol(
            "http://192.0.2.1:8080/",
            Protocol.HTTP,
            TLSMetadata(False, TLSTrust.NOT_APPLICABLE),
        )
    )
    executor.close()

    assert result.status is ProtocolStatus.PARTIAL
    assert result.observation is ProtocolObservation.SINGLE
    assert result.technologies[0].name == "Tech-robots"
    assert result.stages[0].technologies[0].name == "Tech-robots"
    assert result.stages[1].status is StageStatus.INDETERMINATE
    assert result.stages[1].error_codes == (FailureCode.SCAN_TIMEOUT,)


def test_complete_executor_deduplicates_repeated_evidence_but_adds_distinct_patterns():
    static_stage = StageEvidence(
        name=StageName.STATIC,
        status=StageStatus.SUCCESS,
        response_identity=identity(),
        detections=(
            raw("RepeatedTech", "robots", "same"),
            raw("RepeatedTech", "robots", "same"),
            raw("RepeatedTech", "robots", "different"),
        ),
    )
    browser_stage = StageEvidence(
        name=StageName.BROWSER,
        status=StageStatus.SUCCESS_EMPTY,
        response_identity=identity(),
    )

    async def browser_runner(_url, _cookie, _tls):
        return browser_stage

    executor = CompleteScanExecutor(
        static_runner=lambda _url, _cookie, _timeout, _workers, _tls: static_stage,
        browser_runner=browser_runner,
        timeout=5,
    )
    result = asyncio.run(
        executor.analyze_protocol(
            "http://192.0.2.1:8080/",
            Protocol.HTTP,
            TLSMetadata(False, TLSTrust.NOT_APPLICABLE),
        )
    )
    executor.close()

    assert result.technologies[0].name == "RepeatedTech"
    assert result.technologies[0].confidence == 20
