import json
from dataclasses import FrozenInstanceError, replace

import pytest

from wappalyzer.core.analyzer import DETECTION_FIELDS
from wappalyzer.models import (
    CANONICAL_SCHEMA_VERSION,
    CHANNEL_REGISTRY,
    PROTOCOL_ORDER,
    CanonicalRecord,
    ChannelOwner,
    ClaimToken,
    Endpoint,
    EventKind,
    Failure,
    FailureCode,
    FailureDisposition,
    IllegalTransitionError,
    OccurrenceStatus,
    OperationalMetadata,
    Protocol,
    ProtocolResult,
    ProtocolStatus,
    RunEvent,
    RunLifecycle,
    RunSpec,
    RunStatus,
    StageName,
    StageResult,
    StageStatus,
    StaleClaimError,
    TargetOccurrence,
    Technology,
    TLSMetadata,
    TLSTrust,
    aggregate_occurrence_status,
    canonical_json_bytes,
    canonical_ndjson_bytes,
)

DIGEST = "a" * 64
DEFAULT_ENDPOINT = object()


def endpoint():
    return Endpoint(address="192.0.2.10", port=8443)


def occurrence(value=DEFAULT_ENDPOINT):
    return TargetOccurrence(
        sequence=7,
        line_number=9,
        byte_offset=42,
        line_digest=DIGEST,
        endpoint=endpoint() if value is DEFAULT_ENDPOINT else value,
    )


def protocol_result(
    protocol=Protocol.HTTP,
    status=ProtocolStatus.SUCCESS_EMPTY,
    tls=None,
    technologies=(),
):
    return ProtocolResult(
        protocol=protocol,
        status=status,
        requested_url=f"{protocol.value}://192.0.2.10:8443/",
        effective_url=f"{protocol.value}://192.0.2.10:8443/",
        http_status=(
            200
            if status not in {ProtocolStatus.UNAVAILABLE, ProtocolStatus.INDETERMINATE}
            else None
        ),
        tls=tls
        or TLSMetadata(
            present=protocol is Protocol.HTTPS,
            trust=TLSTrust.TRUSTED if protocol is Protocol.HTTPS else TLSTrust.NOT_APPLICABLE,
        ),
        stages=(
            StageResult(
                name=StageName.STATIC,
                status=StageStatus.SUCCESS if technologies else StageStatus.SUCCESS_EMPTY,
            ),
        ),
        technologies=technologies,
    )


def test_enums_are_strict_and_status_layers_are_separate():
    assert CANONICAL_SCHEMA_VERSION == "scan-run-v1"
    assert tuple(item.value for item in PROTOCOL_ORDER) == ("http", "https")
    assert set(OccurrenceStatus) == {
        OccurrenceStatus.INVALID_INPUT,
        OccurrenceStatus.UNREACHABLE,
        OccurrenceStatus.PARTIAL,
        OccurrenceStatus.SUCCESS_EMPTY,
        OccurrenceStatus.SUCCESS,
    }
    assert {
        RunStatus.INGESTING,
        RunStatus.READY,
        RunStatus.EXECUTING,
        RunStatus.PROJECTING,
        RunStatus.PUBLISH_READY,
        RunStatus.COMPLETE,
        RunStatus.INTERRUPTED,
        RunStatus.FAILED_RECOVERABLE,
        RunStatus.FAILED_FATAL,
    } == set(RunStatus)
    assert {
        FailureCode.INVALID_INPUT,
        FailureCode.UNREACHABLE,
        FailureCode.TLS_UNTRUSTED,
        FailureCode.DISCOVERY_TIMEOUT,
        FailureCode.SCAN_TIMEOUT,
        FailureCode.CANCELLED,
        FailureCode.OUTPUT_FAILURE,
        FailureCode.WORKER_FAILURE,
        FailureCode.INTERNAL_FAILURE,
        FailureCode.INSUFFICIENT_RESOURCES,
    } <= set(FailureCode)
    assert OccurrenceStatus.SUCCESS is not ProtocolStatus.SUCCESS
    assert OccurrenceStatus.SUCCESS_EMPTY is not StageStatus.SUCCESS_EMPTY
    assert "tls_untrusted" not in {status.value for status in OccurrenceStatus}

    for enum_type in (
        ChannelOwner,
        EventKind,
        FailureCode,
        FailureDisposition,
        OccurrenceStatus,
        Protocol,
        ProtocolStatus,
        RunStatus,
        StageName,
        StageStatus,
        TLSTrust,
    ):
        assert all(isinstance(member, str) for member in enum_type)
        with pytest.raises(ValueError):
            enum_type("future-value")


@pytest.mark.parametrize(
    ("endpoint_value", "protocols", "expected"),
    [
        (None, (), OccurrenceStatus.INVALID_INPUT),
        (endpoint(), (), OccurrenceStatus.UNREACHABLE),
        (
            endpoint(),
            (protocol_result(status=ProtocolStatus.UNAVAILABLE),),
            OccurrenceStatus.UNREACHABLE,
        ),
        (
            endpoint(),
            (protocol_result(status=ProtocolStatus.INDETERMINATE),),
            OccurrenceStatus.PARTIAL,
        ),
        (
            endpoint(),
            (protocol_result(status=ProtocolStatus.SUCCESS_EMPTY),),
            OccurrenceStatus.SUCCESS_EMPTY,
        ),
        (
            endpoint(),
            (
                protocol_result(
                    status=ProtocolStatus.SUCCESS,
                    technologies=(Technology(name="Example"),),
                ),
            ),
            OccurrenceStatus.SUCCESS,
        ),
        (
            endpoint(),
            (
                protocol_result(status=ProtocolStatus.SUCCESS),
                protocol_result(
                    protocol=Protocol.HTTPS,
                    status=ProtocolStatus.PARTIAL,
                ),
            ),
            OccurrenceStatus.PARTIAL,
        ),
    ],
)
def test_occurrence_outcome_aggregation(endpoint_value, protocols, expected):
    assert aggregate_occurrence_status(endpoint_value, protocols) is expected


def test_target_occurrence_preserves_source_identity_and_tls_is_only_metadata():
    invalid = occurrence(value=None)
    assert invalid.endpoint is None
    assert (invalid.line_number, invalid.byte_offset, invalid.line_digest) == (9, 42, DIGEST)

    untrusted = protocol_result(
        protocol=Protocol.HTTPS,
        status=ProtocolStatus.SUCCESS_EMPTY,
        tls=TLSMetadata(present=True, trust=TLSTrust.UNTRUSTED),
    )
    assert aggregate_occurrence_status(endpoint(), (untrusted,)) is OccurrenceStatus.SUCCESS_EMPTY
    assert endpoint().authority == "192.0.2.10:8443"
    assert Endpoint(address="2001:db8::10", port=8443).authority == "[2001:db8::10]:8443"

    with pytest.raises(FrozenInstanceError):
        invalid.line_number = 10


def test_run_lifecycle_forward_interrupt_resume_and_failure_guards():
    lifecycle = RunLifecycle(status=RunStatus.INGESTING, epoch=3)
    for next_status in (
        RunStatus.READY,
        RunStatus.EXECUTING,
        RunStatus.PROJECTING,
        RunStatus.PUBLISH_READY,
        RunStatus.COMPLETE,
    ):
        lifecycle = lifecycle.transition(next_status)
        assert lifecycle.status is next_status

    executing = RunLifecycle(status=RunStatus.EXECUTING, epoch=3)
    interrupted = executing.interrupt()
    assert (interrupted.status, interrupted.resume_status) == (
        RunStatus.INTERRUPTED,
        RunStatus.EXECUTING,
    )
    resumed = interrupted.resume()
    assert (resumed.status, resumed.epoch) == (RunStatus.EXECUTING, 4)

    recoverable_failure = Failure(
        code=FailureCode.WORKER_FAILURE,
        disposition=FailureDisposition.RECOVERABLE,
    )
    recoverable = executing.fail(recoverable_failure)
    assert recoverable.status is RunStatus.FAILED_RECOVERABLE
    assert recoverable.resume().status is RunStatus.EXECUTING

    fatal_failure = Failure(
        code=FailureCode.INTERNAL_FAILURE,
        disposition=FailureDisposition.FATAL,
    )
    fatal = executing.fail(fatal_failure)
    assert fatal.status is RunStatus.FAILED_FATAL

    with pytest.raises(IllegalTransitionError):
        RunLifecycle(status=RunStatus.INGESTING, epoch=1).transition(RunStatus.COMPLETE)
    with pytest.raises(IllegalTransitionError):
        lifecycle.transition(RunStatus.EXECUTING)
    with pytest.raises(IllegalTransitionError):
        fatal.resume()

    claim = ClaimToken(epoch=4, attempt=2)
    claim.assert_current(epoch=4, attempt=2)
    with pytest.raises(StaleClaimError):
        claim.assert_current(epoch=5, attempt=2)
    with pytest.raises(StaleClaimError):
        claim.assert_current(epoch=4, attempt=3)


def test_run_spec_is_immutable_and_excludes_operational_resources():
    spec = RunSpec(
        input_sha256=DIGEST,
        parser_version="endpoint-v1",
        schema_version=CANONICAL_SCHEMA_VERSION,
        serializer_version="canonical-json-v1",
        engine_version="complete-v1",
        redirect_policy_version="redirect-v1",
        tls_policy_version="tls-v1",
        retry_policy_version="retry-v1",
        timeout_policy_version="timeout-v1",
        evidence_limits_sha256="b" * 64,
        fingerprint_sha256="c" * 64,
        extension_sha256="d" * 64,
        runtime_identity="chromium-example",
        scanner_build="build-example",
    )
    small = OperationalMetadata(
        cpu_count=1,
        memory_bytes=1_000_000_000,
        selected_workers=1,
        degradation_reasons=("memory",),
    )
    large = OperationalMetadata(
        cpu_count=8,
        memory_bytes=8_000_000_000,
        selected_workers=4,
        degradation_reasons=(),
    )

    assert spec == replace(spec)
    assert small != large
    assert not hasattr(spec, "selected_workers")
    assert not hasattr(spec, "memory_bytes")
    with pytest.raises(FrozenInstanceError):
        spec.engine_version = "changed"

    event = RunEvent(
        sequence=5,
        kind=EventKind.RUN_TRANSITION,
        epoch=4,
        status=RunStatus.INTERRUPTED,
        timestamp_ns=123,
    )
    assert event.status is RunStatus.INTERRUPTED
    assert event.timestamp_ns == 123


def test_every_detection_channel_has_one_owner_and_fixture_pair():
    assert set(CHANNEL_REGISTRY) == DETECTION_FIELDS

    for field, registration in CHANNEL_REGISTRY.items():
        assert isinstance(registration.owner, ChannelOwner), field
        assert registration.positive_fixture
        assert registration.negative_fixture
        assert registration.positive_fixture != registration.negative_fixture

    assert CHANNEL_REGISTRY["js"].owner is ChannelOwner.BROWSER
    assert CHANNEL_REGISTRY["xhr"].owner is ChannelOwner.BROWSER


def test_canonical_serialization_is_deterministic_ordered_and_timing_free():
    technologies = (
        Technology(
            name="Zulu",
            version="2",
            confidence=90,
            categories=("Web frameworks", "Analytics"),
            groups=("Marketing", "Core"),
        ),
        Technology(
            name="Alpha",
            version="1",
            confidence=100,
            categories=("Widgets",),
            groups=("Core",),
        ),
    )
    http = protocol_result(status=ProtocolStatus.SUCCESS, technologies=technologies)
    https = protocol_result(
        protocol=Protocol.HTTPS,
        status=ProtocolStatus.SUCCESS_EMPTY,
        tls=TLSMetadata(
            present=True,
            trust=TLSTrust.UNTRUSTED,
            certificate_sha256="e" * 64,
        ),
    )
    record = CanonicalRecord(
        run_id="run-01",
        occurrence=occurrence(),
        status=OccurrenceStatus.SUCCESS,
        protocols=(https, http),
    )
    reordered = replace(
        record,
        protocols=(
            replace(http, technologies=tuple(reversed(technologies))),
            https,
        ),
    )

    encoded = canonical_json_bytes(record)
    assert encoded == canonical_json_bytes(reordered)
    decoded = json.loads(encoded)
    assert encoded == json.dumps(
        decoded,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    assert list(decoded) == [
        "schema_version",
        "run_id",
        "occurrence",
        "endpoint",
        "status",
        "error_codes",
        "protocols",
    ]
    assert list(decoded["occurrence"]) == [
        "sequence",
        "line_number",
        "byte_offset",
        "line_digest",
    ]
    assert [item["protocol"] for item in decoded["protocols"]] == ["http", "https"]
    assert [item["name"] for item in decoded["protocols"][0]["technologies"]] == [
        "Alpha",
        "Zulu",
    ]
    assert decoded["protocols"][0]["technologies"][1]["categories"] == [
        "Analytics",
        "Web frameworks",
    ]
    assert decoded["protocols"][0]["technologies"][1]["groups"] == ["Core", "Marketing"]

    forbidden_keys = {"timestamp", "timestamp_ns", "duration", "raw_error", "traceback"}

    def assert_timing_free(value):
        if isinstance(value, dict):
            assert forbidden_keys.isdisjoint(value)
            for child in value.values():
                assert_timing_free(child)
        elif isinstance(value, list):
            for child in value:
                assert_timing_free(child)

    assert_timing_free(decoded)
    assert canonical_ndjson_bytes(()) == b""
    assert canonical_ndjson_bytes((record,)) == encoded + b"\n"


def test_invalid_input_canonical_row_has_nullable_endpoint_and_no_protocols():
    record = CanonicalRecord(
        run_id="run-01",
        occurrence=occurrence(value=None),
        status=OccurrenceStatus.INVALID_INPUT,
        error_codes=(FailureCode.INVALID_INPUT,),
    )

    decoded = json.loads(canonical_json_bytes(record))
    assert decoded["endpoint"] is None
    assert decoded["protocols"] == []
