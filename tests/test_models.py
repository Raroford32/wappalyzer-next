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
    EvidenceLimit,
    EvidenceTruncation,
    Failure,
    FailureCode,
    FailureDisposition,
    IllegalTransitionError,
    OccurrenceStatus,
    OperationalMetadata,
    Protocol,
    ProtocolObservation,
    ProtocolResult,
    ProtocolStatus,
    ResponseIdentity,
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


def response_identity():
    return ResponseIdentity(
        effective_url="http://192.0.2.10:8443/",
        http_status=200,
        content_sha256=DIGEST,
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


@pytest.mark.parametrize(
    ("factory", "exception", "message"),
    [
        pytest.param(
            lambda: Endpoint(address=123, port=80),
            ValueError,
            "address must be a non-empty string",
            id="endpoint-address-type",
        ),
        pytest.param(
            lambda: Endpoint(address="example.com", port=80),
            ValueError,
            "address must be an IPv4 or IPv6 literal",
            id="endpoint-address-literal",
        ),
        pytest.param(
            lambda: Endpoint(address="fe80::1%eth0", port=80),
            ValueError,
            "address must not contain an IPv6 zone identifier",
            id="endpoint-zone",
        ),
        pytest.param(
            lambda: Endpoint(address="192.0.2.1", port=True),
            ValueError,
            "port must be an integer greater than or equal to 1",
            id="endpoint-port-type",
        ),
        pytest.param(
            lambda: Endpoint(address="192.0.2.1", port=65536),
            ValueError,
            "port must be no greater than 65535",
            id="endpoint-port-maximum",
        ),
        pytest.param(
            lambda: TargetOccurrence(0, 1, 0, DIGEST, "192.0.2.1:80"),
            TypeError,
            "endpoint must be an Endpoint or None",
            id="occurrence-endpoint",
        ),
        pytest.param(
            lambda: TLSMetadata(present=1, trust=TLSTrust.TRUSTED),
            TypeError,
            "present must be a boolean",
            id="tls-present",
        ),
        pytest.param(
            lambda: TLSMetadata(present=True, trust="trusted"),
            TypeError,
            "trust must be a TLSTrust",
            id="tls-trust-type",
        ),
        pytest.param(
            lambda: TLSMetadata(present=False, trust=TLSTrust.TRUSTED),
            ValueError,
            "TLS trust must be not_applicable when TLS is absent",
            id="tls-absent-trust",
        ),
        pytest.param(
            lambda: TLSMetadata(present=True, trust=TLSTrust.NOT_APPLICABLE),
            ValueError,
            "TLS trust cannot be not_applicable when TLS is present",
            id="tls-present-trust",
        ),
        pytest.param(
            lambda: TLSMetadata(
                present=True,
                trust=TLSTrust.TRUSTED,
                certificate_sha256="not-a-digest",
            ),
            ValueError,
            "certificate_sha256 must be a lowercase SHA-256 digest",
            id="tls-certificate-digest",
        ),
        pytest.param(
            lambda: Technology(name="Example", version=1),
            TypeError,
            "version must be a string",
            id="technology-version",
        ),
        pytest.param(
            lambda: Technology(name="Example", confidence=101),
            ValueError,
            "confidence must be no greater than 100",
            id="technology-confidence",
        ),
        pytest.param(
            lambda: Technology(name="Example", categories=("Valid", "")),
            ValueError,
            "categories must contain non-empty strings",
            id="technology-categories",
        ),
        pytest.param(
            lambda: Technology(name="Example", groups=("Valid", 1)),
            ValueError,
            "groups must contain non-empty strings",
            id="technology-groups",
        ),
        pytest.param(
            lambda: ResponseIdentity("http://example.test", 600, DIGEST),
            ValueError,
            "http_status must be no greater than 599",
            id="response-status",
        ),
    ],
)
def test_core_model_validation_contracts(factory, exception, message):
    with pytest.raises(exception, match=message):
        factory()


@pytest.mark.parametrize(
    ("factory", "exception", "message"),
    [
        pytest.param(
            lambda: EvidenceTruncation("unknown", (EvidenceLimit.COUNT,)),
            ValueError,
            "unknown evidence channel",
            id="truncation-channel",
        ),
        pytest.param(
            lambda: EvidenceTruncation("js", ("count",)),
            TypeError,
            "limits must contain only EvidenceLimit values",
            id="truncation-limit-type",
        ),
        pytest.param(
            lambda: EvidenceTruncation("js", ()),
            ValueError,
            "limits must not be empty",
            id="truncation-empty",
        ),
        pytest.param(
            lambda: EvidenceTruncation(
                "js",
                (EvidenceLimit.COUNT, EvidenceLimit.COUNT),
            ),
            ValueError,
            "limits must not contain duplicates",
            id="truncation-duplicate",
        ),
        pytest.param(
            lambda: StageResult(name="static", status=StageStatus.SUCCESS_EMPTY),
            TypeError,
            "name must be a StageName",
            id="stage-name",
        ),
        pytest.param(
            lambda: StageResult(name=StageName.STATIC, status="success_empty"),
            TypeError,
            "status must be a StageStatus",
            id="stage-status",
        ),
        pytest.param(
            lambda: StageResult(
                name=StageName.STATIC,
                status=StageStatus.SUCCESS_EMPTY,
                response_identity="response",
            ),
            TypeError,
            "response_identity must be a ResponseIdentity or None",
            id="stage-response-identity",
        ),
        pytest.param(
            lambda: StageResult(
                name=StageName.STATIC,
                status=StageStatus.SUCCESS_EMPTY,
                error_codes=("cancelled",),
            ),
            TypeError,
            "error_codes must contain only FailureCode values",
            id="stage-error-code",
        ),
        pytest.param(
            lambda: StageResult(
                name=StageName.STATIC,
                status=StageStatus.SUCCESS,
                technologies=(Technology("Example"), Technology("Example", version="2")),
            ),
            ValueError,
            "technologies must contain at most one result per name",
            id="stage-duplicate-technology",
        ),
        pytest.param(
            lambda: StageResult(
                name=StageName.BROWSER,
                status=StageStatus.PARTIAL,
                truncations=(
                    EvidenceTruncation("js", (EvidenceLimit.COUNT,)),
                    EvidenceTruncation("js", (EvidenceLimit.BYTES,)),
                ),
            ),
            ValueError,
            "truncations must contain at most one result per channel",
            id="stage-duplicate-truncation",
        ),
        pytest.param(
            lambda: StageResult(
                name=StageName.BROWSER,
                status=StageStatus.SUCCESS,
                truncations=(EvidenceTruncation("js", (EvidenceLimit.COUNT,)),),
            ),
            ValueError,
            "truncated stage evidence must have partial status",
            id="stage-truncation-status",
        ),
    ],
)
def test_evidence_result_validation_contracts(factory, exception, message):
    with pytest.raises(exception, match=message):
        factory()


@pytest.mark.parametrize(
    ("factory", "exception", "message"),
    [
        pytest.param(
            lambda: replace(protocol_result(), protocol="http"),
            TypeError,
            "protocol must be a Protocol",
            id="protocol",
        ),
        pytest.param(
            lambda: replace(protocol_result(), status="success_empty"),
            TypeError,
            "status must be a ProtocolStatus",
            id="status",
        ),
        pytest.param(
            lambda: replace(protocol_result(), requested_url=""),
            ValueError,
            "requested_url must be a non-empty string",
            id="requested-url",
        ),
        pytest.param(
            lambda: replace(protocol_result(), http_status=600),
            ValueError,
            "http_status must be no greater than 599",
            id="http-status",
        ),
        pytest.param(
            lambda: replace(protocol_result(), tls="tls"),
            TypeError,
            "tls must be TLSMetadata",
            id="tls",
        ),
        pytest.param(
            lambda: replace(protocol_result(), observation="single_observation"),
            TypeError,
            "observation must be a ProtocolObservation",
            id="observation",
        ),
        pytest.param(
            lambda: replace(
                protocol_result(),
                stages=(
                    StageResult(StageName.STATIC, StageStatus.SUCCESS_EMPTY),
                    StageResult(StageName.STATIC, StageStatus.SUCCESS_EMPTY),
                ),
            ),
            ValueError,
            "stages must contain at most one result per stage",
            id="duplicate-stage",
        ),
        pytest.param(
            lambda: replace(
                protocol_result(),
                technologies=(Technology("Example"), Technology("Example", version="2")),
            ),
            ValueError,
            "technologies must contain at most one result per name",
            id="duplicate-technology",
        ),
        pytest.param(
            lambda: replace(
                protocol_result(),
                observation=ProtocolObservation.MULTI,
                technologies=(Technology("Example"),),
            ),
            ValueError,
            "multi-observation results must keep technologies stage-scoped",
            id="multi-observation-technology",
        ),
        pytest.param(
            lambda: replace(
                protocol_result(),
                observation=ProtocolObservation.MULTI,
            ),
            ValueError,
            "multi-observation results must have partial status",
            id="multi-observation-status",
        ),
        pytest.param(
            lambda: Failure(code="cancelled", disposition=FailureDisposition.FATAL),
            TypeError,
            "code must be a FailureCode",
            id="failure-code",
        ),
        pytest.param(
            lambda: Failure(code=FailureCode.CANCELLED, disposition="fatal"),
            TypeError,
            "disposition must be a FailureDisposition",
            id="failure-disposition",
        ),
    ],
)
def test_protocol_and_failure_validation_contracts(factory, exception, message):
    with pytest.raises(exception, match=message):
        factory()


def _recoverable_failure():
    return Failure(
        code=FailureCode.WORKER_FAILURE,
        disposition=FailureDisposition.RECOVERABLE,
    )


def _fatal_failure():
    return Failure(
        code=FailureCode.INTERNAL_FAILURE,
        disposition=FailureDisposition.FATAL,
    )


@pytest.mark.parametrize(
    ("factory", "exception", "message"),
    [
        pytest.param(
            lambda: RunLifecycle(status="ingesting", epoch=0),
            TypeError,
            "status must be a RunStatus",
            id="status",
        ),
        pytest.param(
            lambda: RunLifecycle(status=RunStatus.INTERRUPTED, epoch=0),
            ValueError,
            "interrupted runs require a resumable status and no failure",
            id="interrupted-state",
        ),
        pytest.param(
            lambda: RunLifecycle(
                status=RunStatus.FAILED_RECOVERABLE,
                epoch=0,
                failure=_recoverable_failure(),
            ),
            ValueError,
            "recoverable failures require a resumable status and failure",
            id="recoverable-state",
        ),
        pytest.param(
            lambda: RunLifecycle(
                status=RunStatus.FAILED_FATAL,
                epoch=0,
                resume_status=RunStatus.EXECUTING,
                failure=_fatal_failure(),
            ),
            ValueError,
            "fatal failures require a fatal failure and no resume status",
            id="fatal-state",
        ),
        pytest.param(
            lambda: RunLifecycle(
                status=RunStatus.EXECUTING,
                epoch=0,
                resume_status=RunStatus.EXECUTING,
            ),
            ValueError,
            "active and complete runs cannot carry recovery state",
            id="active-state",
        ),
        pytest.param(
            lambda: RunLifecycle(RunStatus.INGESTING, 0).transition("ready"),
            TypeError,
            "next_status must be a RunStatus",
            id="transition-type",
        ),
        pytest.param(
            lambda: RunLifecycle(RunStatus.COMPLETE, 0).interrupt(),
            IllegalTransitionError,
            "cannot interrupt run in complete",
            id="interrupt-complete",
        ),
        pytest.param(
            lambda: RunLifecycle(RunStatus.EXECUTING, 0).fail("failure"),
            TypeError,
            "failure must be a Failure",
            id="failure-type",
        ),
        pytest.param(
            lambda: RunLifecycle(RunStatus.COMPLETE, 0).fail(_recoverable_failure()),
            IllegalTransitionError,
            "cannot fail run in complete",
            id="failure-complete",
        ),
    ],
)
def test_run_lifecycle_rejects_invalid_state_and_operations(factory, exception, message):
    with pytest.raises(exception, match=message):
        factory()


@pytest.mark.parametrize(
    ("factory", "message"),
    [
        pytest.param(
            lambda: OperationalMetadata(1, 1, 1, ("memory", "")),
            "degradation_reasons must contain non-empty strings",
            id="operational-reason",
        ),
        pytest.param(
            lambda: RunEvent(0, "run_transition", 0, RunStatus.READY, 1),
            "kind must be an EventKind",
            id="event-kind",
        ),
        pytest.param(
            lambda: RunEvent(0, EventKind.RUN_TRANSITION, 0, "ready", 1),
            "status must be a RunStatus",
            id="event-status",
        ),
        pytest.param(
            lambda: RunEvent(
                0,
                EventKind.RUN_TRANSITION,
                0,
                RunStatus.READY,
                1,
                failure="failure",
            ),
            "failure must be a Failure or None",
            id="event-failure",
        ),
    ],
)
def test_operational_metadata_and_event_validation(factory, message):
    with pytest.raises((TypeError, ValueError), match=message):
        factory()


@pytest.mark.parametrize(
    ("factory", "exception", "message"),
    [
        pytest.param(
            lambda: CanonicalRecord(
                run_id="run",
                occurrence="occurrence",
                status=OccurrenceStatus.UNREACHABLE,
            ),
            TypeError,
            "occurrence must be a TargetOccurrence",
            id="occurrence",
        ),
        pytest.param(
            lambda: CanonicalRecord(
                run_id="run",
                occurrence=occurrence(),
                status="unreachable",
            ),
            TypeError,
            "status must be an OccurrenceStatus",
            id="status",
        ),
        pytest.param(
            lambda: CanonicalRecord(
                run_id="run",
                occurrence=occurrence(),
                status=OccurrenceStatus.UNREACHABLE,
                error_codes=("unreachable",),
            ),
            TypeError,
            "error_codes must contain only FailureCode values",
            id="error-code",
        ),
        pytest.param(
            lambda: CanonicalRecord(
                run_id="run",
                occurrence=occurrence(),
                status=OccurrenceStatus.UNREACHABLE,
                protocols=("http",),
            ),
            TypeError,
            "protocols must contain only ProtocolResult values",
            id="protocol-type",
        ),
        pytest.param(
            lambda: CanonicalRecord(
                run_id="run",
                occurrence=occurrence(),
                status=OccurrenceStatus.SUCCESS_EMPTY,
                protocols=(protocol_result(), protocol_result()),
            ),
            ValueError,
            "protocols must contain at most one result per protocol",
            id="duplicate-protocol",
        ),
        pytest.param(
            lambda: CanonicalRecord(
                run_id="run",
                occurrence=occurrence(),
                status=OccurrenceStatus.SUCCESS,
            ),
            ValueError,
            "status success does not match aggregate unreachable",
            id="aggregate-status",
        ),
        pytest.param(
            lambda: CanonicalRecord(
                run_id="run",
                occurrence=occurrence(value=None),
                status=OccurrenceStatus.INVALID_INPUT,
            ),
            ValueError,
            "invalid input records require the invalid_input error code",
            id="invalid-input-code",
        ),
        pytest.param(
            lambda: CanonicalRecord(
                run_id="run",
                occurrence=occurrence(value=None),
                status=OccurrenceStatus.INVALID_INPUT,
                error_codes=(FailureCode.INVALID_INPUT,),
                protocols=(protocol_result(),),
            ),
            ValueError,
            "invalid input records cannot contain protocol results",
            id="invalid-input-protocol",
        ),
        pytest.param(
            lambda: CanonicalRecord(
                run_id="run",
                occurrence=occurrence(),
                status=OccurrenceStatus.UNREACHABLE,
                schema_version="future-schema",
            ),
            ValueError,
            "schema_version must be scan-run-v1",
            id="schema-version",
        ),
    ],
)
def test_canonical_record_validation_contracts(factory, exception, message):
    with pytest.raises(exception, match=message):
        factory()


def test_canonical_serializer_rejects_noncanonical_values():
    with pytest.raises(TypeError, match="record must be a CanonicalRecord"):
        canonical_json_bytes({"run_id": "run"})
