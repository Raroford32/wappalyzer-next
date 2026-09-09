from dataclasses import FrozenInstanceError

import pytest

from wappalyzer.core import utils
from wappalyzer.evidence import (
    EvidenceLimit,
    EvidenceTruncation,
    RawDetection,
    ResponseIdentity,
    StageEvidence,
    merge_stage_evidence,
    resolve_raw_detections,
)
from wappalyzer.models import (
    CHANNEL_REGISTRY,
    ChannelOwner,
    Protocol,
    ProtocolObservation,
    ProtocolStatus,
    StageName,
    StageStatus,
    TLSMetadata,
    TLSTrust,
)

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64


def raw(
    technology,
    channel,
    source_key,
    *,
    version="",
    confidence=100,
    evidence_sha256=DIGEST_A,
):
    return RawDetection(
        technology=technology,
        channel=channel,
        source_key=source_key,
        evidence_sha256=evidence_sha256,
        version=version,
        confidence=confidence,
    )


def identity(url="http://192.0.2.1:8080/", digest=DIGEST_A):
    return ResponseIdentity(
        effective_url=url,
        http_status=200,
        content_sha256=digest,
    )


def test_complete_channel_ownership_uses_browser_for_runtime_observations():
    browser_channels = {
        "cookies",
        "css",
        "dom",
        "headers",
        "html",
        "js",
        "meta",
        "scriptSrc",
        "scripts",
        "text",
        "url",
        "xhr",
    }
    static_channels = {"certIssuer", "dns", "probe", "robots"}

    assert {
        name
        for name, registration in CHANNEL_REGISTRY.items()
        if registration.owner is ChannelOwner.BROWSER
    } == browser_channels
    assert {
        name
        for name, registration in CHANNEL_REGISTRY.items()
        if registration.owner is ChannelOwner.STATIC
    } == static_channels


def test_raw_detections_are_immutable_validated_and_privacy_bounded():
    detection = raw("React", "js", "react-global", version="19.1.0", confidence=50)

    with pytest.raises(FrozenInstanceError):
        detection.confidence = 100
    with pytest.raises(ValueError):
        raw("React", "unknown", "source")
    with pytest.raises(ValueError):
        raw("React", "js", "source", confidence=101)
    with pytest.raises(ValueError):
        raw("React", "js", "source", evidence_sha256="raw secret")


def test_resolver_deduplicates_one_source_and_combines_distinct_sources(monkeypatch):
    database = {
        "A": {"cats": [], "implies": r"B\;confidence:80"},
        "B": {"cats": []},
    }
    monkeypatch.setattr(utils, "tech_db", database)

    candidates = (
        raw("A", "html", "same-pattern", version="9", confidence=25),
        raw(
            "A",
            "html",
            "same-pattern",
            version="10",
            confidence=25,
            evidence_sha256=DIGEST_B,
        ),
        raw("A", "dom", "distinct-pattern", confidence=50),
    )

    resolved = resolve_raw_detections(reversed(candidates))

    assert [(item.name, item.version, item.confidence) for item in resolved] == [
        ("A", "10", 75),
        ("B", "", 75),
    ]


def test_stage_rejects_candidates_owned_by_another_execution_path():
    with pytest.raises(ValueError, match="owned by browser"):
        StageEvidence(
            name=StageName.STATIC,
            status=StageStatus.SUCCESS,
            response_identity=identity(),
            detections=(raw("React", "js", "react-global"),),
        )


def test_truncation_forces_partial_without_discarding_stage_evidence():
    stage = StageEvidence(
        name=StageName.BROWSER,
        status=StageStatus.PARTIAL,
        response_identity=identity(),
        detections=(raw("React", "js", "react-global"),),
        truncations=(
            EvidenceTruncation(
                channel="js",
                limits=(EvidenceLimit.TIMER,),
            ),
        ),
    )

    protocol = merge_stage_evidence(
        protocol=Protocol.HTTP,
        requested_url="http://192.0.2.1:8080/",
        tls=TLSMetadata(present=False, trust=TLSTrust.NOT_APPLICABLE),
        stages=(stage,),
    )

    assert protocol.status is ProtocolStatus.PARTIAL
    assert protocol.stages[0].status is StageStatus.PARTIAL
    assert protocol.stages[0].technologies[0].name == "React"
    assert protocol.stages[0].truncations[0].channel == "js"


def test_coherent_stages_resolve_once_but_divergent_observations_stay_separate():
    static = StageEvidence(
        name=StageName.STATIC,
        status=StageStatus.SUCCESS,
        response_identity=identity(),
        detections=(raw("StaticTech", "robots", "robots-pattern"),),
    )
    browser = StageEvidence(
        name=StageName.BROWSER,
        status=StageStatus.SUCCESS,
        response_identity=identity(),
        detections=(raw("RuntimeTech", "js", "global-pattern"),),
    )
    tls = TLSMetadata(present=False, trust=TLSTrust.NOT_APPLICABLE)

    coherent = merge_stage_evidence(
        protocol=Protocol.HTTP,
        requested_url="http://192.0.2.1:8080/",
        tls=tls,
        stages=(static, browser),
    )
    divergent = merge_stage_evidence(
        protocol=Protocol.HTTP,
        requested_url="http://192.0.2.1:8080/",
        tls=tls,
        stages=(
            static,
            StageEvidence(
                name=StageName.BROWSER,
                status=StageStatus.SUCCESS,
                response_identity=identity(
                    "http://192.0.2.1:8080/redirected",
                    DIGEST_C,
                ),
                detections=browser.detections,
            ),
        ),
    )

    assert coherent.observation is ProtocolObservation.SINGLE
    assert [item.name for item in coherent.technologies] == [
        "RuntimeTech",
        "StaticTech",
    ]
    assert divergent.observation is ProtocolObservation.MULTI
    assert divergent.status is ProtocolStatus.PARTIAL
    assert divergent.technologies == ()
    assert [stage.technologies[0].name for stage in divergent.stages] == [
        "StaticTech",
        "RuntimeTech",
    ]


def test_missing_stage_identity_is_partial_multi_observation():
    static = StageEvidence(
        name=StageName.STATIC,
        status=StageStatus.SUCCESS,
        response_identity=identity(),
        detections=(raw("StaticTech", "robots", "robots-pattern"),),
    )
    browser = StageEvidence(
        name=StageName.BROWSER,
        status=StageStatus.SUCCESS,
        response_identity=None,
        detections=(raw("RuntimeTech", "js", "global-pattern"),),
    )

    result = merge_stage_evidence(
        protocol=Protocol.HTTP,
        requested_url="http://192.0.2.1:8080/",
        tls=TLSMetadata(present=False, trust=TLSTrust.NOT_APPLICABLE),
        stages=(static, browser),
    )

    assert result.observation is ProtocolObservation.MULTI
    assert result.status is ProtocolStatus.PARTIAL
    assert result.technologies == ()


def test_empty_stage_identity_does_not_split_evidence_bearing_observation():
    static = StageEvidence(
        name=StageName.STATIC,
        status=StageStatus.SUCCESS_EMPTY,
        response_identity=identity(),
    )
    browser = StageEvidence(
        name=StageName.BROWSER,
        status=StageStatus.SUCCESS,
        response_identity=identity(digest=DIGEST_B),
        detections=(raw("RuntimeTech", "js", "global-pattern"),),
    )

    result = merge_stage_evidence(
        protocol=Protocol.HTTP,
        requested_url="http://192.0.2.1:8080/",
        tls=TLSMetadata(present=False, trust=TLSTrust.NOT_APPLICABLE),
        stages=(static, browser),
    )

    assert result.observation is ProtocolObservation.SINGLE
    assert result.status is ProtocolStatus.SUCCESS
    assert [technology.name for technology in result.technologies] == ["RuntimeTech"]


@pytest.mark.parametrize(
    ("factory", "exception", "message"),
    [
        pytest.param(
            lambda: raw("", "js", "source"),
            ValueError,
            "technology must be a non-empty string",
            id="technology",
        ),
        pytest.param(
            lambda: raw("React", "js", "source", version=19),
            TypeError,
            "version must be a string",
            id="version",
        ),
        pytest.param(
            lambda: StageEvidence("static", StageStatus.SUCCESS_EMPTY, None),
            TypeError,
            "name must be a StageName",
            id="stage-name",
        ),
        pytest.param(
            lambda: StageEvidence(StageName.STATIC, "success_empty", None),
            TypeError,
            "status must be a StageStatus",
            id="stage-status",
        ),
        pytest.param(
            lambda: StageEvidence(StageName.STATIC, StageStatus.SUCCESS_EMPTY, "response"),
            TypeError,
            "response_identity must be a ResponseIdentity or None",
            id="response-identity",
        ),
        pytest.param(
            lambda: StageEvidence(
                StageName.STATIC,
                StageStatus.SUCCESS_EMPTY,
                None,
                detections=("detection",),
            ),
            TypeError,
            "detections must contain only RawDetection values",
            id="detection-type",
        ),
        pytest.param(
            lambda: StageEvidence(
                StageName.STATIC,
                StageStatus.SUCCESS_EMPTY,
                None,
                error_codes=("scan_timeout",),
            ),
            TypeError,
            "error_codes must contain only FailureCode values",
            id="error-code-type",
        ),
        pytest.param(
            lambda: StageEvidence(
                StageName.STATIC,
                StageStatus.SUCCESS_EMPTY,
                None,
                truncations=("truncation",),
            ),
            TypeError,
            "truncations must contain only EvidenceTruncation values",
            id="truncation-type",
        ),
        pytest.param(
            lambda: StageEvidence(
                StageName.BROWSER,
                StageStatus.SUCCESS,
                identity(),
                truncations=(EvidenceTruncation("js", (EvidenceLimit.COUNT,)),),
            ),
            ValueError,
            "truncated stage evidence must have partial status",
            id="truncation-status",
        ),
    ],
)
def test_raw_and_stage_evidence_validation_contracts(factory, exception, message):
    with pytest.raises(exception, match=message):
        factory()


def test_resolver_rejects_foreign_values_and_ignores_zero_confidence(monkeypatch):
    monkeypatch.setattr(
        utils,
        "tech_db",
        {
            "Ignored": {"cats": []},
            "Kept": {"cats": []},
        },
    )

    with pytest.raises(TypeError, match="detections must contain only RawDetection values"):
        resolve_raw_detections((object(),))

    resolved = resolve_raw_detections(
        (
            raw("Ignored", "html", "ignored", confidence=0),
            raw("Kept", "html", "kept", confidence=40),
        )
    )

    assert [(item.name, item.confidence) for item in resolved] == [("Kept", 40)]


def _empty_static_stage():
    return StageEvidence(
        name=StageName.STATIC,
        status=StageStatus.SUCCESS_EMPTY,
        response_identity=identity(),
    )


@pytest.mark.parametrize(
    ("factory", "exception", "message"),
    [
        pytest.param(
            lambda: merge_stage_evidence(
                protocol="http",
                requested_url="http://192.0.2.1:8080/",
                tls=TLSMetadata(False, TLSTrust.NOT_APPLICABLE),
                stages=(_empty_static_stage(),),
            ),
            TypeError,
            "protocol must be a Protocol",
            id="protocol",
        ),
        pytest.param(
            lambda: merge_stage_evidence(
                protocol=Protocol.HTTP,
                requested_url="",
                tls=TLSMetadata(False, TLSTrust.NOT_APPLICABLE),
                stages=(_empty_static_stage(),),
            ),
            ValueError,
            "requested_url must be a non-empty string",
            id="requested-url",
        ),
        pytest.param(
            lambda: merge_stage_evidence(
                protocol=Protocol.HTTP,
                requested_url="http://192.0.2.1:8080/",
                tls="tls",
                stages=(_empty_static_stage(),),
            ),
            TypeError,
            "tls must be TLSMetadata",
            id="tls",
        ),
        pytest.param(
            lambda: merge_stage_evidence(
                protocol=Protocol.HTTP,
                requested_url="http://192.0.2.1:8080/",
                tls=TLSMetadata(False, TLSTrust.NOT_APPLICABLE),
                stages=(),
            ),
            ValueError,
            "at least one stage is required",
            id="empty-stages",
        ),
        pytest.param(
            lambda: merge_stage_evidence(
                protocol=Protocol.HTTP,
                requested_url="http://192.0.2.1:8080/",
                tls=TLSMetadata(False, TLSTrust.NOT_APPLICABLE),
                stages=("static",),
            ),
            TypeError,
            "stages must contain only StageEvidence values",
            id="stage-type",
        ),
        pytest.param(
            lambda: merge_stage_evidence(
                protocol=Protocol.HTTP,
                requested_url="http://192.0.2.1:8080/",
                tls=TLSMetadata(False, TLSTrust.NOT_APPLICABLE),
                stages=(_empty_static_stage(), _empty_static_stage()),
            ),
            ValueError,
            "stages must contain at most one result per stage",
            id="duplicate-stage",
        ),
    ],
)
def test_merge_stage_evidence_validation_contracts(factory, exception, message):
    with pytest.raises(exception, match=message):
        factory()
