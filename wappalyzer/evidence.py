from dataclasses import dataclass
from typing import Iterable, Optional, Sequence, Tuple

from wappalyzer.core.matcher import better_version
from wappalyzer.core.utils import create_result
from wappalyzer.models import (
    CHANNEL_REGISTRY,
    ChannelOwner,
    EvidenceLimit,
    EvidenceTruncation,
    FailureCode,
    Protocol,
    ProtocolObservation,
    ProtocolResult,
    ProtocolStatus,
    ResponseIdentity,
    StageName,
    StageResult,
    StageStatus,
    Technology,
    TLSMetadata,
    _require_digest,
)

_STAGE_ORDER = {stage: index for index, stage in enumerate(StageName)}


def _require_text(name, value):
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")


@dataclass(frozen=True)
class RawDetection:
    technology: str
    channel: str
    source_key: str
    evidence_sha256: str
    version: str = ""
    confidence: int = 100

    def __post_init__(self):
        _require_text("technology", self.technology)
        _require_text("channel", self.channel)
        if self.channel not in CHANNEL_REGISTRY:
            raise ValueError(f"unknown evidence channel: {self.channel}")
        _require_text("source_key", self.source_key)
        _require_digest("evidence_sha256", self.evidence_sha256)
        if not isinstance(self.version, str):
            raise TypeError("version must be a string")
        if (
            isinstance(self.confidence, bool)
            or not isinstance(self.confidence, int)
            or not 0 <= self.confidence <= 100
        ):
            raise ValueError("confidence must be an integer from zero through 100")

    @property
    def deduplication_key(self):
        return self.channel, self.technology, self.source_key


@dataclass(frozen=True)
class StageEvidence:
    name: StageName
    status: StageStatus
    response_identity: Optional[ResponseIdentity]
    detections: Tuple[RawDetection, ...] = ()
    error_codes: Tuple[FailureCode, ...] = ()
    truncations: Tuple[EvidenceTruncation, ...] = ()

    def __post_init__(self):
        if not isinstance(self.name, StageName):
            raise TypeError("name must be a StageName")
        if not isinstance(self.status, StageStatus):
            raise TypeError("status must be a StageStatus")
        if self.response_identity is not None and not isinstance(
            self.response_identity,
            ResponseIdentity,
        ):
            raise TypeError("response_identity must be a ResponseIdentity or None")
        detections = tuple(self.detections)
        error_codes = tuple(self.error_codes)
        truncations = tuple(self.truncations)
        if any(not isinstance(item, RawDetection) for item in detections):
            raise TypeError("detections must contain only RawDetection values")
        if any(not isinstance(item, FailureCode) for item in error_codes):
            raise TypeError("error_codes must contain only FailureCode values")
        if any(not isinstance(item, EvidenceTruncation) for item in truncations):
            raise TypeError("truncations must contain only EvidenceTruncation values")
        expected_owner = (
            ChannelOwner.STATIC if self.name is StageName.STATIC else ChannelOwner.BROWSER
        )
        for detection in detections:
            owner = CHANNEL_REGISTRY[detection.channel].owner
            if owner is not expected_owner:
                raise ValueError(
                    f"{detection.channel} is owned by {owner.value}, not {self.name.value}"
                )
        if truncations and self.status is not StageStatus.PARTIAL:
            raise ValueError("truncated stage evidence must have partial status")
        object.__setattr__(self, "detections", detections)
        object.__setattr__(self, "error_codes", error_codes)
        object.__setattr__(self, "truncations", truncations)


def _candidate_rank(candidate):
    return (
        candidate.confidence,
        bool(candidate.version),
        candidate.version,
        candidate.evidence_sha256,
    )


def resolve_raw_detections(
    detections: Iterable[RawDetection],
) -> Tuple[Technology, ...]:
    deduplicated = {}
    for candidate in detections:
        if not isinstance(candidate, RawDetection):
            raise TypeError("detections must contain only RawDetection values")
        key = candidate.deduplication_key
        current = deduplicated.get(key)
        if current is None:
            deduplicated[key] = candidate
            continue
        version = better_version(candidate.version, current.version)
        winner = max((current, candidate), key=_candidate_rank)
        deduplicated[key] = RawDetection(
            technology=winner.technology,
            channel=winner.channel,
            source_key=winner.source_key,
            evidence_sha256=winner.evidence_sha256,
            version=version,
            confidence=max(current.confidence, candidate.confidence),
        )

    direct = {}
    for candidate in sorted(
        deduplicated.values(),
        key=lambda item: (
            item.technology,
            item.channel,
            item.source_key,
            item.evidence_sha256,
        ),
    ):
        if candidate.confidence == 0:
            continue
        current = direct.setdefault(
            candidate.technology,
            {"version": "", "confidence": 0},
        )
        current["version"] = better_version(
            candidate.version,
            current["version"],
        )
        current["confidence"] = min(
            100,
            current["confidence"] + candidate.confidence,
        )

    resolved = create_result(direct)
    return tuple(
        Technology(
            name=name,
            version=value["version"],
            confidence=value["confidence"],
            categories=tuple(value["categories"]),
            groups=tuple(value["groups"]),
        )
        for name, value in sorted(resolved.items())
    )


def _stage_result(stage):
    return StageResult(
        name=stage.name,
        status=stage.status,
        error_codes=stage.error_codes,
        response_identity=stage.response_identity,
        technologies=resolve_raw_detections(stage.detections),
        truncations=stage.truncations,
    )


def _protocol_status(stages, technologies, observation):
    statuses = {stage.status for stage in stages}
    if (
        observation is ProtocolObservation.MULTI
        or StageStatus.PARTIAL in statuses
        or StageStatus.INDETERMINATE in statuses
    ):
        return ProtocolStatus.PARTIAL
    has_detections = bool(technologies) or any(stage.detections for stage in stages)
    return ProtocolStatus.SUCCESS if has_detections else ProtocolStatus.SUCCESS_EMPTY


def merge_stage_evidence(
    *,
    protocol: Protocol,
    requested_url: str,
    tls: TLSMetadata,
    stages: Sequence[StageEvidence],
) -> ProtocolResult:
    if not isinstance(protocol, Protocol):
        raise TypeError("protocol must be a Protocol")
    _require_text("requested_url", requested_url)
    if not isinstance(tls, TLSMetadata):
        raise TypeError("tls must be TLSMetadata")
    stages = tuple(stages)
    if not stages:
        raise ValueError("at least one stage is required")
    if any(not isinstance(stage, StageEvidence) for stage in stages):
        raise TypeError("stages must contain only StageEvidence values")
    if len({stage.name for stage in stages}) != len(stages):
        raise ValueError("stages must contain at most one result per stage")

    ordered_stages = tuple(sorted(stages, key=lambda item: _STAGE_ORDER[item.name]))
    stage_results = tuple(_stage_result(stage) for stage in ordered_stages)
    identities = {
        stage.response_identity for stage in ordered_stages if stage.response_identity is not None
    }
    identity_missing = any(stage.response_identity is None for stage in ordered_stages)
    observation = (
        ProtocolObservation.MULTI
        if len(identities) > 1 or (identities and identity_missing)
        else ProtocolObservation.SINGLE
    )
    technologies = (
        ()
        if observation is ProtocolObservation.MULTI
        else resolve_raw_detections(
            detection for stage in ordered_stages for detection in stage.detections
        )
    )
    effective_identity = next(
        (
            stage.response_identity
            for stage in reversed(ordered_stages)
            if stage.response_identity is not None
        ),
        None,
    )
    errors = tuple(
        code for code in FailureCode if any(code in stage.error_codes for stage in ordered_stages)
    )

    return ProtocolResult(
        protocol=protocol,
        status=_protocol_status(ordered_stages, technologies, observation),
        requested_url=requested_url,
        effective_url=(
            effective_identity.effective_url if effective_identity is not None else requested_url
        ),
        http_status=(effective_identity.http_status if effective_identity is not None else None),
        tls=tls,
        observation=observation,
        stages=stage_results,
        technologies=technologies,
        error_codes=errors,
    )


__all__ = [
    "EvidenceLimit",
    "EvidenceTruncation",
    "RawDetection",
    "ResponseIdentity",
    "StageEvidence",
    "merge_stage_evidence",
    "resolve_raw_detections",
]
