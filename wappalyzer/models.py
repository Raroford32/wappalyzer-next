import ipaddress
import json
from dataclasses import dataclass, replace
from enum import Enum
from types import MappingProxyType
from typing import Iterable, Mapping, Optional, Sequence, Tuple

CANONICAL_SCHEMA_VERSION = "scan-run-v1"


class IllegalTransitionError(RuntimeError):
    """Raised when a run lifecycle transition is not permitted."""


class StaleClaimError(RuntimeError):
    """Raised when work is committed by an obsolete claim."""


class StringEnum(str, Enum):
    """A closed string enum compatible with Python 3.9."""


class Protocol(StringEnum):
    HTTP = "http"
    HTTPS = "https"


PROTOCOL_ORDER = (Protocol.HTTP, Protocol.HTTPS)


class OccurrenceStatus(StringEnum):
    INVALID_INPUT = "invalid_input"
    UNREACHABLE = "unreachable"
    PARTIAL = "partial"
    SUCCESS_EMPTY = "success_empty"
    SUCCESS = "success"


class ProtocolStatus(StringEnum):
    UNAVAILABLE = "unavailable"
    INDETERMINATE = "indeterminate"
    PARTIAL = "partial"
    SUCCESS_EMPTY = "success_empty"
    SUCCESS = "success"


class StageStatus(StringEnum):
    INDETERMINATE = "indeterminate"
    PARTIAL = "partial"
    SUCCESS_EMPTY = "success_empty"
    SUCCESS = "success"


class RunStatus(StringEnum):
    INGESTING = "ingesting"
    READY = "ready"
    EXECUTING = "executing"
    PROJECTING = "projecting"
    PUBLISH_READY = "publish_ready"
    COMPLETE = "complete"
    INTERRUPTED = "interrupted"
    FAILED_RECOVERABLE = "failed_recoverable"
    FAILED_FATAL = "failed_fatal"


class FailureCode(StringEnum):
    INVALID_INPUT = "invalid_input"
    UNREACHABLE = "unreachable"
    TLS_UNTRUSTED = "tls_untrusted"
    DISCOVERY_TIMEOUT = "discovery_timeout"
    SCAN_TIMEOUT = "scan_timeout"
    CANCELLED = "cancelled"
    OUTPUT_FAILURE = "output_failure"
    WORKER_FAILURE = "worker_failure"
    INTERNAL_FAILURE = "internal_failure"
    INSUFFICIENT_RESOURCES = "insufficient_resources"


class FailureDisposition(StringEnum):
    RECOVERABLE = "recoverable"
    FATAL = "fatal"


class TLSTrust(StringEnum):
    NOT_APPLICABLE = "not_applicable"
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    INDETERMINATE = "indeterminate"


class StageName(StringEnum):
    STATIC = "static"
    BROWSER = "browser"


class EventKind(StringEnum):
    RUN_TRANSITION = "run_transition"
    RUN_INTERRUPTED = "run_interrupted"
    RUN_RESUMED = "run_resumed"
    RUN_FAILURE = "run_failure"


class ChannelOwner(StringEnum):
    STATIC = "static"
    BROWSER = "browser"


class ProtocolObservation(StringEnum):
    SINGLE = "single_observation"
    MULTI = "multi_observation"


class EvidenceLimit(StringEnum):
    COUNT = "count"
    BYTES = "bytes"
    TIMER = "timer"
    REDIRECT = "redirect"
    POLICY = "policy"
    WORKER = "worker"


def _require_int(name: str, value: int, minimum: int = 0) -> None:
    if type(value) is not int or value < minimum:
        raise ValueError(f"{name} must be an integer greater than or equal to {minimum}")


def _require_text(name: str, value: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")


def _require_digest(name: str, value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")


def _as_tuple(values: Sequence[object]) -> Tuple[object, ...]:
    return tuple(values)


def _require_members(name: str, values: Sequence[object], member_type: type) -> None:
    if any(not isinstance(value, member_type) for value in values):
        raise TypeError(f"{name} must contain only {member_type.__name__} values")


@dataclass(frozen=True)
class Endpoint:
    address: str
    port: int

    def __post_init__(self) -> None:
        _require_text("address", self.address)
        if "%" in self.address:
            raise ValueError("address must not contain an IPv6 zone identifier")
        try:
            normalized = ipaddress.ip_address(self.address)
        except ValueError as error:
            raise ValueError("address must be an IPv4 or IPv6 literal") from error
        _require_int("port", self.port, 1)
        if self.port > 65535:
            raise ValueError("port must be no greater than 65535")
        object.__setattr__(self, "address", str(normalized))

    @property
    def authority(self) -> str:
        address = f"[{self.address}]" if ":" in self.address else self.address
        return f"{address}:{self.port}"


@dataclass(frozen=True)
class TargetOccurrence:
    sequence: int
    line_number: int
    byte_offset: int
    line_digest: str
    endpoint: Optional[Endpoint]

    def __post_init__(self) -> None:
        _require_int("sequence", self.sequence)
        _require_int("line_number", self.line_number, 1)
        _require_int("byte_offset", self.byte_offset)
        _require_digest("line_digest", self.line_digest)
        if self.endpoint is not None and not isinstance(self.endpoint, Endpoint):
            raise TypeError("endpoint must be an Endpoint or None")


@dataclass(frozen=True)
class TLSMetadata:
    present: bool
    trust: TLSTrust
    certificate_sha256: Optional[str] = None

    def __post_init__(self) -> None:
        if type(self.present) is not bool:
            raise TypeError("present must be a boolean")
        if not isinstance(self.trust, TLSTrust):
            raise TypeError("trust must be a TLSTrust")
        if not self.present and self.trust is not TLSTrust.NOT_APPLICABLE:
            raise ValueError("TLS trust must be not_applicable when TLS is absent")
        if self.present and self.trust is TLSTrust.NOT_APPLICABLE:
            raise ValueError("TLS trust cannot be not_applicable when TLS is present")
        if self.certificate_sha256 is not None:
            _require_digest("certificate_sha256", self.certificate_sha256)


@dataclass(frozen=True)
class Technology:
    name: str
    version: str = ""
    confidence: int = 100
    categories: Tuple[str, ...] = ()
    groups: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text("name", self.name)
        if not isinstance(self.version, str):
            raise TypeError("version must be a string")
        _require_int("confidence", self.confidence)
        if self.confidence > 100:
            raise ValueError("confidence must be no greater than 100")
        categories = _as_tuple(self.categories)
        groups = _as_tuple(self.groups)
        if any(not isinstance(value, str) or not value for value in categories):
            raise ValueError("categories must contain non-empty strings")
        if any(not isinstance(value, str) or not value for value in groups):
            raise ValueError("groups must contain non-empty strings")
        object.__setattr__(self, "categories", categories)
        object.__setattr__(self, "groups", groups)


@dataclass(frozen=True)
class ResponseIdentity:
    effective_url: str
    http_status: int
    content_sha256: str

    def __post_init__(self) -> None:
        _require_text("effective_url", self.effective_url)
        _require_int("http_status", self.http_status, 100)
        if self.http_status > 599:
            raise ValueError("http_status must be no greater than 599")
        _require_digest("content_sha256", self.content_sha256)


@dataclass(frozen=True)
class EvidenceTruncation:
    channel: str
    limits: Tuple[EvidenceLimit, ...]

    def __post_init__(self) -> None:
        _require_text("channel", self.channel)
        if self.channel not in CHANNEL_REGISTRY:
            raise ValueError(f"unknown evidence channel: {self.channel}")
        limits = _as_tuple(self.limits)
        _require_members("limits", limits, EvidenceLimit)
        if not limits:
            raise ValueError("limits must not be empty")
        if len(set(limits)) != len(limits):
            raise ValueError("limits must not contain duplicates")
        object.__setattr__(self, "limits", limits)


@dataclass(frozen=True)
class StageResult:
    name: StageName
    status: StageStatus
    error_codes: Tuple[FailureCode, ...] = ()
    response_identity: Optional[ResponseIdentity] = None
    technologies: Tuple[Technology, ...] = ()
    truncations: Tuple[EvidenceTruncation, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.name, StageName):
            raise TypeError("name must be a StageName")
        if not isinstance(self.status, StageStatus):
            raise TypeError("status must be a StageStatus")
        error_codes = _as_tuple(self.error_codes)
        technologies = _as_tuple(self.technologies)
        truncations = _as_tuple(self.truncations)
        _require_members("error_codes", error_codes, FailureCode)
        if self.response_identity is not None and not isinstance(
            self.response_identity,
            ResponseIdentity,
        ):
            raise TypeError("response_identity must be a ResponseIdentity or None")
        _require_members("technologies", technologies, Technology)
        _require_members("truncations", truncations, EvidenceTruncation)
        if len({technology.name for technology in technologies}) != len(technologies):
            raise ValueError("technologies must contain at most one result per name")
        if len({truncation.channel for truncation in truncations}) != len(truncations):
            raise ValueError("truncations must contain at most one result per channel")
        if truncations and self.status is not StageStatus.PARTIAL:
            raise ValueError("truncated stage evidence must have partial status")
        object.__setattr__(self, "error_codes", error_codes)
        object.__setattr__(self, "technologies", technologies)
        object.__setattr__(self, "truncations", truncations)


@dataclass(frozen=True)
class ProtocolResult:
    protocol: Protocol
    status: ProtocolStatus
    requested_url: str
    effective_url: str
    http_status: Optional[int]
    tls: TLSMetadata
    observation: ProtocolObservation = ProtocolObservation.SINGLE
    stages: Tuple[StageResult, ...] = ()
    technologies: Tuple[Technology, ...] = ()
    error_codes: Tuple[FailureCode, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.protocol, Protocol):
            raise TypeError("protocol must be a Protocol")
        if not isinstance(self.status, ProtocolStatus):
            raise TypeError("status must be a ProtocolStatus")
        _require_text("requested_url", self.requested_url)
        _require_text("effective_url", self.effective_url)
        if self.http_status is not None:
            _require_int("http_status", self.http_status, 100)
            if self.http_status > 599:
                raise ValueError("http_status must be no greater than 599")
        if not isinstance(self.tls, TLSMetadata):
            raise TypeError("tls must be TLSMetadata")
        if not isinstance(self.observation, ProtocolObservation):
            raise TypeError("observation must be a ProtocolObservation")
        stages = _as_tuple(self.stages)
        technologies = _as_tuple(self.technologies)
        error_codes = _as_tuple(self.error_codes)
        _require_members("stages", stages, StageResult)
        _require_members("technologies", technologies, Technology)
        _require_members("error_codes", error_codes, FailureCode)
        if len({stage.name for stage in stages}) != len(stages):
            raise ValueError("stages must contain at most one result per stage")
        if len({technology.name for technology in technologies}) != len(technologies):
            raise ValueError("technologies must contain at most one result per name")
        if self.observation is ProtocolObservation.MULTI and technologies:
            raise ValueError("multi-observation results must keep technologies stage-scoped")
        object.__setattr__(self, "stages", stages)
        object.__setattr__(self, "technologies", technologies)
        object.__setattr__(self, "error_codes", error_codes)


@dataclass(frozen=True)
class Failure:
    code: FailureCode
    disposition: FailureDisposition

    def __post_init__(self) -> None:
        if not isinstance(self.code, FailureCode):
            raise TypeError("code must be a FailureCode")
        if not isinstance(self.disposition, FailureDisposition):
            raise TypeError("disposition must be a FailureDisposition")


_FORWARD_RUN_STATUS = {
    RunStatus.INGESTING: RunStatus.READY,
    RunStatus.READY: RunStatus.EXECUTING,
    RunStatus.EXECUTING: RunStatus.PROJECTING,
    RunStatus.PROJECTING: RunStatus.PUBLISH_READY,
    RunStatus.PUBLISH_READY: RunStatus.COMPLETE,
}
_RESUMABLE_RUN_STATUSES = frozenset(_FORWARD_RUN_STATUS)


@dataclass(frozen=True)
class RunLifecycle:
    status: RunStatus
    epoch: int
    resume_status: Optional[RunStatus] = None
    failure: Optional[Failure] = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, RunStatus):
            raise TypeError("status must be a RunStatus")
        _require_int("epoch", self.epoch)

        if self.status is RunStatus.INTERRUPTED:
            if self.resume_status not in _RESUMABLE_RUN_STATUSES or self.failure is not None:
                raise ValueError("interrupted runs require a resumable status and no failure")
        elif self.status is RunStatus.FAILED_RECOVERABLE:
            if (
                self.resume_status not in _RESUMABLE_RUN_STATUSES
                or self.failure is None
                or self.failure.disposition is not FailureDisposition.RECOVERABLE
            ):
                raise ValueError("recoverable failures require a resumable status and failure")
        elif self.status is RunStatus.FAILED_FATAL:
            if (
                self.resume_status is not None
                or self.failure is None
                or self.failure.disposition is not FailureDisposition.FATAL
            ):
                raise ValueError("fatal failures require a fatal failure and no resume status")
        elif self.resume_status is not None or self.failure is not None:
            raise ValueError("active and complete runs cannot carry recovery state")

    def transition(self, next_status: RunStatus) -> "RunLifecycle":
        if not isinstance(next_status, RunStatus):
            raise TypeError("next_status must be a RunStatus")
        if _FORWARD_RUN_STATUS.get(self.status) is not next_status:
            raise IllegalTransitionError(
                f"cannot transition run from {self.status.value} to {next_status.value}"
            )
        return replace(self, status=next_status)

    def interrupt(self) -> "RunLifecycle":
        if self.status not in _RESUMABLE_RUN_STATUSES:
            raise IllegalTransitionError(f"cannot interrupt run in {self.status.value}")
        return replace(
            self,
            status=RunStatus.INTERRUPTED,
            resume_status=self.status,
        )

    def fail(self, failure: Failure) -> "RunLifecycle":
        if not isinstance(failure, Failure):
            raise TypeError("failure must be a Failure")
        if self.status not in _RESUMABLE_RUN_STATUSES:
            raise IllegalTransitionError(f"cannot fail run in {self.status.value}")
        if failure.disposition is FailureDisposition.RECOVERABLE:
            return replace(
                self,
                status=RunStatus.FAILED_RECOVERABLE,
                resume_status=self.status,
                failure=failure,
            )
        return replace(
            self,
            status=RunStatus.FAILED_FATAL,
            resume_status=None,
            failure=failure,
        )

    def resume(self) -> "RunLifecycle":
        if self.status not in {RunStatus.INTERRUPTED, RunStatus.FAILED_RECOVERABLE}:
            raise IllegalTransitionError(f"cannot resume run in {self.status.value}")
        return RunLifecycle(status=self.resume_status, epoch=self.epoch + 1)


@dataclass(frozen=True)
class ClaimToken:
    epoch: int
    attempt: int

    def __post_init__(self) -> None:
        _require_int("epoch", self.epoch)
        _require_int("attempt", self.attempt, 1)

    def assert_current(self, epoch: int, attempt: int) -> None:
        _require_int("epoch", epoch)
        _require_int("attempt", attempt, 1)
        if self.epoch != epoch or self.attempt != attempt:
            raise StaleClaimError(
                f"claim ({self.epoch}, {self.attempt}) is not current ({epoch}, {attempt})"
            )


@dataclass(frozen=True)
class RunSpec:
    input_sha256: str
    parser_version: str
    schema_version: str
    serializer_version: str
    engine_version: str
    redirect_policy_version: str
    tls_policy_version: str
    retry_policy_version: str
    timeout_policy_version: str
    evidence_limits_sha256: str
    fingerprint_sha256: str
    extension_sha256: str
    runtime_identity: str
    scanner_build: str

    def __post_init__(self) -> None:
        for name in (
            "input_sha256",
            "evidence_limits_sha256",
            "fingerprint_sha256",
            "extension_sha256",
        ):
            _require_digest(name, getattr(self, name))
        for name in (
            "parser_version",
            "schema_version",
            "serializer_version",
            "engine_version",
            "redirect_policy_version",
            "tls_policy_version",
            "retry_policy_version",
            "timeout_policy_version",
            "runtime_identity",
            "scanner_build",
        ):
            _require_text(name, getattr(self, name))


@dataclass(frozen=True)
class OperationalMetadata:
    cpu_count: int
    memory_bytes: int
    selected_workers: int
    degradation_reasons: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_int("cpu_count", self.cpu_count)
        _require_int("memory_bytes", self.memory_bytes)
        _require_int("selected_workers", self.selected_workers)
        reasons = _as_tuple(self.degradation_reasons)
        if any(not isinstance(reason, str) or not reason for reason in reasons):
            raise ValueError("degradation_reasons must contain non-empty strings")
        object.__setattr__(self, "degradation_reasons", reasons)


@dataclass(frozen=True)
class RunEvent:
    sequence: int
    kind: EventKind
    epoch: int
    status: RunStatus
    timestamp_ns: int
    failure: Optional[Failure] = None

    def __post_init__(self) -> None:
        _require_int("sequence", self.sequence)
        if not isinstance(self.kind, EventKind):
            raise TypeError("kind must be an EventKind")
        _require_int("epoch", self.epoch)
        if not isinstance(self.status, RunStatus):
            raise TypeError("status must be a RunStatus")
        _require_int("timestamp_ns", self.timestamp_ns)
        if self.failure is not None and not isinstance(self.failure, Failure):
            raise TypeError("failure must be a Failure or None")


@dataclass(frozen=True)
class ChannelRegistration:
    owner: ChannelOwner
    positive_fixture: str
    negative_fixture: str


def _channel(owner: ChannelOwner, name: str) -> ChannelRegistration:
    return ChannelRegistration(
        owner=owner,
        positive_fixture=f"channels/{name}/positive",
        negative_fixture=f"channels/{name}/negative",
    )


CHANNEL_REGISTRY: Mapping[str, ChannelRegistration] = MappingProxyType(
    {
        name: _channel(
            (
                ChannelOwner.STATIC
                if name in {"certIssuer", "dns", "probe", "robots"}
                else ChannelOwner.BROWSER
            ),
            name,
        )
        for name in (
            "certIssuer",
            "cookies",
            "css",
            "dns",
            "dom",
            "headers",
            "html",
            "js",
            "meta",
            "probe",
            "robots",
            "scriptSrc",
            "scripts",
            "text",
            "url",
            "xhr",
        )
    }
)


def aggregate_occurrence_status(
    endpoint: Optional[Endpoint],
    protocols: Sequence[ProtocolResult],
) -> OccurrenceStatus:
    if endpoint is None:
        return OccurrenceStatus.INVALID_INPUT
    if not protocols:
        return OccurrenceStatus.UNREACHABLE

    statuses = {result.status for result in protocols}
    if ProtocolStatus.INDETERMINATE in statuses or ProtocolStatus.PARTIAL in statuses:
        return OccurrenceStatus.PARTIAL
    if ProtocolStatus.SUCCESS in statuses:
        return OccurrenceStatus.SUCCESS
    if ProtocolStatus.SUCCESS_EMPTY in statuses:
        return OccurrenceStatus.SUCCESS_EMPTY
    return OccurrenceStatus.UNREACHABLE


@dataclass(frozen=True)
class CanonicalRecord:
    run_id: str
    occurrence: TargetOccurrence
    status: OccurrenceStatus
    error_codes: Tuple[FailureCode, ...] = ()
    protocols: Tuple[ProtocolResult, ...] = ()
    schema_version: str = CANONICAL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_text("run_id", self.run_id)
        if not isinstance(self.occurrence, TargetOccurrence):
            raise TypeError("occurrence must be a TargetOccurrence")
        if not isinstance(self.status, OccurrenceStatus):
            raise TypeError("status must be an OccurrenceStatus")
        error_codes = _as_tuple(self.error_codes)
        protocols = _as_tuple(self.protocols)
        _require_members("error_codes", error_codes, FailureCode)
        _require_members("protocols", protocols, ProtocolResult)
        if len({result.protocol for result in protocols}) != len(protocols):
            raise ValueError("protocols must contain at most one result per protocol")
        expected_status = aggregate_occurrence_status(self.occurrence.endpoint, protocols)
        if self.status is not expected_status:
            raise ValueError(
                f"status {self.status.value} does not match aggregate {expected_status.value}"
            )
        if self.status is OccurrenceStatus.INVALID_INPUT:
            if FailureCode.INVALID_INPUT not in error_codes:
                raise ValueError("invalid input records require the invalid_input error code")
            if protocols:
                raise ValueError("invalid input records cannot contain protocol results")
        if self.schema_version != CANONICAL_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {CANONICAL_SCHEMA_VERSION}")
        object.__setattr__(self, "error_codes", error_codes)
        object.__setattr__(self, "protocols", protocols)


_PROTOCOL_RANK = {protocol: index for index, protocol in enumerate(PROTOCOL_ORDER)}
_STAGE_RANK = {stage: index for index, stage in enumerate(StageName)}
_FAILURE_RANK = {code: index for index, code in enumerate(FailureCode)}
_EVIDENCE_LIMIT_RANK = {
    limit: index for index, limit in enumerate(EvidenceLimit)
}


def _ordered_errors(error_codes: Sequence[FailureCode]) -> list:
    return [code.value for code in sorted(set(error_codes), key=lambda code: _FAILURE_RANK[code])]


def _technology_document(technology: Technology) -> dict:
    return {
        "name": technology.name,
        "version": technology.version,
        "confidence": technology.confidence,
        "categories": sorted(set(technology.categories)),
        "groups": sorted(set(technology.groups)),
    }


def _stage_document(stage: StageResult) -> dict:
    return {
        "name": stage.name.value,
        "status": stage.status.value,
        "error_codes": _ordered_errors(stage.error_codes),
        "response_identity": (
            {
                "effective_url": stage.response_identity.effective_url,
                "http_status": stage.response_identity.http_status,
                "content_sha256": stage.response_identity.content_sha256,
            }
            if stage.response_identity is not None
            else None
        ),
        "technologies": [
            _technology_document(technology)
            for technology in sorted(
                stage.technologies,
                key=lambda item: (
                    item.name,
                    item.version,
                    item.confidence,
                    item.categories,
                    item.groups,
                ),
            )
        ],
        "truncations": [
            {
                "channel": truncation.channel,
                "limits": [
                    limit.value
                    for limit in sorted(
                        truncation.limits,
                        key=lambda item: _EVIDENCE_LIMIT_RANK[item],
                    )
                ],
            }
            for truncation in sorted(
                stage.truncations,
                key=lambda item: item.channel,
            )
        ],
    }


def _tls_document(tls: TLSMetadata) -> dict:
    document = {
        "present": tls.present,
        "trust": tls.trust.value,
    }
    if tls.certificate_sha256 is not None:
        document["certificate_sha256"] = tls.certificate_sha256
    return document


def _protocol_document(result: ProtocolResult) -> dict:
    return {
        "protocol": result.protocol.value,
        "status": result.status.value,
        "requested_url": result.requested_url,
        "effective_url": result.effective_url,
        "http_status": result.http_status,
        "tls": _tls_document(result.tls),
        "observation": result.observation.value,
        "stages": [
            _stage_document(stage)
            for stage in sorted(result.stages, key=lambda item: _STAGE_RANK[item.name])
        ],
        "technologies": [
            _technology_document(technology)
            for technology in sorted(
                result.technologies,
                key=lambda item: (
                    item.name,
                    item.version,
                    item.confidence,
                    item.categories,
                    item.groups,
                ),
            )
        ],
        "error_codes": _ordered_errors(result.error_codes),
    }


def _canonical_document(record: CanonicalRecord) -> dict:
    endpoint = record.occurrence.endpoint
    return {
        "schema_version": record.schema_version,
        "run_id": record.run_id,
        "occurrence": {
            "sequence": record.occurrence.sequence,
            "line_number": record.occurrence.line_number,
            "byte_offset": record.occurrence.byte_offset,
            "line_digest": record.occurrence.line_digest,
        },
        "endpoint": (
            {"address": endpoint.address, "port": endpoint.port} if endpoint is not None else None
        ),
        "status": record.status.value,
        "error_codes": _ordered_errors(record.error_codes),
        "protocols": [
            _protocol_document(result)
            for result in sorted(
                record.protocols,
                key=lambda item: _PROTOCOL_RANK[item.protocol],
            )
        ],
    }


def canonical_json_bytes(record: CanonicalRecord) -> bytes:
    if not isinstance(record, CanonicalRecord):
        raise TypeError("record must be a CanonicalRecord")
    return json.dumps(
        _canonical_document(record),
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_ndjson_bytes(records: Iterable[CanonicalRecord]) -> bytes:
    return b"".join(canonical_json_bytes(record) + b"\n" for record in records)
