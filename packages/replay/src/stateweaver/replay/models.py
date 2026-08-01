"""Versioned, deterministic replay data structures."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Annotated, Any, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    field_serializer,
    field_validator,
    model_validator,
)
from stateweaver.contracts import (
    ActionEnvelope,
    ArtifactHandle,
    HttpRequestAction,
    OracleResult,
    TraceId,
)

NonEmpty = Annotated[str, Field(min_length=1, max_length=256)]
Sha256 = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]


def _jsonable(value: Any) -> JsonValue:
    """Convert supported model values to their stable JSON representation."""

    if isinstance(value, BaseModel):
        return _jsonable(value.model_dump(mode="python", by_alias=True, exclude_none=False))
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("canonical datetimes must be timezone-aware")
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("canonical JSON mappings require string keys")
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, (set, frozenset)):
        converted = [_jsonable(item) for item in value]
        return sorted(
            converted,
            key=lambda item: json.dumps(
                item,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
        )
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"Unsupported canonical JSON value: {type(value).__name__}")


def canonical_sha256(value: Any) -> str:
    """Hash canonical JSON without depending on insertion order or platform formatting."""

    encoded = json.dumps(
        _jsonable(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("JSON mappings require string keys")
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item) for item in value)
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("JSON floating-point values must be finite")
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw_json(item) for item in value]
    return value


class StrictFrozenModel(BaseModel):
    """Immutable boundary model that rejects undeclared input."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class CaptureLayer(StrEnum):
    APPLICATION = "application"
    DATABASE = "database"
    CACHE = "cache"
    QUEUE = "queue"
    BROWSER = "browser"
    CONFIGURATION = "configuration"
    CLOCK = "clock"


class StateArtifact(StrictFrozenModel):
    """One normalized, content-addressed state layer."""

    layer: CaptureLayer
    schema_version: Annotated[str, Field(pattern=r"^[1-9][0-9]*\.[0-9]+$")] = "1.0"
    payload: Mapping[str, JsonValue]
    content_hash: Sha256

    @field_validator("payload")
    @classmethod
    def payload_is_deeply_immutable(cls, value: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
        return cast(Mapping[str, JsonValue], _freeze_json(value))

    @field_serializer("payload")
    def serialize_payload(self, value: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
        return cast(dict[str, JsonValue], _thaw_json(value))

    @model_validator(mode="after")
    def hash_matches_payload(self) -> StateArtifact:
        expected = canonical_sha256(self.payload)
        if self.content_hash != expected:
            raise ValueError(f"content_hash does not match payload; expected {expected}")
        return self

    @classmethod
    def from_payload(
        cls,
        *,
        layer: CaptureLayer,
        payload: Mapping[str, JsonValue],
        schema_version: str = "1.0",
    ) -> StateArtifact:
        return cls(
            layer=layer,
            schema_version=schema_version,
            payload=payload,
            content_hash=canonical_sha256(payload),
        )


class StateCapture(StrictFrozenModel):
    """Security-relevant state captured at a controlled point in a replay."""

    capture_id: NonEmpty
    controlled_at: datetime
    artifacts: tuple[StateArtifact, ...]
    fingerprint: Sha256

    @field_validator("controlled_at")
    @classmethod
    def controlled_time_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("controlled_at must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def fingerprint_matches_artifacts(self) -> StateCapture:
        layers = [artifact.layer for artifact in self.artifacts]
        if len(layers) != len(set(layers)):
            raise ValueError("a capture cannot contain duplicate layers")
        canonical = {
            "controlled_at": self.controlled_at,
            "artifacts": sorted(
                (
                    {
                        "layer": artifact.layer,
                        "schema_version": artifact.schema_version,
                        "content_hash": artifact.content_hash,
                    }
                    for artifact in self.artifacts
                ),
                key=lambda item: str(item["layer"]),
            ),
        }
        expected = canonical_sha256(canonical)
        if self.fingerprint != expected:
            raise ValueError(f"fingerprint does not match artifacts; expected {expected}")
        return self

    @classmethod
    def from_artifacts(
        cls,
        *,
        capture_id: str,
        controlled_at: datetime,
        artifacts: tuple[StateArtifact, ...],
    ) -> StateCapture:
        if controlled_at.tzinfo is None or controlled_at.utcoffset() is None:
            # Route invalid input through the model so callers receive the same
            # structured ValidationError as direct construction.
            return cls(
                capture_id=capture_id,
                controlled_at=controlled_at,
                artifacts=artifacts,
                fingerprint=f"sha256:{'0' * 64}",
            )
        canonical = {
            "controlled_at": controlled_at,
            "artifacts": sorted(
                (
                    {
                        "layer": artifact.layer,
                        "schema_version": artifact.schema_version,
                        "content_hash": artifact.content_hash,
                    }
                    for artifact in artifacts
                ),
                key=lambda item: str(item["layer"]),
            ),
        }
        return cls(
            capture_id=capture_id,
            controlled_at=controlled_at,
            artifacts=artifacts,
            fingerprint=canonical_sha256(canonical),
        )


class RootSeed(StrictFrozenModel):
    """Pinned clean state from which every candidate chain is rebuilt."""

    root_seed_id: NonEmpty
    target_version: NonEmpty
    random_seed: Annotated[int, Field(ge=0, le=2**63 - 1)]
    clock_epoch: datetime
    capture: StateCapture
    adapter_versions: Mapping[NonEmpty, NonEmpty] = Field(default_factory=dict)

    @field_validator("adapter_versions")
    @classmethod
    def adapter_versions_are_immutable(cls, value: Mapping[str, str]) -> Mapping[str, str]:
        return MappingProxyType(dict(value))

    @field_serializer("adapter_versions")
    def serialize_adapter_versions(self, value: Mapping[str, str]) -> dict[str, str]:
        return dict(value)

    @field_validator("clock_epoch")
    @classmethod
    def epoch_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("clock_epoch must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def capture_matches_epoch(self) -> RootSeed:
        if self.capture.controlled_at != self.clock_epoch:
            raise ValueError("root capture controlled_at must equal clock_epoch")
        return self


class ReplayObservation(StrictFrozenModel):
    """Redacted machine observation emitted by a typed action executor."""

    observation_id: NonEmpty
    kind: NonEmpty
    payload: Mapping[str, JsonValue]
    evidence_ids: tuple[NonEmpty, ...] = ()

    @field_validator("payload")
    @classmethod
    def payload_is_deeply_immutable(cls, value: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
        return cast(Mapping[str, JsonValue], _freeze_json(value))

    @field_serializer("payload")
    def serialize_payload(self, value: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
        return cast(dict[str, JsonValue], _thaw_json(value))


class OracleExpectation(StrictFrozenModel):
    """Expected verdict set for one named oracle after a replay step."""

    oracle_id: NonEmpty
    allowed_results: frozenset[NonEmpty]

    @field_validator("allowed_results")
    @classmethod
    def at_least_one_allowed_result(cls, value: frozenset[str]) -> frozenset[str]:
        if not value:
            raise ValueError("allowed_results cannot be empty")
        return value


class ReplayStep(StrictFrozenModel):
    step_id: NonEmpty
    action: ActionEnvelope
    oracle_expectations: tuple[OracleExpectation, ...] = ()
    timeout_seconds: Annotated[float, Field(gt=0, le=60)] = 10.0

    @model_validator(mode="after")
    def timeout_does_not_expand_authorization(self) -> ReplayStep:
        if self.timeout_seconds * 1_000 > self.action.timeout_ms:
            raise ValueError("step timeout cannot exceed the authorized action timeout")
        oracle_ids = [expectation.oracle_id for expectation in self.oracle_expectations]
        if len(oracle_ids) != len(set(oracle_ids)):
            raise ValueError("oracle expectations must be unique by oracle_id")
        return self


class ReplayPlan(StrictFrozenModel):
    schema_version: Annotated[str, Field(pattern=r"^[1-9][0-9]*\.[0-9]+$")] = "1.0"
    plan_id: NonEmpty
    root_seed_id: NonEmpty
    steps: Annotated[tuple[ReplayStep, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def identifiers_are_unique(self) -> ReplayPlan:
        step_ids = [step.step_id for step in self.steps]
        reserved = {"root", "preflight", "environment", "cleanup"}
        if reserved & set(step_ids):
            raise ValueError("replay step IDs cannot use reserved boundary names")
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("step_id values must be unique")
        idempotency_keys = [step.action.idempotency_key for step in self.steps]
        if len(idempotency_keys) != len(set(idempotency_keys)):
            raise ValueError("idempotency_key values must be unique within a replay plan")
        sequences = [step.action.sequence for step in self.steps]
        if sequences != sorted(sequences) or len(sequences) != len(set(sequences)):
            raise ValueError("action sequence values must be unique and monotonically increasing")
        return self


class ReplayStepStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ReplayStepResult(StrictFrozenModel):
    step_id: NonEmpty
    status: ReplayStepStatus
    before_fingerprint: Sha256 | None = None
    after_fingerprint: Sha256 | None = None
    observations: tuple[ReplayObservation, ...] = ()
    oracle_results: tuple[OracleResult, ...] = ()
    failure_code: NonEmpty | None = None
    failure_message: Annotated[str, Field(max_length=500)] | None = None

    @model_validator(mode="after")
    def failure_shape_matches_status(self) -> ReplayStepResult:
        has_failure = self.failure_code is not None or self.failure_message is not None
        if self.status is ReplayStepStatus.FAILED and not has_failure:
            raise ValueError("failed step requires failure_code or failure_message")
        if self.status is not ReplayStepStatus.FAILED and has_failure:
            raise ValueError("only failed steps may contain failure details")
        return self


class ReplayActionLogEntry(StrictFrozenModel):
    """Content-addressed causal record for one planned replay action."""

    step_id: NonEmpty
    action: ActionEnvelope
    action_id: NonEmpty
    action_type: NonEmpty
    sequence: int = Field(ge=0)
    status: ReplayStepStatus
    idempotency_key: Sha256
    policy_decision_ref: NonEmpty
    trace_id: TraceId
    parameter_artifact: ArtifactHandle | None = None
    envelope_hash: Sha256
    request_template_hash: Sha256
    before_fingerprint: Sha256 | None = None
    after_fingerprint: Sha256 | None = None
    observation_hash: Sha256
    oracle_results_hash: Sha256
    evidence_ids: tuple[NonEmpty, ...] = ()

    @field_validator("evidence_ids")
    @classmethod
    def evidence_is_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("action-log evidence IDs must be unique")
        return value

    @model_validator(mode="after")
    def duplicated_action_fields_match_envelope(self) -> ReplayActionLogEntry:
        parameter_artifact = (
            self.action.action.body_artifact
            if isinstance(self.action.action, HttpRequestAction)
            else None
        )
        if (
            self.action_id != self.action.action_id
            or self.action_type != self.action.action_type
            or self.sequence != self.action.sequence
            or self.idempotency_key != self.action.idempotency_key
            or self.policy_decision_ref != self.action.policy_decision_ref
            or self.parameter_artifact != parameter_artifact
            or self.envelope_hash != canonical_sha256(self.action)
            or self.request_template_hash != canonical_sha256(self.action.action)
        ):
            raise ValueError("action-log metadata does not match its typed envelope")
        return self


class ReplayRunStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    ROOT_DIVERGED = "root_diverged"
    CLEANUP_FAILED = "cleanup_failed"


class DeterminismClassification(StrEnum):
    DETERMINISTIC = "DETERMINISTIC"
    NONDETERMINISTIC = "NONDETERMINISTIC"


class ReplayRunResult(StrictFrozenModel):
    run_id: NonEmpty
    plan_id: NonEmpty
    status: ReplayRunStatus
    root_fingerprint: Sha256 | None = None
    final_fingerprint: Sha256 | None = None
    steps: tuple[ReplayStepResult, ...]
    action_log: tuple[ReplayActionLogEntry, ...]
    failed_step_id: NonEmpty | None = None
    trace_hash: Sha256

    @model_validator(mode="after")
    def action_log_matches_step_results(self) -> ReplayRunResult:
        step_ids = [step.step_id for step in self.steps]
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("replay result step IDs must be unique")
        failed_steps = [step for step in self.steps if step.status is ReplayStepStatus.FAILED]
        if self.status is ReplayRunStatus.SUCCEEDED:
            if not self.steps or any(
                step.status is not ReplayStepStatus.PASSED for step in self.steps
            ):
                raise ValueError("a successful replay requires only passed action steps")
            if self.root_fingerprint is None or self.final_fingerprint is None:
                raise ValueError("a successful replay requires root and final fingerprints")
            if self.failed_step_id is not None:
                raise ValueError("a successful replay cannot identify a failed step")
        else:
            if not failed_steps:
                raise ValueError("a non-successful replay requires a failed boundary step")
            if self.failed_step_id != failed_steps[0].step_id:
                raise ValueError("failed_step_id must identify the first failed boundary step")
        if self.status is ReplayRunStatus.ROOT_DIVERGED and (
            failed_steps[0].step_id != "root"
            or failed_steps[0].failure_code != "ROOT_FINGERPRINT_MISMATCH"
        ):
            raise ValueError("root-diverged status requires a root fingerprint failure")
        cleanup_steps = [step for step in failed_steps if step.step_id == "cleanup"]
        if (self.status is ReplayRunStatus.CLEANUP_FAILED) != bool(cleanup_steps):
            raise ValueError("cleanup-failed status must match a cleanup boundary failure")

        log_ids = [entry.step_id for entry in self.action_log]
        if len(log_ids) != len(set(log_ids)):
            raise ValueError("action-log step IDs must be unique")
        reserved = {"root", "preflight", "environment", "cleanup"}
        expected_ids = [step.step_id for step in self.steps if step.step_id not in reserved]
        if log_ids != expected_ids:
            raise ValueError("action log must match replay action-step order exactly")
        results = {step.step_id: step for step in self.steps}
        for entry in self.action_log:
            result = results.get(entry.step_id)
            if result is None or result.status is not entry.status:
                raise ValueError("action-log status does not match its replay step")
            evidence_ids = tuple(
                dict.fromkeys(
                    evidence_id
                    for evidence_group in (
                        *(item.evidence_ids for item in result.observations),
                        *(item.evidence_ids for item in result.oracle_results),
                    )
                    for evidence_id in evidence_group
                )
            )
            if (
                entry.before_fingerprint != result.before_fingerprint
                or entry.after_fingerprint != result.after_fingerprint
                or entry.observation_hash != canonical_sha256(result.observations)
                or entry.oracle_results_hash != canonical_sha256(result.oracle_results)
                or entry.evidence_ids != evidence_ids
            ):
                raise ValueError("action-log result hashes do not match the replay step")
            expected_trace_id = canonical_sha256(
                {
                    "plan_id": self.plan_id,
                    "step_id": entry.step_id,
                    "envelope_hash": entry.envelope_hash,
                }
            ).removeprefix("sha256:")[:32]
            if entry.trace_id != expected_trace_id:
                raise ValueError("action-log trace ID does not match its causal inputs")
        expected_trace_hash = canonical_sha256(
            {
                "plan_id": self.plan_id,
                "status": self.status,
                "root_fingerprint": self.root_fingerprint,
                "final_fingerprint": self.final_fingerprint,
                "steps": self.steps,
                "action_log": self.action_log,
                "failed_step_id": self.failed_step_id,
            }
        )
        if self.trace_hash != expected_trace_hash:
            raise ValueError("trace_hash does not match replay result content")
        return self

    def deterministic_signature(self) -> Sha256:
        """Hash replay semantics while excluding the caller-supplied run identifier."""

        return canonical_sha256(
            {
                "plan_id": self.plan_id,
                "status": self.status,
                "root_fingerprint": self.root_fingerprint,
                "final_fingerprint": self.final_fingerprint,
                "steps": self.steps,
                "action_log": self.action_log,
                "failed_step_id": self.failed_step_id,
            }
        )


class DeterminismReport(StrictFrozenModel):
    plan_id: NonEmpty
    run_ids: Annotated[tuple[NonEmpty, ...], Field(min_length=2)]
    run_statuses: Annotated[tuple[ReplayRunStatus, ...], Field(min_length=2)]
    signatures: Annotated[tuple[Sha256, ...], Field(min_length=2)]
    deterministic: bool
    all_runs_succeeded: bool
    classification: DeterminismClassification
    divergent_run_id: NonEmpty | None = None

    @model_validator(mode="after")
    def classification_matches_boolean(self) -> DeterminismReport:
        if len(self.run_ids) != len(self.run_statuses) or len(self.run_ids) != len(self.signatures):
            raise ValueError("determinism report run vectors must have equal lengths")
        if len(self.run_ids) != len(set(self.run_ids)):
            raise ValueError("determinism report run IDs must be unique")
        expected_success = all(status is ReplayRunStatus.SUCCEEDED for status in self.run_statuses)
        if self.all_runs_succeeded is not expected_success:
            raise ValueError("all_runs_succeeded does not match run statuses")
        signatures_match = not self.signatures or len(set(self.signatures)) == 1
        if self.deterministic is not signatures_match:
            raise ValueError("deterministic flag does not match replay signatures")
        expected = (
            DeterminismClassification.DETERMINISTIC
            if self.deterministic
            else DeterminismClassification.NONDETERMINISTIC
        )
        if self.classification is not expected:
            raise ValueError("determinism classification is inconsistent")
        if self.deterministic != (self.divergent_run_id is None):
            raise ValueError("divergent_run_id must identify a nondeterministic run")
        if not self.deterministic:
            reference = self.signatures[0]
            first_divergent = next(
                run_id
                for run_id, signature in zip(self.run_ids, self.signatures, strict=True)
                if signature != reference
            )
            if self.divergent_run_id != first_divergent:
                raise ValueError("divergent_run_id does not identify the first divergent signature")
        return self
