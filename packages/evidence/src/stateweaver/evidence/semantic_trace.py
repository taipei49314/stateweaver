"""Deterministic event semantics derived from immutable replay results.

The models in this module are occurrence-bound: an artifact and every event name the exact
``run_id`` that produced them.  ``semantic_trace_hash`` deliberately removes only occurrence
identity so independent runs with identical replay semantics remain comparable.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Annotated, ClassVar, Final, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)
from stateweaver.replay import (
    ReplayActionLogEntry,
    ReplayRunResult,
    ReplayStepResult,
    canonical_sha256,
)

TRACE_SCHEMA_VERSION: Final = "2.0"
SEMANTIC_TRACE_ALGORITHM: Final = "stateweaver.replay-step-events.v1"

_EVENT_ID_DOMAIN: Final = "stateweaver.reality.trace-event-id.v2"
_EVENT_HASH_DOMAIN: Final = "stateweaver.reality.trace-event.v2"
_EVENT_TRACE_ID_DOMAIN: Final = "stateweaver.reality.event-trace-id.v2"
_FAILURE_MESSAGE_DOMAIN: Final = "stateweaver.reality.failure-message.v1"
_SEMANTIC_TRACE_DOMAIN: Final = "stateweaver.reality.semantic-trace.v2"
_RESERVED_BOUNDARIES: Final = frozenset({"root", "preflight", "environment", "cleanup"})

NonEmpty = Annotated[str, StringConstraints(min_length=1, max_length=256)]
FactName = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9]*(?:[._:-][a-z0-9][a-z0-9_-]*)*$",
    ),
]
Sha256 = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
TraceId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
EventId = Annotated[str, StringConstraints(pattern=r"^trace\.event:[0-9a-f]{24}$")]
type RealityTraceFactValue = str | int | bool | tuple[str, ...] | None


class _SemanticTraceModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
        str_strip_whitespace=True,
        validate_default=True,
    )


class RealityTraceLane(StrEnum):
    PRIMARY = "primary"
    CONTROL = "control"
    PATCH = "patch"


class RealityTraceEventKind(StrEnum):
    BOUNDARY = "boundary"
    ACTION = "action"


class RealityTraceEventType(StrEnum):
    REPLAY_STARTED = "replay.started"
    REPLAY_STEP = "replay.step"
    REPLAY_COMPLETED = "replay.completed"
    PATCH_REPLAY_COMPLETED = "patch.replay.completed"


class RealityTraceFact(_SemanticTraceModel):
    """One canonical, typed fact in an event projection."""

    name: FactName
    value: RealityTraceFactValue


def _canonical_facts(
    values: Mapping[str, RealityTraceFactValue],
) -> tuple[RealityTraceFact, ...]:
    return tuple(RealityTraceFact(name=name, value=value) for name, value in sorted(values.items()))


def _event_kind(event_type: RealityTraceEventType, step_id: str | None) -> RealityTraceEventKind:
    if event_type is not RealityTraceEventType.REPLAY_STEP or step_id in _RESERVED_BOUNDARIES:
        return RealityTraceEventKind.BOUNDARY
    return RealityTraceEventKind.ACTION


def _event_id(
    *,
    event_type: RealityTraceEventType,
    run_id: str,
    plan_id: str,
    sequence: int,
    step_id: str | None,
) -> str:
    digest = canonical_sha256(
        {
            "domain": _EVENT_ID_DOMAIN,
            "event_type": event_type,
            "plan_id": plan_id,
            "run_id": run_id,
            "sequence": sequence,
            "step_id": step_id,
        }
    )
    return f"trace.event:{digest.removeprefix('sha256:')[:24]}"


def _derived_trace_id(
    *, event_type: RealityTraceEventType, plan_id: str, sequence: int, step_id: str | None
) -> str:
    return canonical_sha256(
        {
            "domain": _EVENT_TRACE_ID_DOMAIN,
            "event_type": event_type,
            "plan_id": plan_id,
            "sequence": sequence,
            "step_id": step_id,
        }
    ).removeprefix("sha256:")[:32]


def _event_projection(
    *,
    event_id: str,
    event_type: RealityTraceEventType,
    kind: RealityTraceEventKind,
    run_id: str,
    plan_id: str,
    sequence: int,
    trace_id: str,
    step_id: str | None,
    payload: tuple[RealityTraceFact, ...],
) -> dict[str, object]:
    return {
        "domain": _EVENT_HASH_DOMAIN,
        "event_id": event_id,
        "event_type": event_type,
        "kind": kind,
        "payload": payload,
        "plan_id": plan_id,
        "run_id": run_id,
        "sequence": sequence,
        "step_id": step_id,
        "trace_id": trace_id,
    }


class RealityTraceEventV2(_SemanticTraceModel):
    """One occurrence-bound event with a content-derived identity and hash."""

    event_id: EventId
    event_type: RealityTraceEventType
    kind: RealityTraceEventKind
    run_id: NonEmpty
    plan_id: NonEmpty
    sequence: Annotated[int, Field(ge=0)]
    trace_id: TraceId
    step_id: NonEmpty | None = None
    payload: Annotated[tuple[RealityTraceFact, ...], Field(min_length=1)]
    event_sha256: Sha256

    @classmethod
    def create(
        cls,
        *,
        event_type: RealityTraceEventType,
        run_id: str,
        plan_id: str,
        sequence: int,
        trace_id: str | None,
        step_id: str | None,
        payload: tuple[RealityTraceFact, ...],
    ) -> Self:
        canonical_payload = tuple(
            sorted(
                (RealityTraceFact.model_validate(fact) for fact in payload),
                key=lambda fact: fact.name,
            )
        )
        kind = _event_kind(event_type, step_id)
        resolved_trace_id = trace_id or _derived_trace_id(
            event_type=event_type,
            plan_id=plan_id,
            sequence=sequence,
            step_id=step_id,
        )
        event_id = _event_id(
            event_type=event_type,
            run_id=run_id,
            plan_id=plan_id,
            sequence=sequence,
            step_id=step_id,
        )
        event_sha256 = canonical_sha256(
            _event_projection(
                event_id=event_id,
                event_type=event_type,
                kind=kind,
                run_id=run_id,
                plan_id=plan_id,
                sequence=sequence,
                trace_id=resolved_trace_id,
                step_id=step_id,
                payload=canonical_payload,
            )
        )
        return cls(
            event_id=event_id,
            event_type=event_type,
            kind=kind,
            run_id=run_id,
            plan_id=plan_id,
            sequence=sequence,
            trace_id=resolved_trace_id,
            step_id=step_id,
            payload=canonical_payload,
            event_sha256=event_sha256,
        )

    @field_validator("payload")
    @classmethod
    def payload_is_canonical_and_unique(
        cls, value: tuple[RealityTraceFact, ...]
    ) -> tuple[RealityTraceFact, ...]:
        names = tuple(fact.name for fact in value)
        if names != tuple(sorted(names)) or len(names) != len(set(names)):
            raise ValueError("trace event facts must be unique and canonically ordered")
        return value

    @model_validator(mode="after")
    def identity_shape_and_hash_match_content(self) -> RealityTraceEventV2:
        is_step = self.event_type is RealityTraceEventType.REPLAY_STEP
        if is_step != (self.step_id is not None):
            raise ValueError("only replay step events may carry a step id")
        expected_kind = _event_kind(self.event_type, self.step_id)
        if self.kind is not expected_kind:
            raise ValueError("trace event kind does not match its event type and step")
        expected_id = _event_id(
            event_type=self.event_type,
            run_id=self.run_id,
            plan_id=self.plan_id,
            sequence=self.sequence,
            step_id=self.step_id,
        )
        if self.event_id != expected_id:
            raise ValueError("trace event id does not match its occurrence identity")
        expected_hash = canonical_sha256(
            _event_projection(
                event_id=self.event_id,
                event_type=self.event_type,
                kind=self.kind,
                run_id=self.run_id,
                plan_id=self.plan_id,
                sequence=self.sequence,
                trace_id=self.trace_id,
                step_id=self.step_id,
                payload=self.payload,
            )
        )
        if self.event_sha256 != expected_hash:
            raise ValueError("trace event hash does not match its content")
        return self

    def semantic_projection(self) -> dict[str, object]:
        """Return the event projection with occurrence-only identity removed."""

        return {
            "event_type": self.event_type,
            "kind": self.kind,
            "payload": self.payload,
            "plan_id": self.plan_id,
            "sequence": self.sequence,
            "step_id": self.step_id,
            "trace_id": self.trace_id,
        }


def _semantic_trace_sha256(
    *,
    lane: RealityTraceLane,
    plan_id: str,
    replay_trace_hash: str,
    events: tuple[RealityTraceEventV2, ...],
) -> str:
    return canonical_sha256(
        {
            "algorithm": SEMANTIC_TRACE_ALGORITHM,
            "domain": _SEMANTIC_TRACE_DOMAIN,
            "events": tuple(event.semantic_projection() for event in events),
            "lane": lane,
            "plan_id": plan_id,
            "replay_trace_hash": replay_trace_hash,
            "schema_version": TRACE_SCHEMA_VERSION,
        }
    )


def _evidence_ids(step: ReplayStepResult) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            evidence_id
            for evidence_group in (
                *(observation.evidence_ids for observation in step.observations),
                *(oracle.evidence_ids for oracle in step.oracle_results),
            )
            for evidence_id in evidence_group
        )
    )


def _failure_message_sha256(message: str | None) -> str | None:
    if message is None:
        return None
    return canonical_sha256({"domain": _FAILURE_MESSAGE_DOMAIN, "message": message})


def _step_payload(
    step: ReplayStepResult, action: ReplayActionLogEntry | None
) -> tuple[RealityTraceFact, ...]:
    evidence_ids = _evidence_ids(step)
    return _canonical_facts(
        {
            "action_id": None if action is None else action.action_id,
            "action_sequence": None if action is None else action.sequence,
            "action_trace_id": None if action is None else action.trace_id,
            "action_type": None if action is None else action.action_type,
            "after_fingerprint": step.after_fingerprint,
            "before_fingerprint": step.before_fingerprint,
            "envelope_hash": None if action is None else action.envelope_hash,
            "evidence_ids": evidence_ids,
            "failure_code": step.failure_code,
            "failure_message_sha256": _failure_message_sha256(step.failure_message),
            "idempotency_key": None if action is None else action.idempotency_key,
            "observation_hash": canonical_sha256(step.observations),
            "oracle_results_hash": canonical_sha256(step.oracle_results),
            "parameter_artifact": None if action is None else action.parameter_artifact,
            "policy_decision_ref": None if action is None else action.policy_decision_ref,
            "request_template_hash": None if action is None else action.request_template_hash,
            "status": step.status.value,
        }
    )


class RealityTraceArtifactV2(_SemanticTraceModel):
    """A replay trace whose complete event narrative is deterministically reconstructable."""

    schema_version: Literal["2.0"] = "2.0"
    algorithm: Literal["stateweaver.replay-step-events.v1"] = SEMANTIC_TRACE_ALGORITHM
    lane: RealityTraceLane
    run_id: NonEmpty
    plan_id: NonEmpty
    replay_trace_hash: Sha256
    semantic_trace_hash: Sha256
    events: Annotated[tuple[RealityTraceEventV2, ...], Field(min_length=3)]

    @classmethod
    def create(
        cls,
        *,
        lane: RealityTraceLane,
        run_id: str,
        plan_id: str,
        replay_trace_hash: str,
        events: tuple[RealityTraceEventV2, ...],
    ) -> Self:
        validated_events = tuple(RealityTraceEventV2.model_validate(event) for event in events)
        return cls(
            lane=lane,
            run_id=run_id,
            plan_id=plan_id,
            replay_trace_hash=replay_trace_hash,
            semantic_trace_hash=_semantic_trace_sha256(
                lane=lane,
                plan_id=plan_id,
                replay_trace_hash=replay_trace_hash,
                events=validated_events,
            ),
            events=validated_events,
        )

    @classmethod
    def from_replay_result(cls, result: ReplayRunResult, *, lane: RealityTraceLane) -> Self:
        validated = ReplayRunResult.model_validate(result.model_dump(mode="python"))
        action_by_step = {entry.step_id: entry for entry in validated.action_log}
        events: list[RealityTraceEventV2] = [
            RealityTraceEventV2.create(
                event_type=RealityTraceEventType.REPLAY_STARTED,
                run_id=validated.run_id,
                plan_id=validated.plan_id,
                sequence=0,
                trace_id=None,
                step_id=None,
                payload=_canonical_facts(
                    {
                        "lane": lane.value,
                        "root_fingerprint": validated.root_fingerprint,
                    }
                ),
            )
        ]
        for sequence, step in enumerate(validated.steps, start=1):
            action = action_by_step.get(step.step_id)
            if step.step_id not in _RESERVED_BOUNDARIES and action is None:
                raise ValueError("replay action step is missing its typed action-log entry")
            trace_id = (
                action.trace_id
                if action is not None
                else _derived_trace_id(
                    event_type=RealityTraceEventType.REPLAY_STEP,
                    plan_id=validated.plan_id,
                    sequence=sequence,
                    step_id=step.step_id,
                )
            )
            events.append(
                RealityTraceEventV2.create(
                    event_type=RealityTraceEventType.REPLAY_STEP,
                    run_id=validated.run_id,
                    plan_id=validated.plan_id,
                    sequence=sequence,
                    trace_id=trace_id,
                    step_id=step.step_id,
                    payload=_step_payload(step, action),
                )
            )
        completed_type = (
            RealityTraceEventType.PATCH_REPLAY_COMPLETED
            if lane is RealityTraceLane.PATCH
            else RealityTraceEventType.REPLAY_COMPLETED
        )
        completion_sequence = len(events)
        events.append(
            RealityTraceEventV2.create(
                event_type=completed_type,
                run_id=validated.run_id,
                plan_id=validated.plan_id,
                sequence=completion_sequence,
                trace_id=None,
                step_id=None,
                payload=_canonical_facts(
                    {
                        "failed_step_id": validated.failed_step_id,
                        "final_fingerprint": validated.final_fingerprint,
                        "replay_trace_hash": validated.trace_hash,
                        "run_status": validated.status.value,
                    }
                ),
            )
        )
        return cls.create(
            lane=lane,
            run_id=validated.run_id,
            plan_id=validated.plan_id,
            replay_trace_hash=validated.trace_hash,
            events=tuple(events),
        )

    @model_validator(mode="after")
    def event_closure_and_semantic_hash_match(self) -> RealityTraceArtifactV2:
        sequences = tuple(event.sequence for event in self.events)
        if sequences != tuple(range(len(self.events))):
            raise ValueError("trace event sequences must be contiguous and ordered")
        if len({event.event_id for event in self.events}) != len(self.events):
            raise ValueError("trace event ids must be unique")
        if any(event.run_id != self.run_id for event in self.events):
            raise ValueError("trace events must bind the artifact run id")
        if any(event.plan_id != self.plan_id for event in self.events):
            raise ValueError("trace events must bind the artifact plan id")
        if self.events[0].event_type is not RealityTraceEventType.REPLAY_STARTED:
            raise ValueError("trace must start with replay.started")
        expected_completion = (
            RealityTraceEventType.PATCH_REPLAY_COMPLETED
            if self.lane is RealityTraceLane.PATCH
            else RealityTraceEventType.REPLAY_COMPLETED
        )
        if self.events[-1].event_type is not expected_completion:
            raise ValueError("trace completion event does not match its lane")
        step_events = self.events[1:-1]
        if any(event.event_type is not RealityTraceEventType.REPLAY_STEP for event in step_events):
            raise ValueError("trace interior must contain only replay.step events")
        step_ids = tuple(event.step_id for event in step_events)
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("trace step event ids must be unique")
        expected_hash = _semantic_trace_sha256(
            lane=self.lane,
            plan_id=self.plan_id,
            replay_trace_hash=self.replay_trace_hash,
            events=self.events,
        )
        if self.semantic_trace_hash != expected_hash:
            raise ValueError("semantic trace hash does not match event semantics")
        return self

    def matches_replay_result(self, result: ReplayRunResult) -> bool:
        return self == type(self).from_replay_result(result, lane=self.lane)

    def require_replay_result(self, result: ReplayRunResult) -> None:
        if not self.matches_replay_result(result):
            raise ValueError("replay trace semantics do not match the replay result")


def derive_reality_trace_v2(
    result: ReplayRunResult, *, lane: RealityTraceLane
) -> RealityTraceArtifactV2:
    """Derive the only valid V2 event narrative for a typed replay result."""

    return RealityTraceArtifactV2.from_replay_result(result, lane=lane)


# Compatibility aliases let the M6 resolver adopt V2 without obscuring its explicit schema class.
RealityTraceEvent = RealityTraceEventV2
RealityTraceArtifact = RealityTraceArtifactV2

__all__ = [
    "SEMANTIC_TRACE_ALGORITHM",
    "TRACE_SCHEMA_VERSION",
    "RealityTraceArtifact",
    "RealityTraceArtifactV2",
    "RealityTraceEvent",
    "RealityTraceEventKind",
    "RealityTraceEventType",
    "RealityTraceEventV2",
    "RealityTraceFact",
    "RealityTraceLane",
    "derive_reality_trace_v2",
]
