"""Versioned, self-verifying event contracts defined by Architecture section 15."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Literal, Self, cast

from pydantic import ConfigDict, JsonValue, field_serializer, field_validator, model_validator

from .actions import RequestedBy
from .base import (
    AwareTimestampMixin,
    ContractId,
    ContractModel,
    PositiveInt,
    Sha256Digest,
    TraceId,
    freeze_json,
    sha256_digest,
    thaw_json,
)
from .enums import EventType

_EVENT_SEMANTIC_DOMAIN = "stateweaver.event.semantic.v2"
_EVENT_ID_DOMAIN = "stateweaver.event.id.v2"
_EVENT_HISTORY_DOMAIN = "stateweaver.event.history.v2"


class _EventContractV2(ContractModel):
    """Closed v2 base that also revalidates untrusted constructed model instances."""

    model_config = ConfigDict(revalidate_instances="always")

    schema_version: Literal["2.0"] = "2.0"


def _semantic_hash(
    *,
    schema_version: Literal["2.0"],
    event_type: EventType,
    experiment_id: ContractId,
    run_id: ContractId,
    world_id: ContractId | None,
    actor: RequestedBy,
    trace_id: TraceId,
    timestamp: datetime,
    sequence: int,
    prev_event_hash: Sha256Digest | None,
    payload_hash: Sha256Digest,
) -> Sha256Digest:
    return sha256_digest(
        {
            "domain": _EVENT_SEMANTIC_DOMAIN,
            "schema_version": schema_version,
            "event_type": event_type,
            "experiment_id": experiment_id,
            "run_id": run_id,
            "world_id": world_id,
            "actor": actor,
            "trace_id": trace_id,
            "timestamp": timestamp,
            "sequence": sequence,
            "prev_event_hash": prev_event_hash,
            "payload_hash": payload_hash,
        }
    )


def _event_id(semantic_hash: Sha256Digest) -> Sha256Digest:
    return sha256_digest(
        {
            "domain": _EVENT_ID_DOMAIN,
            "semantic_hash": semantic_hash,
        }
    )


def _history_hash(
    *,
    schema_version: Literal["2.0"],
    experiment_id: ContractId,
    run_id: ContractId,
    event_count: int,
    head_hash: Sha256Digest,
    events: tuple[EventEnvelope, ...],
) -> Sha256Digest:
    return sha256_digest(
        {
            "domain": _EVENT_HISTORY_DOMAIN,
            "schema_version": schema_version,
            "experiment_id": experiment_id,
            "run_id": run_id,
            "event_count": event_count,
            "head_hash": head_hash,
            "events": tuple(
                {
                    "event_id": event.event_id,
                    "semantic_hash": event.semantic_hash,
                }
                for event in events
            ),
        }
    )


class EventEnvelope(AwareTimestampMixin, _EventContractV2):
    """One immutable event whose semantic hash binds its complete causal context.

    ``payload_hash`` intentionally remains the digest of the canonical payload alone so callers can
    deduplicate payload content. ``semantic_hash`` is domain separated and binds that payload digest
    to every envelope metadata field, its sequence, and the preceding event hash.
    """

    event_id: Sha256Digest
    sequence: PositiveInt = 1
    prev_event_hash: Sha256Digest | None = None
    event_type: EventType
    experiment_id: ContractId
    run_id: ContractId
    world_id: ContractId | None = None
    actor: RequestedBy
    trace_id: TraceId
    timestamp: datetime
    payload_hash: Sha256Digest
    semantic_hash: Sha256Digest
    payload: Mapping[str, JsonValue]

    @field_validator("payload", mode="before")
    @classmethod
    def immutable_json_is_revalidation_safe(cls, value: object) -> object:
        """Restore JSON arrays before strict validation of an already-frozen payload."""

        return thaw_json(freeze_json(value))

    @field_validator("payload")
    @classmethod
    def payload_is_deeply_immutable(cls, value: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
        return cast(Mapping[str, JsonValue], freeze_json(value))

    @field_serializer("payload")
    def serialize_payload(self, value: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
        return cast(dict[str, JsonValue], thaw_json(value))

    @field_validator("timestamp")
    @classmethod
    def timestamp_is_absolute(cls, value: datetime) -> datetime:
        checked = cls.timestamp_must_have_timezone(value)
        assert checked is not None
        return checked

    @model_validator(mode="after")
    def integrity_fields_match_content(self) -> EventEnvelope:
        actor = RequestedBy.model_validate(self.actor.model_dump(mode="python"))
        if self.payload_hash != sha256_digest(self.payload):
            raise ValueError("payload_hash does not match canonical payload")

        expected_semantic_hash = _semantic_hash(
            schema_version=self.schema_version,
            event_type=self.event_type,
            experiment_id=self.experiment_id,
            run_id=self.run_id,
            world_id=self.world_id,
            actor=actor,
            trace_id=self.trace_id,
            timestamp=self.timestamp,
            sequence=self.sequence,
            prev_event_hash=self.prev_event_hash,
            payload_hash=self.payload_hash,
        )
        if self.semantic_hash != expected_semantic_hash:
            raise ValueError("semantic_hash does not match the canonical event projection")
        if self.event_id != _event_id(self.semantic_hash):
            raise ValueError("event_id does not match semantic_hash")
        return self

    @classmethod
    def create(
        cls,
        *,
        event_type: EventType,
        experiment_id: ContractId,
        run_id: ContractId,
        actor: RequestedBy,
        trace_id: TraceId,
        timestamp: datetime,
        payload: Mapping[str, JsonValue],
        world_id: ContractId | None = None,
        sequence: PositiveInt = 1,
        prev_event_hash: Sha256Digest | None = None,
    ) -> Self:
        immutable_payload = cast(Mapping[str, JsonValue], freeze_json(payload))
        payload_hash = sha256_digest(immutable_payload)
        semantic_hash = _semantic_hash(
            schema_version="2.0",
            event_type=event_type,
            experiment_id=experiment_id,
            run_id=run_id,
            world_id=world_id,
            actor=actor,
            trace_id=trace_id,
            timestamp=timestamp,
            sequence=sequence,
            prev_event_hash=prev_event_hash,
            payload_hash=payload_hash,
        )
        return cls(
            event_id=_event_id(semantic_hash),
            sequence=sequence,
            prev_event_hash=prev_event_hash,
            event_type=event_type,
            experiment_id=experiment_id,
            run_id=run_id,
            world_id=world_id,
            actor=actor,
            trace_id=trace_id,
            timestamp=timestamp,
            payload_hash=payload_hash,
            semantic_hash=semantic_hash,
            payload=cast(Mapping[str, JsonValue], thaw_json(immutable_payload)),
        )


class EventHistory(_EventContractV2):
    """A non-empty, exact event sequence with a self-contained hash chain.

    This contract detects partial mutation, truncation, reordering, and cross-run splicing when a
    serialized history is revalidated. It is not an external freshness attestation: distinguishing
    a fully reminted stale history requires a separately trusted checkpoint or signed receipt.
    """

    experiment_id: ContractId
    run_id: ContractId
    event_count: PositiveInt
    head_hash: Sha256Digest
    history_hash: Sha256Digest
    events: tuple[EventEnvelope, ...]

    @model_validator(mode="after")
    def history_is_exact_and_self_consistent(self) -> EventHistory:
        events = tuple(
            EventEnvelope.model_validate(event.model_dump(mode="python")) for event in self.events
        )
        if not events:
            raise ValueError("event history must not be empty")
        if self.event_count != len(events):
            raise ValueError("event_count does not match events")

        event_ids = tuple(event.event_id for event in events)
        if len(event_ids) != len(set(event_ids)):
            raise ValueError("event history event_id values must be unique")

        previous: EventEnvelope | None = None
        for expected_sequence, event in enumerate(events, start=1):
            if event.sequence != expected_sequence:
                raise ValueError("event history sequence must be exactly 1..event_count")
            if event.experiment_id != self.experiment_id or event.run_id != self.run_id:
                raise ValueError("every event must match the history experiment_id and run_id")
            if previous is None:
                if event.prev_event_hash is not None:
                    raise ValueError("the first event must not have prev_event_hash")
            else:
                if event.prev_event_hash != previous.semantic_hash:
                    raise ValueError("event prev_event_hash does not match the preceding event")
                if event.timestamp < previous.timestamp:
                    raise ValueError("event timestamps must be nondecreasing")
            previous = event

        expected_head_hash = events[-1].semantic_hash
        if self.head_hash != expected_head_hash:
            raise ValueError("head_hash does not match the final event")
        expected_history_hash = _history_hash(
            schema_version=self.schema_version,
            experiment_id=self.experiment_id,
            run_id=self.run_id,
            event_count=self.event_count,
            head_hash=self.head_hash,
            events=events,
        )
        if self.history_hash != expected_history_hash:
            raise ValueError("history_hash does not match the canonical event history")
        return self

    @classmethod
    def create(
        cls,
        *,
        experiment_id: ContractId,
        run_id: ContractId,
        events: tuple[EventEnvelope, ...],
    ) -> Self:
        if not events:
            raise ValueError("event history must not be empty")
        head_hash = events[-1].semantic_hash
        event_count = len(events)
        return cls(
            experiment_id=experiment_id,
            run_id=run_id,
            event_count=event_count,
            head_hash=head_hash,
            history_hash=_history_hash(
                schema_version="2.0",
                experiment_id=experiment_id,
                run_id=run_id,
                event_count=event_count,
                head_hash=head_hash,
                events=events,
            ),
            events=events,
        )
