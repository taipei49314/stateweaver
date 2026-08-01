"""Durable event envelope defined by Architecture section 15."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Self, cast

from pydantic import JsonValue, field_serializer, field_validator, model_validator

from .actions import RequestedBy
from .base import (
    AwareTimestampMixin,
    ContractId,
    Sha256Digest,
    TraceId,
    VersionedContract,
    freeze_json,
    sha256_digest,
    thaw_json,
)
from .enums import EventType


class EventEnvelope(AwareTimestampMixin, VersionedContract):
    event_type: EventType
    experiment_id: ContractId
    run_id: ContractId
    world_id: ContractId | None = None
    actor: RequestedBy
    trace_id: TraceId
    timestamp: datetime
    payload_hash: Sha256Digest
    payload: Mapping[str, JsonValue]

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
    def payload_hash_matches_payload(self) -> EventEnvelope:
        if self.payload_hash != sha256_digest(self.payload):
            raise ValueError("payload_hash does not match canonical payload")
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
    ) -> Self:
        return cls(
            event_type=event_type,
            experiment_id=experiment_id,
            run_id=run_id,
            world_id=world_id,
            actor=actor,
            trace_id=trace_id,
            timestamp=timestamp,
            payload_hash=sha256_digest(payload),
            payload=payload,
        )
