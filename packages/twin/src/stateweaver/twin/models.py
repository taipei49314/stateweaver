"""Closed, framework-free input and output models for the Security Semantic Twin."""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from datetime import datetime
from types import MappingProxyType
from typing import Any

from pydantic import Field, field_validator, model_validator
from stateweaver.contracts import (
    Action,
    ContractId,
    Entity,
    EvidenceRecord,
    Fact,
    FidelityProfile,
    HttpMethod,
    Provenance,
    ProvenanceKind,
    Relation,
    StateCondition,
    StateEffect,
    TransitionFragment,
    canonical_json_bytes,
    sha256_digest,
)
from stateweaver.contracts.base import ContractModel, JsonScalar, VersionedContract

_OPENAPI_METHODS = frozenset(method.value.lower() for method in HttpMethod)
_SECRET_KEY = re.compile(
    r"(?:authorization|cookie|password|secret|credential|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token)",
    re.IGNORECASE,
)
_SECRET_TEXT = re.compile(
    r"(?:\bbearer\s+[A-Za-z0-9._~+/-]+|\b(?:api[_-]?key|access[_-]?token)\s*[:=])",
    re.IGNORECASE,
)


def _freeze_openapi(value: object) -> object:
    """Accept JSON-shaped API descriptions without retaining secret-like material."""

    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("OpenAPI mappings require string keys")
            # OpenAPI path-template keys may legitimately name authorization endpoints;
            # they are route metadata, not credential-bearing object fields.
            if not key.startswith("/") and _SECRET_KEY.search(key):
                raise ValueError("OpenAPI mappings cannot contain credential-like keys")
            result[key] = _freeze_openapi(item)
        return MappingProxyType(result)
    if isinstance(value, list | tuple):
        return tuple(_freeze_openapi(item) for item in value)
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("OpenAPI mappings require finite numbers")
    if isinstance(value, str):
        if _SECRET_TEXT.search(value):
            raise ValueError("OpenAPI mappings cannot contain credential-like text")
        return value
    if value is None or isinstance(value, int | float | bool):
        return value
    raise ValueError("OpenAPI mappings must contain JSON values")


class OpenApiIngestion(ContractModel):
    """Caller-supplied, JSON-only OpenAPI source; no parser or URL fetch is present."""

    document_id: ContractId
    service_id: ContractId
    document: Mapping[str, object]
    provenance: Provenance

    @field_validator("document")
    @classmethod
    def document_is_safe_json(cls, value: Mapping[str, object]) -> Mapping[str, object]:
        frozen = _freeze_openapi(value)
        if not isinstance(frozen, Mapping):  # pragma: no cover - defensive narrowing
            raise ValueError("OpenAPI document must be a mapping")
        return frozen

    @model_validator(mode="after")
    def source_claim_is_evidence_bound(self) -> OpenApiIngestion:
        if self.provenance.kind is not ProvenanceKind.DECLARED or not self.provenance.evidence_ids:
            raise ValueError("OpenAPI ingestion requires declared, evidence-bound provenance")
        return self


class SourceRoute(ContractModel):
    """A deterministic FastAPI-style route declaration, not a live framework object."""

    route_id: ContractId
    service_id: ContractId
    path: str
    methods: tuple[HttpMethod, ...]
    operation_id: ContractId | None = None
    policy_checks: tuple[str, ...] = ()
    provenance: Provenance

    @field_validator("path")
    @classmethod
    def path_is_relative(cls, value: str) -> str:
        if not value.startswith("/") or "?" in value or "#" in value or "//" in value:
            raise ValueError("source route path must be a relative path without query or fragment")
        return value

    @field_validator("policy_checks")
    @classmethod
    def policy_checks_are_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("source route policy checks must be unique")
        return value

    @model_validator(mode="after")
    def route_has_declared_evidence(self) -> SourceRoute:
        if not self.methods or len(self.methods) != len(set(self.methods)):
            raise ValueError("source route methods must be nonempty and unique")
        if self.provenance.kind is not ProvenanceKind.DECLARED or not self.provenance.evidence_ids:
            raise ValueError("source routes require declared, evidence-bound provenance")
        return self


class OrmResource(ContractModel):
    """A deterministic SQLAlchemy-style resource declaration, never a database connection."""

    resource_id: ContractId
    service_id: ContractId
    table_name: str
    tenant_field: str
    owner_field: str | None = None
    provenance: Provenance

    @field_validator("table_name", "tenant_field", "owner_field")
    @classmethod
    def source_identifiers_are_safe(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", value):
            raise ValueError("ORM identifiers must use letters, numbers, and underscores")
        return value

    @model_validator(mode="after")
    def resource_has_declared_evidence(self) -> OrmResource:
        if self.provenance.kind is not ProvenanceKind.DECLARED or not self.provenance.evidence_ids:
            raise ValueError("ORM resources require declared, evidence-bound provenance")
        return self


class StateDelta(ContractModel):
    """One caller-observed before/effect/after relation for a synthetic flow."""

    delta_id: ContractId
    subject: ContractId
    precondition: StateCondition
    effect: StateEffect
    observable: StateCondition
    provenance: Provenance
    observed_at: datetime

    @field_validator("observed_at")
    @classmethod
    def timestamp_is_absolute(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("state delta time must include a UTC offset")
        return value

    @model_validator(mode="after")
    def delta_is_runtime_bound(self) -> StateDelta:
        if self.provenance.kind is not ProvenanceKind.OBSERVED or not self.provenance.evidence_ids:
            raise ValueError("state deltas require observed, evidence-bound provenance")
        return self


class TelemetryFlow(ContractModel):
    """A caller-supplied OTel-style action flow and its observed state deltas."""

    transition_id: ContractId
    name: str
    action: Action
    deltas: tuple[StateDelta, ...]
    provenance: Provenance
    fidelity: FidelityProfile
    consistent_replays: int = Field(default=1, ge=1)

    @model_validator(mode="after")
    def flow_is_observed_and_complete(self) -> TelemetryFlow:
        if not self.name or not self.deltas:
            raise ValueError("telemetry flow requires a name and at least one state delta")
        if self.provenance.kind is not ProvenanceKind.OBSERVED or not self.provenance.evidence_ids:
            raise ValueError("telemetry flow requires observed, evidence-bound provenance")
        if len({delta.delta_id for delta in self.deltas}) != len(self.deltas):
            raise ValueError("telemetry flow state delta IDs must be unique")
        levels = (
            self.fidelity.code,
            self.fidelity.identity,
            self.fidelity.database,
            self.fidelity.cache,
            self.fidelity.queue,
            self.fidelity.timing,
        )
        if not any(level.value in {"exact", "observed"} for level in levels):
            raise ValueError("observed telemetry flow requires observed fidelity")
        return self


class TwinConflict(VersionedContract):
    """An explicit disagreement between two evidence-bound state facts."""

    conflict_id: ContractId
    subject: ContractId
    predicate: str
    left_fact_id: ContractId
    right_fact_id: ContractId
    left_value: JsonScalar
    right_value: JsonScalar
    evidence_ids: tuple[ContractId, ...]

    @model_validator(mode="after")
    def conflict_is_specific(self) -> TwinConflict:
        if self.left_fact_id == self.right_fact_id or self.left_value == self.right_value:
            raise ValueError("a conflict must compare distinct facts with different values")
        if not self.evidence_ids or len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("a conflict requires unique evidence IDs")
        return self


class SecuritySemanticTwin(VersionedContract):
    """Canonical, partial security state. Facts never silently replace conflicts."""

    twin_id: ContractId
    entities: tuple[Entity, ...]
    relations: tuple[Relation, ...]
    facts: tuple[Fact, ...]
    transitions: tuple[TransitionFragment, ...]
    conflicts: tuple[TwinConflict, ...]
    evidence_ids: tuple[ContractId, ...]

    @model_validator(mode="after")
    def content_is_unique_and_evidence_complete(self) -> SecuritySemanticTwin:
        collections = (
            (self.entities, "entity_id"),
            (self.relations, "relation_id"),
            (self.facts, "fact_id"),
            (self.transitions, "transition_id"),
            (self.conflicts, "conflict_id"),
        )
        for items, attribute in collections:
            identifiers = [getattr(item, attribute) for item in items]
            if len(identifiers) != len(set(identifiers)):
                raise ValueError(f"twin {attribute} values must be unique")
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("twin evidence IDs must be unique")
        referenced = {
            evidence_id for item in self.facts for evidence_id in item.provenance.evidence_ids
        }
        referenced.update(
            evidence_id
            for item in self.entities
            if item.provenance is not None
            for evidence_id in item.provenance.evidence_ids
        )
        referenced.update(
            evidence_id for item in self.relations for evidence_id in item.provenance.evidence_ids
        )
        referenced.update(
            evidence_id for item in self.transitions for evidence_id in item.evidence_ids
        )
        referenced.update(
            evidence_id for item in self.conflicts for evidence_id in item.evidence_ids
        )
        if referenced != set(self.evidence_ids):
            raise ValueError("twin evidence index must exactly match referenced evidence")
        return self

    @property
    def fingerprint(self) -> str:
        return sha256_digest(self)

    def canonical_output(self) -> bytes:
        return canonical_json_bytes(self)


class TwinBuildInput(ContractModel):
    """All caller-supplied inputs for one local, offline twin build."""

    twin_id: ContractId
    evidence_records: tuple[EvidenceRecord, ...]
    openapi_documents: tuple[OpenApiIngestion, ...] = ()
    source_routes: tuple[SourceRoute, ...] = ()
    orm_resources: tuple[OrmResource, ...] = ()
    telemetry_flows: tuple[TelemetryFlow, ...] = ()
    supplied_facts: tuple[Fact, ...] = ()
    supplied_relations: tuple[Relation, ...] = ()

    @model_validator(mode="after")
    def ids_are_unique(self) -> TwinBuildInput:
        collections = (
            (self.evidence_records, "evidence_id"),
            (self.openapi_documents, "document_id"),
            (self.source_routes, "route_id"),
            (self.orm_resources, "resource_id"),
            (self.telemetry_flows, "transition_id"),
            (self.supplied_facts, "fact_id"),
            (self.supplied_relations, "relation_id"),
        )
        for items, attribute in collections:
            identifiers = [getattr(item, attribute) for item in items]
            if len(identifiers) != len(set(identifiers)):
                raise ValueError(f"twin input {attribute} values must be unique")
        return self


def ordered(items: tuple[Any, ...] | list[Any], attribute: str) -> tuple[Any, ...]:
    """Return a deterministic tuple without mutating caller-owned input."""

    return tuple(sorted(items, key=lambda item: str(getattr(item, attribute))))
