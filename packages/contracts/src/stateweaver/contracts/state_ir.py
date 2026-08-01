"""Security-semantic entities, facts, relations, and transitions."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import Field, StringConstraints, field_validator, model_validator

from .actions import Action, StatePath
from .base import (
    AwareTimestampMixin,
    ContractId,
    ContractModel,
    JsonScalar,
    Name,
    Probability,
    VersionedContract,
    validate_effect_operation_value,
)
from .enums import (
    ComparisonOperator,
    EffectOperation,
    EntityKind,
    FidelityLevel,
    ProvenanceKind,
    RelationKind,
    Taint,
)

Predicate = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=2,
        max_length=128,
        pattern=r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$",
    ),
]


class StateAttribute(ContractModel):
    name: Predicate
    value: JsonScalar


class Provenance(ContractModel):
    kind: ProvenanceKind
    evidence_ids: tuple[ContractId, ...] = ()
    adapter: Name | None = None
    adapter_version: Name | None = None

    @model_validator(mode="after")
    def observed_claims_require_evidence(self) -> Provenance:
        if self.kind is ProvenanceKind.OBSERVED and not self.evidence_ids:
            raise ValueError("observed provenance requires evidence")
        if self.kind is ProvenanceKind.INFERRED and not self.evidence_ids:
            raise ValueError("inferred provenance requires supporting evidence")
        if self.kind in {ProvenanceKind.HYPOTHESIZED, ProvenanceKind.UNKNOWN} and self.evidence_ids:
            raise ValueError(f"{self.kind.value} provenance cannot claim evidence")
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("provenance evidence ids must be unique")
        if (self.adapter is None) != (self.adapter_version is None):
            raise ValueError("adapter and adapter_version must be supplied together")
        return self


def _validate_provenance_taint(provenance: Provenance, taint: Taint) -> None:
    """Keep claim origin separate from the trust level of its content."""

    if provenance.kind is ProvenanceKind.OBSERVED and taint not in {
        Taint.TRUSTED_RUNTIME,
        Taint.UNTRUSTED_TARGET_CONTENT,
    }:
        raise ValueError("observed facts and relations require runtime or target-content taint")
    if provenance.kind is ProvenanceKind.HYPOTHESIZED and taint is not Taint.MODEL_GENERATED:
        raise ValueError("hypothesized facts and relations require model-generated taint")
    if provenance.kind is ProvenanceKind.DECLARED and taint is not Taint.TRUSTED_SOURCE:
        raise ValueError("declared facts and relations require trusted source taint")


class Entity(VersionedContract):
    entity_id: ContractId
    kind: EntityKind
    label: str | None = None
    attributes: tuple[StateAttribute, ...] = ()
    provenance: Provenance | None = None

    @field_validator("attributes")
    @classmethod
    def attribute_names_are_unique(
        cls, value: tuple[StateAttribute, ...]
    ) -> tuple[StateAttribute, ...]:
        names = [attribute.name for attribute in value]
        if len(names) != len(set(names)):
            raise ValueError("entity attribute names must be unique")
        return value


class Relation(VersionedContract):
    relation_id: ContractId
    subject: ContractId
    predicate: RelationKind
    object: ContractId
    provenance: Provenance
    confidence: Probability = 1.0
    taint: Taint = Taint.TRUSTED_RUNTIME

    @model_validator(mode="after")
    def relation_is_not_self_referential(self) -> Relation:
        if self.subject == self.object:
            raise ValueError("security relations must connect distinct entities")
        _validate_provenance_taint(self.provenance, self.taint)
        return self


class Fact(AwareTimestampMixin, VersionedContract):
    fact_id: ContractId
    subject: ContractId
    predicate: Predicate
    object: JsonScalar
    valid_from: datetime
    valid_to: datetime | None = None
    provenance: Provenance
    confidence: Probability
    taint: Taint

    @field_validator("valid_from", "valid_to")
    @classmethod
    def validity_timestamps_are_absolute(cls, value: datetime | None) -> datetime | None:
        return cls.timestamp_must_have_timezone(value)

    @model_validator(mode="after")
    def validity_interval_is_forward(self) -> Fact:
        if self.valid_to is not None and self.valid_to <= self.valid_from:
            raise ValueError("valid_to must be later than valid_from")
        _validate_provenance_taint(self.provenance, self.taint)
        return self


class StateCondition(ContractModel):
    path: StatePath
    operator: ComparisonOperator
    value: JsonScalar = None
    reference: StatePath | None = None

    @model_validator(mode="after")
    def operand_shape_is_valid(self) -> StateCondition:
        existence = self.operator in {ComparisonOperator.EXISTS, ComparisonOperator.NOT_EXISTS}
        if existence and (self.value is not None or self.reference is not None):
            raise ValueError("existence conditions do not accept an operand")
        if not existence and (self.value is None) == (self.reference is None):
            raise ValueError("comparison condition requires exactly one value or reference")
        return self


class StateEffect(ContractModel):
    path: StatePath
    operation: EffectOperation
    value: JsonScalar = None

    @model_validator(mode="after")
    def effect_shape_is_valid(self) -> StateEffect:
        validate_effect_operation_value(self.operation, self.value)
        return self


class FidelityProfile(ContractModel):
    code: FidelityLevel = FidelityLevel.UNKNOWN
    identity: FidelityLevel = FidelityLevel.UNKNOWN
    database: FidelityLevel = FidelityLevel.UNKNOWN
    cache: FidelityLevel = FidelityLevel.UNKNOWN
    queue: FidelityLevel = FidelityLevel.UNKNOWN
    timing: FidelityLevel = FidelityLevel.UNKNOWN


class TransitionFragment(VersionedContract):
    transition_id: ContractId
    name: str
    source: ProvenanceKind
    preconditions: tuple[StateCondition, ...]
    action: Action
    effects: tuple[StateEffect, ...]
    observables: tuple[StateCondition, ...]
    evidence_ids: tuple[ContractId, ...] = ()
    fidelity: FidelityProfile
    consistent_replays: Annotated[int, Field(ge=0)] = 0

    @model_validator(mode="after")
    def promotion_evidence_is_sufficient(self) -> TransitionFragment:
        if not self.preconditions:
            raise ValueError("transition requires at least one precondition")
        if not self.effects:
            raise ValueError("transition requires at least one effect")
        if not self.observables:
            raise ValueError("transition requires at least one observable")
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("transition evidence ids must be unique")
        if self.source is ProvenanceKind.INFERRED and self.consistent_replays < 2:
            raise ValueError("inferred transitions require at least two consistent replays")
        if (
            self.source
            in {
                ProvenanceKind.INFERRED,
                ProvenanceKind.DECLARED,
                ProvenanceKind.MOCKED,
            }
            and not self.evidence_ids
        ):
            raise ValueError(f"{self.source.value} transitions require supporting evidence")
        if self.source is ProvenanceKind.OBSERVED and not self.evidence_ids:
            raise ValueError("observed transitions require runtime evidence")
        if (
            self.source in {ProvenanceKind.HYPOTHESIZED, ProvenanceKind.UNKNOWN}
            and self.evidence_ids
        ):
            raise ValueError(f"{self.source.value} transitions cannot claim evidence")
        fidelity_levels = (
            self.fidelity.code,
            self.fidelity.identity,
            self.fidelity.database,
            self.fidelity.cache,
            self.fidelity.queue,
            self.fidelity.timing,
        )
        if self.source is ProvenanceKind.HYPOTHESIZED and any(
            level in {FidelityLevel.EXACT, FidelityLevel.OBSERVED} for level in fidelity_levels
        ):
            raise ValueError("hypothesized transitions cannot claim exact or observed fidelity")
        if self.source is ProvenanceKind.MOCKED and any(
            level in {FidelityLevel.EXACT, FidelityLevel.OBSERVED} for level in fidelity_levels
        ):
            raise ValueError("mocked transitions cannot claim exact or observed fidelity")
        if self.source is ProvenanceKind.UNKNOWN and any(
            level is not FidelityLevel.UNKNOWN for level in fidelity_levels
        ):
            raise ValueError("unknown transitions cannot claim fidelity")
        if self.source is ProvenanceKind.OBSERVED and not any(
            level in {FidelityLevel.EXACT, FidelityLevel.OBSERVED} for level in fidelity_levels
        ):
            raise ValueError("observed transitions require observed fidelity")
        return self
