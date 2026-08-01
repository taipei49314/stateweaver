"""Deterministic, offline construction of a partial Security Semantic Twin."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from stateweaver.contracts import (
    Entity,
    EntityKind,
    EvidenceKind,
    EvidenceRecord,
    Fact,
    Provenance,
    ProvenanceKind,
    Relation,
    RelationKind,
    Taint,
    TransitionFragment,
    canonical_json_bytes,
    sha256_digest,
)

from .models import (
    OpenApiIngestion,
    OrmResource,
    SecuritySemanticTwin,
    SourceRoute,
    StateDelta,
    TelemetryFlow,
    TwinBuildInput,
    TwinConflict,
    ordered,
)

_OPENAPI_OPERATION_FIELDS = frozenset({"operationId", "summary", "description"})
_OPENAPI_TOP_LEVEL_FIELDS = frozenset({"openapi", "info", "paths"})
_OPENAPI_METHODS = frozenset({"get", "head", "options", "post", "put", "patch", "delete"})
_DELTA_KINDS = frozenset(
    {
        EvidenceKind.DATABASE_DIFF,
        EvidenceKind.CACHE_DIFF,
        EvidenceKind.QUEUE_DIFF,
        EvidenceKind.STATE_SNAPSHOT,
    }
)


class TwinBuildError(ValueError):
    """A value-safe, deterministic rejection of malformed twin input."""


class SecuritySemanticTwinBuilder:
    """Compile caller-provided evidence into semantic state without any I/O."""

    def build(self, input: TwinBuildInput) -> SecuritySemanticTwin:
        evidence: dict[str, EvidenceRecord] = {
            record.evidence_id: record for record in input.evidence_records
        }
        entities: dict[str, Entity] = {}
        relations: dict[str, Relation] = {}
        facts: dict[str, Fact] = {}
        transitions: dict[str, TransitionFragment] = {}

        for document in input.openapi_documents:
            self._validate_provenance(document.provenance, evidence, source=True)
            _insert_unique(entities, _service_entity(document.service_id), "entity_id")
            for entity, relation, fact in _openapi_semantics(document, evidence):
                _insert_unique(entities, entity, "entity_id")
                _insert_unique(relations, relation, "relation_id")
                _insert_unique(facts, fact, "fact_id")

        for route in input.source_routes:
            self._validate_provenance(route.provenance, evidence, source=True)
            _insert_unique(entities, _service_entity(route.service_id), "entity_id")
            for entity, relation, fact in _route_semantics(route, evidence):
                _insert_unique(entities, entity, "entity_id")
                _insert_unique(relations, relation, "relation_id")
                _insert_unique(facts, fact, "fact_id")

        for resource in input.orm_resources:
            self._validate_provenance(resource.provenance, evidence, source=True)
            _insert_unique(entities, _service_entity(resource.service_id), "entity_id")
            for entity, relation, fact in _resource_semantics(resource, evidence):
                _insert_unique(entities, entity, "entity_id")
                _insert_unique(relations, relation, "relation_id")
                _insert_unique(facts, fact, "fact_id")

        for fact in input.supplied_facts:
            self._validate_provenance(fact.provenance, evidence, source=False)
            _insert_unique(facts, fact, "fact_id")
        for relation in input.supplied_relations:
            self._validate_provenance(relation.provenance, evidence, source=False)
            _insert_unique(relations, relation, "relation_id")

        for flow in input.telemetry_flows:
            transition, delta_facts = self._transition_from_flow(flow, evidence)
            _insert_unique(transitions, transition, "transition_id")
            for fact in delta_facts:
                _insert_unique(facts, fact, "fact_id")

        conflicts = _find_conflicts(tuple(facts.values()))
        evidence_ids = _referenced_evidence_ids(
            entities=tuple(entities.values()),
            relations=tuple(relations.values()),
            facts=tuple(facts.values()),
            transitions=tuple(transitions.values()),
            conflicts=conflicts,
        )
        return SecuritySemanticTwin(
            twin_id=input.twin_id,
            entities=ordered(tuple(entities.values()), "entity_id"),
            relations=ordered(tuple(relations.values()), "relation_id"),
            facts=ordered(tuple(facts.values()), "fact_id"),
            transitions=ordered(tuple(transitions.values()), "transition_id"),
            conflicts=ordered(conflicts, "conflict_id"),
            evidence_ids=evidence_ids,
        )

    def _validate_provenance(
        self,
        provenance: Provenance,
        evidence: Mapping[str, EvidenceRecord],
        *,
        source: bool,
    ) -> None:
        missing = set(provenance.evidence_ids) - set(evidence)
        if missing:
            raise TwinBuildError("provenance references evidence outside the supplied registry")
        if source:
            if provenance.kind is not ProvenanceKind.DECLARED:
                raise TwinBuildError("source facts must retain declared provenance")
            if any(
                evidence[item].taint is not Taint.TRUSTED_SOURCE for item in provenance.evidence_ids
            ):
                raise TwinBuildError("source facts require trusted-source evidence")
        elif provenance.kind is ProvenanceKind.OBSERVED and any(
            evidence[item].taint not in {Taint.TRUSTED_RUNTIME, Taint.UNTRUSTED_TARGET_CONTENT}
            for item in provenance.evidence_ids
        ):
            raise TwinBuildError("observed facts require runtime or target-content evidence")

    def _transition_from_flow(
        self, flow: TelemetryFlow, evidence: Mapping[str, EvidenceRecord]
    ) -> tuple[TransitionFragment, tuple[Fact, ...]]:
        self._validate_provenance(flow.provenance, evidence, source=False)
        trace_records = tuple(evidence[item] for item in flow.provenance.evidence_ids)
        if not any(record.kind is EvidenceKind.OTEL_TRACE for record in trace_records):
            raise TwinBuildError("telemetry flow provenance requires OTel trace evidence")
        if any(record.taint is not Taint.TRUSTED_RUNTIME for record in trace_records):
            raise TwinBuildError("telemetry flow evidence must be trusted runtime evidence")
        for delta in flow.deltas:
            self._validate_provenance(delta.provenance, evidence, source=False)
            delta_records = tuple(evidence[item] for item in delta.provenance.evidence_ids)
            if not any(record.kind in _DELTA_KINDS for record in delta_records):
                raise TwinBuildError("each state delta requires state-delta evidence")
            if any(record.taint is not Taint.TRUSTED_RUNTIME for record in delta_records):
                raise TwinBuildError("state-delta evidence must be trusted runtime evidence")
        all_evidence_ids = tuple(
            sorted(
                {
                    *flow.provenance.evidence_ids,
                    *(item for delta in flow.deltas for item in delta.provenance.evidence_ids),
                }
            )
        )
        kinds = {evidence[item].kind for item in all_evidence_ids}
        if EvidenceKind.OTEL_TRACE not in kinds or not kinds & _DELTA_KINDS:
            raise TwinBuildError(
                "observed transition requires both OTel trace and state-delta evidence"
            )
        transition = TransitionFragment(
            transition_id=flow.transition_id,
            name=flow.name,
            source=ProvenanceKind.OBSERVED,
            preconditions=tuple(delta.precondition for delta in flow.deltas),
            action=flow.action,
            effects=tuple(delta.effect for delta in flow.deltas),
            observables=tuple(delta.observable for delta in flow.deltas),
            evidence_ids=all_evidence_ids,
            fidelity=flow.fidelity,
            consistent_replays=flow.consistent_replays,
        )
        return transition, tuple(_delta_fact(delta) for delta in flow.deltas)


def _openapi_semantics(
    document: OpenApiIngestion, evidence: Mapping[str, EvidenceRecord]
) -> tuple[tuple[Entity, Relation, Fact], ...]:
    raw = document.document
    if set(raw) - _OPENAPI_TOP_LEVEL_FIELDS or not isinstance(raw.get("openapi"), str):
        raise TwinBuildError("OpenAPI document has unsupported top-level fields")
    paths = raw.get("paths")
    if not isinstance(paths, Mapping) or not paths:
        raise TwinBuildError("OpenAPI document requires a nonempty paths mapping")
    at = _evidence_time(document.provenance, evidence)
    results: list[tuple[Entity, Relation, Fact]] = []
    for path, operations in sorted(paths.items()):
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or not isinstance(operations, Mapping)
        ):
            raise TwinBuildError("OpenAPI paths must map relative paths to operation mappings")
        for method, operation in sorted(operations.items()):
            if not isinstance(method, str) or method.lower() not in _OPENAPI_METHODS:
                raise TwinBuildError("OpenAPI operation method is unsupported")
            if not isinstance(operation, Mapping) or set(operation) - _OPENAPI_OPERATION_FIELDS:
                raise TwinBuildError("OpenAPI operation has unsupported fields")
            operation_id = operation.get("operationId")
            if operation_id is not None and not isinstance(operation_id, str):
                raise TwinBuildError("OpenAPI operationId must be a string")
            suffix = _stable_suffix(document.document_id, path, method.lower())
            endpoint_id = f"endpoint.{suffix}"
            entity = Entity(
                entity_id=endpoint_id,
                kind=EntityKind.ENDPOINT,
                label=operation_id or f"{method.upper()} {path}",
                provenance=document.provenance,
            )
            relation = Relation(
                relation_id=f"relation.{suffix}",
                subject=endpoint_id,
                predicate=RelationKind.CONTROLLED_BY,
                object=document.service_id,
                provenance=document.provenance,
                taint=Taint.TRUSTED_SOURCE,
            )
            fact = Fact(
                fact_id=f"fact.{suffix}",
                subject=endpoint_id,
                predicate="route_method",
                object=method.upper(),
                valid_from=at,
                provenance=document.provenance,
                confidence=1.0,
                taint=Taint.TRUSTED_SOURCE,
            )
            results.append((entity, relation, fact))
    return tuple(results)


def _service_entity(service_id: str) -> Entity:
    """Keep every generated ``controlled_by`` relation internally resolvable."""

    return Entity(entity_id=service_id, kind=EntityKind.SERVICE, label=service_id)


def _route_semantics(
    route: SourceRoute, evidence: Mapping[str, EvidenceRecord]
) -> tuple[tuple[Entity, Relation, Fact], ...]:
    at = _evidence_time(route.provenance, evidence)
    output: list[tuple[Entity, Relation, Fact]] = []
    for method in sorted(route.methods, key=str):
        suffix = _stable_suffix(route.route_id, method.value)
        endpoint_id = f"endpoint.{suffix}"
        entity = Entity(
            entity_id=endpoint_id,
            kind=EntityKind.ENDPOINT,
            label=route.operation_id or f"{method.value} {route.path}",
            provenance=route.provenance,
        )
        relation = Relation(
            relation_id=f"relation.{suffix}",
            subject=endpoint_id,
            predicate=RelationKind.CONTROLLED_BY,
            object=route.service_id,
            provenance=route.provenance,
            taint=Taint.TRUSTED_SOURCE,
        )
        fact = Fact(
            fact_id=f"fact.{suffix}",
            subject=endpoint_id,
            predicate="route_path",
            object=route.path,
            valid_from=at,
            provenance=route.provenance,
            confidence=1.0,
            taint=Taint.TRUSTED_SOURCE,
        )
        output.append((entity, relation, fact))
    return tuple(output)


def _resource_semantics(
    resource: OrmResource, evidence: Mapping[str, EvidenceRecord]
) -> tuple[tuple[Entity, Relation, Fact], ...]:
    at = _evidence_time(resource.provenance, evidence)
    entity = Entity(
        entity_id=resource.resource_id,
        kind=EntityKind.RESOURCE,
        label=resource.table_name,
        provenance=resource.provenance,
    )
    relation = Relation(
        relation_id=f"relation.{_stable_suffix(resource.resource_id, resource.service_id)}",
        subject=resource.resource_id,
        predicate=RelationKind.CONTROLLED_BY,
        object=resource.service_id,
        provenance=resource.provenance,
        taint=Taint.TRUSTED_SOURCE,
    )
    facts = [
        Fact(
            fact_id=f"fact.{_stable_suffix(resource.resource_id, 'table')}",
            subject=resource.resource_id,
            predicate="table_name",
            object=resource.table_name,
            valid_from=at,
            provenance=resource.provenance,
            confidence=1.0,
            taint=Taint.TRUSTED_SOURCE,
        ),
        Fact(
            fact_id=f"fact.{_stable_suffix(resource.resource_id, 'tenant')}",
            subject=resource.resource_id,
            predicate="tenant_field",
            object=resource.tenant_field,
            valid_from=at,
            provenance=resource.provenance,
            confidence=1.0,
            taint=Taint.TRUSTED_SOURCE,
        ),
    ]
    if resource.owner_field is not None:
        facts.append(
            Fact(
                fact_id=f"fact.{_stable_suffix(resource.resource_id, 'owner')}",
                subject=resource.resource_id,
                predicate="owner_field",
                object=resource.owner_field,
                valid_from=at,
                provenance=resource.provenance,
                confidence=1.0,
                taint=Taint.TRUSTED_SOURCE,
            )
        )
    return tuple((entity, relation, fact) for fact in facts)


def _delta_fact(delta: StateDelta) -> Fact:
    predicate = delta.effect.path.rsplit(".", 1)[-1]
    return Fact(
        fact_id=f"fact.{_stable_suffix(delta.delta_id)}",
        subject=delta.subject,
        predicate=predicate,
        object=delta.effect.value,
        valid_from=delta.observed_at,
        provenance=delta.provenance,
        confidence=1.0,
        taint=Taint.TRUSTED_RUNTIME,
    )


def _find_conflicts(facts: tuple[Fact, ...]) -> tuple[TwinConflict, ...]:
    grouped: dict[tuple[str, str], list[Fact]] = {}
    for fact in facts:
        grouped.setdefault((fact.subject, fact.predicate), []).append(fact)
    conflicts: list[TwinConflict] = []
    for (subject, predicate), candidates in sorted(grouped.items()):
        ordered_facts = sorted(candidates, key=lambda item: item.fact_id)
        for index, left in enumerate(ordered_facts):
            for right in ordered_facts[index + 1 :]:
                if left.object == right.object or not _intervals_overlap(left, right):
                    continue
                evidence_ids = tuple(
                    sorted({*left.provenance.evidence_ids, *right.provenance.evidence_ids})
                )
                conflicts.append(
                    TwinConflict(
                        conflict_id=f"conflict.{_stable_suffix(left.fact_id, right.fact_id)}",
                        subject=subject,
                        predicate=predicate,
                        left_fact_id=left.fact_id,
                        right_fact_id=right.fact_id,
                        left_value=left.object,
                        right_value=right.object,
                        evidence_ids=evidence_ids,
                    )
                )
    return tuple(conflicts)


def _intervals_overlap(left: Fact, right: Fact) -> bool:
    return (left.valid_to is None or right.valid_from < left.valid_to) and (
        right.valid_to is None or left.valid_from < right.valid_to
    )


def _evidence_time(provenance: Provenance, evidence: Mapping[str, EvidenceRecord]) -> datetime:
    return min(evidence[item].created_at for item in provenance.evidence_ids)


def _stable_suffix(*parts: object) -> str:
    return sha256_digest(parts).removeprefix("sha256:")[:24]


def _referenced_evidence_ids(
    *,
    entities: tuple[Entity, ...],
    relations: tuple[Relation, ...],
    facts: tuple[Fact, ...],
    transitions: tuple[TransitionFragment, ...],
    conflicts: tuple[TwinConflict, ...],
) -> tuple[str, ...]:
    referenced: set[str] = set()
    for entity in entities:
        if entity.provenance is not None:
            referenced.update(entity.provenance.evidence_ids)
    for relation in relations:
        referenced.update(relation.provenance.evidence_ids)
    for fact in facts:
        referenced.update(fact.provenance.evidence_ids)
    for transition in transitions:
        referenced.update(transition.evidence_ids)
    for conflict in conflicts:
        referenced.update(conflict.evidence_ids)
    return tuple(sorted(referenced))


def _insert_unique(collection: dict[str, Any], item: Any, attribute: str) -> None:
    identifier = str(getattr(item, attribute))
    existing = collection.get(identifier)
    if existing is None:
        collection[identifier] = item
    elif canonical_json_bytes(existing) != canonical_json_bytes(item):
        raise TwinBuildError("distinct semantic records reuse the same identifier")
