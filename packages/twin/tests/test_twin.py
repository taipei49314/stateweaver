from __future__ import annotations

from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st
from stateweaver.contracts import (
    ActionTarget,
    ComparisonOperator,
    EffectOperation,
    EntityKind,
    EvidenceKind,
    EvidenceProducer,
    EvidenceRecord,
    Fact,
    FidelityLevel,
    FidelityProfile,
    HttpMethod,
    HttpRequestAction,
    Provenance,
    ProvenanceKind,
    StateCondition,
    StateEffect,
    Taint,
)
from stateweaver.twin import (
    OpenApiIngestion,
    OrmResource,
    SecuritySemanticTwin,
    SecuritySemanticTwinBuilder,
    SourceRoute,
    StateDelta,
    TelemetryFlow,
    TwinBuildError,
    TwinBuildInput,
)

EPOCH = datetime(2026, 1, 1, tzinfo=UTC)


def _evidence(evidence_id: str, kind: EvidenceKind, taint: Taint) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=evidence_id,
        kind=kind,
        artifact_uri=f"artifact://synthetic/{evidence_id}",
        sha256="sha256:" + "a" * 64,
        produced_by=EvidenceProducer(adapter="synthetic_adapter", version="v1"),
        redaction_policy_version="synthetic-redaction-v1",
        taint=taint,
        created_at=EPOCH,
    )


def _source_provenance() -> Provenance:
    return Provenance(kind=ProvenanceKind.DECLARED, evidence_ids=("ev.source.001",))


def _runtime_provenance(evidence_id: str) -> Provenance:
    return Provenance(kind=ProvenanceKind.OBSERVED, evidence_ids=(evidence_id,))


def _flow(*, transition_id: str = "transition.synthetic.001") -> TelemetryFlow:
    return TelemetryFlow(
        transition_id=transition_id,
        name="synthetic document read",
        action=HttpRequestAction(
            method=HttpMethod.GET,
            target=ActionTarget(scheme="http", host="localhost", port=80, path="/api/documents"),
            expected_statuses=(200,),
        ),
        deltas=(
            StateDelta(
                delta_id="delta.synthetic.001",
                subject="session.synthetic.001",
                precondition=StateCondition(
                    path="session.authorization_generation",
                    operator=ComparisonOperator.EQ,
                    value=1,
                ),
                effect=StateEffect(
                    path="session.authorization_generation",
                    operation=EffectOperation.SET,
                    value=2,
                ),
                observable=StateCondition(
                    path="response.status",
                    operator=ComparisonOperator.EQ,
                    value=200,
                ),
                provenance=_runtime_provenance("ev.delta.001"),
                observed_at=EPOCH,
            ),
        ),
        provenance=_runtime_provenance("ev.trace.001"),
        fidelity=FidelityProfile(
            code=FidelityLevel.EXACT,
            identity=FidelityLevel.OBSERVED,
            database=FidelityLevel.OBSERVED,
            cache=FidelityLevel.PARTIAL,
            queue=FidelityLevel.UNKNOWN,
            timing=FidelityLevel.OBSERVED,
        ),
    )


def _input(*, paths: dict[str, object] | None = None) -> TwinBuildInput:
    return TwinBuildInput(
        twin_id="twin.synthetic.001",
        evidence_records=(
            _evidence("ev.source.001", EvidenceKind.STATE_SNAPSHOT, Taint.TRUSTED_SOURCE),
            _evidence("ev.trace.001", EvidenceKind.OTEL_TRACE, Taint.TRUSTED_RUNTIME),
            _evidence("ev.delta.001", EvidenceKind.DATABASE_DIFF, Taint.TRUSTED_RUNTIME),
        ),
        openapi_documents=(
            OpenApiIngestion(
                document_id="openapi.synthetic.001",
                service_id="service.synthetic.001",
                document={
                    "openapi": "3.1.0",
                    "paths": paths or {"/api/documents": {"get": {"operationId": "document.read"}}},
                },
                provenance=_source_provenance(),
            ),
        ),
        source_routes=(
            SourceRoute(
                route_id="route.synthetic.001",
                service_id="service.synthetic.001",
                path="/api/documents",
                methods=(HttpMethod.GET,),
                operation_id="operation.synthetic.001",
                policy_checks=("principal.tenant",),
                provenance=_source_provenance(),
            ),
        ),
        orm_resources=(
            OrmResource(
                resource_id="resource.synthetic.001",
                service_id="service.synthetic.001",
                table_name="documents",
                tenant_field="tenant_id",
                owner_field="owner_id",
                provenance=_source_provenance(),
            ),
        ),
        telemetry_flows=(_flow(),),
    )


def test_builds_canonical_evidence_bound_twin_and_observed_transition() -> None:
    twin = SecuritySemanticTwinBuilder().build(_input())

    assert twin.transitions[0].transition_id == "transition.synthetic.001"
    assert twin.transitions[0].source is ProvenanceKind.OBSERVED
    assert set(twin.transitions[0].evidence_ids) == {"ev.trace.001", "ev.delta.001"}
    assert twin.transitions[0].effects[0].path == "session.authorization_generation"
    assert twin.transitions[0].fidelity.database is FidelityLevel.OBSERVED
    assert {entity.kind for entity in twin.entities} >= {EntityKind.ENDPOINT, EntityKind.RESOURCE}
    entity_ids = {entity.entity_id for entity in twin.entities}
    assert all(
        relation.subject in entity_ids and relation.object in entity_ids
        for relation in twin.relations
    )
    assert twin.evidence_ids == tuple(sorted(twin.evidence_ids))
    assert twin.canonical_output() == twin.canonical_output()
    assert twin.fingerprint.startswith("sha256:")


def test_output_is_deterministic_when_openapi_mapping_order_changes() -> None:
    first = _input(
        paths={
            "/api/a": {"get": {"operationId": "a.read"}},
            "/api/b": {"post": {"operationId": "b.write"}},
        }
    )
    second = _input(
        paths={
            "/api/b": {"post": {"operationId": "b.write"}},
            "/api/a": {"get": {"operationId": "a.read"}},
        }
    )
    builder = SecuritySemanticTwinBuilder()
    assert builder.build(first).fingerprint == builder.build(second).fingerprint


@given(st.permutations(("/api/a", "/api/b", "/api/c")))
def test_openapi_path_permutations_have_one_canonical_fingerprint(order: tuple[str, ...]) -> None:
    paths: dict[str, object] = {
        path: {"get": {"operationId": f"operation.{path.rsplit('/', 1)[-1]}"}} for path in order
    }
    reordered = dict(reversed(tuple(paths.items())))
    builder = SecuritySemanticTwinBuilder()
    assert (
        builder.build(_input(paths=paths)).fingerprint
        == builder.build(_input(paths=reordered)).fingerprint
    )


def test_rejects_flow_without_both_trace_and_delta_evidence() -> None:
    input = _input()
    incomplete = input.model_copy(
        update={
            "evidence_records": tuple(
                record for record in input.evidence_records if record.evidence_id != "ev.delta.001"
            )
        }
    )
    with pytest.raises(TwinBuildError, match="registry"):
        SecuritySemanticTwinBuilder().build(incomplete)


def test_rejects_trace_and_delta_evidence_role_substitution() -> None:
    input = _input()
    flow = input.telemetry_flows[0]
    swapped_delta = flow.deltas[0].model_copy(
        update={"provenance": _runtime_provenance("ev.trace.001")}
    )
    swapped_flow = flow.model_copy(
        update={
            "provenance": _runtime_provenance("ev.delta.001"),
            "deltas": (swapped_delta,),
        }
    )

    with pytest.raises(TwinBuildError, match="OTel trace evidence"):
        SecuritySemanticTwinBuilder().build(
            input.model_copy(update={"telemetry_flows": (swapped_flow,)})
        )


def test_unused_registry_evidence_does_not_enter_the_twin_slice() -> None:
    input = _input()
    extra = _evidence("ev.unused.001", EvidenceKind.HTTP_EXCHANGE, Taint.TRUSTED_RUNTIME)

    twin = SecuritySemanticTwinBuilder().build(
        input.model_copy(update={"evidence_records": (*input.evidence_records, extra)})
    )

    assert "ev.unused.001" not in twin.evidence_ids


def test_twin_evidence_index_rejects_unreferenced_ids() -> None:
    twin = SecuritySemanticTwinBuilder().build(_input())

    with pytest.raises(ValueError, match="exactly match"):
        SecuritySemanticTwin(
            twin_id=twin.twin_id,
            entities=twin.entities,
            relations=twin.relations,
            facts=twin.facts,
            transitions=twin.transitions,
            conflicts=twin.conflicts,
            evidence_ids=(*twin.evidence_ids, "ev.unused.001"),
        )


def test_rejects_source_evidence_that_is_not_trusted_source() -> None:
    input = _input()
    records = list(input.evidence_records)
    records[0] = _evidence("ev.source.001", EvidenceKind.STATE_SNAPSHOT, Taint.TRUSTED_RUNTIME)
    with pytest.raises(TwinBuildError, match="trusted-source"):
        SecuritySemanticTwinBuilder().build(
            input.model_copy(update={"evidence_records": tuple(records)})
        )


def test_rejects_credential_like_openapi_data() -> None:
    with pytest.raises(ValueError, match="credential"):
        OpenApiIngestion(
            document_id="openapi.synthetic.001",
            service_id="service.synthetic.001",
            document={"openapi": "3.1.0", "paths": {}, "authorization": "Bearer unsafe"},
            provenance=_source_provenance(),
        )


def test_rejects_unknown_openapi_operation_fields() -> None:
    input = _input(paths={"/api/documents": {"get": {"requestBody": {}}}})
    with pytest.raises(TwinBuildError, match="unsupported fields"):
        SecuritySemanticTwinBuilder().build(input)


def test_preserves_runtime_source_disagreement_as_explicit_conflict() -> None:
    first = Fact(
        fact_id="fact.conflict.001",
        subject="resource.synthetic.001",
        predicate="visibility",
        object="tenant_a",
        valid_from=EPOCH,
        provenance=_source_provenance(),
        confidence=1.0,
        taint=Taint.TRUSTED_SOURCE,
    )
    second = Fact(
        fact_id="fact.conflict.002",
        subject="resource.synthetic.001",
        predicate="visibility",
        object="tenant_b",
        valid_from=EPOCH,
        provenance=_runtime_provenance("ev.delta.001"),
        confidence=1.0,
        taint=Taint.TRUSTED_RUNTIME,
    )
    input = _input().model_copy(update={"supplied_facts": (second, first)})

    twin = SecuritySemanticTwinBuilder().build(input)

    assert len(twin.conflicts) == 1
    assert twin.conflicts[0].left_value == "tenant_a"
    assert twin.conflicts[0].right_value == "tenant_b"
    assert set(twin.conflicts[0].evidence_ids) == {"ev.source.001", "ev.delta.001"}
