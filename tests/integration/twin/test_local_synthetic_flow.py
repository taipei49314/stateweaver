"""End-to-end, socket-free construction of one observed semantic transition."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, cast

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Column, Integer, MetaData, String, Table
from stateweaver.adapters.fastapi_sqlalchemy import (
    SourceExtractionSpec,
    SqlAlchemyResourceSpec,
    extract_fastapi_openapi,
    extract_fastapi_routes,
    extract_sqlalchemy_resources,
)
from stateweaver.adapters.telemetry.opentelemetry import (
    ADAPTER_NAME,
    ADAPTER_VERSION,
    TraceIngestRequest,
    canonical_spans_sha256,
    decode_otlp_json,
    ingest_otlp_json,
)
from stateweaver.contracts import (
    ActionTarget,
    ComparisonOperator,
    EffectOperation,
    EntityKind,
    EvidenceKind,
    EvidenceProducer,
    EvidenceRecord,
    FidelityLevel,
    FidelityProfile,
    HttpMethod,
    HttpRequestAction,
    Provenance,
    ProvenanceKind,
    StateCondition,
    StateEffect,
    Taint,
    TraceContext,
    sha256_digest,
)
from stateweaver.twin import SecuritySemanticTwinBuilder, StateDelta, TwinBuildInput

EPOCH = datetime(2026, 1, 1, tzinfo=UTC)
EPOCH_NANOS = 1_767_225_600_000_000_000
TRACE_ID = "2" * 32
ROOT_SPAN_ID = "c" * 16
DATABASE_SPAN_ID = "d" * 16


def _attribute(key: str, kind: str, value: object) -> dict[str, Any]:
    return {"key": key, "value": {kind: value}}


def _otlp_document(*, method: str, route: str, status: int) -> dict[str, Any]:
    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        _attribute("service.name", "stringValue", "synthetic-document-service")
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "synthetic-testclient", "version": "1.0.0"},
                        "spans": [
                            {
                                "traceId": TRACE_ID,
                                "spanId": ROOT_SPAN_ID,
                                "name": f"{method} {route}",
                                "kind": "SPAN_KIND_SERVER",
                                "startTimeUnixNano": str(EPOCH_NANOS),
                                "endTimeUnixNano": str(EPOCH_NANOS + 12_000_000),
                                "attributes": [
                                    _attribute("http.request.method", "stringValue", method),
                                    _attribute("http.route", "stringValue", route),
                                    _attribute(
                                        "http.response.status_code", "intValue", str(status)
                                    ),
                                ],
                            },
                            {
                                "traceId": TRACE_ID,
                                "spanId": DATABASE_SPAN_ID,
                                "parentSpanId": ROOT_SPAN_ID,
                                "name": "synthetic documents metadata-backed read",
                                "kind": "SPAN_KIND_INTERNAL",
                                "startTimeUnixNano": str(EPOCH_NANOS + 2_000_000),
                                "endTimeUnixNano": str(EPOCH_NANOS + 10_000_000),
                                "attributes": [
                                    _attribute(
                                        "db.system.name",
                                        "stringValue",
                                        "synthetic-sqlalchemy-metadata",
                                    )
                                ],
                            },
                        ],
                    }
                ],
            }
        ]
    }


def test_testclient_source_and_trace_evidence_build_one_observed_transition() -> None:
    """Bind an actual ASGI response to source, trace, state, and twin semantics."""

    app = FastAPI(title="Synthetic document service", version="1.0.0")
    read_counter = {"value": 0}

    @app.get("/api/documents/{document_id}", operation_id="read_document")
    def read_document(document_id: str) -> dict[str, str | int]:
        read_counter["value"] += 1
        return {
            "document_id": document_id,
            "tenant_id": "tenant-synthetic",
            "read_count": read_counter["value"],
        }

    metadata = MetaData()
    documents = Table(
        "documents",
        metadata,
        Column("document_id", String, primary_key=True),
        Column("tenant_id", String, nullable=False),
        Column("owner_id", String, nullable=False),
        Column("read_count", Integer, nullable=False),
    )
    extraction = SourceExtractionSpec(
        service_id="service.synthetic.integration",
        evidence_id="evidence.source.integration",
        include_path_prefixes=("/api/documents",),
        policy_checks_by_operation={"read_document": ("principal.tenant",)},
    )
    routes = extract_fastapi_routes(app, extraction)
    openapi = extract_fastapi_openapi(app, extraction)
    resources = extract_sqlalchemy_resources(
        (documents,),
        {
            "documents": SqlAlchemyResourceSpec(
                resource_id="resource.synthetic.documents",
                tenant_field="tenant_id",
                owner_field="owner_id",
            )
        },
        extraction,
    )
    route = routes[0]

    before_count = read_counter["value"]
    with TestClient(app, base_url="http://localhost") as client:
        response = client.get("/api/documents/document-001")
    payload = cast(dict[str, object], response.json())
    document_id = payload.get("document_id")
    observed_count = payload.get("read_count")
    assert response.status_code == 200
    assert document_id == "document-001"
    assert isinstance(observed_count, int) and not isinstance(observed_count, bool)
    assert observed_count == before_count + 1 == read_counter["value"]
    assert response.request.url.host == "localhost"
    assert response.request.url.path == "/api/documents/document-001"
    assert route.path == "/api/documents/{document_id}"
    assert route.operation_id == "operation.read_document"

    document = _otlp_document(
        method=response.request.method,
        route=route.path,
        status=response.status_code,
    )
    spans = decode_otlp_json(document)
    root_span = next(span for span in spans if span.parent_span_id is None)
    trace_evidence = EvidenceRecord(
        evidence_id="evidence.trace.integration",
        kind=EvidenceKind.OTEL_TRACE,
        artifact_uri="artifact://synthetic/integration/trace",
        sha256=canonical_spans_sha256(spans),
        produced_by=EvidenceProducer(adapter=ADAPTER_NAME, version=ADAPTER_VERSION),
        trace_context=TraceContext(trace_id=root_span.trace_id, span_id=root_span.span_id),
        redaction_policy_version="synthetic-v1",
        taint=Taint.TRUSTED_RUNTIME,
        created_at=EPOCH + timedelta(milliseconds=20),
    )
    source_evidence = EvidenceRecord(
        evidence_id=extraction.evidence_id,
        kind=EvidenceKind.STATE_SNAPSHOT,
        artifact_uri="artifact://synthetic/integration/source",
        sha256=sha256_digest(
            (
                openapi.document_id,
                openapi.service_id,
                openapi.document,
                routes,
                resources,
            )
        ),
        produced_by=EvidenceProducer(adapter="fastapi_sqlalchemy", version="0.1.0"),
        redaction_policy_version="synthetic-v1",
        taint=Taint.TRUSTED_SOURCE,
        created_at=EPOCH - timedelta(seconds=1),
    )
    state_evidence = EvidenceRecord(
        evidence_id="evidence.state.integration",
        kind=EvidenceKind.STATE_SNAPSHOT,
        artifact_uri="artifact://synthetic/integration/state",
        sha256=sha256_digest(
            {
                "document_id": document_id,
                "read_count_before": before_count,
                "read_count_after": observed_count,
                "response_status": response.status_code,
            }
        ),
        produced_by=EvidenceProducer(adapter="testclient-observer", version="0.1.0"),
        redaction_policy_version="synthetic-v1",
        taint=Taint.TRUSTED_RUNTIME,
        created_at=EPOCH + timedelta(milliseconds=20),
    )
    delta = StateDelta(
        delta_id="delta.synthetic.read_count",
        subject=resources[0].resource_id,
        precondition=StateCondition(
            path="resource.read_count",
            operator=ComparisonOperator.EQ,
            value=before_count,
        ),
        effect=StateEffect(
            path="resource.read_count",
            operation=EffectOperation.SET,
            value=observed_count,
        ),
        observable=StateCondition(
            path="response.read_count",
            operator=ComparisonOperator.EQ,
            value=observed_count,
        ),
        provenance=Provenance(
            kind=ProvenanceKind.OBSERVED,
            evidence_ids=(state_evidence.evidence_id,),
            adapter=state_evidence.produced_by.adapter,
            adapter_version=state_evidence.produced_by.version,
        ),
        observed_at=EPOCH + timedelta(milliseconds=6),
    )
    action = HttpRequestAction(
        method=HttpMethod(response.request.method),
        target=ActionTarget(
            scheme="http",
            host="localhost",
            port=response.request.url.port or 80,
            path=response.request.url.path,
        ),
        expected_statuses=(response.status_code,),
    )
    flow = ingest_otlp_json(
        TraceIngestRequest(
            transition_id="transition.synthetic.document_read",
            name="synthetic document read",
            action=action,
            expected_route=route.path,
            trace_evidence=trace_evidence,
            state_deltas=(delta,),
            fidelity=FidelityProfile(
                code=FidelityLevel.EXACT,
                database=FidelityLevel.PARTIAL,
                timing=FidelityLevel.OBSERVED,
            ),
        ),
        document,
    )
    twin = SecuritySemanticTwinBuilder().build(
        TwinBuildInput(
            twin_id="twin.synthetic.integration",
            evidence_records=(source_evidence, trace_evidence, state_evidence),
            openapi_documents=(openapi,),
            source_routes=routes,
            orm_resources=resources,
            telemetry_flows=(flow,),
        )
    )

    transition = twin.transitions[0]
    assert transition.source is ProvenanceKind.OBSERVED
    assert transition.action == action
    assert transition.preconditions == (delta.precondition,)
    assert transition.effects == (delta.effect,)
    assert transition.observables == (delta.observable,)
    assert transition.evidence_ids == tuple(
        sorted((trace_evidence.evidence_id, state_evidence.evidence_id))
    )
    assert set(twin.evidence_ids) == {
        source_evidence.evidence_id,
        trace_evidence.evidence_id,
        state_evidence.evidence_id,
    }
    assert trace_evidence.trace_context == TraceContext(
        trace_id=root_span.trace_id,
        span_id=root_span.span_id,
    )
    assert root_span.attribute_map()["http.response.status_code"] == response.status_code
    assert any(
        entity.entity_id == resources[0].resource_id and entity.kind is EntityKind.RESOURCE
        for entity in twin.entities
    )
    assert any(
        fact.subject == resources[0].resource_id
        and fact.predicate == "read_count"
        and fact.object == observed_count
        and fact.provenance.kind is ProvenanceKind.OBSERVED
        for fact in twin.facts
    )
