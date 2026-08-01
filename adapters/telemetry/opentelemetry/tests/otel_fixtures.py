"""Uniquely named fixtures for the offline OpenTelemetry adapter."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from stateweaver.adapters.telemetry.opentelemetry import (
    ADAPTER_NAME,
    ADAPTER_VERSION,
    TraceIngestRequest,
    canonical_spans_sha256,
    decode_otlp_json,
)
from stateweaver.contracts import (
    ActionTarget,
    ComparisonOperator,
    EffectOperation,
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
)
from stateweaver.twin import StateDelta

EPOCH = datetime(2026, 1, 1, tzinfo=UTC)
EPOCH_NANOS = 1_767_225_600_000_000_000
TRACE_ID = "1" * 32
ROOT_SPAN_ID = "a" * 16
CHILD_SPAN_ID = "b" * 16
type OtlpJson = dict[str, Any]


def attribute(key: str, kind: str, value: object) -> OtlpJson:
    return {"key": key, "value": {kind: value}}


def root_span() -> OtlpJson:
    return {
        "traceId": TRACE_ID,
        "spanId": ROOT_SPAN_ID,
        "name": "GET /api/documents/{document_id}",
        "kind": "SPAN_KIND_SERVER",
        "startTimeUnixNano": str(EPOCH_NANOS),
        "endTimeUnixNano": str(EPOCH_NANOS + 10_000_000),
        "attributes": [
            attribute("http.request.method", "stringValue", "GET"),
            attribute("http.route", "stringValue", "/api/documents/{document_id}"),
            attribute("http.response.status_code", "intValue", "200"),
        ],
    }


def child_span(*, span_id: str = CHILD_SPAN_ID, parent: str = ROOT_SPAN_ID) -> OtlpJson:
    return {
        "traceId": TRACE_ID,
        "spanId": span_id,
        "parentSpanId": parent,
        "name": "synthetic database read",
        "kind": "SPAN_KIND_CLIENT",
        "startTimeUnixNano": str(EPOCH_NANOS + 2_000_000),
        "endTimeUnixNano": str(EPOCH_NANOS + 8_000_000),
        "attributes": [attribute("db.system.name", "stringValue", "synthetic-postgresql")],
    }


def otlp_document(spans: list[OtlpJson] | None = None) -> OtlpJson:
    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [attribute("service.name", "stringValue", "synthetic-lab")]
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "synthetic-instrumentation", "version": "1.0.0"},
                        "spans": spans or [root_span(), child_span()],
                    }
                ],
            }
        ]
    }


def state_delta(index: int = 1) -> StateDelta:
    return StateDelta(
        delta_id=f"delta.synthetic.{index:03d}",
        subject="session.synthetic.001",
        precondition=StateCondition(
            path="session.generation",
            operator=ComparisonOperator.EQ,
            value=index,
        ),
        effect=StateEffect(
            path="session.generation",
            operation=EffectOperation.SET,
            value=index + 1,
        ),
        observable=StateCondition(
            path="response.status",
            operator=ComparisonOperator.EQ,
            value=200,
        ),
        provenance=Provenance(
            kind=ProvenanceKind.OBSERVED,
            evidence_ids=(f"ev.database.{index:03d}",),
            adapter="synthetic-state",
            adapter_version="0.1.0",
        ),
        observed_at=EPOCH + timedelta(milliseconds=4 + index),
    )


def trace_evidence(
    *,
    trace_id: str = TRACE_ID,
    span_id: str = ROOT_SPAN_ID,
    sha256: str | None = None,
) -> EvidenceRecord:
    if sha256 is None:
        sha256 = canonical_spans_sha256(decode_otlp_json(otlp_document()))
    return EvidenceRecord(
        evidence_id="ev.trace.001",
        kind=EvidenceKind.OTEL_TRACE,
        artifact_uri="artifact://synthetic/trace/001",
        sha256=sha256,
        produced_by=EvidenceProducer(adapter=ADAPTER_NAME, version=ADAPTER_VERSION),
        trace_context=TraceContext(trace_id=trace_id, span_id=span_id),
        redaction_policy_version="synthetic-v1",
        taint=Taint.TRUSTED_RUNTIME,
        created_at=EPOCH + timedelta(milliseconds=20),
    )


def request(*, deltas: tuple[StateDelta, ...] | None = None) -> TraceIngestRequest:
    return TraceIngestRequest(
        transition_id="transition.synthetic.001",
        name="synthetic document read flow",
        action=HttpRequestAction(
            method=HttpMethod.GET,
            target=ActionTarget(
                scheme="http",
                host="localhost",
                port=8000,
                path="/api/documents/document-001",
            ),
            expected_statuses=(200,),
        ),
        expected_route="/api/documents/{document_id}",
        trace_evidence=trace_evidence(),
        state_deltas=deltas or (state_delta(),),
        fidelity=FidelityProfile(
            code=FidelityLevel.EXACT,
            identity=FidelityLevel.OBSERVED,
            database=FidelityLevel.OBSERVED,
            timing=FidelityLevel.OBSERVED,
        ),
    )
