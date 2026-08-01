from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta

import pytest
from otel_fixtures import (
    EPOCH,
    EPOCH_NANOS,
    OtlpJson,
    attribute,
    child_span,
    otlp_document,
    request,
    root_span,
    state_delta,
    trace_evidence,
)
from pydantic import ValidationError
from stateweaver.adapters.telemetry.opentelemetry import (
    ADAPTER_NAME,
    ADAPTER_VERSION,
    TelemetryIngestError,
    TraceIngestRequest,
    decode_otlp_json,
    ingest_otlp_json,
    ingest_spans,
    validate_spans,
)
from stateweaver.contracts import (
    ActionTarget,
    EvidenceKind,
    EvidenceProducer,
    EvidenceRecord,
    FidelityProfile,
    HttpMethod,
    HttpRequestAction,
    ProvenanceKind,
    Taint,
)


def test_ingests_observed_http_trace_into_evidence_bound_telemetry_flow() -> None:
    supplied = request()

    flow = ingest_otlp_json(supplied, otlp_document())

    assert flow.transition_id == supplied.transition_id
    assert flow.action == supplied.action
    assert flow.deltas == supplied.state_deltas
    assert flow.fidelity == supplied.fidelity
    assert flow.provenance.kind is ProvenanceKind.OBSERVED
    assert flow.provenance.evidence_ids == ("ev.trace.001",)
    assert flow.provenance.adapter == ADAPTER_NAME
    assert flow.provenance.adapter_version == ADAPTER_VERSION


def test_span_and_delta_permutations_have_identical_output() -> None:
    first_request = request(deltas=(state_delta(1), state_delta(2)))
    second_request = request(deltas=(state_delta(2), state_delta(1)))
    first_document = otlp_document([root_span(), child_span()])
    second_document = otlp_document([child_span(), root_span()])

    first = ingest_otlp_json(first_request, first_document)
    second = ingest_otlp_json(second_request, second_document)

    assert first.canonical_bytes() == second.canonical_bytes()
    assert decode_otlp_json(first_document) == decode_otlp_json(second_document)


def test_rejects_disconnected_parent_reference() -> None:
    disconnected = child_span(parent="c" * 16)
    with pytest.raises(TelemetryIngestError, match="disconnected"):
        ingest_otlp_json(request(), otlp_document([root_span(), disconnected]))


def test_rejects_parent_cycle_even_when_a_separate_root_exists() -> None:
    first = child_span(span_id="b" * 16, parent="c" * 16)
    second = child_span(span_id="c" * 16, parent="b" * 16)
    with pytest.raises(TelemetryIngestError, match="cycle"):
        ingest_otlp_json(request(), otlp_document([root_span(), first, second]))


@pytest.mark.parametrize(
    ("key", "kind", "value"),
    [
        ("http.request.header.authorization", "stringValue", "synthetic"),
        ("app.note", "stringValue", "Bearer synthetic-never-print"),
    ],
)
def test_rejects_secret_like_attributes_without_echoing_values(
    key: str, kind: str, value: object
) -> None:
    document = otlp_document()
    spans = document["resourceSpans"][0]["scopeSpans"][0]["spans"]
    spans[0]["attributes"].append(attribute(key, kind, value))

    with pytest.raises(TelemetryIngestError) as raised:
        ingest_otlp_json(request(), document)
    assert "synthetic-never-print" not in str(raised.value)


@pytest.mark.parametrize(
    ("attribute_key", "attribute_kind", "attribute_value", "message"),
    [
        ("http.request.method", "stringValue", "POST", "method"),
        ("http.route", "stringValue", "/api/other", "route"),
        ("http.response.status_code", "intValue", "403", "status"),
    ],
)
def test_rejects_http_span_and_typed_action_mismatch(
    attribute_key: str,
    attribute_kind: str,
    attribute_value: object,
    message: str,
) -> None:
    root = root_span()
    root["attributes"] = [item for item in root["attributes"] if item["key"] != attribute_key] + [
        attribute(attribute_key, attribute_kind, attribute_value)
    ]
    with pytest.raises(TelemetryIngestError, match=message):
        ingest_otlp_json(request(), otlp_document([root, child_span()]))


@pytest.mark.parametrize(
    "mutation",
    [
        lambda document: document.update({"unknown": True}),
        lambda document: document["resourceSpans"][0]["scopeSpans"][0]["spans"][0].update(
            {"traceId": "not-w3c"}
        ),
        lambda document: document["resourceSpans"][0]["scopeSpans"][0]["spans"][0].update(
            {"startTimeUnixNano": "not-a-time"}
        ),
    ],
)
def test_rejects_malformed_otlp_json(
    mutation: Callable[[OtlpJson], None],
) -> None:
    document = otlp_document()
    mutation(document)
    with pytest.raises(TelemetryIngestError):
        decode_otlp_json(document)


def test_rejects_child_outside_parent_time_boundary() -> None:
    child = child_span()
    child["endTimeUnixNano"] = str(EPOCH_NANOS + 20_000_000)
    with pytest.raises(TelemetryIngestError, match="time boundary"):
        ingest_otlp_json(request(), otlp_document([root_span(), child]))


def test_rejects_duplicate_span_ids() -> None:
    with pytest.raises(TelemetryIngestError, match="unique"):
        ingest_otlp_json(request(), otlp_document([root_span(), child_span(), child_span()]))


def test_rejects_trace_evidence_context_mismatch() -> None:
    supplied = request().model_copy(update={"trace_evidence": trace_evidence(span_id="c" * 16)})
    with pytest.raises(TelemetryIngestError, match="context"):
        ingest_otlp_json(supplied, otlp_document())


def test_rejects_state_delta_outside_trace_boundary() -> None:
    delta = state_delta().model_copy(update={"observed_at": EPOCH + timedelta(seconds=1)})
    supplied = request(deltas=(delta,))
    with pytest.raises(TelemetryIngestError, match="state delta"):
        ingest_otlp_json(supplied, otlp_document())


def test_rejects_wrong_evidence_kind_and_producer() -> None:
    evidence = EvidenceRecord(
        evidence_id="ev.trace.001",
        kind=EvidenceKind.STATE_SNAPSHOT,
        artifact_uri="artifact://synthetic/trace/001",
        sha256="sha256:" + "a" * 64,
        produced_by=EvidenceProducer(adapter="other-adapter", version="0.1.0"),
        trace_context=trace_evidence().trace_context,
        redaction_policy_version="synthetic-v1",
        taint=Taint.TRUSTED_RUNTIME,
        created_at=EPOCH + timedelta(milliseconds=20),
    )
    payload = request().model_dump(mode="python")
    payload["trace_evidence"] = evidence
    with pytest.raises(ValidationError, match="adapter"):
        TraceIngestRequest.model_validate(payload)


def test_rejects_nonlocal_typed_action_before_trace_processing() -> None:
    payload = request().model_dump(mode="python")
    payload["action"] = HttpRequestAction(
        method=HttpMethod.GET,
        target=ActionTarget(
            scheme="https", host="example.com", port=443, path="/api/documents/document-001"
        ),
        expected_statuses=(200,),
    )
    with pytest.raises(ValidationError, match="local synthetic"):
        TraceIngestRequest.model_validate(payload)


def test_typed_span_ingest_revalidates_forged_instances() -> None:
    spans = decode_otlp_json(otlp_document())
    root = spans[0].model_copy(update={"trace_id": "not-w3c"})
    with pytest.raises(TelemetryIngestError, match="typed"):
        validate_spans((root, spans[1]))


def test_direct_typed_span_ingest_matches_json_ingest() -> None:
    spans = decode_otlp_json(otlp_document())
    assert ingest_spans(request(), spans) == ingest_otlp_json(request(), otlp_document())


def test_rejects_semantic_trace_tampering_against_evidence_digest() -> None:
    document = otlp_document()
    child = document["resourceSpans"][0]["scopeSpans"][0]["spans"][1]
    child["attributes"] = [attribute("db.system.name", "stringValue", "synthetic-sqlite")]

    with pytest.raises(TelemetryIngestError, match="digest"):
        ingest_otlp_json(request(), document)


def test_rejects_trace_request_without_observed_fidelity() -> None:
    payload = request().model_dump(mode="python")
    payload["fidelity"] = FidelityProfile()

    with pytest.raises(ValidationError, match="observed fidelity"):
        TraceIngestRequest.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "all_zero_id"),
    [("traceId", "0" * 32), ("spanId", "0" * 16)],
)
def test_rejects_all_zero_w3c_identifiers(field: str, all_zero_id: str) -> None:
    document = otlp_document()
    root = document["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    root[field] = all_zero_id

    with pytest.raises(TelemetryIngestError):
        decode_otlp_json(document)
