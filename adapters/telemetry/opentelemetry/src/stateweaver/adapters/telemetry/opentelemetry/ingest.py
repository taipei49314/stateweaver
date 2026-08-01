"""Offline OTLP JSON decoding and causal conversion to ``TelemetryFlow``."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError
from stateweaver.contracts import HttpMethod, Provenance, ProvenanceKind, sha256_digest
from stateweaver.twin import TelemetryFlow

from .models import (
    ADAPTER_NAME,
    ADAPTER_VERSION,
    MAX_SPANS,
    MAX_UNIX_NANO,
    OtlpSpan,
    SpanAttribute,
    SpanKind,
    TelemetryIngestError,
    TraceIngestRequest,
    _WireAnyValue,
    _WireDocument,
    _WireSpan,
)

_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_SPAN_KIND_BY_CODE = {
    0: SpanKind.UNSPECIFIED,
    1: SpanKind.INTERNAL,
    2: SpanKind.SERVER,
    3: SpanKind.CLIENT,
    4: SpanKind.PRODUCER,
    5: SpanKind.CONSUMER,
}


def decode_otlp_json(document: Mapping[str, object]) -> tuple[OtlpSpan, ...]:
    """Decode the supported OTLP JSON subset without reading files or opening sockets."""

    try:
        safe = _json_ready(document)
        wire = _WireDocument.model_validate_json(
            json.dumps(
                safe,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        spans: list[OtlpSpan] = []
        for resource_spans in wire.resource_spans:
            if resource_spans.resource is not None:
                for attribute in resource_spans.resource.attributes:
                    SpanAttribute(key=attribute.key, value=_scalar(attribute.value))
            for scope_spans in resource_spans.scope_spans:
                for item in scope_spans.spans:
                    spans.append(_typed_span(item))
        if not spans:
            raise TelemetryIngestError("OTLP document does not contain spans")
        return validate_spans(spans)
    except TelemetryIngestError:
        raise
    except (ValidationError, TypeError, ValueError, OverflowError, RecursionError) as error:
        raise TelemetryIngestError("OTLP JSON is malformed or contains unsafe data") from error


def validate_spans(spans: Sequence[OtlpSpan]) -> tuple[OtlpSpan, ...]:
    """Revalidate typed spans and require one connected, time-bounded parent DAG."""

    try:
        normalized = tuple(
            OtlpSpan.model_validate(span.model_dump(mode="python")) for span in spans
        )
    except ValidationError as error:
        raise TelemetryIngestError("typed OTLP span is invalid") from error
    if not normalized:
        raise TelemetryIngestError("trace must contain at least one span")
    if len(normalized) > MAX_SPANS:
        raise TelemetryIngestError("trace span count exceeds the local ingestion limit")
    trace_ids = {item.trace_id for item in normalized}
    span_ids = [item.span_id for item in normalized]
    if len(trace_ids) != 1:
        raise TelemetryIngestError("trace ingestion requires exactly one W3C trace ID")
    if len(span_ids) != len(set(span_ids)):
        raise TelemetryIngestError("trace span IDs must be unique")
    by_id = {item.span_id: item for item in normalized}
    roots = [item for item in normalized if item.parent_span_id is None]
    if len(roots) != 1:
        raise TelemetryIngestError("trace DAG must have exactly one connected root")
    for item in normalized:
        if item.parent_span_id is not None and item.parent_span_id not in by_id:
            raise TelemetryIngestError("trace DAG contains a disconnected parent reference")
    _reject_cycles(normalized, by_id)
    _validate_connectivity(roots[0], normalized, by_id)
    _validate_time_bounds(normalized, by_id)
    return tuple(sorted(normalized, key=lambda item: (item.start_time_unix_nano, item.span_id)))


def ingest_spans(request: TraceIngestRequest, spans: Sequence[OtlpSpan]) -> TelemetryFlow:
    """Validate causal bindings and emit one evidence-preserving semantic flow."""

    try:
        request = TraceIngestRequest.model_validate(request.model_dump(mode="python"))
    except ValidationError as error:
        raise TelemetryIngestError("trace ingest request is invalid") from error
    normalized = validate_spans(spans)
    root = next(item for item in normalized if item.parent_span_id is None)
    _match_http_root(request, root)
    evidence = request.trace_evidence
    context = evidence.trace_context
    if context is None or context.trace_id != root.trace_id or context.span_id != root.span_id:
        raise TelemetryIngestError("trace evidence context does not match the HTTP root span")
    if _datetime_to_nanos(evidence.created_at) < root.end_time_unix_nano:
        raise TelemetryIngestError("trace evidence was created before the trace completed")
    if evidence.sha256 != canonical_spans_sha256(normalized):
        raise TelemetryIngestError("trace evidence digest does not match canonical typed spans")
    for delta in request.state_deltas:
        observed = _datetime_to_nanos(delta.observed_at)
        if not root.start_time_unix_nano <= observed <= root.end_time_unix_nano:
            raise TelemetryIngestError("state delta falls outside the trace time boundary")
    return TelemetryFlow(
        transition_id=request.transition_id,
        name=request.name,
        action=request.action,
        deltas=request.state_deltas,
        provenance=Provenance(
            kind=ProvenanceKind.OBSERVED,
            evidence_ids=(evidence.evidence_id,),
            adapter=ADAPTER_NAME,
            adapter_version=ADAPTER_VERSION,
        ),
        fidelity=request.fidelity,
        consistent_replays=request.consistent_replays,
    )


def ingest_otlp_json(request: TraceIngestRequest, document: Mapping[str, object]) -> TelemetryFlow:
    """Decode caller-supplied OTLP JSON and emit an offline semantic flow."""

    return ingest_spans(request, decode_otlp_json(document))


def canonical_spans_sha256(spans: Sequence[OtlpSpan]) -> str:
    """Hash the order-independent, validated semantic trace representation."""

    return sha256_digest(validate_spans(spans))


def _typed_span(item: _WireSpan) -> OtlpSpan:
    parent = item.parent_span_id if item.parent_span_id not in {None, ""} else None
    return OtlpSpan(
        trace_id=item.trace_id,
        span_id=item.span_id,
        parent_span_id=parent,
        name=item.name,
        kind=_span_kind(item.kind),
        start_time_unix_nano=_unix_nano(item.start_time_unix_nano),
        end_time_unix_nano=_unix_nano(item.end_time_unix_nano),
        attributes=tuple(
            SpanAttribute(key=attribute.key, value=_scalar(attribute.value))
            for attribute in item.attributes
        ),
    )


def _span_kind(value: str | int) -> SpanKind:
    if isinstance(value, bool):
        raise TelemetryIngestError("OTLP span kind is invalid")
    if isinstance(value, int):
        try:
            return _SPAN_KIND_BY_CODE[value]
        except KeyError as error:
            raise TelemetryIngestError("OTLP span kind is invalid") from error
    try:
        return SpanKind(value)
    except ValueError as error:
        raise TelemetryIngestError("OTLP span kind is invalid") from error


def _unix_nano(value: str | int) -> int:
    if isinstance(value, bool):
        raise TelemetryIngestError("OTLP nanosecond timestamp is invalid")
    if isinstance(value, str):
        if not value.isascii() or not value.isdecimal():
            raise TelemetryIngestError("OTLP nanosecond timestamp is invalid")
        parsed = int(value)
    else:
        parsed = value
    if not 0 <= parsed <= MAX_UNIX_NANO:
        raise TelemetryIngestError("OTLP nanosecond timestamp is outside supported range")
    return parsed


def _scalar(value: _WireAnyValue) -> Any:
    return value.scalar()


def _reject_cycles(spans: tuple[OtlpSpan, ...], by_id: Mapping[str, OtlpSpan]) -> None:
    finished: set[str] = set()
    for item in spans:
        if item.span_id in finished:
            continue
        current: OtlpSpan | None = item
        path: list[str] = []
        active: set[str] = set()
        while current is not None and current.span_id not in finished:
            if current.span_id in active:
                raise TelemetryIngestError("trace parent graph contains a cycle")
            active.add(current.span_id)
            path.append(current.span_id)
            current = by_id.get(current.parent_span_id) if current.parent_span_id else None
        finished.update(path)


def _validate_connectivity(
    root: OtlpSpan,
    spans: tuple[OtlpSpan, ...],
    by_id: Mapping[str, OtlpSpan],
) -> None:
    children: dict[str, list[str]] = {item.span_id: [] for item in spans}
    for item in spans:
        if item.parent_span_id is not None:
            children[item.parent_span_id].append(item.span_id)
    pending = [root.span_id]
    reached: set[str] = set()
    while pending:
        current = pending.pop()
        if current in reached:
            continue
        reached.add(current)
        pending.extend(children[current])
    if reached != set(by_id):
        raise TelemetryIngestError("trace parent graph is disconnected")


def _validate_time_bounds(spans: tuple[OtlpSpan, ...], by_id: Mapping[str, OtlpSpan]) -> None:
    for item in spans:
        if item.parent_span_id is None:
            continue
        parent = by_id[item.parent_span_id]
        if not (
            parent.start_time_unix_nano
            <= item.start_time_unix_nano
            < item.end_time_unix_nano
            <= parent.end_time_unix_nano
        ):
            raise TelemetryIngestError("child span falls outside its parent time boundary")


def _match_http_root(request: TraceIngestRequest, root: OtlpSpan) -> None:
    if root.kind is not SpanKind.SERVER:
        raise TelemetryIngestError("trace root must be an HTTP server span")
    attributes = root.attribute_map()
    method = attributes.get("http.request.method")
    route = attributes.get("http.route")
    status = attributes.get("http.response.status_code")
    if not isinstance(method, str) or method not in {item.value for item in HttpMethod}:
        raise TelemetryIngestError("HTTP root method attribute is missing or invalid")
    if not isinstance(route, str) or route != request.expected_route:
        raise TelemetryIngestError("HTTP root route does not match the typed action")
    if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
        raise TelemetryIngestError("HTTP root status attribute is missing or invalid")
    if request.action.method is None or method != request.action.method.value:
        raise TelemetryIngestError("HTTP root method does not match the typed action")
    if status not in request.action.expected_statuses:
        raise TelemetryIngestError("HTTP root status does not match the typed action expectation")


def _datetime_to_nanos(value: datetime) -> int:
    absolute = value.astimezone(UTC)
    delta = absolute - _UNIX_EPOCH
    return ((delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1_000


def _json_ready(value: object, depth: int = 0) -> object:
    if depth > 64:
        raise TelemetryIngestError("OTLP JSON exceeds the maximum nesting depth")
    if isinstance(value, Mapping):
        if len(value) > 16_384:
            raise TelemetryIngestError("OTLP JSON mapping exceeds the local ingestion limit")
        output: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TelemetryIngestError("OTLP JSON mapping keys must be strings")
            output[key] = _json_ready(item, depth + 1)
        return output
    if isinstance(value, list | tuple):
        if len(value) > 16_384:
            raise TelemetryIngestError("OTLP JSON array exceeds the local ingestion limit")
        return [_json_ready(item, depth + 1) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        raise TelemetryIngestError("OTLP JSON numbers must be finite")
    if isinstance(value, str) and len(value) > 16_384:
        raise TelemetryIngestError("OTLP JSON string exceeds the local ingestion limit")
    if value is None or isinstance(value, str | int | float | bool):
        return value
    raise TelemetryIngestError("OTLP JSON contains a non-JSON value")
