"""Offline OpenTelemetry trace ingestion for StateWeaver's semantic twin."""

from .ingest import (
    canonical_spans_sha256,
    decode_otlp_json,
    ingest_otlp_json,
    ingest_spans,
    validate_spans,
)
from .models import (
    ADAPTER_NAME,
    ADAPTER_VERSION,
    OtlpSpan,
    SpanAttribute,
    SpanKind,
    TelemetryIngestError,
    TraceIngestRequest,
)

__all__ = [
    "ADAPTER_NAME",
    "ADAPTER_VERSION",
    "OtlpSpan",
    "SpanAttribute",
    "SpanKind",
    "TelemetryIngestError",
    "TraceIngestRequest",
    "canonical_spans_sha256",
    "decode_otlp_json",
    "ingest_otlp_json",
    "ingest_spans",
    "validate_spans",
]
