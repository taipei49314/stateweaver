"""Closed OTLP subset and typed trace-ingestion request models."""

from __future__ import annotations

import math
import re
from enum import StrEnum
from typing import Annotated

from pydantic import Field, StringConstraints, field_validator, model_validator
from stateweaver.contracts import (
    EvidenceKind,
    EvidenceRecord,
    FidelityProfile,
    HttpRequestAction,
    Taint,
)
from stateweaver.contracts.base import (
    ContractId,
    ContractModel,
    JsonScalar,
    SpanId,
    TraceId,
)
from stateweaver.twin import StateDelta

ADAPTER_NAME = "opentelemetry-json"
ADAPTER_VERSION = "0.1.0"
MAX_UNIX_NANO = 253_402_300_799_999_999_999
MAX_SPANS = 4_096
MAX_ATTRIBUTES = 256
AttributeKey = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z][A-Za-z0-9_.-]*$",
    ),
]
RouteTemplate = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=256, pattern=r"^/"),
]
_SECRET_KEY = re.compile(
    r"(?:authorization|cookie|password|secret|credential|api[_-]?key|"
    r"access[_-]?token|refresh[_-]?token|raw[_-]?token)",
    re.IGNORECASE,
)
_SECRET_TEXT = re.compile(
    r"(?:\bbearer\s+[A-Za-z0-9._~+/-]+|"
    r"\b(?:authorization|cookie|password|api[_-]?key|access[_-]?token)\s*[:=])",
    re.IGNORECASE,
)


class TelemetryIngestError(ValueError):
    """Value-safe rejection that never includes untrusted telemetry content."""


class SpanKind(StrEnum):
    UNSPECIFIED = "SPAN_KIND_UNSPECIFIED"
    INTERNAL = "SPAN_KIND_INTERNAL"
    SERVER = "SPAN_KIND_SERVER"
    CLIENT = "SPAN_KIND_CLIENT"
    PRODUCER = "SPAN_KIND_PRODUCER"
    CONSUMER = "SPAN_KIND_CONSUMER"


class SpanAttribute(ContractModel):
    key: AttributeKey
    value: JsonScalar

    @model_validator(mode="after")
    def attribute_is_safe(self) -> SpanAttribute:
        if isinstance(self.value, str) and len(self.value) > 4_096:
            raise ValueError("telemetry attribute strings are bounded")
        if _SECRET_KEY.search(self.key) or (
            isinstance(self.value, str) and _SECRET_TEXT.search(self.value)
        ):
            raise ValueError("secret-like telemetry attribute is not permitted")
        return self


class OtlpSpan(ContractModel):
    trace_id: TraceId
    span_id: SpanId
    parent_span_id: SpanId | None = None
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)]
    kind: SpanKind
    start_time_unix_nano: Annotated[int, Field(ge=0, le=MAX_UNIX_NANO)]
    end_time_unix_nano: Annotated[int, Field(ge=1, le=MAX_UNIX_NANO)]
    attributes: tuple[SpanAttribute, ...] = ()

    @field_validator("attributes")
    @classmethod
    def attributes_are_canonical(
        cls, value: tuple[SpanAttribute, ...]
    ) -> tuple[SpanAttribute, ...]:
        keys = [item.key for item in value]
        if len(value) > MAX_ATTRIBUTES:
            raise ValueError("span attribute count exceeds the local ingestion limit")
        if len(keys) != len(set(keys)):
            raise ValueError("span attribute keys must be unique")
        return tuple(sorted(value, key=lambda item: item.key))

    @model_validator(mode="after")
    def identifiers_and_time_are_valid(self) -> OtlpSpan:
        if set(self.trace_id) == {"0"} or set(self.span_id) == {"0"}:
            raise ValueError("W3C trace and span IDs cannot be all zero")
        if self.parent_span_id is not None and set(self.parent_span_id) == {"0"}:
            raise ValueError("W3C parent span ID cannot be all zero")
        if self.parent_span_id == self.span_id:
            raise ValueError("a span cannot parent itself")
        if self.end_time_unix_nano <= self.start_time_unix_nano:
            raise ValueError("span end time must be later than start time")
        return self

    def attribute_map(self) -> dict[str, JsonScalar]:
        return {item.key: item.value for item in self.attributes}


class TraceIngestRequest(ContractModel):
    transition_id: ContractId
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)]
    action: HttpRequestAction
    expected_route: RouteTemplate
    trace_evidence: EvidenceRecord
    state_deltas: tuple[StateDelta, ...]
    fidelity: FidelityProfile
    consistent_replays: Annotated[int, Field(ge=1)] = 1

    @field_validator("state_deltas")
    @classmethod
    def deltas_are_canonical(cls, value: tuple[StateDelta, ...]) -> tuple[StateDelta, ...]:
        if not value:
            raise ValueError("trace ingestion requires at least one state delta")
        identifiers = [item.delta_id for item in value]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("state delta IDs must be unique")
        return tuple(sorted(value, key=lambda item: item.delta_id))

    @model_validator(mode="after")
    def request_is_local_and_evidence_bound(self) -> TraceIngestRequest:
        target = self.action.target
        if target is None or self.action.method is None or not self.action.expected_statuses:
            raise ValueError("trace ingestion requires a concrete typed HTTP expectation")
        if target.host not in {"localhost", "127.0.0.1"}:
            raise ValueError("trace ingestion is restricted to local synthetic targets")
        if not _route_template_is_valid(self.expected_route):
            raise ValueError("expected route template is invalid")
        if not _route_matches(self.expected_route, target.path):
            raise ValueError("expected route does not match the typed action path")
        evidence = self.trace_evidence
        if (
            evidence.kind is not EvidenceKind.OTEL_TRACE
            or evidence.taint is not Taint.TRUSTED_RUNTIME
            or evidence.trace_context is None
            or evidence.produced_by.adapter != ADAPTER_NAME
            or evidence.produced_by.version != ADAPTER_VERSION
        ):
            raise ValueError("trace evidence is not bound to this adapter")
        levels = (
            self.fidelity.code,
            self.fidelity.identity,
            self.fidelity.database,
            self.fidelity.cache,
            self.fidelity.queue,
            self.fidelity.timing,
        )
        if not any(level.value in {"exact", "observed"} for level in levels):
            raise ValueError("observed trace ingestion requires observed fidelity")
        return self


class _WireAnyValue(ContractModel):
    string_value: str | None = Field(default=None, alias="stringValue")
    bool_value: bool | None = Field(default=None, alias="boolValue")
    int_value: str | int | None = Field(default=None, alias="intValue")
    double_value: float | None = Field(default=None, alias="doubleValue")

    @model_validator(mode="after")
    def exactly_one_scalar_is_present(self) -> _WireAnyValue:
        values = (self.string_value, self.bool_value, self.int_value, self.double_value)
        if sum(value is not None for value in values) != 1:
            raise ValueError("OTLP attribute value must contain exactly one scalar")
        if self.double_value is not None and not math.isfinite(self.double_value):
            raise ValueError("OTLP double attribute must be finite")
        return self

    def scalar(self) -> JsonScalar:
        if self.string_value is not None:
            return self.string_value
        if self.bool_value is not None:
            return self.bool_value
        if self.int_value is not None:
            if isinstance(self.int_value, str):
                if not re.fullmatch(r"-?[0-9]+", self.int_value):
                    raise TelemetryIngestError("OTLP integer attribute is invalid")
                parsed = int(self.int_value)
            else:
                parsed = self.int_value
            if not -(2**63) <= parsed < 2**63:
                raise TelemetryIngestError("OTLP integer attribute is outside int64")
            return parsed
        return self.double_value


class _WireAttribute(ContractModel):
    key: AttributeKey
    value: _WireAnyValue


class _WireSpan(ContractModel):
    trace_id: str = Field(alias="traceId")
    span_id: str = Field(alias="spanId")
    parent_span_id: str | None = Field(default=None, alias="parentSpanId")
    name: str
    kind: str | int = SpanKind.UNSPECIFIED.value
    start_time_unix_nano: str | int = Field(alias="startTimeUnixNano")
    end_time_unix_nano: str | int = Field(alias="endTimeUnixNano")
    attributes: tuple[_WireAttribute, ...] = ()


class _WireScope(ContractModel):
    name: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    version: Annotated[str, StringConstraints(min_length=1, max_length=64)] | None = None


class _WireScopeSpans(ContractModel):
    scope: _WireScope | None = None
    spans: tuple[_WireSpan, ...]


class _WireResource(ContractModel):
    attributes: tuple[_WireAttribute, ...] = ()


class _WireResourceSpans(ContractModel):
    resource: _WireResource | None = None
    scope_spans: tuple[_WireScopeSpans, ...] = Field(alias="scopeSpans")


class _WireDocument(ContractModel):
    resource_spans: tuple[_WireResourceSpans, ...] = Field(alias="resourceSpans")


def _route_template_is_valid(route: str) -> bool:
    if "?" in route or "#" in route or "//" in route:
        return False
    for segment in route.split("/")[1:]:
        if ("{" in segment or "}" in segment) and not re.fullmatch(
            r"\{[A-Za-z_][A-Za-z0-9_]*\}", segment
        ):
            return False
    return True


def _route_matches(template: str, path: str) -> bool:
    template_segments = template.strip("/").split("/")
    path_segments = path.strip("/").split("/")
    if len(template_segments) != len(path_segments):
        return False
    return all(
        bool(re.fullmatch(r"\{[A-Za-z_][A-Za-z0-9_]*\}", expected)) or expected == observed
        for expected, observed in zip(template_segments, path_segments, strict=True)
    )
