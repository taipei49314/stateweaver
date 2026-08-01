"""Content-addressed evidence metadata; artifact bytes remain out of band."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from urllib.parse import unquote, urlsplit

from pydantic import StringConstraints, field_validator, model_validator

from .base import (
    AwareTimestampMixin,
    ContractId,
    ContractModel,
    Name,
    Sha256Digest,
    SpanId,
    TraceId,
    VersionedContract,
)
from .enums import EvidenceKind, Taint

ArtifactUri = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=10, max_length=2048),
]


class EvidenceProducer(ContractModel):
    adapter: Name
    version: Name


class TraceContext(ContractModel):
    trace_id: TraceId
    span_id: SpanId


class EvidenceRecord(AwareTimestampMixin, VersionedContract):
    evidence_id: ContractId
    kind: EvidenceKind
    artifact_uri: ArtifactUri
    sha256: Sha256Digest
    produced_by: EvidenceProducer
    trace_context: TraceContext | None = None
    redaction_policy_version: Name
    taint: Taint
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def created_at_is_absolute(cls, value: datetime) -> datetime:
        checked = cls.timestamp_must_have_timezone(value)
        assert checked is not None
        return checked

    @model_validator(mode="after")
    def artifact_reference_is_safe(self) -> EvidenceRecord:
        parsed = urlsplit(self.artifact_uri)
        if parsed.scheme not in {"artifact", "s3"}:
            raise ValueError("artifact_uri must use the artifact or s3 scheme")
        if not parsed.netloc:
            raise ValueError("artifact_uri must include a storage namespace")
        decoded_path = unquote(parsed.path)
        if parsed.query or parsed.fragment or "\\" in decoded_path:
            raise ValueError("artifact_uri must not contain query, fragment, or backslash")
        if any(segment in {".", ".."} for segment in decoded_path.split("/")):
            raise ValueError("artifact_uri must not contain traversal segments")
        return self
