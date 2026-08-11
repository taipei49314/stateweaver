"""Typed admission receipt for one application-emitted runtime observation."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, ClassVar, Final, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)
from stateweaver.adapters.telemetry.opentelemetry import RuntimeObservationReceipt
from stateweaver.contracts import (
    ActionEnvelope,
    EvidenceKind,
    EvidenceProducer,
    EvidenceRecord,
    FidelityLevel,
    FidelityProfile,
    HttpMethod,
    HttpRequestAction,
    ProvenanceKind,
    StateCondition,
    StateEffect,
    Taint,
    TransitionFragment,
    sha256_digest,
)
from stateweaver.contracts import (
    canonical_json_bytes as contract_json_bytes,
)
from stateweaver.contracts.base import ContractId, Sha256Digest

from ._io import (
    HASH_KEY_RE,
    SENSITIVE_KEY_RE,
    SENSITIVE_TEXT_RE,
    EvidenceInputError,
    assert_secret_free,
    atomic_json,
    canonical_json_bytes,
)

RUNTIME_OBSERVATION_QUALIFICATION_PATH = "qualification/m3/runtime-observation-receipt.json"
OBSERVED_FRAGMENT_QUALIFICATION_PATH = "qualification/m3/observed-fragment-receipt.json"
RUNTIME_OBSERVATION_SCHEMA_VERSION: Final[
    Literal["stateweaver-runtime-observation-qualification-v1"]
] = "stateweaver-runtime-observation-qualification-v1"
RUNTIME_OBSERVATION_STATUS: Final[Literal["RUNTIME_OBSERVATION_QUALIFIED"]] = (
    "RUNTIME_OBSERVATION_QUALIFIED"
)
_MAX_ADAPTER_RECEIPT_BYTES = 2 * 1_048_576
_REPOSITORY_MARKER_RE = re.compile(r"^[0-9a-f]{40}$")
_TRACE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_SPAN_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_ROUTE_RE = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%{}/-]{1,511}$")
_LIMITATIONS = (
    "This receipt qualifies one repository-owned socket-free ASGI runtime observation.",
    "It is not a live-provider, materialized-world, trusted-broker, or public-release receipt.",
)
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def _assert_runtime_redacted(value: object) -> None:
    """Allow the typed authorization object while rejecting secret-like fields and text."""

    if isinstance(value, Mapping):
        for key, item in value.items():
            if (
                SENSITIVE_KEY_RE.search(key)
                and not HASH_KEY_RE.search(key)
                and key != "authorization"
            ):
                raise ValueError("runtime qualification contains a secret-like field")
            _assert_runtime_redacted(item)
        return
    if isinstance(value, list | tuple):
        for item in value:
            _assert_runtime_redacted(item)
        return
    if isinstance(value, str) and SENSITIVE_TEXT_RE.search(value):
        raise ValueError("runtime qualification contains secret-like text")


class RuntimeObservationQualificationError(ValueError):
    """Value-safe rejection of a malformed or mismatched runtime qualification."""


class _QualificationModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)


class RuntimeAuthorizationQualification(_QualificationModel):
    """Stable projection of the server-owned authorization and budget reservation."""

    action_id: ContractId
    policy_decision_ref: ContractId
    idempotency_key: Sha256Digest
    envelope_digest: Sha256Digest
    policy_request_hash: Sha256Digest
    scope_manifest_hash: Sha256Digest
    budget_reservation_id: Sha256Digest
    decision_digest: Sha256Digest
    requests_before: Annotated[int, Field(ge=0)]
    write_requests_before: Annotated[int, Field(ge=0)]


class RuntimeObservedPathQualification(_QualificationModel):
    """One exact runtime capture-to-state mapping."""

    delta_id: ContractId
    subject: ContractId
    capture_path: Annotated[str, StringConstraints(min_length=3, max_length=256)]
    state_path: Annotated[str, StringConstraints(min_length=3, max_length=256)]


class RuntimeCaptureQualification(_QualificationModel):
    """One retained canonical before/after runtime capture."""

    observation_id: ContractId
    world_id: ContractId
    source_digest: Sha256Digest
    phase: Literal["before", "after"]
    sequence: Annotated[int, Field(ge=1)]
    captured_at: datetime
    payload_json: Annotated[
        str,
        StringConstraints(min_length=2, max_length=1_048_576),
    ]
    payload_digest: Sha256Digest

    @model_validator(mode="after")
    def _validate_payload(self) -> RuntimeCaptureQualification:
        if self.captured_at.tzinfo is None or self.captured_at.utcoffset() is None:
            raise ValueError("runtime capture timestamp must be absolute")
        try:
            document: object = json.loads(self.payload_json)
        except (json.JSONDecodeError, RecursionError):
            raise ValueError("runtime capture payload is invalid") from None
        if not isinstance(document, dict):
            raise ValueError("runtime capture payload must be an object")
        if contract_json_bytes(document).decode("utf-8") != self.payload_json:
            raise ValueError("runtime capture payload is not canonical")
        if sha256_digest(document) != self.payload_digest:
            raise ValueError("runtime capture digest does not match its payload")
        try:
            assert_secret_free(document)
        except EvidenceInputError:
            raise ValueError("runtime capture is not redacted") from None
        return self


class RuntimeTraceQualification(_QualificationModel):
    """Application-emitted server span fields retained by the qualification."""

    exporter_id: ContractId
    exporter_sequence: Annotated[int, Field(ge=1)]
    trace_id: str
    span_id: str
    method: HttpMethod
    route: str
    status: Annotated[int, Field(ge=100, le=599)]
    start_time_unix_nano: Annotated[int, Field(ge=0)]
    end_time_unix_nano: Annotated[int, Field(ge=1)]
    span_digest: Sha256Digest

    @model_validator(mode="after")
    def _validate_trace(self) -> RuntimeTraceQualification:
        if (
            _TRACE_ID_RE.fullmatch(self.trace_id) is None
            or set(self.trace_id) == {"0"}
            or _SPAN_ID_RE.fullmatch(self.span_id) is None
            or set(self.span_id) == {"0"}
            or _ROUTE_RE.fullmatch(self.route) is None
            or self.end_time_unix_nano <= self.start_time_unix_nano
        ):
            raise ValueError("runtime trace binding is invalid")
        return self


class RuntimeStateChangeQualification(_QualificationModel):
    """One state change derived from retained before/after capture bytes."""

    delta_id: ContractId
    subject: ContractId
    precondition: StateCondition
    effect: StateEffect
    observable: StateCondition
    evidence_id: ContractId
    observed_at: datetime

    @model_validator(mode="after")
    def _validate_timestamp(self) -> RuntimeStateChangeQualification:
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise ValueError("runtime state-change timestamp must be absolute")
        return self


class RuntimeObservationProjection(_QualificationModel):
    """Adapter-independent typed projection used for acceptance admission."""

    repository_marker: str
    adapter: EvidenceProducer
    observation_id: ContractId
    world_id: ContractId
    transition_id: ContractId
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)]
    source_digest: Sha256Digest
    action_envelope: ActionEnvelope
    action_digest: Sha256Digest
    execution_id: ContractId
    execution_digest: Sha256Digest
    observation_claim_digest: Sha256Digest
    authorization: RuntimeAuthorizationQualification
    expected_route: str
    observed_paths: tuple[RuntimeObservedPathQualification, ...]
    before_capture: RuntimeCaptureQualification
    after_capture: RuntimeCaptureQualification
    trace: RuntimeTraceQualification
    trace_evidence: EvidenceRecord
    state_evidence: EvidenceRecord
    state_changes: tuple[RuntimeStateChangeQualification, ...]
    fidelity: FidelityProfile
    transition_fragment: TransitionFragment

    @model_validator(mode="after")
    def _validate_projection(self) -> RuntimeObservationProjection:
        if _REPOSITORY_MARKER_RE.fullmatch(self.repository_marker) is None:
            raise ValueError("runtime qualification repository marker is invalid")
        action = self.action_envelope.action
        if not isinstance(action, HttpRequestAction):
            raise ValueError("runtime qualification action is not HTTP")
        if (
            self.action_envelope.world_id != self.world_id
            or self.action_digest != sha256_digest(self.action_envelope)
            or self.authorization.action_id != self.action_envelope.action_id
            or self.authorization.policy_decision_ref != self.action_envelope.policy_decision_ref
            or self.authorization.idempotency_key != self.action_envelope.idempotency_key
            or self.authorization.envelope_digest != self.action_digest
        ):
            raise ValueError("runtime qualification action binding is invalid")
        target = action.target
        if (
            target is None
            or target.host not in {"localhost", "127.0.0.1"}
            or target.path != self.expected_route
            or self.trace.method is not action.method
            or self.trace.route != self.expected_route
            or self.trace.status not in action.expected_statuses
            or _ROUTE_RE.fullmatch(self.expected_route) is None
        ):
            raise ValueError("runtime qualification route binding is invalid")
        before = self.before_capture
        after = self.after_capture
        for capture in (before, after):
            if (
                capture.observation_id != self.observation_id
                or capture.world_id != self.world_id
                or capture.source_digest != self.source_digest
            ):
                raise ValueError("runtime qualification capture binding is invalid")
        if (
            before.phase != "before"
            or after.phase != "after"
            or after.sequence != before.sequence + 1
            or after.captured_at < before.captured_at
        ):
            raise ValueError("runtime qualification captures are out of order")
        trace = self.trace
        trace_start = _unix_nanos(before.captured_at)
        trace_end = _unix_nanos(after.captured_at)
        if not trace_start <= trace.start_time_unix_nano < trace.end_time_unix_nano <= trace_end:
            raise ValueError("runtime qualification trace is outside its captures")
        trace_evidence = self.trace_evidence
        state_evidence = self.state_evidence
        if (
            trace_evidence.kind is not EvidenceKind.OTEL_TRACE
            or state_evidence.kind is not EvidenceKind.STATE_SNAPSHOT
            or trace_evidence.taint is not Taint.TRUSTED_RUNTIME
            or state_evidence.taint is not Taint.TRUSTED_RUNTIME
            or trace_evidence.produced_by != self.adapter
            or state_evidence.produced_by != self.adapter
            or trace_evidence.trace_context is None
            or state_evidence.trace_context != trace_evidence.trace_context
            or trace_evidence.trace_context.trace_id != trace.trace_id
            or trace_evidence.trace_context.span_id != trace.span_id
            or trace_evidence.sha256 != trace.span_digest
            or trace_evidence.redaction_policy_version != state_evidence.redaction_policy_version
        ):
            raise ValueError("runtime qualification evidence binding is invalid")
        if not self.observed_paths or not self.state_changes:
            raise ValueError("runtime qualification requires observed state changes")
        path_ids = tuple(item.delta_id for item in self.observed_paths)
        change_ids = tuple(item.delta_id for item in self.state_changes)
        if (
            len(path_ids) != len(set(path_ids))
            or len(change_ids) != len(set(change_ids))
            or set(path_ids) != set(change_ids)
        ):
            raise ValueError("runtime qualification observed paths do not match state changes")
        if any(
            change.evidence_id != state_evidence.evidence_id
            or not trace.start_time_unix_nano
            <= _unix_nanos(change.observed_at)
            <= trace.end_time_unix_nano
            for change in self.state_changes
        ):
            raise ValueError("runtime qualification state-change evidence is invalid")
        transition = self.transition_fragment
        if (
            transition.transition_id != self.transition_id
            or transition.name != self.name
            or transition.source is not ProvenanceKind.OBSERVED
            or transition.action != action
            or transition.preconditions != tuple(item.precondition for item in self.state_changes)
            or transition.effects != tuple(item.effect for item in self.state_changes)
            or transition.observables != tuple(item.observable for item in self.state_changes)
            or transition.evidence_ids
            != tuple(sorted((trace_evidence.evidence_id, state_evidence.evidence_id)))
            or transition.fidelity != self.fidelity
            or transition.consistent_replays != 1
        ):
            raise ValueError("runtime qualification transition is not derived from its evidence")
        roots = {item.capture_path.split(".", 1)[0] for item in self.observed_paths}
        expected_fidelity = FidelityProfile(
            code=FidelityLevel.OBSERVED,
            identity=(
                FidelityLevel.OBSERVED
                if action.identity_handle is not None
                else FidelityLevel.UNKNOWN
            ),
            database=(FidelityLevel.OBSERVED if "database" in roots else FidelityLevel.UNKNOWN),
            cache=FidelityLevel.OBSERVED if "cache" in roots else FidelityLevel.UNKNOWN,
            queue=FidelityLevel.OBSERVED if "queue" in roots else FidelityLevel.UNKNOWN,
            timing=FidelityLevel.OBSERVED,
        )
        if self.fidelity != expected_fidelity:
            raise ValueError("runtime qualification fidelity is not derived from observed paths")
        _assert_runtime_redacted(self.model_dump(mode="json"))
        return self


class RuntimeObservationQualificationReceipt(_QualificationModel):
    """Canonical admission receipt retained in the acceptance proof."""

    schema_version: Literal["stateweaver-runtime-observation-qualification-v1"]
    status: Literal["RUNTIME_OBSERVATION_QUALIFIED"]
    runtime_observation_verified: Literal[True]
    exit_criterion_satisfied: Literal[True]
    release_eligible: Literal[False]
    external_attestation_required: Literal[True]
    adapter_receipt_json: Annotated[
        str,
        StringConstraints(min_length=2, max_length=_MAX_ADAPTER_RECEIPT_BYTES),
    ]
    adapter_receipt_sha256: Sha256Digest
    projection: RuntimeObservationProjection
    semantic_digest: Sha256Digest
    limitations: tuple[str, ...]
    receipt_digest: Sha256Digest

    @model_validator(mode="after")
    def _validate_receipt(self) -> RuntimeObservationQualificationReceipt:
        try:
            adapter_payload: object = json.loads(self.adapter_receipt_json)
            adapter_receipt = RuntimeObservationReceipt.model_validate_json(
                self.adapter_receipt_json
            )
        except (json.JSONDecodeError, ValidationError, ValueError, RecursionError):
            raise ValueError("runtime adapter receipt is invalid") from None
        if not isinstance(adapter_payload, dict):
            raise ValueError("runtime adapter receipt must be an object")
        if contract_json_bytes(adapter_payload).decode("utf-8") != self.adapter_receipt_json:
            raise ValueError("runtime adapter receipt is not canonical")
        adapter_digest = f"sha256:{hashlib.sha256(self.adapter_receipt_json.encode()).hexdigest()}"
        if adapter_digest != self.adapter_receipt_sha256:
            raise ValueError("runtime adapter receipt digest is invalid")
        if not _adapter_receipt_matches_projection(adapter_receipt, self.projection):
            raise ValueError("runtime adapter receipt does not match its qualification")
        _assert_runtime_redacted(adapter_payload)
        if self.semantic_digest != runtime_semantic_digest(self.projection):
            raise ValueError("runtime qualification semantic digest is invalid")
        if self.limitations != _LIMITATIONS:
            raise ValueError("runtime qualification limitations are invalid")
        expected_receipt_digest = sha256_digest(
            self.model_dump(mode="python", exclude={"receipt_digest"})
        )
        if self.receipt_digest != expected_receipt_digest:
            raise ValueError("runtime qualification receipt digest is invalid")
        return self


def _adapter_receipt_matches_projection(
    adapter: RuntimeObservationReceipt,
    projection: RuntimeObservationProjection,
) -> bool:
    issued = adapter.issued_trace
    span = issued.span
    trace = projection.trace
    if (
        adapter.observation_id != projection.observation_id
        or adapter.world_id != projection.world_id
        or adapter.transition_id != projection.transition_id
        or adapter.name != projection.name
        or adapter.action_envelope != projection.action_envelope
        or adapter.action != projection.action_envelope.action
        or adapter.action_digest != projection.action_digest
        or adapter.execution_id != projection.execution_id
        or adapter.execution_digest != projection.execution_digest
        or adapter.observation_claim_digest != projection.observation_claim_digest
        or adapter.expected_route != projection.expected_route
        or adapter.source_digest != projection.source_digest
        or adapter.authorization.model_dump(mode="json")
        != projection.authorization.model_dump(mode="json")
        or tuple(item.model_dump(mode="json") for item in adapter.observed_paths)
        != tuple(item.model_dump(mode="json") for item in projection.observed_paths)
        or adapter.before_capture.model_dump(mode="json")
        != projection.before_capture.model_dump(mode="json")
        or adapter.after_capture.model_dump(mode="json")
        != projection.after_capture.model_dump(mode="json")
        or adapter.trace_evidence != projection.trace_evidence
        or adapter.state_evidence != projection.state_evidence
        or issued.observation_id != projection.observation_id
        or issued.world_id != projection.world_id
        or issued.action_digest != projection.action_digest
        or issued.execution_id != projection.execution_id
        or issued.execution_digest != projection.execution_digest
        or issued.observation_claim_digest != projection.observation_claim_digest
        or issued.source_digest != projection.source_digest
        or issued.exporter_id != trace.exporter_id
        or issued.sequence != trace.exporter_sequence
        or issued.span_digest != trace.span_digest
        or span.trace_id != trace.trace_id
        or span.span_id != trace.span_id
        or span.start_time_unix_nano != trace.start_time_unix_nano
        or span.end_time_unix_nano != trace.end_time_unix_nano
    ):
        return False
    if len(adapter.deltas) != len(projection.state_changes):
        return False
    for delta, change in zip(adapter.deltas, projection.state_changes, strict=True):
        if (
            delta.delta_id != change.delta_id
            or delta.subject != change.subject
            or delta.precondition != change.precondition
            or delta.effect != change.effect
            or delta.observable != change.observable
            or delta.observed_at != change.observed_at
            or delta.provenance.evidence_ids != (change.evidence_id,)
            or delta.provenance.adapter != projection.adapter.adapter
            or delta.provenance.adapter_version != projection.adapter.version
        ):
            return False
    return True


def _unix_nanos(value: datetime) -> int:
    delta = value.astimezone(UTC) - _EPOCH
    return ((delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1_000


def runtime_semantic_digest(projection: RuntimeObservationProjection) -> str:
    """Hash stable user-flow semantics while excluding run-generated IDs and clocks."""

    transition = projection.transition_fragment
    payload = {
        "schema_version": "stateweaver-runtime-observation-semantic-v1",
        "repository_marker": projection.repository_marker,
        "adapter": projection.adapter,
        "world_id": projection.world_id,
        "transition_id": projection.transition_id,
        "name": projection.name,
        "source_digest": projection.source_digest,
        "action_envelope": projection.action_envelope,
        "action_digest": projection.action_digest,
        "authorization": projection.authorization,
        "expected_route": projection.expected_route,
        "observed_paths": projection.observed_paths,
        "before": {
            "payload_json": projection.before_capture.payload_json,
            "payload_digest": projection.before_capture.payload_digest,
        },
        "after": {
            "payload_json": projection.after_capture.payload_json,
            "payload_digest": projection.after_capture.payload_digest,
        },
        "trace": {
            "method": projection.trace.method,
            "route": projection.trace.route,
            "status": projection.trace.status,
        },
        "state_changes": [
            {
                "delta_id": item.delta_id,
                "subject": item.subject,
                "precondition": item.precondition,
                "effect": item.effect,
                "observable": item.observable,
            }
            for item in projection.state_changes
        ],
        "fidelity": projection.fidelity,
        "transition": {
            "transition_id": transition.transition_id,
            "name": transition.name,
            "source": transition.source,
            "preconditions": transition.preconditions,
            "action": transition.action,
            "effects": transition.effects,
            "observables": transition.observables,
            "fidelity": transition.fidelity,
            "consistent_replays": transition.consistent_replays,
        },
    }
    return sha256_digest(payload)


def build_runtime_observation_qualification(
    *,
    adapter_receipt: Mapping[str, Any],
    projection: RuntimeObservationProjection,
) -> RuntimeObservationQualificationReceipt:
    """Build a canonical self-hashed receipt from adapter-validated inputs."""

    try:
        adapter_receipt_json = contract_json_bytes(adapter_receipt).decode("utf-8")
        adapter_receipt_sha256 = (
            f"sha256:{hashlib.sha256(adapter_receipt_json.encode()).hexdigest()}"
        )
        semantic_digest = runtime_semantic_digest(projection)
        fields: dict[str, object] = {
            "schema_version": RUNTIME_OBSERVATION_SCHEMA_VERSION,
            "status": RUNTIME_OBSERVATION_STATUS,
            "runtime_observation_verified": True,
            "exit_criterion_satisfied": True,
            "release_eligible": False,
            "external_attestation_required": True,
            "adapter_receipt_json": adapter_receipt_json,
            "adapter_receipt_sha256": adapter_receipt_sha256,
            "projection": projection,
            "semantic_digest": semantic_digest,
            "limitations": _LIMITATIONS,
        }
        return RuntimeObservationQualificationReceipt(
            schema_version=RUNTIME_OBSERVATION_SCHEMA_VERSION,
            status=RUNTIME_OBSERVATION_STATUS,
            runtime_observation_verified=True,
            exit_criterion_satisfied=True,
            release_eligible=False,
            external_attestation_required=True,
            adapter_receipt_json=adapter_receipt_json,
            adapter_receipt_sha256=adapter_receipt_sha256,
            projection=projection,
            semantic_digest=semantic_digest,
            limitations=_LIMITATIONS,
            receipt_digest=sha256_digest(fields),
        )
    except (TypeError, ValueError, ValidationError, EvidenceInputError, RecursionError):
        raise RuntimeObservationQualificationError(
            "runtime observation qualification receipt is invalid"
        ) from None


def validate_runtime_observation_qualification(
    value: Mapping[str, object],
    *,
    expected_repository_marker: str,
) -> RuntimeObservationQualificationReceipt:
    """Revalidate an untrusted JSON-shaped receipt and its exact source binding."""

    try:
        checked = RuntimeObservationQualificationReceipt.model_validate_json(
            canonical_json_bytes(value)
        )
    except (TypeError, ValueError, ValidationError, EvidenceInputError, RecursionError):
        raise RuntimeObservationQualificationError(
            "runtime observation qualification receipt is invalid"
        ) from None
    if checked.projection.repository_marker != expected_repository_marker:
        raise RuntimeObservationQualificationError(
            "runtime observation qualification source does not match"
        )
    return checked


def write_runtime_observation_qualification(
    output: Path,
    receipt: RuntimeObservationQualificationReceipt,
) -> None:
    """Atomically retain one canonical runtime qualification receipt."""

    atomic_json(output, receipt.model_dump(mode="json"))


def load_runtime_observation_qualification(
    path: Path,
    *,
    expected_repository_marker: str,
) -> RuntimeObservationQualificationReceipt:
    """Load one bounded canonical receipt without following a final symlink."""

    if path.is_symlink():
        raise RuntimeObservationQualificationError(
            "runtime observation qualification receipt is invalid"
        )
    try:
        size = path.stat().st_size
        content = path.read_bytes()
    except OSError:
        raise RuntimeObservationQualificationError(
            "runtime observation qualification receipt is invalid"
        ) from None
    if size != len(content) or not 1 <= size <= 4 * 1_048_576:
        raise RuntimeObservationQualificationError(
            "runtime observation qualification receipt is invalid"
        )
    try:
        parsed: object = json.loads(content.decode("utf-8"))
        if not isinstance(parsed, Mapping) or canonical_json_bytes(parsed) != content:
            raise RuntimeObservationQualificationError(
                "runtime observation qualification receipt is invalid"
            )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        EvidenceInputError,
        ValueError,
        RecursionError,
    ):
        raise RuntimeObservationQualificationError(
            "runtime observation qualification receipt is invalid"
        ) from None
    return validate_runtime_observation_qualification(
        parsed,
        expected_repository_marker=expected_repository_marker,
    )


def observed_fragment_qualification_payload(
    receipt: RuntimeObservationQualificationReceipt,
) -> dict[str, object]:
    """Derive the separate registry path for the evidence-backed fragment exit."""

    payload: dict[str, object] = {
        "schema_version": "stateweaver-observed-fragment-qualification-v1",
        "status": "OBSERVED_FRAGMENT_QUALIFIED",
        "repository_marker": receipt.projection.repository_marker,
        "runtime_receipt_digest": receipt.receipt_digest,
        "runtime_semantic_digest": receipt.semantic_digest,
        "source_digest": receipt.projection.source_digest,
        "action_digest": receipt.projection.action_digest,
        "before_capture_digest": receipt.projection.before_capture.payload_digest,
        "after_capture_digest": receipt.projection.after_capture.payload_digest,
        "transition_fragment": receipt.projection.transition_fragment.model_dump(mode="json"),
        "evidence_ids": list(receipt.projection.transition_fragment.evidence_ids),
        "exit_criterion_satisfied": True,
        "release_eligible": False,
        "external_attestation_required": True,
        "limitations": list(_LIMITATIONS),
    }
    payload["receipt_digest"] = sha256_digest(payload)
    return payload


def runtime_observation_admissions(
    receipt: RuntimeObservationQualificationReceipt,
) -> dict[str, str]:
    """Return the exact M3 rows admitted by this one verified receipt."""

    return dict.fromkeys(
        ("M3-T03", "M3-T04", "M3-T05", "M3-X01", "SW-M3-OBSERVED"),
        receipt.receipt_digest,
    )


__all__ = [
    "OBSERVED_FRAGMENT_QUALIFICATION_PATH",
    "RUNTIME_OBSERVATION_QUALIFICATION_PATH",
    "RUNTIME_OBSERVATION_SCHEMA_VERSION",
    "RUNTIME_OBSERVATION_STATUS",
    "RuntimeAuthorizationQualification",
    "RuntimeCaptureQualification",
    "RuntimeObservationProjection",
    "RuntimeObservationQualificationError",
    "RuntimeObservationQualificationReceipt",
    "RuntimeObservedPathQualification",
    "RuntimeStateChangeQualification",
    "RuntimeTraceQualification",
    "build_runtime_observation_qualification",
    "load_runtime_observation_qualification",
    "observed_fragment_qualification_payload",
    "runtime_observation_admissions",
    "runtime_semantic_digest",
    "validate_runtime_observation_qualification",
    "write_runtime_observation_qualification",
]
