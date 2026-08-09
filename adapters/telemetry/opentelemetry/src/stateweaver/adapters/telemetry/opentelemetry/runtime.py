"""Socket-free runtime observation for repository-owned ASGI applications.

The caller supplies a typed action and typed paths to observe.  Trace bytes,
capture values, evidence, deltas, fidelity, and taint are all issued or derived
inside this controller.
"""

from __future__ import annotations

import asyncio
import json
import secrets
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import BaseModel, Field, StringConstraints, ValidationError, model_validator
from stateweaver.contracts import (
    ActionEnvelope,
    ComparisonOperator,
    EffectOperation,
    EvidenceKind,
    EvidenceProducer,
    EvidenceRecord,
    FidelityLevel,
    FidelityProfile,
    HttpRequestAction,
    Provenance,
    ProvenanceKind,
    StateCondition,
    StateEffect,
    Taint,
    TraceContext,
    canonical_json_bytes,
    sha256_digest,
)
from stateweaver.contracts.base import ContractId, ContractModel, JsonScalar, Sha256Digest
from stateweaver.twin import StateDelta, TelemetryFlow

from .ingest import canonical_spans_sha256, ingest_spans
from .models import (
    _SECRET_KEY,
    _SECRET_TEXT,
    ADAPTER_NAME,
    ADAPTER_VERSION,
    OtlpSpan,
    RouteTemplate,
    SpanAttribute,
    SpanKind,
    TelemetryIngestError,
    TraceIngestRequest,
)

_REDACTION_POLICY = "runtime-redaction-v1"
_MAX_CAPTURE_BYTES = 1_048_576
_MAX_CAPTURE_DEPTH = 32
_MAX_IDEMPOTENCY_RECORDS = 4_096
_PATH = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=3,
        max_length=256,
        pattern=r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$",
    ),
]
_NAME = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=256),
]
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


class RuntimeObservationError(ValueError):
    """Fail-closed, value-safe runtime observation rejection."""


class RuntimeExecutionReceiptBinding(ContractModel):
    """Redacted receipt binding to the existing server-owned authorization."""

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


if TYPE_CHECKING:
    from stateweaver.adapters.in_process_lab import (
        InProcessLabEnvironment,
        InProcessLabRuntimeExecution,
    )


class ObservedStatePath(ContractModel):
    """A typed mapping from a runtime capture path into semantic state."""

    delta_id: ContractId
    subject: ContractId
    capture_path: _PATH
    state_path: _PATH


class RuntimeObservationRequest(ContractModel):
    """Caller-controlled portion of one runtime observation."""

    world_id: ContractId
    transition_id: ContractId
    name: _NAME
    action_envelope: ActionEnvelope
    expected_route: RouteTemplate
    observed_paths: tuple[ObservedStatePath, ...]

    @model_validator(mode="after")
    def request_is_bounded_and_local(self) -> RuntimeObservationRequest:
        action = self.action_envelope.action
        if not isinstance(action, HttpRequestAction):
            raise ValueError("runtime observation requires an authorized HTTP action envelope")
        target = action.target
        if target is None or action.method is None or not action.expected_statuses:
            raise ValueError("runtime observation requires a concrete typed HTTP expectation")
        if target.host not in {"localhost", "127.0.0.1"}:
            raise ValueError("runtime observation is restricted to local synthetic targets")
        if self.world_id != self.action_envelope.world_id:
            raise ValueError("runtime observation world does not match its action envelope")
        if not self.observed_paths:
            raise ValueError("runtime observation requires at least one observed state path")
        identifiers = [item.delta_id for item in self.observed_paths]
        capture_paths = [item.capture_path for item in self.observed_paths]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("observed delta identifiers must be unique")
        if len(capture_paths) != len(set(capture_paths)):
            raise ValueError("observed capture paths must be unique")
        return self

    @property
    def action(self) -> HttpRequestAction:
        """Return the HTTP action after the model validator has closed the union."""

        action = self.action_envelope.action
        if not isinstance(action, HttpRequestAction):  # pragma: no cover - validator invariant
            raise RuntimeObservationError("runtime observation action is not HTTP")
        return action


class RuntimeStateCapture(ContractModel):
    """Canonical, redacted state captured by the controller itself."""

    observation_id: ContractId
    world_id: ContractId
    source_digest: Sha256Digest
    phase: Literal["before", "after"]
    sequence: Annotated[int, Field(ge=1)]
    captured_at: datetime
    payload_json: Annotated[str, StringConstraints(min_length=2, max_length=_MAX_CAPTURE_BYTES)]
    payload_digest: Sha256Digest

    @model_validator(mode="after")
    def payload_is_canonical_safe_json(self) -> RuntimeStateCapture:
        if self.captured_at.tzinfo is None or self.captured_at.utcoffset() is None:
            raise ValueError("runtime capture time must include a UTC offset")
        document = _decode_capture(self.payload_json)
        if canonical_json_bytes(document).decode("utf-8") != self.payload_json:
            raise ValueError("runtime capture payload must use canonical JSON")
        if sha256_digest(document) != self.payload_digest:
            raise ValueError("runtime capture digest does not match its payload")
        return self

    def document(self) -> dict[str, object]:
        return _decode_capture(self.payload_json)


class IssuedRuntimeTrace(ContractModel):
    """One trace issued by the process-local exporter."""

    observation_id: ContractId
    exporter_id: ContractId
    sequence: Annotated[int, Field(ge=1)]
    world_id: ContractId
    execution_id: ContractId
    execution_digest: Sha256Digest
    observation_claim_digest: Sha256Digest
    action_digest: Sha256Digest
    authorization_digest: Sha256Digest
    source_digest: Sha256Digest
    span: OtlpSpan
    span_digest: Sha256Digest

    @model_validator(mode="after")
    def trace_is_bound_to_issuer_and_context(self) -> IssuedRuntimeTrace:
        if canonical_spans_sha256((self.span,)) != self.span_digest:
            raise ValueError("issued trace digest does not match its canonical span")
        attributes = self.span.attribute_map()
        expected = {
            "stateweaver.observation.id": self.observation_id,
            "stateweaver.exporter.id": self.exporter_id,
            "stateweaver.exporter.sequence": self.sequence,
            "stateweaver.world.id": self.world_id,
            "stateweaver.execution.id": self.execution_id,
            "stateweaver.execution.digest": self.execution_digest,
            "stateweaver.observation.claim.digest": self.observation_claim_digest,
            "stateweaver.action.digest": self.action_digest,
            "stateweaver.policy.binding.digest": self.authorization_digest,
            "stateweaver.source.digest": self.source_digest,
        }
        if any(attributes.get(key) != value for key, value in expected.items()):
            raise ValueError("issued trace attributes do not match its runtime binding")
        if self.span.kind is not SpanKind.SERVER or self.span.parent_span_id is not None:
            raise ValueError("issued runtime trace must contain one root server span")
        return self


class RuntimeObservationReceipt(ContractModel):
    """Canonical binding of source, action, trace, captures, and derived deltas."""

    observation_id: ContractId
    world_id: ContractId
    transition_id: ContractId
    name: _NAME
    action_envelope: ActionEnvelope
    action: HttpRequestAction
    action_digest: Sha256Digest
    execution_id: ContractId
    execution_digest: Sha256Digest
    observation_claim_digest: Sha256Digest
    authorization: RuntimeExecutionReceiptBinding
    expected_route: RouteTemplate
    source_digest: Sha256Digest
    observed_paths: tuple[ObservedStatePath, ...]
    before_capture: RuntimeStateCapture
    after_capture: RuntimeStateCapture
    issued_trace: IssuedRuntimeTrace
    trace_evidence: EvidenceRecord
    state_evidence: EvidenceRecord
    deltas: tuple[StateDelta, ...]
    receipt_digest: Sha256Digest

    @model_validator(mode="after")
    def receipt_bindings_are_consistent(self) -> RuntimeObservationReceipt:
        if (
            self.action_envelope.action != self.action
            or self.action_envelope.world_id != self.world_id
            or self.action_digest != sha256_digest(self.action_envelope)
        ):
            raise ValueError("receipt action envelope does not match the typed action")
        authorization = self.authorization
        if (
            authorization.action_id != self.action_envelope.action_id
            or authorization.policy_decision_ref != self.action_envelope.policy_decision_ref
            or authorization.idempotency_key != self.action_envelope.idempotency_key
            or authorization.envelope_digest != self.action_digest
        ):
            raise ValueError("runtime authorization does not match the action envelope")
        self._validate_capture_bindings()
        self._validate_trace_bindings()
        self._validate_evidence_bindings()
        self._validate_derived_deltas()
        expected_digest = sha256_digest(self.model_dump(mode="python", exclude={"receipt_digest"}))
        if self.receipt_digest != expected_digest:
            raise ValueError("runtime observation receipt digest does not match its contents")
        return self

    def _validate_capture_bindings(self) -> None:
        before = self.before_capture
        after = self.after_capture
        for capture in (before, after):
            if (
                capture.observation_id != self.observation_id
                or capture.world_id != self.world_id
                or capture.source_digest != self.source_digest
            ):
                raise ValueError("runtime capture is not bound to this observation")
        if before.phase != "before" or after.phase != "after":
            raise ValueError("runtime captures are out of order")
        if after.sequence != before.sequence + 1 or after.captured_at < before.captured_at:
            raise ValueError("runtime capture order is invalid")

    def _validate_trace_bindings(self) -> None:
        issued = self.issued_trace
        if (
            issued.observation_id != self.observation_id
            or issued.world_id != self.world_id
            or issued.execution_id != self.execution_id
            or issued.execution_digest != self.execution_digest
            or issued.observation_claim_digest != self.observation_claim_digest
            or issued.action_digest != self.action_digest
            or issued.authorization_digest != sha256_digest(self.authorization)
            or issued.source_digest != self.source_digest
        ):
            raise ValueError("issued trace is not bound to this observation")
        attributes = issued.span.attribute_map()
        if attributes.get("http.route") != self.expected_route:
            raise ValueError("issued trace route does not match the observation")
        start = _nanos_to_datetime(issued.span.start_time_unix_nano)
        end = _nanos_to_datetime(issued.span.end_time_unix_nano)
        if not self.before_capture.captured_at <= start <= end <= self.after_capture.captured_at:
            raise ValueError("trace and state capture order is invalid")

    def _validate_evidence_bindings(self) -> None:
        trace = self.trace_evidence
        state = self.state_evidence
        span = self.issued_trace.span
        if (
            trace.kind is not EvidenceKind.OTEL_TRACE
            or trace.taint is not Taint.TRUSTED_RUNTIME
            or trace.sha256 != self.issued_trace.span_digest
            or trace.trace_context != TraceContext(trace_id=span.trace_id, span_id=span.span_id)
        ):
            raise ValueError("trace evidence is not bound to the exporter-issued trace")
        if (
            state.kind is not EvidenceKind.STATE_SNAPSHOT
            or state.taint is not Taint.TRUSTED_RUNTIME
            or state.trace_context != trace.trace_context
            or state.sha256 != sha256_digest(_state_evidence_binding(self))
        ):
            raise ValueError("state evidence is not bound to the trace and captures")
        for evidence in (trace, state):
            if (
                evidence.produced_by.adapter != ADAPTER_NAME
                or evidence.produced_by.version != ADAPTER_VERSION
                or evidence.redaction_policy_version != _REDACTION_POLICY
            ):
                raise ValueError("runtime evidence was not issued by this adapter")

    def _validate_derived_deltas(self) -> None:
        if len(self.deltas) != len(self.observed_paths):
            raise ValueError("derived state delta count does not match observed paths")
        before = self.before_capture.document()
        after = self.after_capture.document()
        by_id = {delta.delta_id: delta for delta in self.deltas}
        span = self.issued_trace.span
        for path in self.observed_paths:
            delta = by_id.get(path.delta_id)
            before_value = _path_scalar(before, path.capture_path)
            after_value = _path_scalar(after, path.capture_path)
            if delta is None or before_value == after_value:
                raise ValueError("observed path does not contain a runtime state change")
            if (
                delta.subject != path.subject
                or delta.precondition
                != StateCondition(
                    path=path.state_path,
                    operator=ComparisonOperator.EQ,
                    value=before_value,
                )
                or delta.effect
                != StateEffect(
                    path=path.state_path,
                    operation=EffectOperation.SET,
                    value=after_value,
                )
                or delta.observable
                != StateCondition(
                    path=path.state_path,
                    operator=ComparisonOperator.EQ,
                    value=after_value,
                )
                or delta.provenance
                != Provenance(
                    kind=ProvenanceKind.OBSERVED,
                    evidence_ids=(self.state_evidence.evidence_id,),
                    adapter=ADAPTER_NAME,
                    adapter_version=ADAPTER_VERSION,
                )
            ):
                raise ValueError("state delta was not derived from the bound captures")
            observed_nanos = _datetime_to_nanos(delta.observed_at)
            if not span.start_time_unix_nano <= observed_nanos <= span.end_time_unix_nano:
                raise ValueError("derived state delta falls outside the issued trace")


class RuntimeObservationResult(ContractModel):
    flow: TelemetryFlow
    receipt: RuntimeObservationReceipt

    @model_validator(mode="after")
    def flow_matches_receipt(self) -> RuntimeObservationResult:
        if (
            self.flow.transition_id != self.receipt.transition_id
            or self.flow.name != self.receipt.name
            or self.flow.action != self.receipt.action
            or self.flow.deltas != self.receipt.deltas
            or self.flow.provenance.evidence_ids != (self.receipt.trace_evidence.evidence_id,)
        ):
            raise ValueError("telemetry flow is not bound to its runtime receipt")
        return self


class _ProcessLocalExporter:
    def __init__(self) -> None:
        self.exporter_id = f"exporter.{secrets.token_hex(12)}"
        self._sequence = 0
        self._issued: dict[str, IssuedRuntimeTrace] = {}

    def issue(
        self,
        *,
        observation_id: str,
        world_id: str,
        execution_id: str,
        execution_digest: str,
        observation_claim_digest: str,
        action_digest: str,
        authorization_digest: str,
        source_digest: str,
        method: str,
        route: str,
        status: int,
        start_nanos: int,
        end_nanos: int,
        application_attributes: Mapping[str, object],
    ) -> IssuedRuntimeTrace:
        self._sequence += 1
        trace_id = secrets.token_hex(16)
        span_id = secrets.token_hex(8)
        attributes: list[SpanAttribute] = [
            SpanAttribute(key="http.request.method", value=method),
            SpanAttribute(key="http.route", value=route),
            SpanAttribute(key="http.response.status_code", value=status),
            SpanAttribute(key="stateweaver.observation.id", value=observation_id),
            SpanAttribute(key="stateweaver.exporter.id", value=self.exporter_id),
            SpanAttribute(key="stateweaver.exporter.sequence", value=self._sequence),
            SpanAttribute(key="stateweaver.world.id", value=world_id),
            SpanAttribute(key="stateweaver.execution.id", value=execution_id),
            SpanAttribute(key="stateweaver.execution.digest", value=execution_digest),
            SpanAttribute(
                key="stateweaver.observation.claim.digest",
                value=observation_claim_digest,
            ),
            SpanAttribute(key="stateweaver.action.digest", value=action_digest),
            SpanAttribute(key="stateweaver.policy.binding.digest", value=authorization_digest),
            SpanAttribute(key="stateweaver.source.digest", value=source_digest),
        ]
        try:
            for key, value in application_attributes.items():
                attributes.append(SpanAttribute(key=key, value=_json_scalar(value)))
            span = OtlpSpan(
                trace_id=trace_id,
                span_id=span_id,
                name=f"{method} {route}",
                kind=SpanKind.SERVER,
                start_time_unix_nano=start_nanos,
                end_time_unix_nano=max(end_nanos, start_nanos + 1_000),
                attributes=tuple(attributes),
            )
            issued = IssuedRuntimeTrace(
                observation_id=observation_id,
                exporter_id=self.exporter_id,
                sequence=self._sequence,
                world_id=world_id,
                execution_id=execution_id,
                execution_digest=execution_digest,
                observation_claim_digest=observation_claim_digest,
                action_digest=action_digest,
                authorization_digest=authorization_digest,
                source_digest=source_digest,
                span=span,
                span_digest=canonical_spans_sha256((span,)),
            )
        except (TypeError, ValueError, ValidationError):
            raise RuntimeObservationError("unsafe runtime trace attributes were rejected") from None
        self._issued[observation_id] = issued
        return issued

    def verify(self, issued: IssuedRuntimeTrace) -> None:
        recorded = self._issued.get(issued.observation_id)
        if recorded is None or recorded != issued:
            raise RuntimeObservationError(
                "runtime trace is not present in the process-local ledger"
            )


class RuntimeObservationController:
    """Observe the actual ASGI lifecycle owned by one exact lab environment."""

    __slots__ = (
        "_capture_sequence",
        "_environment",
        "_environment_class",
        "_execution_class",
        "_exporter",
        "_idempotency_ledger",
        "_lock",
        "_poisoned",
        "_receipt_ledger",
        "_source_digest",
        "_timeout_error_type",
    )

    def __init__(self, environment: object) -> None:
        try:
            from stateweaver.adapters.in_process_lab import (
                InProcessLabEnvironment,
                InProcessLabRuntimeExecution,
                LabExecutionTimeoutError,
            )

            if type(environment) is not InProcessLabEnvironment:
                raise RuntimeObservationError(
                    "runtime observation requires the exact in-process lab environment"
                )
            assert isinstance(environment, InProcessLabEnvironment)
            source_digest = environment.runtime_source_digest
        except RuntimeObservationError:
            raise RuntimeObservationError(
                "runtime observation requires the exact in-process lab environment"
            ) from None
        except Exception:
            raise RuntimeObservationError(
                "runtime observation environment binding is invalid"
            ) from None
        self._environment: InProcessLabEnvironment = environment
        self._environment_class = InProcessLabEnvironment
        self._execution_class = InProcessLabRuntimeExecution
        self._timeout_error_type = LabExecutionTimeoutError
        self._source_digest = source_digest
        self._exporter = _ProcessLocalExporter()
        self._capture_sequence = 0
        self._receipt_ledger: dict[str, str] = {}
        self._idempotency_ledger: dict[str, tuple[Sha256Digest, RuntimeObservationResult]] = {}
        self._poisoned = False
        self._lock = asyncio.Lock()

    async def observe(self, request: RuntimeObservationRequest) -> RuntimeObservationResult:
        """Capture before/action/after and derive evidence-bound deltas."""

        try:
            if not isinstance(request, RuntimeObservationRequest):
                raise TypeError("request must be a RuntimeObservationRequest")
            request = RuntimeObservationRequest.model_validate(request.model_dump(mode="python"))
        except (TypeError, ValueError, ValidationError):
            raise RuntimeObservationError("runtime observation request is invalid") from None
        timed_out = False
        try:
            async with asyncio.timeout(request.action_envelope.timeout_ms / 1_000):
                async with self._lock:
                    if self._poisoned:
                        raise RuntimeObservationError(
                            "runtime observation controller is poisoned after an "
                            "uncertain execution"
                        )
                    request_digest = sha256_digest(request)
                    idempotency_key = request.action_envelope.idempotency_key
                    cached = self._idempotency_ledger.get(idempotency_key)
                    if cached is not None:
                        cached_digest, result = cached
                        if cached_digest != request_digest:
                            raise RuntimeObservationError(
                                "runtime observation idempotency key semantics changed"
                            )
                        return result
                    if len(self._idempotency_ledger) >= _MAX_IDEMPOTENCY_RECORDS:
                        raise RuntimeObservationError(
                            "runtime observation idempotency ledger is full"
                        )
                    result = await self._observe_locked(request)
                    self._idempotency_ledger[idempotency_key] = (request_digest, result)
                    return result
        except TimeoutError:
            timed_out = True
        except asyncio.CancelledError:
            self._poisoned = True
            raise
        if timed_out:
            self._poisoned = True
            raise RuntimeObservationError(
                "authorized runtime action exceeded its deadline"
            ) from None
        raise RuntimeObservationError("runtime observation ended without a result") from None

    def verify(
        self,
        receipt: RuntimeObservationReceipt | Mapping[str, object],
    ) -> RuntimeObservationReceipt:
        """Revalidate canonical bindings and the controller's process-local issuance ledger."""

        try:
            payload = (
                receipt.model_dump(mode="python")
                if isinstance(receipt, RuntimeObservationReceipt)
                else dict(receipt)
            )
            checked = RuntimeObservationReceipt.model_validate_json(canonical_json_bytes(payload))
        except (TypeError, ValueError, ValidationError):
            raise RuntimeObservationError("runtime observation receipt is invalid") from None
        self._exporter.verify(checked.issued_trace)
        recorded_digest = self._receipt_ledger.get(checked.observation_id)
        if recorded_digest != checked.receipt_digest:
            raise RuntimeObservationError(
                "runtime receipt is not present in the process-local ledger"
            )
        return checked

    async def _observe_locked(self, request: RuntimeObservationRequest) -> RuntimeObservationResult:
        observation_id = f"observation.{secrets.token_hex(12)}"
        envelope = request.action_envelope
        action_digest = sha256_digest(envelope)
        try:
            route = self._environment_class.resolve_runtime_route(
                self._environment,
                envelope,
            )
            source_digest = self._environment.runtime_source_digest
        except Exception:
            raise RuntimeObservationError(
                "repository runtime source or action binding is invalid"
            ) from None
        if route != request.expected_route or source_digest != self._source_digest:
            raise RuntimeObservationError("typed route or source does not match the repository app")
        execution: InProcessLabRuntimeExecution | None = None
        execution_failure: Literal["deadline", "execution"] | None = None
        try:
            candidate = await self._environment_class.execute_observed(
                self._environment,
                envelope,
            )
            if type(candidate) is not self._execution_class:
                raise RuntimeObservationError("runtime execution receipt type is invalid")
            execution = candidate
        except asyncio.CancelledError:
            self._poisoned = True
            raise
        except Exception as error:
            execution_failure = (
                "deadline" if type(error) is self._timeout_error_type else "execution"
            )
        if execution_failure is not None:
            self._poisoned = True
            if execution_failure == "deadline":
                raise RuntimeObservationError(
                    "authorized runtime action exceeded its deadline"
                ) from None
            raise RuntimeObservationError(
                "server-side runtime authorization or ASGI execution was rejected"
            ) from None
        if execution is None:  # pragma: no cover - closed by the branches above
            self._poisoned = True
            raise RuntimeObservationError("runtime execution receipt is missing")

        try:
            authorization = _authorization_binding(execution)
            if (
                execution.envelope_digest != action_digest
                or execution.source_digest != source_digest
                or execution.method is not request.action.method
                or execution.route != request.expected_route
                or execution.status not in request.action.expected_statuses
            ):
                raise RuntimeObservationError(
                    "actual ASGI execution does not match the authorized request"
                )
            observation_claim_digest = await self._environment_class.claim_runtime_observation(
                self._environment,
                execution,
            )
            before = self._capture_bound(
                environment_capture=execution.before_capture,
                captured_at_unix_nano=execution.before_captured_at_unix_nano,
                observation_id=observation_id,
                world_id=request.world_id,
                source_digest=source_digest,
                phase="before",
            )
            issued = self._exporter.issue(
                observation_id=observation_id,
                world_id=request.world_id,
                execution_id=execution.execution_id,
                execution_digest=execution.execution_digest,
                observation_claim_digest=observation_claim_digest,
                action_digest=action_digest,
                authorization_digest=sha256_digest(authorization),
                source_digest=source_digest,
                method=execution.method.value,
                route=execution.route,
                status=execution.status,
                start_nanos=execution.started_at_unix_nano,
                end_nanos=execution.ended_at_unix_nano,
                application_attributes={},
            )
            if self._environment.runtime_source_digest != source_digest:
                raise RuntimeObservationError("repository app source changed during observation")
            after = self._capture_bound(
                environment_capture=execution.after_capture,
                captured_at_unix_nano=execution.after_captured_at_unix_nano,
                observation_id=observation_id,
                world_id=request.world_id,
                source_digest=source_digest,
                phase="after",
            )
            return self._build_result(
                request=request,
                observation_id=observation_id,
                action_digest=action_digest,
                execution_id=execution.execution_id,
                execution_digest=execution.execution_digest,
                observation_claim_digest=observation_claim_digest,
                authorization=authorization,
                source_digest=source_digest,
                before=before,
                after=after,
                issued=issued,
            )
        except RuntimeObservationError:
            self._poisoned = True
            raise RuntimeObservationError(
                "authorized runtime observation could not be finalized"
            ) from None
        except Exception:
            self._poisoned = True
            raise RuntimeObservationError(
                "authorized runtime observation could not be finalized"
            ) from None

    def _capture_bound(
        self,
        *,
        environment_capture: object,
        captured_at_unix_nano: int,
        observation_id: str,
        world_id: str,
        source_digest: str,
        phase: Literal["before", "after"],
    ) -> RuntimeStateCapture:
        try:
            document = _environment_capture_document(environment_capture)
            _reject_secret_like_json(document)
            payload_json = canonical_json_bytes(document).decode("utf-8")
            if len(payload_json.encode("utf-8")) > _MAX_CAPTURE_BYTES:
                raise RuntimeObservationError("runtime state capture exceeds the local byte limit")
        except RuntimeObservationError:
            raise RuntimeObservationError("runtime state capture is invalid") from None
        except Exception:
            raise RuntimeObservationError("runtime state capture is invalid") from None
        self._capture_sequence += 1
        return RuntimeStateCapture(
            observation_id=observation_id,
            world_id=world_id,
            source_digest=source_digest,
            phase=phase,
            sequence=self._capture_sequence,
            captured_at=_nanos_to_datetime(captured_at_unix_nano),
            payload_json=payload_json,
            payload_digest=sha256_digest(document),
        )

    def _build_result(
        self,
        *,
        request: RuntimeObservationRequest,
        observation_id: str,
        action_digest: str,
        execution_id: str,
        execution_digest: str,
        observation_claim_digest: str,
        authorization: RuntimeExecutionReceiptBinding,
        source_digest: str,
        before: RuntimeStateCapture,
        after: RuntimeStateCapture,
        issued: IssuedRuntimeTrace,
    ) -> RuntimeObservationResult:
        evidence_suffix = observation_id.removeprefix("observation.")
        context = TraceContext(trace_id=issued.span.trace_id, span_id=issued.span.span_id)
        trace_evidence = EvidenceRecord(
            evidence_id=f"evidence.otel.{evidence_suffix}",
            kind=EvidenceKind.OTEL_TRACE,
            artifact_uri=f"artifact://runtime-observation/{evidence_suffix}/trace",
            sha256=issued.span_digest,
            produced_by=EvidenceProducer(adapter=ADAPTER_NAME, version=ADAPTER_VERSION),
            trace_context=context,
            redaction_policy_version=_REDACTION_POLICY,
            taint=Taint.TRUSTED_RUNTIME,
            created_at=datetime.now(UTC),
        )
        state_id = f"evidence.state.{evidence_suffix}"
        observed_at = _nanos_to_datetime(issued.span.end_time_unix_nano)
        deltas = _derive_deltas(
            request.observed_paths,
            before,
            after,
            evidence_id=state_id,
            observed_at=observed_at,
        )
        state_binding = {
            "observation_id": observation_id,
            "world_id": request.world_id,
            "action_digest": action_digest,
            "execution_id": execution_id,
            "execution_digest": execution_digest,
            "observation_claim_digest": observation_claim_digest,
            "authorization": authorization,
            "source_digest": source_digest,
            "before_digest": before.payload_digest,
            "after_digest": after.payload_digest,
            "observed_paths": request.observed_paths,
            "deltas": deltas,
        }
        state_evidence = EvidenceRecord(
            evidence_id=state_id,
            kind=EvidenceKind.STATE_SNAPSHOT,
            artifact_uri=f"artifact://runtime-observation/{evidence_suffix}/state",
            sha256=sha256_digest(state_binding),
            produced_by=EvidenceProducer(adapter=ADAPTER_NAME, version=ADAPTER_VERSION),
            trace_context=context,
            redaction_policy_version=_REDACTION_POLICY,
            taint=Taint.TRUSTED_RUNTIME,
            created_at=datetime.now(UTC),
        )
        fidelity = _runtime_fidelity(request)
        ingest_request = TraceIngestRequest(
            transition_id=request.transition_id,
            name=request.name,
            action=request.action,
            expected_route=request.expected_route,
            trace_evidence=trace_evidence,
            state_deltas=deltas,
            fidelity=fidelity,
        )
        try:
            flow = ingest_spans(ingest_request, (issued.span,))
        except TelemetryIngestError:
            raise RuntimeObservationError("controller-issued telemetry failed ingestion") from None
        receipt_fields: dict[str, object] = {
            "observation_id": observation_id,
            "world_id": request.world_id,
            "transition_id": request.transition_id,
            "name": request.name,
            "action_envelope": request.action_envelope,
            "action": request.action,
            "action_digest": action_digest,
            "execution_id": execution_id,
            "execution_digest": execution_digest,
            "observation_claim_digest": observation_claim_digest,
            "authorization": authorization,
            "expected_route": request.expected_route,
            "source_digest": source_digest,
            "observed_paths": request.observed_paths,
            "before_capture": before,
            "after_capture": after,
            "issued_trace": issued,
            "trace_evidence": trace_evidence,
            "state_evidence": state_evidence,
            "deltas": deltas,
        }
        receipt = RuntimeObservationReceipt(
            observation_id=observation_id,
            world_id=request.world_id,
            transition_id=request.transition_id,
            name=request.name,
            action_envelope=request.action_envelope,
            action=request.action,
            action_digest=action_digest,
            execution_id=execution_id,
            execution_digest=execution_digest,
            observation_claim_digest=observation_claim_digest,
            authorization=authorization,
            expected_route=request.expected_route,
            source_digest=source_digest,
            observed_paths=request.observed_paths,
            before_capture=before,
            after_capture=after,
            issued_trace=issued,
            trace_evidence=trace_evidence,
            state_evidence=state_evidence,
            deltas=deltas,
            receipt_digest=sha256_digest(receipt_fields),
        )
        result = RuntimeObservationResult(flow=flow, receipt=receipt)
        self._receipt_ledger[observation_id] = receipt.receipt_digest
        return result


def _environment_capture_document(capture: object) -> dict[str, object]:
    artifacts = getattr(capture, "artifacts", None)
    if not isinstance(artifacts, tuple):
        raise RuntimeObservationError("bound environment capture has an invalid artifact set")
    document: dict[str, object] = {}
    for artifact in artifacts:
        layer = getattr(getattr(artifact, "layer", None), "value", None)
        payload = getattr(artifact, "payload", None)
        if not isinstance(layer, str) or layer in document:
            raise RuntimeObservationError("bound environment capture has invalid layer names")
        document[layer] = _json_document(payload, label="environment capture layer")
    expected_layers = {
        "application",
        "database",
        "cache",
        "queue",
        "browser",
        "configuration",
        "clock",
    }
    if set(document) != expected_layers:
        raise RuntimeObservationError("bound environment capture is missing required layers")
    return document


def _authorization_binding(
    execution: InProcessLabRuntimeExecution,
) -> RuntimeExecutionReceiptBinding:
    """Copy only immutable, redacted fields from the server authorization receipt."""

    authorization = execution.authorization
    return RuntimeExecutionReceiptBinding(
        action_id=authorization.action_id,
        policy_decision_ref=authorization.policy_decision_ref,
        idempotency_key=authorization.idempotency_key,
        envelope_digest=authorization.envelope_hash,
        policy_request_hash=authorization.policy_request_hash,
        scope_manifest_hash=authorization.scope_manifest_hash,
        budget_reservation_id=authorization.budget_reservation_id,
        decision_digest=sha256_digest(authorization.decision),
        requests_before=authorization.requests_before,
        write_requests_before=authorization.write_requests_before,
    )


def _derive_deltas(
    paths: Sequence[ObservedStatePath],
    before: RuntimeStateCapture,
    after: RuntimeStateCapture,
    *,
    evidence_id: str,
    observed_at: datetime,
) -> tuple[StateDelta, ...]:
    before_document = before.document()
    after_document = after.document()
    output: list[StateDelta] = []
    for path in paths:
        before_value = _path_scalar(before_document, path.capture_path)
        after_value = _path_scalar(after_document, path.capture_path)
        if before_value == after_value:
            raise RuntimeObservationError("observed state path did not change during the action")
        output.append(
            StateDelta(
                delta_id=path.delta_id,
                subject=path.subject,
                precondition=StateCondition(
                    path=path.state_path,
                    operator=ComparisonOperator.EQ,
                    value=before_value,
                ),
                effect=StateEffect(
                    path=path.state_path,
                    operation=EffectOperation.SET,
                    value=after_value,
                ),
                observable=StateCondition(
                    path=path.state_path,
                    operator=ComparisonOperator.EQ,
                    value=after_value,
                ),
                provenance=Provenance(
                    kind=ProvenanceKind.OBSERVED,
                    evidence_ids=(evidence_id,),
                    adapter=ADAPTER_NAME,
                    adapter_version=ADAPTER_VERSION,
                ),
                observed_at=observed_at,
            )
        )
    return tuple(sorted(output, key=lambda item: item.delta_id))


def _runtime_fidelity(request: RuntimeObservationRequest) -> FidelityProfile:
    roots = {item.capture_path.split(".", 1)[0] for item in request.observed_paths}
    return FidelityProfile(
        code=FidelityLevel.OBSERVED,
        identity=(
            FidelityLevel.OBSERVED
            if request.action.identity_handle is not None
            else FidelityLevel.UNKNOWN
        ),
        database=(FidelityLevel.OBSERVED if "database" in roots else FidelityLevel.UNKNOWN),
        cache=FidelityLevel.OBSERVED if "cache" in roots else FidelityLevel.UNKNOWN,
        queue=FidelityLevel.OBSERVED if "queue" in roots else FidelityLevel.UNKNOWN,
        timing=FidelityLevel.OBSERVED,
    )


def _state_evidence_binding(receipt: RuntimeObservationReceipt) -> dict[str, object]:
    return {
        "observation_id": receipt.observation_id,
        "world_id": receipt.world_id,
        "action_digest": receipt.action_digest,
        "execution_id": receipt.execution_id,
        "execution_digest": receipt.execution_digest,
        "observation_claim_digest": receipt.observation_claim_digest,
        "authorization": receipt.authorization,
        "source_digest": receipt.source_digest,
        "before_digest": receipt.before_capture.payload_digest,
        "after_digest": receipt.after_capture.payload_digest,
        "observed_paths": receipt.observed_paths,
        "deltas": receipt.deltas,
    }


def _json_document(value: object, *, label: str) -> dict[str, object]:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", by_alias=True, exclude_none=False)
    normalized = _normalize_json(value, depth=0)
    if not isinstance(normalized, dict):
        raise RuntimeObservationError(f"{label} must be a JSON object")
    return normalized


def _normalize_json(value: object, *, depth: int) -> object:
    if depth > _MAX_CAPTURE_DEPTH:
        raise RuntimeObservationError("JSON document exceeds the local nesting limit")
    if isinstance(value, Mapping):
        output: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise RuntimeObservationError("JSON object keys must be strings")
            output[key] = _normalize_json(item, depth=depth + 1)
        return output
    if isinstance(value, (list, tuple)):
        return [_normalize_json(item, depth=depth + 1) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        canonical_json_bytes(value)
        return value
    raise RuntimeObservationError("runtime document contains a non-JSON value")


def _decode_capture(payload_json: str) -> dict[str, object]:
    try:
        value = json.loads(payload_json)
        document = _json_document(value, label="runtime state capture")
        _reject_secret_like_json(document)
        return document
    except RuntimeObservationError:
        raise ValueError("runtime capture payload is invalid") from None
    except (json.JSONDecodeError, TypeError, ValueError):
        raise ValueError("runtime capture payload is invalid") from None


def _reject_secret_like_json(value: object, *, depth: int = 0) -> None:
    if depth > _MAX_CAPTURE_DEPTH:
        raise RuntimeObservationError("runtime state capture exceeds the nesting limit")
    if isinstance(value, Mapping):
        for key, item in value.items():
            if _SECRET_KEY.search(key):
                raise RuntimeObservationError("runtime state capture contains a secret-like key")
            _reject_secret_like_json(item, depth=depth + 1)
    elif isinstance(value, list):
        for item in value:
            _reject_secret_like_json(item, depth=depth + 1)
    elif isinstance(value, str) and _SECRET_TEXT.search(value):
        raise RuntimeObservationError("runtime state capture contains secret-like text")


def _path_scalar(document: Mapping[str, object], path: str) -> JsonScalar:
    current: object = document
    for segment in path.split("."):
        if not isinstance(current, Mapping) or segment not in current:
            raise RuntimeObservationError("observed state path is absent from the runtime capture")
        current = current[segment]
    try:
        return _json_scalar(current)
    except (TypeError, ValueError, ValidationError):
        raise RuntimeObservationError("observed state path must resolve to a JSON scalar") from None


def _json_scalar(value: object) -> JsonScalar:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError("value is not a JSON scalar")


def _datetime_to_nanos(value: datetime) -> int:
    absolute = value.astimezone(UTC)
    delta = absolute - _EPOCH
    return ((delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1_000


def _nanos_to_datetime(value: int) -> datetime:
    return _EPOCH + timedelta(microseconds=value // 1_000)


__all__ = [
    "IssuedRuntimeTrace",
    "ObservedStatePath",
    "RuntimeExecutionReceiptBinding",
    "RuntimeObservationController",
    "RuntimeObservationError",
    "RuntimeObservationReceipt",
    "RuntimeObservationRequest",
    "RuntimeObservationResult",
    "RuntimeStateCapture",
]
