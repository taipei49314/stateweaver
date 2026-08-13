"""Clean-wheel producer and independent verifier for the M3 runtime observation."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from pydantic import ValidationError
from stateweaver.adapters.in_process_lab import (
    CANONICAL_RANDOM_SEED,
    FixedLabActionRegistry,
    InProcessLabEnvironment,
    LabAction,
    PolicyAuthorization,
    lab_action_artifact,
    lab_http_action_spec,
)
from stateweaver.adapters.telemetry.opentelemetry import (
    RuntimeObservationController,
    RuntimeObservationReceipt,
    RuntimeObservationRequest,
    RuntimeObservationResult,
)
from stateweaver.contracts import (
    ActionEnvelope,
    ActionTarget,
    EnvironmentMode,
    EvidenceProducer,
    FidelityProfile,
    HttpMethod,
    HttpRequestAction,
    Provenance,
    ProvenanceKind,
    RequestedBy,
    RequesterType,
    RiskClass,
    ScopeAction,
    ScopeActions,
    ScopeIdentities,
    ScopeLimits,
    ScopeManifest,
    ScopeMetadata,
    ScopeSpec,
    ScopeTargets,
    ScopeValidity,
    TargetSelector,
    TransitionFragment,
    canonical_json_bytes,
)
from stateweaver.evidence import (
    RuntimeAuthorizationQualification,
    RuntimeCaptureQualification,
    RuntimeObservationProjection,
    RuntimeObservationQualificationError,
    RuntimeObservationQualificationReceipt,
    RuntimeObservedPathQualification,
    RuntimeStateChangeQualification,
    RuntimeTraceQualification,
    build_runtime_observation_qualification,
    runtime_semantic_digest,
)
from stateweaver.policy import BudgetSnapshot, PolicyRequest, evaluate_policy
from stateweaver.replay import canonical_sha256
from stateweaver.twin import SecuritySemanticTwinBuilder, TelemetryFlow, TwinBuildInput
from stateweaver_lab import LabMode
from stateweaver_lab.fixtures import FixtureBearer
from stateweaver_lab.models import (
    AdvanceClockLabAction,
    AdvanceClockRequest,
    ClaimReferenceLabAction,
    ClaimReferenceRequest,
    DeferQueueLabAction,
    DelayQueueRequest,
    DocumentId,
    DowngradeRoleLabAction,
    PrimeAuthorizationCacheLabAction,
    PrimeAuthorizationCacheRequest,
    PrincipalId,
    PublishReferenceLabAction,
    PublishReferenceRequest,
    QueueJobId,
    ReadDocumentLabAction,
    ReadDocumentRequest,
    ReferenceId,
    RetainSessionLabAction,
    Role,
    RoleDowngradeRequest,
)

from .network_guard import deny_network_egress

_EVALUATED_AT = datetime(2026, 7, 29, tzinfo=UTC)
OBSERVED_LAB_ACTIONS: tuple[LabAction, ...] = (
    RetainSessionLabAction(),
    PrimeAuthorizationCacheLabAction(
        payload=PrimeAuthorizationCacheRequest(document_id=DocumentId.TENANT_A_OWNED)
    ),
    DowngradeRoleLabAction(
        payload=RoleDowngradeRequest(
            principal_id=PrincipalId.A_EDITOR,
            new_role=Role.VIEWER,
            propagation="queued",
        )
    ),
    DeferQueueLabAction(
        payload=DelayQueueRequest(job_id=QueueJobId.ROLE_SYNC_A, delay_seconds=240)
    ),
    PublishReferenceLabAction(
        payload=PublishReferenceRequest(
            document_id=DocumentId.TENANT_B_PROTECTED,
            recipient_id=PrincipalId.A_EDITOR,
        )
    ),
    ClaimReferenceLabAction(payload=ClaimReferenceRequest(reference_id=ReferenceId.B_TO_A)),
    AdvanceClockLabAction(payload=AdvanceClockRequest(seconds=90)),
    ReadDocumentLabAction(
        actor=FixtureBearer.TENANT_A_OLD_EDITOR,
        payload=ReadDocumentRequest(document_id=DocumentId.TENANT_B_PROTECTED),
    ),
)
OBSERVED_CHAIN_LENGTH = 8


def _write_count_before(ordinal: int) -> int:
    return sum(
        lab_http_action_spec(item).method.value not in {"GET", "HEAD", "OPTIONS"}
        for item in OBSERVED_LAB_ACTIONS[: ordinal - 1]
    )


def _action_envelope(ordinal: int = 1) -> ActionEnvelope:
    lab_action = OBSERVED_LAB_ACTIONS[ordinal - 1]
    spec = lab_http_action_spec(lab_action)
    action_id = f"action.runtime.qualification.observed-{ordinal:02d}"
    return ActionEnvelope(
        action_id=action_id,
        experiment_id="experiment.runtime.qualification",
        world_id="world.runtime.qualification",
        scope_action=ScopeAction.HTTP_REQUEST,
        action=HttpRequestAction(
            method=spec.method,
            target=ActionTarget(
                scheme="http",
                host="localhost",
                port=80,
                path=spec.path,
            ),
            body_artifact=lab_action_artifact(lab_action),
            identity_handle=spec.identity_handle,
            expected_statuses=spec.expected_statuses,
        ),
        risk_class=(
            RiskClass.PASSIVE
            if spec.method.value in {"GET", "HEAD", "OPTIONS"}
            else RiskClass.REVERSIBLE_STATE_CHANGE
        ),
        idempotency_key=canonical_sha256(
            {"action_id": action_id, "purpose": "runtime-qualification"}
        ),
        requested_by=RequestedBy(
            type=RequesterType.WORKFLOW,
            role="runtime_qualification",
        ),
        policy_decision_ref=f"decision.runtime.qualification.observed-{ordinal:02d}",
        timeout_ms=1_000,
    )


def _policy_request(envelope: ActionEnvelope, ordinal: int = 1) -> PolicyRequest:
    scope = ScopeManifest(
        metadata=ScopeMetadata(name="runtime-qualification"),
        spec=ScopeSpec(
            environmentMode=EnvironmentMode.SOURCE_BACKED,
            targets=ScopeTargets(
                include=(
                    TargetSelector(
                        host="localhost",
                        ports=(80,),
                        paths=("/v1/lab/**",),
                    ),
                )
            ),
            identities=ScopeIdentities(allowed=("test_user_a", "test_user_b", "test_admin")),
            actions=ScopeActions(allow=(ScopeAction.HTTP_REQUEST,)),
            limits=ScopeLimits(
                requestsPerSecond=10.0,
                concurrentMaterializedWorlds=1,
                maxWriteRequests=8,
            ),
            validity=ScopeValidity(
                notBefore=datetime(2026, 1, 1, tzinfo=UTC),
                expiresAt=datetime(2027, 1, 1, tzinfo=UTC),
            ),
        ),
    )
    return PolicyRequest(
        scope_manifest=scope,
        action_envelope=envelope,
        budget=BudgetSnapshot(
            requests_in_window=ordinal - 1,
            request_window_seconds=1.0,
            write_requests_used=_write_count_before(ordinal),
        ),
        evaluated_at=_EVALUATED_AT,
    )


def _request(envelope: ActionEnvelope, ordinal: int = 1) -> RuntimeObservationRequest:
    from stateweaver.adapters.telemetry.opentelemetry import ObservedStatePath

    lab_action = OBSERVED_LAB_ACTIONS[ordinal - 1]
    expected_route = (
        "/v1/lab/documents/{document_id}"
        if isinstance(lab_action, ReadDocumentLabAction)
        else lab_http_action_spec(lab_action).path
    )
    return RuntimeObservationRequest(
        world_id=envelope.world_id,
        transition_id=f"transition.runtime.qualification.observed-{ordinal:02d}",
        name=f"actual ASGI observation {ordinal}",
        action_envelope=envelope,
        expected_route=expected_route,
        observed_paths=(
            ObservedStatePath(
                delta_id=f"delta.runtime.qualification.evidence-count-{ordinal:02d}",
                subject="resource.lab.application",
                capture_path="application.evidence_count",
                state_path=f"chain.observed_step_{ordinal:02d}",
            ),
        ),
    )


def _transition_for_result(result: RuntimeObservationResult) -> TransitionFragment:
    twin = SecuritySemanticTwinBuilder().build(
        TwinBuildInput(
            twin_id="twin.runtime.qualification",
            evidence_records=(
                result.receipt.trace_evidence,
                result.receipt.state_evidence,
            ),
            telemetry_flows=(result.flow,),
        )
    )
    if len(twin.transitions) != 1:
        raise RuntimeObservationQualificationError(
            "runtime observation did not produce exactly one transition"
        )
    return twin.transitions[0]


def _projection(
    *,
    repository_marker: str,
    result: RuntimeObservationResult,
) -> RuntimeObservationProjection:
    receipt = result.receipt
    span = receipt.issued_trace.span
    attributes = span.attribute_map()
    status = attributes.get("http.response.status_code")
    method = attributes.get("http.request.method")
    route = attributes.get("http.route")
    if type(status) is not int or not isinstance(method, str) or not isinstance(route, str):
        raise RuntimeObservationQualificationError("runtime trace attributes are invalid")
    try:
        authorization = RuntimeAuthorizationQualification.model_validate_json(
            canonical_json_bytes(receipt.authorization.model_dump(mode="json"))
        )
        before = RuntimeCaptureQualification.model_validate_json(
            canonical_json_bytes(receipt.before_capture.model_dump(mode="json"))
        )
        after = RuntimeCaptureQualification.model_validate_json(
            canonical_json_bytes(receipt.after_capture.model_dump(mode="json"))
        )
        observed_paths = tuple(
            RuntimeObservedPathQualification.model_validate_json(
                canonical_json_bytes(item.model_dump(mode="json"))
            )
            for item in receipt.observed_paths
        )
        state_changes = []
        for item in receipt.deltas:
            if len(item.provenance.evidence_ids) != 1:
                raise RuntimeObservationQualificationError(
                    "runtime state change has ambiguous evidence"
                )
            state_changes.append(
                RuntimeStateChangeQualification(
                    delta_id=item.delta_id,
                    subject=item.subject,
                    precondition=item.precondition,
                    effect=item.effect,
                    observable=item.observable,
                    evidence_id=item.provenance.evidence_ids[0],
                    observed_at=item.observed_at,
                )
            )
        trace = RuntimeTraceQualification(
            exporter_id=receipt.issued_trace.exporter_id,
            exporter_sequence=receipt.issued_trace.sequence,
            trace_id=span.trace_id,
            span_id=span.span_id,
            method=HttpMethod(method),
            route=route,
            status=status,
            start_time_unix_nano=span.start_time_unix_nano,
            end_time_unix_nano=span.end_time_unix_nano,
            span_digest=receipt.issued_trace.span_digest,
        )
        return RuntimeObservationProjection(
            repository_marker=repository_marker,
            adapter=EvidenceProducer(
                adapter=receipt.trace_evidence.produced_by.adapter,
                version=receipt.trace_evidence.produced_by.version,
            ),
            observation_id=receipt.observation_id,
            world_id=receipt.world_id,
            transition_id=receipt.transition_id,
            name=receipt.name,
            source_digest=receipt.source_digest,
            action_envelope=receipt.action_envelope,
            action_digest=receipt.action_digest,
            execution_id=receipt.execution_id,
            execution_digest=receipt.execution_digest,
            observation_claim_digest=receipt.observation_claim_digest,
            authorization=authorization,
            expected_route=receipt.expected_route,
            observed_paths=observed_paths,
            before_capture=before,
            after_capture=after,
            trace=trace,
            trace_evidence=receipt.trace_evidence,
            state_evidence=receipt.state_evidence,
            state_changes=tuple(state_changes),
            fidelity=result.flow.fidelity,
            transition_fragment=_transition_for_result(result),
        )
    except (TypeError, ValueError, ValidationError):
        raise RuntimeObservationQualificationError(
            "runtime observation projection is invalid"
        ) from None


async def _execute_runtime_qualifications(
    repository_marker: str,
    *,
    count: int,
) -> tuple[RuntimeObservationQualificationReceipt, ...]:
    lab_actions = OBSERVED_LAB_ACTIONS[:count]
    envelopes = tuple(_action_envelope(ordinal) for ordinal in range(1, count + 1))
    policy_requests = tuple(
        _policy_request(envelope, ordinal) for ordinal, envelope in enumerate(envelopes, start=1)
    )
    authorizations = tuple(
        PolicyAuthorization.bind(envelope, request, evaluate_policy(request))
        for envelope, request in zip(envelopes, policy_requests, strict=True)
    )
    registry = FixedLabActionRegistry(
        by_action_id={
            envelope.action_id: lab_action
            for envelope, lab_action in zip(envelopes, lab_actions, strict=True)
        },
        by_body_artifact={lab_action_artifact(item): item for item in lab_actions},
        policy_authorizations={
            envelope.policy_decision_ref: authorization
            for envelope, authorization in zip(envelopes, authorizations, strict=True)
        },
    )
    environment = InProcessLabEnvironment(mode=LabMode.VULNERABLE, registry=registry)
    try:
        await environment.create_root_seed(
            root_seed_id="root.runtime.qualification",
            random_seed=CANONICAL_RANDOM_SEED,
        )
        controller = RuntimeObservationController(environment)
        qualifications: list[RuntimeObservationQualificationReceipt] = []
        for ordinal, envelope in enumerate(envelopes, start=1):
            result = await controller.observe(_request(envelope, ordinal))
            verified = controller.verify(result.receipt)
            if verified != result.receipt:
                raise RuntimeObservationQualificationError(
                    "runtime observation process-local verification failed"
                )
            projection = _projection(repository_marker=repository_marker, result=result)
            qualifications.append(
                build_runtime_observation_qualification(
                    adapter_receipt=verified.model_dump(mode="json"),
                    projection=projection,
                )
            )
        return tuple(qualifications)
    finally:
        await environment.cleanup()


def _result_from_adapter_receipt(
    receipt: RuntimeObservationReceipt,
    *,
    fidelity: FidelityProfile,
) -> RuntimeObservationResult:
    flow = TelemetryFlow(
        transition_id=receipt.transition_id,
        name=receipt.name,
        action=receipt.action,
        deltas=receipt.deltas,
        provenance=Provenance(
            kind=ProvenanceKind.OBSERVED,
            evidence_ids=(receipt.trace_evidence.evidence_id,),
            adapter=receipt.trace_evidence.produced_by.adapter,
            adapter_version=receipt.trace_evidence.produced_by.version,
        ),
        fidelity=fidelity,
        consistent_replays=1,
    )
    return RuntimeObservationResult(flow=flow, receipt=receipt)


def validate_runtime_qualification_against_adapter(
    qualification: RuntimeObservationQualificationReceipt,
) -> RuntimeObservationQualificationReceipt:
    """Parse the retained adapter receipt and rederive every typed projection field."""

    try:
        adapter_receipt = RuntimeObservationReceipt.model_validate_json(
            qualification.adapter_receipt_json
        )
        result = _result_from_adapter_receipt(
            adapter_receipt,
            fidelity=qualification.projection.fidelity,
        )
        expected_projection = _projection(
            repository_marker=qualification.projection.repository_marker,
            result=result,
        )
    except (TypeError, ValueError, ValidationError, RuntimeObservationQualificationError):
        raise RuntimeObservationQualificationError(
            "runtime adapter receipt does not match its qualification"
        ) from None
    if (
        expected_projection != qualification.projection
        or runtime_semantic_digest(expected_projection) != qualification.semantic_digest
    ):
        raise RuntimeObservationQualificationError(
            "runtime adapter receipt does not match its qualification"
        )
    return qualification


def qualify_runtime_observation(
    repository_marker: str,
) -> RuntimeObservationQualificationReceipt:
    """Execute one authorized ASGI operation under the network-deny guard."""

    async def guarded() -> tuple[RuntimeObservationQualificationReceipt, int]:
        with deny_network_egress() as guard:
            receipt = (await _execute_runtime_qualifications(repository_marker, count=1))[0]
        return receipt, guard.denied_attempts

    receipt, denied_attempts = asyncio.run(guarded())
    if denied_attempts:
        raise RuntimeObservationQualificationError(
            "runtime observation attempted denied network access"
        )
    return validate_runtime_qualification_against_adapter(receipt)


def qualify_runtime_observation_chain(
    repository_marker: str,
) -> tuple[RuntimeObservationQualificationReceipt, ...]:
    """Execute eight sequential, actual-ASGI observations in one clean lab root."""

    async def guarded() -> tuple[tuple[RuntimeObservationQualificationReceipt, ...], int]:
        with deny_network_egress() as guard:
            receipts = await _execute_runtime_qualifications(
                repository_marker,
                count=OBSERVED_CHAIN_LENGTH,
            )
        return receipts, guard.denied_attempts

    receipts, denied_attempts = asyncio.run(guarded())
    if denied_attempts or len(receipts) != OBSERVED_CHAIN_LENGTH:
        raise RuntimeObservationQualificationError(
            "runtime observation chain did not remain offline and complete"
        )
    return tuple(validate_runtime_qualification_against_adapter(item) for item in receipts)


__all__ = [
    "OBSERVED_CHAIN_LENGTH",
    "OBSERVED_LAB_ACTIONS",
    "qualify_runtime_observation",
    "qualify_runtime_observation_chain",
    "validate_runtime_qualification_against_adapter",
]
