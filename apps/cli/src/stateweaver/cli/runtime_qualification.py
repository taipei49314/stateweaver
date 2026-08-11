"""Clean-wheel producer and independent verifier for the M3 runtime observation."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from pydantic import ValidationError
from stateweaver.adapters.in_process_lab import (
    CANONICAL_RANDOM_SEED,
    FixedLabActionRegistry,
    InProcessLabEnvironment,
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
from stateweaver_lab.models import RetainSessionLabAction

from .network_guard import deny_network_egress

_EVALUATED_AT = datetime(2026, 7, 29, tzinfo=UTC)
_LAB_ACTION = RetainSessionLabAction()


def _action_envelope() -> ActionEnvelope:
    spec = lab_http_action_spec(_LAB_ACTION)
    action_id = "action.runtime.qualification.retain"
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
            body_artifact=lab_action_artifact(_LAB_ACTION),
            identity_handle=spec.identity_handle,
            expected_statuses=spec.expected_statuses,
        ),
        risk_class=RiskClass.REVERSIBLE_STATE_CHANGE,
        idempotency_key=canonical_sha256(
            {"action_id": action_id, "purpose": "runtime-qualification"}
        ),
        requested_by=RequestedBy(
            type=RequesterType.WORKFLOW,
            role="runtime_qualification",
        ),
        policy_decision_ref="decision.runtime.qualification.retain",
        timeout_ms=1_000,
    )


def _policy_request(envelope: ActionEnvelope) -> PolicyRequest:
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
            identities=ScopeIdentities(allowed=("test_user_a",)),
            actions=ScopeActions(allow=(ScopeAction.HTTP_REQUEST,)),
            limits=ScopeLimits(
                requestsPerSecond=10.0,
                concurrentMaterializedWorlds=1,
                maxWriteRequests=4,
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
            requests_in_window=0,
            request_window_seconds=1.0,
            write_requests_used=0,
        ),
        evaluated_at=_EVALUATED_AT,
    )


def _request(envelope: ActionEnvelope) -> RuntimeObservationRequest:
    from stateweaver.adapters.telemetry.opentelemetry import ObservedStatePath

    return RuntimeObservationRequest(
        world_id=envelope.world_id,
        transition_id="transition.runtime.qualification.retain",
        name="retain synthetic old session",
        action_envelope=envelope,
        expected_route="/v1/lab/session/retain",
        observed_paths=(
            ObservedStatePath(
                delta_id="delta.runtime.qualification.evidence-count",
                subject="resource.lab.application",
                capture_path="application.evidence_count",
                state_path="session.evidence_count",
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


async def _execute_runtime_qualification(
    repository_marker: str,
) -> RuntimeObservationQualificationReceipt:
    envelope = _action_envelope()
    policy_request = _policy_request(envelope)
    authorization = PolicyAuthorization.bind(
        envelope,
        policy_request,
        evaluate_policy(policy_request),
    )
    registry = FixedLabActionRegistry(
        by_action_id={envelope.action_id: _LAB_ACTION},
        by_body_artifact={lab_action_artifact(_LAB_ACTION): _LAB_ACTION},
        policy_authorizations={envelope.policy_decision_ref: authorization},
    )
    environment = InProcessLabEnvironment(mode=LabMode.VULNERABLE, registry=registry)
    try:
        await environment.create_root_seed(
            root_seed_id="root.runtime.qualification",
            random_seed=CANONICAL_RANDOM_SEED,
        )
        controller = RuntimeObservationController(environment)
        result = await controller.observe(_request(envelope))
        verified = controller.verify(result.receipt)
        if verified != result.receipt:
            raise RuntimeObservationQualificationError(
                "runtime observation process-local verification failed"
            )
        projection = _projection(repository_marker=repository_marker, result=result)
        return build_runtime_observation_qualification(
            adapter_receipt=verified.model_dump(mode="json"),
            projection=projection,
        )
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
            receipt = await _execute_runtime_qualification(repository_marker)
        return receipt, guard.denied_attempts

    receipt, denied_attempts = asyncio.run(guarded())
    if denied_attempts:
        raise RuntimeObservationQualificationError(
            "runtime observation attempted denied network access"
        )
    return validate_runtime_qualification_against_adapter(receipt)


__all__ = [
    "qualify_runtime_observation",
    "validate_runtime_qualification_against_adapter",
]
