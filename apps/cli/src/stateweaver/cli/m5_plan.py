"""The sole deterministic compiler for the M5 execution and control plans.

This module deliberately compiles plans only.  It does not create roots, open an
environment, execute an action, or evaluate an oracle.  Both the process runner
and a materialized runner therefore receive identical action, scope, and policy
authorization bytes from this boundary.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict, model_validator
from stateweaver.adapters.in_process_lab import (
    ORACLE_ID,
    FixedLabActionRegistry,
    LabAction,
    lab_action_artifact,
    lab_http_action_spec,
)
from stateweaver.compiler import CompilerFragment, TerminalGoal
from stateweaver.compiler.models import FragmentBinding
from stateweaver.contracts import (
    ActionEnvelope,
    ActionGuard,
    ActionTarget,
    EnvironmentMode,
    ExpectedEffect,
    HttpRequestAction,
    OracleOutcome,
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
    Sha256Digest,
    TargetSelector,
    sha256_digest,
)
from stateweaver.policy import BudgetSnapshot, PolicyAuthorization, PolicyRequest, evaluate_policy
from stateweaver.replay import OracleExpectation, ReplayPlan, ReplayStep
from stateweaver.workflows.world import ObservedChainAdmission, compile_observed_promotion

from .materialized_search_qualification import MaterializedSearchQualificationReceipt
from .runtime_qualification import OBSERVED_CHAIN_LENGTH, OBSERVED_LAB_ACTIONS

M5_PLAN_ID = "plan.m5.clean-root"
M5_EVALUATED_AT = datetime(2026, 7, 29, tzinfo=UTC)

type M5ControlName = Literal[
    "masked_response",
    "mock_only_response",
    "fresh_session",
    "same_tenant_document",
]


class M5PlanError(ValueError):
    """The validated M4 input cannot produce the fixed M5 plan."""


class _M5PlanModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)


class M5ControlPlan(_M5PlanModel):
    """One exact, independently authorized M5 negative-control plan."""

    name: M5ControlName
    expected_outcome: OracleOutcome
    expected_status: int
    replay_plan: ReplayPlan
    policy_authorizations: tuple[PolicyAuthorization, ...]
    registry: FixedLabActionRegistry

    @model_validator(mode="after")
    def _content_is_bound(self) -> M5ControlPlan:
        _validate_plan_registry(self.replay_plan, self.policy_authorizations, self.registry)
        expected_boundaries: dict[M5ControlName, tuple[OracleOutcome, int]] = {
            "masked_response": (OracleOutcome.SATISFIED, 200),
            "mock_only_response": (OracleOutcome.INCONCLUSIVE, 200),
            "fresh_session": (OracleOutcome.SATISFIED, 403),
            "same_tenant_document": (OracleOutcome.SATISFIED, 200),
        }
        if (
            self.replay_plan.plan_id != f"plan.m5.control-{self.name}"
            or self.replay_plan.root_seed_id != f"root.m5.control-{self.name}"
            or len(self.replay_plan.steps) < 1
            or (self.expected_outcome, self.expected_status) != expected_boundaries[self.name]
        ):
            raise ValueError("M5 control plan is not canonically bound")
        return self


class M5ExecutionPlan(_M5PlanModel):
    """Frozen M5 input shared by every process or materialized execution path."""

    m4_receipt_digest: Sha256Digest
    observed_chain_digest: Sha256Digest
    compiler_admission: ObservedChainAdmission
    scope_manifest: ScopeManifest
    replay_plan: ReplayPlan
    policy_authorizations: tuple[PolicyAuthorization, ...]
    registry: FixedLabActionRegistry
    negative_controls: tuple[M5ControlPlan, ...]

    @model_validator(mode="after")
    def _content_is_bound(self) -> M5ExecutionPlan:
        admission = self.compiler_admission
        if (
            self.m4_receipt_digest == ""
            or self.observed_chain_digest == ""
            or self.replay_plan.plan_id != M5_PLAN_ID
            or self.replay_plan.root_seed_id != admission.compiled_chain.root_seed_id
            or self.scope_manifest.metadata.name != "m5-clean-root"
            or not _fresh_plan_matches_admission(self.replay_plan, admission)
        ):
            raise ValueError("M5 execution plan is not bound to the admitted M4 chain")
        _validate_plan_registry(self.replay_plan, self.policy_authorizations, self.registry)
        expected_controls: tuple[M5ControlName, ...] = (
            "masked_response",
            "mock_only_response",
            "fresh_session",
            "same_tenant_document",
        )
        if tuple(item.name for item in self.negative_controls) != expected_controls:
            raise ValueError("M5 control plans are incomplete or reordered")
        return self


def m5_scope() -> ScopeManifest:
    """Return the sole M5 policy scope, retained verbatim in every plan build."""

    return ScopeManifest(
        metadata=ScopeMetadata(name="m5-clean-root"),
        spec=ScopeSpec(
            environmentMode=EnvironmentMode.SOURCE_BACKED,
            targets=ScopeTargets(
                include=(TargetSelector(host="localhost", ports=(80,), paths=("/v1/lab/**",)),)
            ),
            identities=ScopeIdentities(allowed=("test_user_a", "test_user_b", "test_admin")),
            actions=ScopeActions(allow=(ScopeAction.HTTP_REQUEST,)),
            limits=ScopeLimits(
                requestsPerSecond=100.0,
                concurrentMaterializedWorlds=1,
                maxWriteRequests=8,
            ),
            validity=ScopeValidity(
                notBefore=datetime(2020, 1, 1, tzinfo=UTC),
                expiresAt=datetime(2100, 1, 1, tzinfo=UTC),
            ),
        ),
    )


def compile_m5_plan(m4: MaterializedSearchQualificationReceipt) -> M5ExecutionPlan:
    """Compile the only accepted M5 replay and control plans from validated M4 input."""

    try:
        closed_m4 = MaterializedSearchQualificationReceipt.model_validate(
            m4.model_dump(mode="python")
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise M5PlanError("M5 input is not a validated M4 receipt") from error
    admission = _compiler_admission(closed_m4)
    scope = m5_scope()
    replay_plan, policy_authorizations, registry = _fresh_plan(admission, scope=scope)
    controls = _compile_negative_controls(scope=scope)
    return M5ExecutionPlan(
        m4_receipt_digest=closed_m4.receipt_digest,
        observed_chain_digest=closed_m4.observed_chain_digest,
        compiler_admission=admission,
        scope_manifest=scope,
        replay_plan=replay_plan,
        policy_authorizations=policy_authorizations,
        registry=registry,
        negative_controls=controls,
    )


def _compiler_admission(m4: MaterializedSearchQualificationReceipt) -> ObservedChainAdmission:
    allocation_id = m4.stages[-1].promotions[0].allocation.allocation_id
    fragments: list[CompilerFragment] = []
    previous: str | None = None
    for qualification in m4.observed_chain:
        fragment = qualification.projection.transition_fragment
        source_envelope = qualification.projection.action_envelope
        action = source_envelope.model_copy(
            update={
                "world_id": allocation_id,
                "policy_decision_ref": m4.winner.gates.policy_decision_ref,
                "preconditions": tuple(
                    ActionGuard(path=item.path, expected=item.value)
                    for item in fragment.preconditions
                ),
                "expected_effects": tuple(
                    ExpectedEffect(path=item.path, operation=item.operation, value=item.value)
                    for item in fragment.effects
                ),
            }
        )
        typed = action.action
        if not isinstance(typed, HttpRequestAction):
            raise M5PlanError("M5 observed action is not HTTP")
        fragments.append(
            CompilerFragment(
                fragment=fragment,
                envelope=action,
                world_id=allocation_id,
                binding=FragmentBinding(
                    identity_handle=typed.identity_handle,
                    artifact_handle=typed.body_artifact,
                ),
                after=() if previous is None else (previous,),
            )
        )
        previous = fragment.transition_id
    goal = TerminalGoal(
        goal_id="goal.m5.observed-chain",
        conditions=tuple(
            condition
            for qualification in m4.observed_chain
            for condition in qualification.projection.transition_fragment.observables
        ),
    )
    return compile_observed_promotion(
        batch=m4.stages[-1].search_batch,
        workflow=m4.stages[-1],
        candidate_id=m4.winner.candidate_id,
        chain_id="chain.m5.observed-clean-root",
        fragments=fragments,
        goal=goal,
    )


def _fresh_plan(
    admission: ObservedChainAdmission,
    *,
    scope: ScopeManifest | None = None,
) -> tuple[ReplayPlan, tuple[PolicyAuthorization, ...], FixedLabActionRegistry]:
    """Reauthorize the admitted actions without altering their compiled semantics."""

    compiled = admission.compiled_chain
    candidate = ReplayPlan(
        plan_id=M5_PLAN_ID,
        root_seed_id=compiled.root_seed_id,
        steps=tuple(
            ReplayStep(
                step_id=f"step.{index:02d}",
                action=action,
                oracle_expectations=(
                    (
                        OracleExpectation(
                            oracle_id=ORACLE_ID,
                            allowed_results=frozenset({OracleOutcome.VIOLATED.value}),
                        ),
                    )
                    if index == len(compiled.action_envelopes)
                    else ()
                ),
                timeout_seconds=action.timeout_ms / 1_000,
            )
            for index, action in enumerate(compiled.action_envelopes, start=1)
        ),
    )
    return _authorize_existing_plan(
        candidate,
        lab_actions=OBSERVED_LAB_ACTIONS,
        scope=m5_scope() if scope is None else scope,
    )


def _authorize_existing_plan(
    candidate: ReplayPlan,
    *,
    lab_actions: tuple[LabAction, ...],
    scope: ScopeManifest,
) -> tuple[ReplayPlan, tuple[PolicyAuthorization, ...], FixedLabActionRegistry]:
    actions: list[ActionEnvelope] = []
    authorizations: dict[str, PolicyAuthorization] = {}
    write_requests_used = 0
    for index, step in enumerate(candidate.steps, start=1):
        decision_ref = f"policy.{candidate.plan_id.removeprefix('plan.')}-{index:02d}"
        action = step.action.model_copy(
            update={
                "policy_decision_ref": decision_ref,
                "requested_by": RequestedBy(
                    type=RequesterType.WORKFLOW,
                    role="m5_clean_root",
                ),
                "sequence": index,
            }
        )
        request = PolicyRequest(
            scope_manifest=scope,
            action_envelope=action,
            budget=BudgetSnapshot(
                requests_in_window=index - 1,
                request_window_seconds=1.0,
                write_requests_used=write_requests_used,
            ),
            evaluated_at=M5_EVALUATED_AT,
        )
        decision = evaluate_policy(request)
        if not decision.allowed:
            raise M5PlanError("fresh M5 policy did not allow the plan")
        actions.append(action)
        authorizations[decision_ref] = PolicyAuthorization.bind(action, request, decision)
        typed_action = action.action
        if not isinstance(typed_action, HttpRequestAction) or typed_action.method is None:
            raise M5PlanError("fresh M5 action is not concrete HTTP")
        if typed_action.method.value not in {"GET", "HEAD", "OPTIONS"}:
            write_requests_used += 1
    plan = ReplayPlan(
        plan_id=candidate.plan_id,
        root_seed_id=candidate.root_seed_id,
        steps=tuple(
            ReplayStep(
                step_id=step.step_id,
                action=action,
                oracle_expectations=step.oracle_expectations,
                timeout_seconds=action.timeout_ms / 1_000,
            )
            for step, action in zip(candidate.steps, actions, strict=True)
        ),
    )
    registry = FixedLabActionRegistry(
        by_action_id={
            action.action_id: lab for action, lab in zip(actions, lab_actions, strict=True)
        },
        by_body_artifact={lab_action_artifact(item): item for item in lab_actions},
        policy_authorizations=authorizations,
    )
    ordered = tuple(authorizations[step.action.policy_decision_ref] for step in plan.steps)
    return plan, ordered, registry


def _compile_negative_controls(*, scope: ScopeManifest) -> tuple[M5ControlPlan, ...]:
    from .foundation import _negative_control_actions

    selected = {
        name: (actions, expected_outcome, expected_status)
        for name, actions, expected_outcome, expected_status in _negative_control_actions()
        if name
        in {
            "masked_response",
            "mock_only_response",
            "fresh_session",
            "same_tenant_document",
        }
    }
    ordered_names: tuple[M5ControlName, ...] = (
        "masked_response",
        "mock_only_response",
        "fresh_session",
        "same_tenant_document",
    )
    if tuple(name for name in ordered_names if name in selected) != ordered_names:
        raise M5PlanError("M5 negative-control set is incomplete")
    controls: list[M5ControlPlan] = []
    for name in ordered_names:
        actions, expected_outcome, expected_status = selected[name]
        plan, authorizations, registry = _build_control_plan(
            name=name,
            actions=actions,
            allowed_final_outcomes=frozenset({expected_outcome.value}),
            scope=scope,
        )
        controls.append(
            M5ControlPlan(
                name=name,
                expected_outcome=expected_outcome,
                expected_status=expected_status,
                replay_plan=plan,
                policy_authorizations=authorizations,
                registry=registry,
            )
        )
    return tuple(controls)


def _build_control_plan(
    *,
    name: M5ControlName,
    actions: tuple[LabAction, ...],
    allowed_final_outcomes: frozenset[str],
    scope: ScopeManifest,
) -> tuple[ReplayPlan, tuple[PolicyAuthorization, ...], FixedLabActionRegistry]:
    plan_id = f"plan.m5.control-{name}"
    candidate_actions: list[ActionEnvelope] = []
    for sequence, lab_action in enumerate(actions, start=1):
        spec = lab_http_action_spec(lab_action)
        body_artifact = lab_action_artifact(lab_action)
        candidate_actions.append(
            ActionEnvelope(
                action_id=(
                    f"action.{plan_id.removeprefix('plan.').replace('.', '-')}-{sequence:02d}"
                ),
                experiment_id="experiment.m5.clean-root",
                world_id=f"world.m5.control-{name}",
                scope_action=ScopeAction.HTTP_REQUEST,
                action=HttpRequestAction(
                    method=spec.method,
                    target=ActionTarget(scheme="http", host="localhost", port=80, path=spec.path),
                    identity_handle=spec.identity_handle,
                    body_artifact=body_artifact,
                    expected_statuses=spec.expected_statuses,
                ),
                risk_class=(
                    RiskClass.PASSIVE
                    if spec.method.value == "GET"
                    else RiskClass.REVERSIBLE_STATE_CHANGE
                ),
                idempotency_key=sha256_digest(
                    {
                        "m5_control": name,
                        "sequence": sequence,
                        "lab_action": lab_action,
                        "body_artifact": body_artifact,
                    }
                ),
                requested_by=RequestedBy(type=RequesterType.WORKFLOW, role="m5_clean_root"),
                policy_decision_ref=f"policy.{plan_id.removeprefix('plan.')}-{sequence:02d}",
                sequence=sequence,
                timeout_ms=10_000,
            )
        )
    candidate = ReplayPlan(
        plan_id=plan_id,
        root_seed_id=f"root.m5.control-{name}",
        steps=tuple(
            ReplayStep(
                step_id=f"step.{index:02d}",
                action=action,
                oracle_expectations=(
                    (
                        OracleExpectation(
                            oracle_id=ORACLE_ID,
                            allowed_results=allowed_final_outcomes,
                        ),
                    )
                    if index == len(candidate_actions)
                    else ()
                ),
                timeout_seconds=action.timeout_ms / 1_000,
            )
            for index, action in enumerate(candidate_actions, start=1)
        ),
    )
    return _authorize_control_plan(candidate, actions=actions, scope=scope)


def _authorize_control_plan(
    candidate: ReplayPlan,
    *,
    actions: tuple[LabAction, ...],
    scope: ScopeManifest,
) -> tuple[ReplayPlan, tuple[PolicyAuthorization, ...], FixedLabActionRegistry]:
    return _authorize_existing_plan(
        candidate,
        lab_actions=actions,
        scope=scope,
    )


def _validate_plan_registry(
    plan: ReplayPlan,
    authorizations: tuple[PolicyAuthorization, ...],
    registry: FixedLabActionRegistry,
) -> None:
    if len(plan.steps) != len(authorizations):
        raise ValueError("M5 plan does not retain one policy authorization per action")
    if tuple(item.action_id for item in authorizations) != tuple(
        item.action.action_id for item in plan.steps
    ):
        raise ValueError("M5 policy authorization action binding is invalid")
    if tuple(item.policy_decision_ref for item in authorizations) != tuple(
        item.action.policy_decision_ref for item in plan.steps
    ):
        raise ValueError("M5 policy authorization ordering is invalid")
    if len({item.idempotency_key for item in authorizations}) != len(authorizations):
        raise ValueError("M5 policy authorization idempotency keys are not unique")
    if tuple(registry.by_action_id) != tuple(item.action.action_id for item in plan.steps):
        raise ValueError("M5 registry action ordering is invalid")
    if tuple(registry.policy_authorizations) != tuple(
        item.policy_decision_ref for item in authorizations
    ):
        raise ValueError("M5 registry policy authorization binding is invalid")
    for step, authorization in zip(plan.steps, authorizations, strict=True):
        if (
            authorization.action_id != step.action.action_id
            or authorization.idempotency_key != step.action.idempotency_key
            or authorization.envelope_hash != sha256_digest(step.action)
            or registry.policy_authorizations.get(step.action.policy_decision_ref) != authorization
            or step.action.action_id not in registry.by_action_id
        ):
            raise ValueError("M5 plan registry content binding is invalid")


def _fresh_plan_matches_admission(plan: ReplayPlan, admission: ObservedChainAdmission) -> bool:
    compiled = admission.compiled_chain
    if len(plan.steps) != OBSERVED_CHAIN_LENGTH or len(plan.steps) != len(
        compiled.action_envelopes
    ):
        return False
    for step, source in zip(plan.steps, compiled.action_envelopes, strict=True):
        action = step.action
        if (
            action.action_id != source.action_id
            or action.experiment_id != source.experiment_id
            or action.world_id != source.world_id
            or action.scope_action is not source.scope_action
            or action.action != source.action
            or action.risk_class is not source.risk_class
            or action.idempotency_key != source.idempotency_key
            or action.preconditions != source.preconditions
            or action.expected_effects != source.expected_effects
            or action.timeout_ms != source.timeout_ms
        ):
            return False
    final_expectations = plan.steps[-1].oracle_expectations
    return (
        len(final_expectations) == 1
        and final_expectations[0].oracle_id == ORACLE_ID
        and final_expectations[0].allowed_results == frozenset({OracleOutcome.VIOLATED.value})
        and all(not item.oracle_expectations for item in plan.steps[:-1])
    )


__all__ = [
    "M5_EVALUATED_AT",
    "M5_PLAN_ID",
    "M5ControlName",
    "M5ControlPlan",
    "M5ExecutionPlan",
    "M5PlanError",
    "compile_m5_plan",
    "m5_scope",
]
