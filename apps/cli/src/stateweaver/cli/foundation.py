"""Typed, deterministic, in-process StateWeaver foundation verification."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from stateweaver.adapters.in_process_lab import (
    CANONICAL_RANDOM_SEED,
    ORACLE_ID,
    FixedLabActionRegistry,
    InProcessLabEnvironment,
    LabAction,
    PolicyAuthorization,
    lab_action_artifact,
    lab_http_action_spec,
)
from stateweaver.contracts import (
    ActionEnvelope,
    ActionTarget,
    EnvironmentMode,
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
    TargetSelector,
)
from stateweaver.policy import BudgetSnapshot, PolicyRequest, evaluate_policy
from stateweaver.replay import (
    DeterminismClassification,
    DeterminismReport,
    OracleExpectation,
    ReplayActionLogEntry,
    ReplayKernel,
    ReplayPlan,
    ReplayRunResult,
    ReplayRunStatus,
    ReplayStep,
    RootSeed,
    canonical_sha256,
)
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
    EvidenceRecordResponse,
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

from .network_guard import NETWORK_GUARD_VERSION, deny_network_egress

_ROOT_SEED_ID: Final = "root.foundation-canonical-v1"
_PLAN_ID: Final = "plan.foundation-canonical-v1"
_WORLD_ID: Final = "world.foundation-canonical-v1"
_EXPERIMENT_ID: Final = "experiment.foundation-canonical-v1"
_EVALUATED_AT: Final = datetime(2026, 1, 1, tzinfo=UTC)
_VULNERABLE_RUN_IDS: Final = tuple(f"run.vulnerable-{index}" for index in range(1, 6))


@dataclass(frozen=True)
class ScenarioResult:
    """A compact public projection of one deterministic replay scenario."""

    name: str
    status: str
    oracle_outcome: str | None
    final_response_status: int | None
    failed_step_id: str | None
    failure_code: str | None
    evidence_count: int
    action_log: tuple[ReplayActionLogEntry, ...]
    action_log_hash: str
    signature: str
    plan: ReplayPlan
    root_seed: RootSeed
    replay_result: ReplayRunResult
    evidence_records: tuple[EvidenceRecordResponse, ...]
    policy_authorizations: tuple[PolicyAuthorization, ...]


@dataclass(frozen=True)
class VerificationReport:
    """Machine-readable foundation acceptance result."""

    accepted: bool
    plan_hash: str
    vulnerable: tuple[ScenarioResult, ...]
    vulnerable_deterministic: bool
    vulnerable_all_runs_succeeded: bool
    patched_uses_identical_plan: bool
    patched: ScenarioResult
    negative_controls: tuple[ScenarioResult, ...]
    canonical_plan: ReplayPlan
    scope_manifest: ScopeManifest

    def to_json(self) -> dict[str, object]:
        vulnerable_reference = self.vulnerable[0]
        all_scenarios = (vulnerable_reference, self.patched, *self.negative_controls)
        decisions: dict[str, object] = {}
        for scenario in all_scenarios:
            for authorization in scenario.policy_authorizations:
                serialized = authorization.model_dump(mode="json")
                previous = decisions.setdefault(authorization.policy_decision_ref, serialized)
                if previous != serialized:
                    raise RuntimeError(
                        "policy decision reference was reused with different content"
                    )
        return {
            "accepted": self.accepted,
            "model_calls": 0,
            "network_mode": "offline-in-process",
            "network_guard": NETWORK_GUARD_VERSION,
            "canonical_plan": self.canonical_plan.model_dump(mode="json"),
            "canonical_action_log": [
                entry.model_dump(mode="json") for entry in vulnerable_reference.action_log
            ],
            "root_state": vulnerable_reference.root_seed.model_dump(mode="json"),
            "scope_manifest": self.scope_manifest.model_dump(mode="json", by_alias=True),
            "policy_decisions": decisions,
            "negative_controls": [_scenario_projection(item) for item in self.negative_controls],
            "patched": {
                "evidence_count": self.patched.evidence_count,
                "action_log_hash": self.patched.action_log_hash,
                "action_log_count": len(self.patched.action_log),
                "failed_step_id": self.patched.failed_step_id,
                "failure_code": self.patched.failure_code,
                "oracle_outcome": self.patched.oracle_outcome,
                "response_status": self.patched.final_response_status,
                "status": self.patched.status,
                "proof": _scenario_projection(self.patched),
            },
            "patched_uses_identical_plan": self.patched_uses_identical_plan,
            "plan_hash": self.plan_hash,
            "vulnerable": {
                "all_runs_succeeded": self.vulnerable_all_runs_succeeded,
                "action_log_hash": vulnerable_reference.action_log_hash,
                "action_log_count": len(vulnerable_reference.action_log),
                "deterministic": self.vulnerable_deterministic,
                "oracle_outcome": vulnerable_reference.oracle_outcome,
                "response_status": vulnerable_reference.final_response_status,
                "run_count": len(self.vulnerable),
                "signature": vulnerable_reference.signature,
                "attempts": [_scenario_projection(item) for item in self.vulnerable],
            },
        }


def _scenario_projection(result: ScenarioResult) -> dict[str, object]:
    """Return the complete redacted proof projection for one replay scenario."""

    final_step = result.replay_result.steps[-1] if result.replay_result.steps else None
    return {
        "action_log_hash": result.action_log_hash,
        "evidence_count": result.evidence_count,
        "evidence_records": [item.model_dump(mode="json") for item in result.evidence_records],
        "failed_step_id": result.failed_step_id,
        "failure_code": result.failure_code,
        "name": result.name,
        "oracle_outcome": result.oracle_outcome,
        "oracle_results": (
            [item.model_dump(mode="json") for item in final_step.oracle_results]
            if final_step is not None
            else []
        ),
        "plan": result.plan.model_dump(mode="json"),
        "replay_result": result.replay_result.model_dump(mode="json"),
        "response_status": result.final_response_status,
        "root_seed": result.root_seed.model_dump(mode="json"),
        "signature": result.signature,
        "status": result.status,
        "terminal_observations": (
            [item.model_dump(mode="json") for item in final_step.observations]
            if final_step is not None
            else []
        ),
    }


def _canonical_lab_actions() -> tuple[LabAction, ...]:
    return (
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
    )


def _read_document(
    actor: FixtureBearer,
    document_id: DocumentId = DocumentId.TENANT_B_PROTECTED,
) -> LabAction:
    return ReadDocumentLabAction(
        actor=actor,
        payload=ReadDocumentRequest(document_id=document_id),
    )


def _scope_manifest() -> ScopeManifest:
    return ScopeManifest(
        metadata=ScopeMetadata(name="foundation-cli"),
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
                maxWriteRequests=32,
            ),
            validity=ScopeValidity(
                notBefore=datetime(2020, 1, 1, tzinfo=UTC),
                expiresAt=datetime(2100, 1, 1, tzinfo=UTC),
            ),
        ),
    )


def _risk_for(action: LabAction) -> RiskClass:
    return (
        RiskClass.PASSIVE
        if lab_http_action_spec(action).method.value == "GET"
        else RiskClass.REVERSIBLE_STATE_CHANGE
    )


def _plan_and_registry(
    *,
    plan_id: str,
    actions: Sequence[LabAction],
    allowed_final_outcomes: frozenset[str],
) -> tuple[ReplayPlan, FixedLabActionRegistry]:
    """Construct fully authorized envelopes and a matching closed action registry."""

    manifest = _scope_manifest()
    envelopes: list[ActionEnvelope] = []
    action_registry: dict[str, LabAction] = {}
    artifact_registry: dict[str, LabAction] = {}
    authorizations: dict[str, PolicyAuthorization] = {}
    write_requests_used = 0
    for sequence, lab_action in enumerate(actions, start=1):
        spec = lab_http_action_spec(lab_action)
        body_artifact = lab_action_artifact(lab_action)
        action_id = f"action.{plan_id.replace('.', '-')}-{sequence:02d}"
        decision_ref = f"policy.{plan_id.replace('.', '-')}-{sequence:02d}"
        envelope = ActionEnvelope(
            action_id=action_id,
            experiment_id=_EXPERIMENT_ID,
            world_id=_WORLD_ID,
            scope_action=ScopeAction.HTTP_REQUEST,
            action=HttpRequestAction(
                method=spec.method,
                target=ActionTarget(scheme="http", host="localhost", port=80, path=spec.path),
                identity_handle=spec.identity_handle,
                body_artifact=body_artifact,
                expected_statuses=spec.expected_statuses,
            ),
            risk_class=_risk_for(lab_action),
            idempotency_key=canonical_sha256(
                {
                    "plan_id": plan_id,
                    "sequence": sequence,
                    "action_type": lab_action.action_type,
                    "body_artifact": body_artifact,
                }
            ),
            requested_by=RequestedBy(type=RequesterType.WORKFLOW, role="foundation_cli"),
            policy_decision_ref=decision_ref,
            sequence=sequence,
            timeout_ms=10_000,
        )
        policy_request = PolicyRequest(
            scope_manifest=manifest,
            action_envelope=envelope,
            budget=BudgetSnapshot(
                requests_in_window=sequence - 1,
                request_window_seconds=1.0,
                write_requests_used=write_requests_used,
            ),
            evaluated_at=_EVALUATED_AT,
        )
        decision = evaluate_policy(policy_request)
        if not decision.allowed:
            raise RuntimeError("foundation policy did not authorize a registered action")
        envelopes.append(envelope)
        action_registry[action_id] = lab_action
        artifact_registry[body_artifact] = lab_action
        authorizations[decision_ref] = PolicyAuthorization.bind(
            envelope,
            policy_request,
            decision,
        )
        if spec.method.value not in {"GET", "HEAD", "OPTIONS"}:
            write_requests_used += 1

    final_step_index = len(envelopes) - 1
    steps = tuple(
        ReplayStep(
            step_id=f"step.{index:02d}",
            action=envelope,
            oracle_expectations=(
                (
                    OracleExpectation(
                        oracle_id=ORACLE_ID,
                        allowed_results=allowed_final_outcomes,
                    ),
                )
                if index == final_step_index
                else ()
            ),
        )
        for index, envelope in enumerate(envelopes, start=0)
    )
    return (
        ReplayPlan(plan_id=plan_id, root_seed_id=_ROOT_SEED_ID, steps=steps),
        FixedLabActionRegistry(
            by_action_id=action_registry,
            by_body_artifact=artifact_registry,
            policy_authorizations=authorizations,
        ),
    )


async def _run_once(
    *,
    name: str,
    mode: LabMode,
    plan: ReplayPlan,
    registry: FixedLabActionRegistry,
    run_id: str,
) -> ScenarioResult:
    environment = InProcessLabEnvironment(mode=mode, registry=registry)
    root = await environment.create_root_seed(
        root_seed_id=_ROOT_SEED_ID,
        random_seed=CANONICAL_RANDOM_SEED,
    )
    kernel = ReplayKernel(environment, {ORACLE_ID: environment.oracle})
    result = await kernel.replay(run_id=run_id, plan=plan, root=root)
    return _scenario_result(
        name,
        result,
        plan=plan,
        root=root,
        evidence_records=environment.evidence_records,
        policy_authorizations=tuple(
            sorted(
                registry.policy_authorizations.values(),
                key=lambda item: item.policy_decision_ref,
            )
        ),
    )


def _scenario_result(
    name: str,
    result: ReplayRunResult,
    *,
    plan: ReplayPlan,
    root: RootSeed,
    evidence_records: tuple[EvidenceRecordResponse, ...],
    policy_authorizations: tuple[PolicyAuthorization, ...],
) -> ScenarioResult:
    final_step = result.steps[-1] if result.steps else None
    oracle_outcome: str | None = None
    response_status: int | None = None
    failure_code: str | None = None
    evidence_count = 0
    if final_step is not None and final_step.oracle_results:
        oracle_outcome = final_step.oracle_results[-1].result.value
    if final_step is not None and final_step.observations:
        value = final_step.observations[-1].payload.get("response_status")
        if isinstance(value, int):
            response_status = value
        evidence_count = sum(len(item.evidence_ids) for item in final_step.observations)
    if final_step is not None:
        failure_code = final_step.failure_code
    return ScenarioResult(
        name=name,
        status=result.status.value,
        oracle_outcome=oracle_outcome,
        final_response_status=response_status,
        failed_step_id=result.failed_step_id,
        failure_code=failure_code,
        evidence_count=evidence_count,
        action_log=result.action_log,
        action_log_hash=canonical_sha256(result.action_log),
        signature=result.deterministic_signature(),
        plan=plan,
        root_seed=root,
        replay_result=result,
        evidence_records=evidence_records,
        policy_authorizations=policy_authorizations,
    )


async def _run_many(
    *,
    name: str,
    mode: LabMode,
    plan: ReplayPlan,
    registry: FixedLabActionRegistry,
    run_ids: Iterable[str],
) -> tuple[ScenarioResult, ...]:
    results: list[ScenarioResult] = []
    for run_id in run_ids:
        results.append(
            await _run_once(name=name, mode=mode, plan=plan, registry=registry, run_id=run_id)
        )
    return tuple(results)


def _verify_recorded_vulnerable_determinism(
    runs: tuple[ScenarioResult, ...],
) -> tuple[bool, bool]:
    """Gate on the exact five attempts retained in the proof output."""

    signatures = tuple(run.signature for run in runs)
    statuses = tuple(run.replay_result.status for run in runs)
    reference = signatures[0]
    divergent_index = next(
        (index for index, signature in enumerate(signatures) if signature != reference), None
    )
    report = DeterminismReport(
        plan_id=runs[0].plan.plan_id,
        run_ids=tuple(run.replay_result.run_id for run in runs),
        run_statuses=statuses,
        signatures=signatures,
        deterministic=divergent_index is None,
        all_runs_succeeded=all(status is ReplayRunStatus.SUCCEEDED for status in statuses),
        classification=(
            DeterminismClassification.DETERMINISTIC
            if divergent_index is None
            else DeterminismClassification.NONDETERMINISTIC
        ),
        divergent_run_id=(
            None if divergent_index is None else runs[divergent_index].replay_result.run_id
        ),
    )
    return report.deterministic, report.all_runs_succeeded


def _negative_control_actions() -> tuple[
    tuple[str, tuple[LabAction, ...], OracleOutcome, int], ...
]:
    setup = _canonical_lab_actions()
    old_reader = _read_document(FixtureBearer.TENANT_A_OLD_EDITOR)
    missing_prerequisites = tuple(
        (
            f"missing_prerequisite_{index}",
            setup[:index] + setup[index + 1 :] + (old_reader,),
            OracleOutcome.SATISFIED,
            403,
        )
        # Omitting role downgrade or reference publication makes a later registered setup action
        # fail before the read. The adapter correctly permits only its fixed 200-status actions,
        # so those two dependency-invalid cases remain covered by the lab package rather than
        # pretending they are successful replays here.
        for index in (0, 1, 3, 5, 6)
    )
    # The two decoys are explicit registered action variants, not arbitrary routes.
    from stateweaver_lab.models import MaskedReadLabAction, MockPolicyLabAction

    return (
        *missing_prerequisites,
        (
            "expired_replay_window",
            (
                *setup[:-1],
                AdvanceClockLabAction(payload=AdvanceClockRequest(seconds=181)),
                old_reader,
            ),
            OracleOutcome.SATISFIED,
            403,
        ),
        (
            "masked_response",
            (
                MaskedReadLabAction(
                    actor=FixtureBearer.TENANT_A_OLD_EDITOR,
                    payload=ReadDocumentRequest(document_id=DocumentId.TENANT_B_PROTECTED),
                ),
            ),
            OracleOutcome.SATISFIED,
            200,
        ),
        (
            "mock_only_response",
            (
                MockPolicyLabAction(
                    actor=FixtureBearer.TENANT_A_OLD_EDITOR,
                    payload=ReadDocumentRequest(document_id=DocumentId.TENANT_B_PROTECTED),
                ),
            ),
            OracleOutcome.INCONCLUSIVE,
            200,
        ),
        (
            "fresh_session",
            (*setup, _read_document(FixtureBearer.TENANT_A_FRESH_VIEWER)),
            OracleOutcome.SATISFIED,
            403,
        ),
        (
            "same_tenant_document",
            (_read_document(FixtureBearer.TENANT_A_OLD_EDITOR, DocumentId.TENANT_A_OWNED),),
            OracleOutcome.SATISFIED,
            200,
        ),
    )


async def _verify_foundation() -> VerificationReport:
    canonical_plan, canonical_registry = _plan_and_registry(
        plan_id=_PLAN_ID,
        actions=(*_canonical_lab_actions(), _read_document(FixtureBearer.TENANT_A_OLD_EDITOR)),
        allowed_final_outcomes=frozenset({OracleOutcome.VIOLATED.value}),
    )
    vulnerable = await _run_many(
        name="canonical_vulnerable",
        mode=LabMode.VULNERABLE,
        plan=canonical_plan,
        registry=canonical_registry,
        run_ids=_VULNERABLE_RUN_IDS,
    )
    deterministic, all_runs_succeeded = _verify_recorded_vulnerable_determinism(vulnerable)
    # Reconstructing this registry is deliberate: the plan is byte-for-byte identical but each
    # environment receives its own immutable registry and its own patched clean root.
    patched_plan, patched_registry = _plan_and_registry(
        plan_id=_PLAN_ID,
        actions=(*_canonical_lab_actions(), _read_document(FixtureBearer.TENANT_A_OLD_EDITOR)),
        allowed_final_outcomes=frozenset({OracleOutcome.VIOLATED.value}),
    )
    patched = await _run_once(
        name="canonical_patched",
        mode=LabMode.PATCHED,
        plan=patched_plan,
        registry=patched_registry,
        run_id="run.patched-1",
    )
    patched_uses_identical_plan = canonical_sha256(canonical_plan) == canonical_sha256(patched_plan)
    negative_controls: list[ScenarioResult] = []
    control_expectations: dict[str, tuple[OracleOutcome, int]] = {}
    for name, actions, expected_outcome, expected_status in _negative_control_actions():
        control_expectations[name] = (expected_outcome, expected_status)
        plan, registry = _plan_and_registry(
            plan_id=f"plan.control-{name}",
            actions=actions,
            allowed_final_outcomes=frozenset({expected_outcome.value}),
        )
        negative_controls.append(
            await _run_once(
                name=name,
                mode=LabMode.VULNERABLE,
                plan=plan,
                registry=registry,
                run_id=f"run.control-{name}",
            )
        )

    vulnerable_accepted = all(
        run.status == ReplayRunStatus.SUCCEEDED.value
        and run.oracle_outcome == OracleOutcome.VIOLATED.value
        and run.final_response_status == 200
        for run in vulnerable
    )
    patched_accepted = (
        patched.status == ReplayRunStatus.FAILED.value
        and patched.oracle_outcome == OracleOutcome.SATISFIED.value
        and patched.final_response_status == 403
        and patched.failed_step_id == "step.07"
        and patched.failure_code == "ORACLE_EXPECTATION_MISMATCH"
        and patched.evidence_count == 1
    )
    controls_accepted = all(
        item.status == ReplayRunStatus.SUCCEEDED.value
        and item.oracle_outcome == control_expectations[item.name][0].value
        and item.final_response_status == control_expectations[item.name][1]
        for item in negative_controls
    )
    return VerificationReport(
        accepted=(
            deterministic
            and all_runs_succeeded
            and patched_uses_identical_plan
            and vulnerable_accepted
            and patched_accepted
            and controls_accepted
        ),
        plan_hash=canonical_sha256(canonical_plan),
        vulnerable=vulnerable,
        vulnerable_deterministic=deterministic,
        vulnerable_all_runs_succeeded=all_runs_succeeded,
        patched_uses_identical_plan=patched_uses_identical_plan,
        patched=patched,
        negative_controls=tuple(negative_controls),
        canonical_plan=canonical_plan,
        scope_manifest=_scope_manifest(),
    )


def verify_foundation() -> VerificationReport:
    """Verify the deterministic local foundation without opening a socket or process."""

    async def guarded_verification() -> tuple[VerificationReport, int]:
        # The event loop creates its internal wakeup socket before this coroutine starts.
        with deny_network_egress() as guard:
            report = await _verify_foundation()
        return report, guard.denied_attempts

    report, denied_attempts = asyncio.run(guarded_verification())
    if denied_attempts:
        raise RuntimeError("foundation attempted denied network access")
    return report
