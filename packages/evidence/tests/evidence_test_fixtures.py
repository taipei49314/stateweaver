"""Unique, synthetic fixtures for acceptance-evidence tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from pydantic import JsonValue
from stateweaver.contracts import (
    ActionEnvelope,
    ActionTarget,
    EnvironmentMode,
    HttpMethod,
    HttpRequestAction,
    OracleOutcome,
    OracleResult,
    OracleType,
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
    CaptureLayer,
    OracleExpectation,
    ReplayActionLogEntry,
    ReplayObservation,
    ReplayPlan,
    ReplayRunResult,
    ReplayRunStatus,
    ReplayStep,
    ReplayStepResult,
    ReplayStepStatus,
    RootSeed,
    StateArtifact,
    StateCapture,
    canonical_sha256,
)

EPOCH = datetime(2026, 1, 1, tzinfo=UTC)


def scope() -> ScopeManifest:
    return ScopeManifest(
        metadata=ScopeMetadata(name="evidence-fixture"),
        spec=ScopeSpec(
            environmentMode=EnvironmentMode.SOURCE_BACKED,
            targets=ScopeTargets(
                include=(TargetSelector(host="localhost", ports=(80,), paths=("/**",)),)
            ),
            identities=ScopeIdentities(allowed=("test_user_a",)),
            actions=ScopeActions(allow=(ScopeAction.HTTP_REQUEST,)),
            limits=ScopeLimits(
                requestsPerSecond=10.0,
                concurrentMaterializedWorlds=1,
                maxWriteRequests=10,
            ),
            validity=ScopeValidity(
                notBefore=EPOCH - timedelta(days=1),
                expiresAt=EPOCH + timedelta(days=1),
            ),
        ),
    )


def _capture(tick: int) -> StateCapture:
    controlled_at = EPOCH + timedelta(seconds=tick)
    artifact = StateArtifact.from_payload(
        layer=CaptureLayer.APPLICATION,
        payload={"mode": "synthetic", "tick": tick},
    )
    return StateCapture.from_artifacts(
        capture_id=f"capture.{tick}",
        controlled_at=controlled_at,
        artifacts=(artifact,),
    )


def _layered_root_capture(mode: str) -> StateCapture:
    sessions: list[JsonValue] = [
        {
            "session_handle": handle,
            "principal_id": principal,
            "issued_role": role,
            "session_generation": 1,
            "issued_at": "2025-12-31T23:55:00Z",
            "expires_at": "2026-01-01T01:00:00Z",
            "identity_hash": canonical_sha256({"identity": principal, "fixture": handle}),
        }
        for handle, principal, role in (
            ("session-a-old", "principal-a", "editor"),
            ("session-b-viewer", "principal-b", "viewer"),
            ("session-lab-admin", "principal-admin", "admin"),
        )
    ]
    artifacts = (
        StateArtifact.from_payload(
            layer=CaptureLayer.APPLICATION,
            payload={
                "evidence_count": 0,
                "reference_claimed_by_session_handle": None,
                "reference_id": "ref-b-to-a",
                "reference_published": False,
                "replay_window_closes_at": None,
                "replay_window_opens_at": None,
                "retained_session_handles": [],
                "role_downgraded_at": None,
                "source_state_fingerprint": canonical_sha256(
                    {"fixture": "layered-root", "mode": mode}
                ),
            },
        ),
        StateArtifact.from_payload(
            layer=CaptureLayer.DATABASE,
            payload={
                "document_ownership": [
                    {"document_id": "doc-a-owned", "tenant_id": "tenant-a"},
                    {"document_id": "doc-b-protected", "tenant_id": "tenant-b"},
                ],
                "policy_generation": 1,
                "principals": [
                    {
                        "principal_id": "principal-a",
                        "role": "editor",
                        "tenant_id": "tenant-a",
                    },
                    {
                        "principal_id": "principal-admin",
                        "role": "admin",
                        "tenant_id": "platform",
                    },
                    {
                        "principal_id": "principal-b",
                        "role": "viewer",
                        "tenant_id": "tenant-b",
                    },
                ],
            },
        ),
        StateArtifact.from_payload(layer=CaptureLayer.CACHE, payload={"entry": None}),
        StateArtifact.from_payload(layer=CaptureLayer.QUEUE, payload={"entry": None}),
        StateArtifact.from_payload(
            layer=CaptureLayer.BROWSER,
            payload={"sessions": sessions},
        ),
        StateArtifact.from_payload(
            layer=CaptureLayer.CONFIGURATION,
            payload={
                "arbitrary_actions_enabled": False,
                "external_egress_enabled": False,
                "mode": mode,
                "network_scope": "in-process-only",
                "seed": "m0-canonical-v1",
            },
        ),
        StateArtifact.from_payload(
            layer=CaptureLayer.CLOCK,
            payload={
                "epoch": "2026-01-01T00:00:00Z",
                "mode": "controlled",
                "now": "2026-01-01T00:00:00Z",
            },
        ),
    )
    return StateCapture.from_artifacts(
        capture_id=f"capture.root.{mode}",
        controlled_at=EPOCH,
        artifacts=artifacts,
    )


def root(*, target_version: str = "lab-vulnerable", layered: bool = False) -> RootSeed:
    mode = "patched" if target_version == "lab-patched" else "vulnerable"
    capture = _layered_root_capture(mode) if layered else _capture(0)
    return RootSeed(
        root_seed_id="root.evidence",
        target_version=target_version,
        random_seed=7,
        clock_epoch=EPOCH,
        capture=capture,
        adapter_versions={"fixture": "1.0.0"},
    )


def plan(
    *,
    plan_id: str = "plan.evidence",
    action_id: str = "action.evidence",
    decision_ref: str = "policy.evidence",
    outcome: OracleOutcome = OracleOutcome.VIOLATED,
    path: str = "/v1/lab/documents/doc-b-protected",
    expected_statuses: tuple[int, ...] = (200, 403),
) -> ReplayPlan:
    envelope = ActionEnvelope(
        action_id=action_id,
        experiment_id="experiment.evidence",
        world_id="world.evidence",
        scope_action=ScopeAction.HTTP_REQUEST,
        action=HttpRequestAction(
            method=HttpMethod.GET,
            target=ActionTarget(
                scheme="http",
                host="localhost",
                port=80,
                path=path,
            ),
            identity_handle="identity:test_user_a",
            expected_statuses=expected_statuses,
        ),
        risk_class=RiskClass.READ_ONLY,
        idempotency_key=canonical_sha256({"action_id": action_id}),
        requested_by=RequestedBy(type=RequesterType.WORKFLOW, role="evidence_fixture"),
        policy_decision_ref=decision_ref,
        sequence=1,
    )
    return ReplayPlan(
        plan_id=plan_id,
        root_seed_id="root.evidence",
        steps=(
            ReplayStep(
                step_id="step.00",
                action=envelope,
                oracle_expectations=(
                    OracleExpectation(
                        oracle_id="oracle.evidence",
                        allowed_results=frozenset({outcome.value}),
                    ),
                ),
            ),
        ),
    )


def scenario(
    *,
    name: str,
    run_id: str,
    replay_plan: ReplayPlan,
    root_seed: RootSeed,
    oracle_outcome: OracleOutcome,
    response_status: int,
    failed: bool = False,
) -> dict[str, object]:
    before = root_seed.capture
    after = _capture(1)
    evidence_id = "ev.synthetic.001"
    mode = "patched" if root_seed.target_version == "lab-patched" else "vulnerable"
    action_type = "document.read"
    observation_kind = "lab.document.read"
    actor_principal_id = "principal-a"
    owner_tenant = "tenant-b"
    resource_id = "doc-b-protected"
    protected_field_present = oracle_outcome is OracleOutcome.VIOLATED
    provenance = "OBSERVED"
    outcome = "tenant_boundary_blocked"
    if oracle_outcome is OracleOutcome.VIOLATED:
        outcome = "cross_tenant_document_disclosed"
        protected_field_present = True
    elif name == "masked_response":
        action_type = "decoy.masked_read"
        observation_kind = "lab.decoy.masked_read"
        outcome = "masked_200"
        protected_field_present = False
    elif name == "mock_only_response":
        action_type = "decoy.mock_policy"
        observation_kind = "lab.decoy.mock_policy"
        outcome = "simulated_allow_only"
        protected_field_present = False
        provenance = "MOCKED"
    elif name == "same_tenant_document":
        actor_principal_id = "principal-a"
        owner_tenant = "tenant-a"
        resource_id = "doc-a-owned"
        outcome = "same_tenant_allowed"
        protected_field_present = True
    evidence_record = {
        "action_type": action_type,
        "actor_principal_id": actor_principal_id,
        "at": "2026-01-01T00:00:01Z",
        "evidence_id": evidence_id,
        "outcome": outcome,
        "provenance": provenance,
        "resource_id": resource_id,
    }
    observation = ReplayObservation(
        observation_id="observation.synthetic.001",
        kind=observation_kind,
        payload={
            "action_type": action_type,
            "outcome": outcome,
            "resource_id": resource_id,
            "controlled_at": "2026-01-01T00:00:01Z",
            "actor_principal_id": actor_principal_id,
            "evidence_record_hash": canonical_sha256(evidence_record),
            "owner_tenant": owner_tenant,
            "protected_field_present": protected_field_present,
            "provenance": provenance,
            "response_status": response_status,
        },
        evidence_ids=(evidence_id,),
    )
    checks: list[JsonValue] = [
        {"check_id": check_id, "passed": oracle_outcome is OracleOutcome.VIOLATED}
        for check_id in (
            "runtime_response_status_is_200",
            "requester_and_owner_tenants_differ",
            "protected_document_id_matches",
            "synthetic_protected_marker_matches_exactly",
            "evidence_provenance_is_observed",
        )
    ]
    observed: dict[str, JsonValue] = {
        "after_fingerprint": after.fingerprint,
        "checks": checks,
        "mode": mode,
        "observation_ids": [observation.observation_id],
        "verdict": "VIOLATED" if oracle_outcome is OracleOutcome.VIOLATED else "NOT_VIOLATED",
    }
    oracle_result_id = (
        "oracle.result:"
        + canonical_sha256(
            {
                "oracle_id": "oracle.cross_tenant_document_disclosure.v1",
                "version": "1.0",
                "world_id": "world.evidence",
                "action_id": replay_plan.steps[-1].action.action_id,
                "observed": observed,
                "evidence_ids": (evidence_id,),
            }
        ).removeprefix("sha256:")[:24]
    )
    oracle = OracleResult(
        oracle_result_id=oracle_result_id,
        oracle_type=OracleType.TENANT_ISOLATION,
        world_id="world.evidence",
        invariant=("actor.tenant == resource.tenant OR response.protected_field_present == false"),
        result=oracle_outcome,
        observed=observed,
        evidence_ids=(evidence_id,),
        deterministic=True,
        evaluator_version="in-process-lab-v1",
    )
    step_status = ReplayStepStatus.FAILED if failed else ReplayStepStatus.PASSED
    step_result = ReplayStepResult(
        step_id="step.00",
        status=step_status,
        before_fingerprint=before.fingerprint,
        after_fingerprint=after.fingerprint,
        observations=(observation,),
        oracle_results=(oracle,),
        failure_code="ORACLE_EXPECTATION_MISMATCH" if failed else None,
        failure_message="oracle result was outside the allowed result set" if failed else None,
    )
    envelope = replay_plan.steps[0].action
    envelope_hash = canonical_sha256(envelope)
    trace_id = canonical_sha256(
        {"plan_id": replay_plan.plan_id, "step_id": "step.00", "envelope_hash": envelope_hash}
    ).removeprefix("sha256:")[:32]
    action_log = (
        ReplayActionLogEntry(
            step_id="step.00",
            action=envelope,
            action_id=envelope.action_id,
            action_type=envelope.action_type,
            sequence=envelope.sequence,
            status=step_status,
            idempotency_key=envelope.idempotency_key,
            policy_decision_ref=envelope.policy_decision_ref,
            trace_id=trace_id,
            envelope_hash=envelope_hash,
            request_template_hash=canonical_sha256(envelope.action),
            before_fingerprint=before.fingerprint,
            after_fingerprint=after.fingerprint,
            observation_hash=canonical_sha256((observation,)),
            oracle_results_hash=canonical_sha256((oracle,)),
            evidence_ids=(evidence_id,),
        ),
    )
    run_status = ReplayRunStatus.FAILED if failed else ReplayRunStatus.SUCCEEDED
    trace_hash = canonical_sha256(
        {
            "plan_id": replay_plan.plan_id,
            "status": run_status,
            "root_fingerprint": before.fingerprint,
            "final_fingerprint": after.fingerprint,
            "steps": (step_result,),
            "action_log": action_log,
            "failed_step_id": "step.00" if failed else None,
        }
    )
    replay_result = ReplayRunResult(
        run_id=run_id,
        plan_id=replay_plan.plan_id,
        status=run_status,
        root_fingerprint=before.fingerprint,
        final_fingerprint=after.fingerprint,
        steps=(step_result,),
        action_log=action_log,
        failed_step_id="step.00" if failed else None,
        trace_hash=trace_hash,
    )
    return {
        "action_log_hash": canonical_sha256(action_log),
        "evidence_count": 1,
        "evidence_records": [evidence_record],
        "failed_step_id": replay_result.failed_step_id,
        "failure_code": step_result.failure_code,
        "name": name,
        "oracle_outcome": oracle_outcome.value,
        "oracle_results": [oracle.model_dump(mode="json")],
        "plan": replay_plan.model_dump(mode="json"),
        "replay_result": replay_result.model_dump(mode="json"),
        "response_status": response_status,
        "root_seed": root_seed.model_dump(mode="json"),
        "signature": replay_result.deterministic_signature(),
        "status": replay_result.status.value,
        "terminal_observations": [observation.model_dump(mode="json")],
    }


def policy_record(replay_plan: ReplayPlan, scope_manifest: ScopeManifest) -> dict[str, object]:
    envelope = replay_plan.steps[0].action
    evaluated_at = EPOCH
    request = PolicyRequest(
        scope_manifest=scope_manifest,
        action_envelope=envelope,
        budget=BudgetSnapshot(
            requests_in_window=0,
            request_window_seconds=1.0,
            write_requests_used=0,
        ),
        evaluated_at=evaluated_at,
    )
    return {
        "action_id": envelope.action_id,
        "budget_reservation_id": canonical_sha256(
            {
                "envelope_hash": canonical_sha256(envelope),
                "scope_manifest_hash": canonical_sha256(scope_manifest),
                "requests_before": 0,
                "write_requests_before": 0,
            }
        ),
        "decision": evaluate_policy(request).model_dump(mode="json"),
        "envelope_hash": canonical_sha256(envelope),
        "evaluated_at": "2026-01-01T00:00:00Z",
        "expires_at": "2026-01-02T00:00:00Z",
        "idempotency_key": envelope.idempotency_key,
        "is_write": False,
        "not_before": "2025-12-31T00:00:00Z",
        "policy_decision_ref": envelope.policy_decision_ref,
        "policy_request_hash": request.fingerprint(),
        "requests_before": 0,
        "scope_manifest_hash": canonical_sha256(scope_manifest),
        "write_requests_before": 0,
    }


def foundation(*, layered_root: bool = False) -> dict[str, object]:
    canonical_plan = plan()
    canonical_root = root(layered=layered_root)
    scope_manifest = scope()
    attempts = [
        scenario(
            name="canonical_vulnerable",
            run_id=f"run.vulnerable.{index}",
            replay_plan=canonical_plan,
            root_seed=canonical_root,
            oracle_outcome=OracleOutcome.VIOLATED,
            response_status=200,
        )
        for index in range(1, 6)
    ]
    patched = scenario(
        name="canonical_patched",
        run_id="run.patched.1",
        replay_plan=canonical_plan,
        root_seed=root(target_version="lab-patched", layered=layered_root),
        oracle_outcome=OracleOutcome.SATISFIED,
        response_status=403,
        failed=True,
    )
    control_specs = (
        *(
            (name, OracleOutcome.SATISFIED, 403, "/v1/lab/documents/doc-b-protected", (200, 403))
            for name in (
                "missing_prerequisite_0",
                "missing_prerequisite_1",
                "missing_prerequisite_3",
                "missing_prerequisite_5",
                "missing_prerequisite_6",
                "expired_replay_window",
                "fresh_session",
            )
        ),
        (
            "masked_response",
            OracleOutcome.SATISFIED,
            200,
            "/v1/lab/decoys/masked/doc-b-protected",
            (200,),
        ),
        (
            "mock_only_response",
            OracleOutcome.INCONCLUSIVE,
            200,
            "/v1/lab/decoys/mock-policy/doc-b-protected",
            (200,),
        ),
        (
            "same_tenant_document",
            OracleOutcome.SATISFIED,
            200,
            "/v1/lab/documents/doc-a-owned",
            (200, 403),
        ),
    )
    controls: list[dict[str, object]] = []
    control_plans: list[ReplayPlan] = []
    for index, (name, outcome, response_status, path, expected_statuses) in enumerate(
        control_specs, start=1
    ):
        control_plan = plan(
            plan_id=f"plan.control.{index}",
            action_id=f"action.control.{index}",
            decision_ref=f"policy.control.{index}",
            outcome=outcome,
            path=path,
            expected_statuses=expected_statuses,
        )
        control_plans.append(control_plan)
        controls.append(
            scenario(
                name=name,
                run_id=f"run.control.{index}",
                replay_plan=control_plan,
                root_seed=canonical_root,
                oracle_outcome=outcome,
                response_status=response_status,
            )
        )
    decisions: dict[str, object] = {
        canonical_plan.steps[0].action.policy_decision_ref: policy_record(
            canonical_plan, scope_manifest
        ),
    }
    decisions.update(
        {
            control_plan.steps[0].action.policy_decision_ref: policy_record(
                control_plan, scope_manifest
            )
            for control_plan in control_plans
        }
    )
    first_replay_result = attempts[0]["replay_result"]
    assert isinstance(first_replay_result, dict)
    return {
        "accepted": True,
        "canonical_action_log": first_replay_result["action_log"],
        "canonical_plan": canonical_plan.model_dump(mode="json"),
        "model_calls": 0,
        "negative_controls": controls,
        "network_mode": "offline-in-process",
        "network_guard": "python-socket-deny-v2",
        "patched": {
            "evidence_count": patched["evidence_count"],
            "action_log_hash": patched["action_log_hash"],
            "action_log_count": len(first_replay_result["action_log"]),
            "failed_step_id": "step.00",
            "failure_code": "ORACLE_EXPECTATION_MISMATCH",
            "oracle_outcome": "SATISFIED",
            "proof": patched,
            "response_status": 403,
            "status": "failed",
        },
        "patched_uses_identical_plan": True,
        "plan_hash": canonical_sha256(canonical_plan),
        "policy_decisions": decisions,
        "root_state": canonical_root.model_dump(mode="json"),
        "scope_manifest": scope_manifest.model_dump(mode="json", by_alias=True),
        "vulnerable": {
            "all_runs_succeeded": True,
            "action_log_hash": attempts[0]["action_log_hash"],
            "action_log_count": len(first_replay_result["action_log"]),
            "attempts": attempts,
            "deterministic": True,
            "oracle_outcome": "VIOLATED",
            "response_status": 200,
            "run_count": 5,
            "signature": attempts[0]["signature"],
        },
    }
