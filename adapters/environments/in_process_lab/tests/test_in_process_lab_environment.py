"""Black-box coverage for the deterministic in-process replay adapter."""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Iterable
from datetime import UTC, datetime

import pytest
from stateweaver.adapters.in_process_lab import (
    ADAPTER_NAME,
    ADAPTER_VERSION,
    CANONICAL_RANDOM_SEED,
    ORACLE_ID,
    AdapterConfigurationError,
    FixedLabActionRegistry,
    InProcessLabEnvironment,
    LabAction,
    LabCaptureRejectedError,
    LabExecutionRejectedError,
    LabExecutionTimeoutError,
    LabIdempotencyConflictError,
    LabPolicyDeniedError,
    LabTargetRejectedError,
    PolicyAuthorization,
    UnknownLabActionError,
    lab_action_artifact,
    lab_http_action_spec,
    state_capture_from_lab_checkpoint,
)
from stateweaver.contracts import (
    ActionEnvelope,
    ActionTarget,
    EnvironmentMode,
    HttpMethod,
    HttpParameter,
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
from stateweaver.policy import (
    BudgetSnapshot,
    PolicyRequest,
    evaluate_policy,
)
from stateweaver.replay import (
    CaptureLayer,
    OracleExpectation,
    ReplayKernel,
    ReplayPlan,
    ReplayRunResult,
    ReplayRunStatus,
    ReplayStep,
    ReplayStepStatus,
    RootSeed,
    StateCapture,
    canonical_sha256,
)
from stateweaver_lab import LabMode, create_app
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
    MaskedReadLabAction,
    MockPolicyLabAction,
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

EVALUATED_AT = datetime(2026, 7, 29, tzinfo=UTC)


def _policy_request(
    envelope: ActionEnvelope,
    *,
    requests_before: int,
    write_requests_before: int,
    allow_action: bool = True,
) -> PolicyRequest:
    actions = (
        ScopeActions(allow=(ScopeAction.HTTP_REQUEST,))
        if allow_action
        else ScopeActions(
            allow=(ScopeAction.PASSIVE_OBSERVATION,),
            deny=(ScopeAction.HTTP_REQUEST,),
        )
    )
    manifest = ScopeManifest(
        metadata=ScopeMetadata(name="adapter-tests"),
        spec=ScopeSpec(
            environmentMode=EnvironmentMode.SOURCE_BACKED,
            targets=ScopeTargets(
                include=(TargetSelector(host="localhost", ports=(80,), paths=("/v1/lab/**",)),)
            ),
            identities=ScopeIdentities(allowed=("test_user_a", "test_user_b", "test_admin")),
            actions=actions,
            limits=ScopeLimits(
                requestsPerSecond=100.0,
                concurrentMaterializedWorlds=1,
                maxWriteRequests=64,
            ),
            validity=ScopeValidity(
                notBefore=datetime(2026, 1, 1, tzinfo=UTC),
                expiresAt=datetime(2027, 1, 1, tzinfo=UTC),
            ),
        ),
    )
    return PolicyRequest(
        scope_manifest=manifest,
        action_envelope=envelope,
        budget=BudgetSnapshot(
            requests_in_window=requests_before,
            request_window_seconds=1.0,
            write_requests_used=write_requests_before,
        ),
        evaluated_at=EVALUATED_AT,
    )


def _authorization(
    envelope: ActionEnvelope,
    *,
    requests_before: int,
    write_requests_before: int,
    allow_action: bool = True,
) -> PolicyAuthorization:
    request = _policy_request(
        envelope,
        requests_before=requests_before,
        write_requests_before=write_requests_before,
        allow_action=allow_action,
    )
    decision = evaluate_policy(request)
    return PolicyAuthorization.bind(envelope, request, decision)


def _typed_chain() -> tuple[LabAction, ...]:
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
        ReadDocumentLabAction(
            actor=FixtureBearer.TENANT_A_OLD_EDITOR,
            payload=ReadDocumentRequest(document_id=DocumentId.TENANT_B_PROTECTED),
        ),
    )


def _envelope(action_id: str, sequence: int, lab_action: LabAction) -> ActionEnvelope:
    spec = lab_http_action_spec(lab_action)
    return ActionEnvelope(
        action_id=action_id,
        experiment_id="experiment.in_process_lab",
        world_id="world.canonical",
        scope_action=ScopeAction.HTTP_REQUEST,
        action=HttpRequestAction(
            method=spec.method,
            target=ActionTarget(scheme="http", host="localhost", port=80, path=spec.path),
            body_artifact=lab_action_artifact(lab_action),
            identity_handle=spec.identity_handle,
            expected_statuses=spec.expected_statuses,
        ),
        risk_class=(
            RiskClass.READ_ONLY if spec.method.value == "GET" else RiskClass.REVERSIBLE_STATE_CHANGE
        ),
        idempotency_key=canonical_sha256({"action_id": action_id, "sequence": sequence}),
        requested_by=RequestedBy(type=RequesterType.WORKFLOW, role="adapter_test"),
        policy_decision_ref=f"decision.{sequence:03d}",
        sequence=sequence,
    )


def _registry(actions: Iterable[tuple[ActionEnvelope, LabAction]]) -> FixedLabActionRegistry:
    pairs = tuple(actions)
    authorizations: dict[str, PolicyAuthorization] = {}
    write_requests_before = 0
    for requests_before, (envelope, lab_action) in enumerate(pairs):
        authorizations[envelope.policy_decision_ref] = _authorization(
            envelope,
            requests_before=requests_before,
            write_requests_before=write_requests_before,
        )
        if lab_http_action_spec(lab_action).method not in {
            HttpMethod.GET,
            HttpMethod.HEAD,
            HttpMethod.OPTIONS,
        }:
            write_requests_before += 1
    return FixedLabActionRegistry(
        by_action_id={envelope.action_id: lab_action for envelope, lab_action in pairs},
        by_body_artifact={lab_action_artifact(lab_action): lab_action for _, lab_action in pairs},
        policy_authorizations=authorizations,
    )


async def _root(environment: InProcessLabEnvironment) -> RootSeed:
    return await environment.create_root_seed(
        root_seed_id="root.canonical", random_seed=CANONICAL_RANDOM_SEED
    )


def _plan(
    actions: tuple[LabAction, ...], *, expect_violation: bool
) -> tuple[ReplayPlan, FixedLabActionRegistry]:
    envelopes = tuple(
        _envelope(f"action.{index:03d}", index, lab_action)
        for index, lab_action in enumerate(actions, start=1)
    )
    steps = tuple(
        ReplayStep(
            step_id=f"step.{index:03d}",
            action=envelope,
            oracle_expectations=(
                (
                    OracleExpectation(
                        oracle_id=ORACLE_ID,
                        allowed_results=frozenset({str(OracleOutcome.VIOLATED)}),
                    ),
                )
                if index == len(envelopes) and expect_violation
                else ()
            ),
        )
        for index, envelope in enumerate(envelopes, start=1)
    )
    return (
        ReplayPlan(plan_id="plan.full_chain", root_seed_id="root.canonical", steps=steps),
        _registry(zip(envelopes, actions, strict=True)),
    )


@pytest.mark.asyncio
async def test_root_creation_reset_and_capture_contain_all_seven_redacted_layers() -> None:
    first_action = RetainSessionLabAction()
    envelope = _envelope("action.001", 1, first_action)
    environment = InProcessLabEnvironment(
        mode=LabMode.VULNERABLE,
        registry=_registry(((envelope, first_action),)),
    )

    root = await _root(environment)
    assert root.target_version == "lab-vulnerable"
    assert root.adapter_versions == {ADAPTER_NAME: ADAPTER_VERSION}
    assert {artifact.layer for artifact in root.capture.artifacts} == set(CaptureLayer)
    assert len(root.capture.artifacts) == 7
    assert await environment.capture() == root.capture

    await environment.execute(envelope)
    assert (await environment.capture()).fingerprint != root.capture.fingerprint
    assert await environment.reset(root) == root.capture

    with pytest.raises(AdapterConfigurationError, match="random seed"):
        await environment.create_root_seed(root_seed_id="root.invalid", random_seed=1)


@pytest.mark.asyncio
async def test_exact_lab_checkpoint_rebuilds_the_same_replay_root_capture() -> None:
    action = RetainSessionLabAction()
    envelope = _envelope("action.001", 1, action)
    environment = InProcessLabEnvironment(
        mode=LabMode.VULNERABLE,
        registry=_registry(((envelope, action),)),
    )
    root = await _root(environment)
    checkpoint = create_app("vulnerable").state.lab.export_checkpoint().canonical_bytes()

    assert state_capture_from_lab_checkpoint(checkpoint) == root.capture
    with pytest.raises(LabCaptureRejectedError, match="canonical replay root"):
        state_capture_from_lab_checkpoint(checkpoint + b" ")


@pytest.mark.asyncio
async def test_full_vulnerable_plan_is_deterministic_over_five_runs() -> None:
    plan, registry = _plan(_typed_chain(), expect_violation=True)
    environment = InProcessLabEnvironment(mode=LabMode.VULNERABLE, registry=registry)
    root = await _root(environment)

    kernel = ReplayKernel(environment, {ORACLE_ID: environment.oracle})
    runs: list[ReplayRunResult] = []
    for index in range(1, 6):
        runs.append(await kernel.replay(run_id=f"run.{index:03d}", plan=plan, root=root))

    assert all(run.status is ReplayRunStatus.SUCCEEDED for run in runs)
    assert all(run.steps[-1].oracle_results[0].result is OracleOutcome.VIOLATED for run in runs)
    assert len({run.deterministic_signature() for run in runs}) == 1
    assert all(len(run.action_log) == len(plan.steps) for run in runs)
    assert all(entry.parameter_artifact is not None for entry in runs[0].action_log)
    assert runs[0].action_log[-1].evidence_ids
    assert len({entry.trace_id for entry in runs[0].action_log}) == len(plan.steps)


@pytest.mark.asyncio
async def test_exact_plan_binds_typed_action_parameters_by_content_hash() -> None:
    advance_90 = AdvanceClockLabAction(payload=AdvanceClockRequest(seconds=90))
    advance_181 = AdvanceClockLabAction(payload=AdvanceClockRequest(seconds=181))
    envelope_90 = _envelope("action.clock", 1, advance_90)
    envelope_181 = _envelope("action.clock", 1, advance_181)
    plan_90 = ReplayPlan(
        plan_id="plan.clock",
        root_seed_id="root.canonical",
        steps=(ReplayStep(step_id="step.clock", action=envelope_90),),
    )
    plan_181 = plan_90.model_copy(
        update={"steps": (ReplayStep(step_id="step.clock", action=envelope_181),)}
    )

    assert isinstance(envelope_90.action, HttpRequestAction)
    assert isinstance(envelope_181.action, HttpRequestAction)
    assert envelope_90.action.body_artifact != envelope_181.action.body_artifact
    assert canonical_sha256(plan_90) != canonical_sha256(plan_181)

    mismatched_registry = _registry(((envelope_90, advance_181),))
    environment = InProcessLabEnvironment(
        mode=LabMode.VULNERABLE,
        registry=mismatched_registry,
    )
    root = await _root(environment)
    with pytest.raises(UnknownLabActionError):
        await environment.execute(envelope_90)
    assert await environment.capture() == root.capture


@pytest.mark.asyncio
async def test_identical_patched_plan_fails_only_at_final_oracle_expectation() -> None:
    plan, registry = _plan(_typed_chain(), expect_violation=True)
    environment = InProcessLabEnvironment(mode=LabMode.PATCHED, registry=registry)
    root = await _root(environment)

    result = await ReplayKernel(environment, {ORACLE_ID: environment.oracle}).replay(
        run_id="run.patched", plan=plan, root=root
    )

    assert result.status is ReplayRunStatus.FAILED
    assert result.failed_step_id == "step.008"
    assert [step.status for step in result.steps] == [ReplayStepStatus.PASSED] * 7 + [
        ReplayStepStatus.FAILED
    ]
    assert result.steps[-1].failure_message == "oracle result was outside the allowed result set"
    assert result.steps[-1].failure_code == "ORACLE_EXPECTATION_MISMATCH"
    assert result.steps[-1].after_fingerprint is not None
    assert result.steps[-1].observations
    assert result.steps[-1].oracle_results[0].result is OracleOutcome.SATISFIED
    assert environment.oracle.last_result is not None
    assert environment.oracle.last_result.result is OracleOutcome.SATISFIED


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("control_action", "expected_outcome"),
    [
        (
            MaskedReadLabAction(
                actor=FixtureBearer.TENANT_A_OLD_EDITOR,
                payload=ReadDocumentRequest(document_id=DocumentId.TENANT_B_PROTECTED),
            ),
            OracleOutcome.SATISFIED,
        ),
        (
            MockPolicyLabAction(
                actor=FixtureBearer.TENANT_A_OLD_EDITOR,
                payload=ReadDocumentRequest(document_id=DocumentId.TENANT_B_PROTECTED),
            ),
            OracleOutcome.INCONCLUSIVE,
        ),
        (
            ReadDocumentLabAction(
                actor=FixtureBearer.TENANT_A_FRESH_VIEWER,
                payload=ReadDocumentRequest(document_id=DocumentId.TENANT_B_PROTECTED),
            ),
            OracleOutcome.SATISFIED,
        ),
        (
            ReadDocumentLabAction(
                actor=FixtureBearer.TENANT_A_OLD_EDITOR,
                payload=ReadDocumentRequest(document_id=DocumentId.TENANT_A_OWNED),
            ),
            OracleOutcome.SATISFIED,
        ),
    ],
)
async def test_masked_mock_fresh_session_and_same_tenant_controls_are_classified(
    control_action: LabAction, expected_outcome: OracleOutcome
) -> None:
    setup = _typed_chain()[:-1]
    actions = (*setup, control_action)
    plan, registry = _plan(actions, expect_violation=False)
    environment = InProcessLabEnvironment(mode=LabMode.VULNERABLE, registry=registry)
    root = await _root(environment)
    last_step = plan.steps[-1].model_copy(
        update={
            "oracle_expectations": (
                OracleExpectation(
                    oracle_id=ORACLE_ID,
                    allowed_results=frozenset({str(expected_outcome)}),
                ),
            )
        }
    )
    plan = plan.model_copy(update={"steps": (*plan.steps[:-1], last_step)})

    result = await ReplayKernel(environment, {ORACLE_ID: environment.oracle}).replay(
        run_id="run.control", plan=plan, root=root
    )

    assert result.status is ReplayRunStatus.SUCCEEDED
    assert result.steps[-1].oracle_results[0].result is expected_outcome


@pytest.mark.asyncio
async def test_capture_fingerprint_includes_authoritative_evidence_semantics() -> None:
    masked = MaskedReadLabAction(
        actor=FixtureBearer.TENANT_A_OLD_EDITOR,
        payload=ReadDocumentRequest(document_id=DocumentId.TENANT_B_PROTECTED),
    )
    mocked = MockPolicyLabAction(
        actor=FixtureBearer.TENANT_A_OLD_EDITOR,
        payload=ReadDocumentRequest(document_id=DocumentId.TENANT_B_PROTECTED),
    )
    masked_envelope = _envelope("action.masked", 1, masked)
    mocked_envelope = _envelope("action.mocked", 2, mocked)
    masked_environment = InProcessLabEnvironment(
        mode=LabMode.VULNERABLE,
        registry=_registry(((masked_envelope, masked),)),
    )
    mocked_environment = InProcessLabEnvironment(
        mode=LabMode.VULNERABLE,
        registry=_registry(((mocked_envelope, mocked),)),
    )
    await _root(masked_environment)
    await _root(mocked_environment)

    await masked_environment.execute(masked_envelope)
    masked_capture = await masked_environment.capture()
    await mocked_environment.execute(mocked_envelope)
    mocked_capture = await mocked_environment.capture()

    assert masked_capture.fingerprint != mocked_capture.fingerprint


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "authorization_case",
    ["missing", "denied", "mismatched", "over_quota", "expired", "future_policy"],
)
async def test_invalid_policy_authorization_has_zero_state_delta(
    authorization_case: str,
) -> None:
    lab_action = RetainSessionLabAction()
    envelope = _envelope("action.001", 1, lab_action)
    authorization = _authorization(envelope, requests_before=0, write_requests_before=0)
    if authorization_case == "missing":
        authorizations: dict[str, PolicyAuthorization] = {}
    elif authorization_case == "denied":
        authorizations = {
            envelope.policy_decision_ref: _authorization(
                envelope,
                requests_before=0,
                write_requests_before=0,
                allow_action=False,
            )
        }
    elif authorization_case == "over_quota":
        authorizations = {
            envelope.policy_decision_ref: _authorization(
                envelope,
                requests_before=100,
                write_requests_before=0,
            )
        }
    elif authorization_case == "expired":
        authorizations = {
            envelope.policy_decision_ref: authorization.model_copy(
                update={
                    "evaluated_at": datetime(2026, 7, 27, tzinfo=UTC),
                    "expires_at": datetime(2026, 7, 28, tzinfo=UTC),
                }
            )
        }
    elif authorization_case == "future_policy":
        authorizations = {
            envelope.policy_decision_ref: authorization.model_copy(
                update={"evaluated_at": datetime(2026, 12, 1, tzinfo=UTC)}
            )
        }
    else:
        authorizations = {
            envelope.policy_decision_ref: authorization.model_copy(
                update={"envelope_hash": canonical_sha256({"tampered": True})}
            )
        }
    registry = FixedLabActionRegistry(
        by_action_id={envelope.action_id: lab_action},
        by_body_artifact={lab_action_artifact(lab_action): lab_action},
        policy_authorizations=authorizations,
    )
    environment = InProcessLabEnvironment(mode=LabMode.VULNERABLE, registry=registry)
    root = await _root(environment)
    before = await environment.capture()

    with pytest.raises(LabPolicyDeniedError):
        await environment.execute(envelope)

    assert await environment.capture() == before == root.capture


@pytest.mark.asyncio
async def test_unknown_remote_and_dynamic_actions_are_rejected_before_state_changes() -> None:
    lab_action = RetainSessionLabAction()
    envelope = _envelope("action.001", 1, lab_action)
    environment = InProcessLabEnvironment(
        mode=LabMode.VULNERABLE, registry=_registry(((envelope, lab_action),))
    )
    await _root(environment)
    before = await environment.capture()
    assert isinstance(envelope.action, HttpRequestAction)
    assert envelope.action.target is not None
    unknown = envelope.model_copy(update={"action_id": "action.unknown"})
    remote_action = envelope.action.model_copy(
        update={
            "target": ActionTarget(
                scheme="https", host="remote.invalid", port=443, path=envelope.action.target.path
            )
        }
    )
    remote = envelope.model_copy(update={"action": remote_action})
    dynamic_action = envelope.action.model_copy(
        update={"query": (HttpParameter(name="unexpected", value="value"),)}
    )
    dynamic = envelope.model_copy(update={"action": dynamic_action})

    with pytest.raises(UnknownLabActionError):
        await environment.execute(unknown)
    with pytest.raises(LabTargetRejectedError):
        await environment.execute(remote)
    with pytest.raises(LabTargetRejectedError):
        await environment.execute(dynamic)

    assert await environment.capture() == before


@pytest.mark.asyncio
async def test_idempotency_reuses_exact_observations_and_rejects_conflicts() -> None:
    lab_action = RetainSessionLabAction()
    envelope = _envelope("action.001", 1, lab_action)
    environment = InProcessLabEnvironment(
        mode=LabMode.VULNERABLE, registry=_registry(((envelope, lab_action),))
    )
    await _root(environment)

    first = await environment.execute(envelope)
    after_first = await environment.capture()
    assert await environment.execute(envelope) == first
    assert await environment.capture() == after_first

    conflicting = envelope.model_copy(update={"sequence": 2})
    with pytest.raises(LabIdempotencyConflictError):
        await environment.execute(conflicting)
    assert await environment.capture() == after_first


@pytest.mark.asyncio
async def test_observed_execution_is_one_actual_asgi_lifecycle_with_server_metadata() -> None:
    lab_action = RetainSessionLabAction()
    envelope = _envelope("action.asgi", 1, lab_action)
    environment = InProcessLabEnvironment(
        mode=LabMode.VULNERABLE,
        registry=_registry(((envelope, lab_action),)),
    )
    await _root(environment)

    execution = await environment.execute_observed(envelope)

    assert execution.envelope_digest == canonical_sha256(envelope)
    assert execution.execution_id.startswith("execution.")
    assert execution.execution_digest == canonical_sha256(
        execution.model_dump(mode="python", exclude={"execution_digest"})
    )
    assert execution.source_digest.startswith("sha256:")
    assert execution.method is HttpMethod.POST
    assert execution.route == "/v1/lab/session/retain"
    assert execution.status == 200
    assert (
        execution.before_captured_at_unix_nano
        <= execution.started_at_unix_nano
        < execution.ended_at_unix_nano
        <= execution.after_captured_at_unix_nano
    )
    assert execution.before_capture != execution.after_capture
    assert execution.observations
    assert len(environment.evidence_records) == 1

    assert await environment.execute_observed(envelope) is execution
    assert await environment.execute(envelope) == execution.observations
    assert len(environment.evidence_records) == 1


def test_repository_app_factory_binding_is_pinned(monkeypatch: pytest.MonkeyPatch) -> None:
    import stateweaver_lab.app as lab_app_module

    lab_action = RetainSessionLabAction()
    envelope = _envelope("action.factory-pin", 1, lab_action)

    def replaced_factory(mode: object) -> object:
        del mode
        raise AssertionError("mutable module factory must not be consulted")

    monkeypatch.setattr(lab_app_module, "create_app", replaced_factory)
    environment = InProcessLabEnvironment(
        mode=LabMode.VULNERABLE,
        registry=_registry(((envelope, lab_action),)),
    )

    assert environment.runtime_source_digest.startswith("sha256:")


@pytest.mark.asyncio
async def test_normal_execution_hides_partial_state_until_receipt_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lab_action = RetainSessionLabAction()
    envelope = _envelope("action.partial-read", 1, lab_action)
    environment = InProcessLabEnvironment(
        mode=LabMode.VULNERABLE,
        registry=_registry(((envelope, lab_action),)),
    )
    await _root(environment)
    state = environment.__dict__["_service"].__dict__["_state"]
    retain = state.retain_old_session
    evidence_appended = threading.Event()
    release_handler = threading.Event()

    def paused_retain(context: object) -> object:
        result = retain(context)
        evidence_appended.set()
        if not release_handler.wait(2.0):
            raise RuntimeError("test handler release timed out")
        return result

    monkeypatch.setattr(state, "retain_old_session", paused_retain)
    execution_task = asyncio.create_task(environment.execute_observed(envelope))
    assert await asyncio.to_thread(evidence_appended.wait, 1.0)
    try:
        with pytest.raises(LabExecutionRejectedError, match="in progress"):
            _ = environment.evidence_records
        with pytest.raises(LabExecutionRejectedError, match="in progress"):
            _ = environment.last_observations
    finally:
        release_handler.set()
        execution = await execution_task

    assert execution.execution_id.startswith("execution.")
    assert len(environment.evidence_records) == 1


@pytest.mark.asyncio
async def test_actual_asgi_timeout_is_bounded_and_quarantines_unfinished_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lab_action = RetainSessionLabAction()
    envelope = _envelope("action.timeout", 1, lab_action).model_copy(update={"timeout_ms": 10})
    environment = InProcessLabEnvironment(
        mode=LabMode.VULNERABLE,
        registry=_registry(((envelope, lab_action),)),
    )
    root = await _root(environment)
    state = environment.__dict__["_service"].__dict__["_state"]
    retain = state.retain_old_session

    def slow_retain(context: object) -> object:
        time.sleep(0.25)
        return retain(context)

    monkeypatch.setattr(state, "retain_old_session", slow_retain)
    started = time.perf_counter()
    with pytest.raises(LabExecutionTimeoutError) as captured:
        await environment.execute_observed(envelope)
    elapsed = time.perf_counter() - started

    assert elapsed < 0.15
    assert captured.value.__cause__ is None
    with pytest.raises(LabExecutionRejectedError, match="still settling"):
        await environment.capture()
    with pytest.raises(LabExecutionRejectedError, match="still settling"):
        await environment.cleanup()

    await asyncio.sleep(0.3)
    with pytest.raises(LabExecutionRejectedError, match=r"cleanup|reset"):
        _ = environment.evidence_records
    restored = await environment.reset(root)
    assert restored == root.capture
    assert not environment.evidence_records


@pytest.mark.asyncio
async def test_cleanup_is_idempotent_and_tampered_roots_are_rejected() -> None:
    lab_action = RetainSessionLabAction()
    envelope = _envelope("action.001", 1, lab_action)
    environment = InProcessLabEnvironment(
        mode=LabMode.VULNERABLE, registry=_registry(((envelope, lab_action),))
    )
    root = await _root(environment)

    await environment.cleanup()
    await environment.cleanup()
    with pytest.raises(LabExecutionRejectedError, match="reset before execution"):
        await environment.execute(envelope)

    bad_target = root.model_copy(update={"target_version": "lab-patched"})
    bad_adapter = root.model_copy(update={"adapter_versions": {ADAPTER_NAME: "9.9.9"}})
    incomplete = StateCapture.from_artifacts(
        capture_id="capture.incomplete",
        controlled_at=root.capture.controlled_at,
        artifacts=root.capture.artifacts[:-1],
    )
    bad_capture = root.model_copy(update={"capture": incomplete})
    for tampered_root in (bad_target, bad_adapter, bad_capture):
        with pytest.raises(AdapterConfigurationError):
            await environment.reset(tampered_root)
