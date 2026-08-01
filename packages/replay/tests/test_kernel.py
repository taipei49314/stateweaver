from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError
from stateweaver.contracts import (
    ActionEnvelope,
    OracleOutcome,
    OracleResult,
    OracleType,
    RequestedBy,
    RequesterType,
    RiskClass,
    ScopeAction,
    TimeAdvanceAction,
)
from stateweaver.replay import (
    CaptureLayer,
    DeterminismClassification,
    OracleExpectation,
    ReplayKernel,
    ReplayObservation,
    ReplayPlan,
    ReplayRunStatus,
    ReplayStep,
    ReplayStepStatus,
    RootSeed,
    StateArtifact,
    StateCapture,
    canonical_sha256,
)

EPOCH = datetime(2026, 7, 29, tzinfo=UTC)


def _action(sequence: int) -> ActionEnvelope:
    return ActionEnvelope(
        action_id=f"act.{sequence:03d}",
        experiment_id="exp.001",
        world_id="world.001",
        scope_action=ScopeAction.CONTROLLED_TIME,
        action=TimeAdvanceAction(milliseconds=1_000),
        risk_class=RiskClass.REVERSIBLE_STATE_CHANGE,
        idempotency_key=canonical_sha256({"sequence": sequence}),
        requested_by=RequestedBy(type=RequesterType.WORKFLOW, role="replay_kernel"),
        policy_decision_ref=f"decision.{sequence:03d}",
        sequence=sequence,
    )


def _capture(tick: int, *, capture_id: str | None = None) -> StateCapture:
    controlled_at = EPOCH + timedelta(seconds=tick)
    artifacts = (
        StateArtifact.from_payload(
            layer=CaptureLayer.APPLICATION,
            payload={"tick": tick, "principal": "identity:test_user_a"},
        ),
        StateArtifact.from_payload(
            layer=CaptureLayer.CLOCK,
            payload={"epoch": controlled_at.isoformat()},
        ),
    )
    return StateCapture.from_artifacts(
        capture_id=capture_id or f"capture.{tick:03d}",
        controlled_at=controlled_at,
        artifacts=artifacts,
    )


def _root() -> RootSeed:
    return RootSeed(
        root_seed_id="root.001",
        target_version="lab-vulnerable",
        random_seed=982341,
        clock_epoch=EPOCH,
        capture=_capture(0),
        adapter_versions={"in_process": "0.1.0"},
    )


def _plan(*actions: ActionEnvelope) -> ReplayPlan:
    return ReplayPlan(
        plan_id="plan.001",
        root_seed_id="root.001",
        steps=tuple(
            ReplayStep(step_id=f"step.{index:03d}", action=action)
            for index, action in enumerate(actions, start=1)
        ),
    )


class FakeEnvironment:
    def __init__(
        self,
        *,
        fail_on_action_id: str | None = None,
        divergent_root: bool = False,
        cleanup_fails: bool = False,
        drift_between_runs: bool = False,
    ) -> None:
        self.tick = 0
        self.fail_on_action_id = fail_on_action_id
        self.divergent_root = divergent_root
        self.cleanup_fails = cleanup_fails
        self.drift_between_runs = drift_between_runs
        self.cleanup_calls = 0
        self.reset_calls = 0

    async def reset(self, root: RootSeed) -> StateCapture:
        self.reset_calls += 1
        self.tick = 1 if self.divergent_root else 0
        return _capture(self.tick)

    async def capture(self) -> StateCapture:
        return _capture(self.tick)

    async def execute(self, action: ActionEnvelope) -> tuple[ReplayObservation, ...]:
        if action.action_id == self.fail_on_action_id:
            raise RuntimeError("synthetic failure detail must not escape")
        assert isinstance(action.action, TimeAdvanceAction)
        increment = self.reset_calls if self.drift_between_runs else 1
        self.tick += increment * (action.action.milliseconds // 1_000)
        return (
            ReplayObservation(
                observation_id=f"observation.{action.sequence:03d}",
                kind="controlled_clock_advanced",
                payload={"tick": self.tick},
            ),
        )

    async def cleanup(self) -> None:
        self.cleanup_calls += 1
        if self.cleanup_fails:
            raise RuntimeError("synthetic cleanup detail must not escape")


class SatisfiedOracle:
    id = "oracle.synthetic"
    version = "1.0"

    async def evaluate(
        self,
        before: StateCapture,
        action: ActionEnvelope,
        after: StateCapture,
        observations: tuple[ReplayObservation, ...],
    ) -> OracleResult:
        del before, observations
        return OracleResult(
            oracle_result_id="oracle.result.001",
            oracle_type=OracleType.CUSTOM_DETERMINISTIC,
            world_id=action.world_id,
            invariant="synthetic tick remains within the expected boundary",
            result=OracleOutcome.SATISFIED,
            observed={"after_fingerprint": after.fingerprint},
            evidence_ids=("evidence.synthetic.001",),
            deterministic=True,
        )


class BoundaryFailingEnvironment(FakeEnvironment):
    def __init__(self, phase: str) -> None:
        super().__init__()
        self.phase = phase
        self.capture_calls = 0
        self.failure_injected = False

    def _fail_once(self, phase: str) -> None:
        if self.phase == phase and not self.failure_injected:
            self.failure_injected = True
            raise RuntimeError("synthetic boundary detail must not escape")

    async def reset(self, root: RootSeed) -> StateCapture:
        self._fail_once("reset")
        return await super().reset(root)

    async def capture(self) -> StateCapture:
        self.capture_calls += 1
        if self.capture_calls == 1:
            self._fail_once("capture_before")
        elif self.capture_calls == 2:
            self._fail_once("capture_after")
        return await super().capture()

    async def execute(self, action: ActionEnvelope) -> tuple[ReplayObservation, ...]:
        self._fail_once("execute")
        return await super().execute(action)


class FailingOracle(SatisfiedOracle):
    async def evaluate(
        self,
        before: StateCapture,
        action: ActionEnvelope,
        after: StateCapture,
        observations: tuple[ReplayObservation, ...],
    ) -> OracleResult:
        del before, action, after, observations
        raise RuntimeError("synthetic oracle detail must not escape")


class NeverResetEnvironment(FakeEnvironment):
    async def reset(self, root: RootSeed) -> StateCapture:
        del root
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


@pytest.mark.asyncio
async def test_replay_is_deterministic_across_five_clean_roots() -> None:
    environment = FakeEnvironment()
    kernel = ReplayKernel(environment, {})
    report = await kernel.verify_determinism(
        plan=_plan(_action(1), _action(2)),
        root=_root(),
        run_ids=("run.001", "run.002", "run.003", "run.004", "run.005"),
    )

    assert report.deterministic is True
    assert report.all_runs_succeeded is True
    assert report.classification is DeterminismClassification.DETERMINISTIC
    assert report.divergent_run_id is None
    assert len(set(report.signatures)) == 1
    assert environment.cleanup_calls == 5


@pytest.mark.asyncio
async def test_observation_drift_is_classified_as_nondeterministic() -> None:
    report = await ReplayKernel(FakeEnvironment(drift_between_runs=True), {}).verify_determinism(
        plan=_plan(_action(1)),
        root=_root(),
        run_ids=("run.001", "run.002", "run.003"),
    )

    assert report.deterministic is False
    assert report.classification is DeterminismClassification.NONDETERMINISTIC
    assert report.divergent_run_id == "run.002"


@pytest.mark.asyncio
async def test_repeatable_failure_is_visible_even_when_its_signature_is_stable() -> None:
    report = await ReplayKernel(
        FakeEnvironment(fail_on_action_id="act.001"), {}
    ).verify_determinism(
        plan=_plan(_action(1)),
        root=_root(),
        run_ids=("run.failed.001", "run.failed.002"),
    )

    assert report.deterministic is True
    assert report.all_runs_succeeded is False
    assert report.run_statuses == (ReplayRunStatus.FAILED, ReplayRunStatus.FAILED)


@pytest.mark.asyncio
async def test_first_failure_is_attributed_and_later_steps_are_skipped() -> None:
    environment = FakeEnvironment(fail_on_action_id="act.001")
    result = await ReplayKernel(environment, {}).replay(
        run_id="run.001",
        plan=_plan(_action(1), _action(2)),
        root=_root(),
    )

    assert result.status is ReplayRunStatus.FAILED
    assert result.failed_step_id == "step.001"
    assert [step.status for step in result.steps] == [
        ReplayStepStatus.FAILED,
        ReplayStepStatus.SKIPPED,
    ]
    assert result.steps[0].failure_message == "RuntimeError"
    assert [entry.status for entry in result.action_log] == [
        ReplayStepStatus.FAILED,
        ReplayStepStatus.SKIPPED,
    ]
    assert result.action_log[0].action_id == "act.001"
    assert result.action_log[0].idempotency_key == _action(1).idempotency_key
    assert result.action_log[0].policy_decision_ref == "decision.001"
    assert len(result.action_log[0].trace_id) == 32
    assert "synthetic failure detail" not in result.model_dump_json()
    assert environment.cleanup_calls == 1


@pytest.mark.asyncio
async def test_oracle_mismatch_preserves_the_observation_and_after_state() -> None:
    action = _action(1)
    plan = ReplayPlan(
        plan_id="plan.oracle-mismatch",
        root_seed_id="root.001",
        steps=(
            ReplayStep(
                step_id="step.oracle",
                action=action,
                oracle_expectations=(
                    OracleExpectation(
                        oracle_id="oracle.synthetic",
                        allowed_results=frozenset({OracleOutcome.VIOLATED}),
                    ),
                ),
            ),
        ),
    )

    result = await ReplayKernel(
        FakeEnvironment(),
        {"oracle.synthetic": SatisfiedOracle()},
    ).replay(run_id="run.oracle-mismatch", plan=plan, root=_root())

    failed = result.steps[0]
    assert result.failed_step_id == "step.oracle"
    assert failed.failure_code == "ORACLE_EXPECTATION_MISMATCH"
    assert failed.after_fingerprint is not None
    assert len(failed.observations) == 1
    assert failed.oracle_results[0].result is OracleOutcome.SATISFIED
    log_entry = result.action_log[0]
    assert log_entry.after_fingerprint == failed.after_fingerprint
    assert log_entry.observation_hash == canonical_sha256(failed.observations)
    assert log_entry.oracle_results_hash == canonical_sha256(failed.oracle_results)
    assert log_entry.request_template_hash == canonical_sha256(action.action)
    assert log_entry.envelope_hash == canonical_sha256(action)


@pytest.mark.asyncio
async def test_action_log_and_trace_hash_reject_forged_content() -> None:
    from stateweaver.replay import ReplayRunResult

    result = await ReplayKernel(FakeEnvironment(), {}).replay(
        run_id="run.integrity",
        plan=_plan(_action(1)),
        root=_root(),
    )
    forged_log = result.model_dump(mode="python")
    forged_log["action_log"][0]["action_id"] = "act.forged"
    with pytest.raises(ValidationError, match="metadata does not match"):
        ReplayRunResult.model_validate(forged_log)

    forged_trace = result.model_dump(mode="python")
    forged_trace["trace_hash"] = f"sha256:{'0' * 64}"
    with pytest.raises(ValidationError, match="trace_hash"):
        ReplayRunResult.model_validate(forged_trace)


@pytest.mark.asyncio
async def test_root_divergence_fails_before_any_action() -> None:
    environment = FakeEnvironment(divergent_root=True)
    result = await ReplayKernel(environment, {}).replay(
        run_id="run.001",
        plan=_plan(_action(1)),
        root=_root(),
    )

    assert result.status is ReplayRunStatus.ROOT_DIVERGED
    assert result.failed_step_id == "root"
    assert result.steps[0].failure_code == "ROOT_FINGERPRINT_MISMATCH"
    assert environment.cleanup_calls == 1


@pytest.mark.asyncio
async def test_cleanup_failure_is_visible_and_redacted() -> None:
    result = await ReplayKernel(FakeEnvironment(cleanup_fails=True), {}).replay(
        run_id="run.001",
        plan=_plan(_action(1)),
        root=_root(),
    )

    assert result.status is ReplayRunStatus.CLEANUP_FAILED
    assert result.failed_step_id == "cleanup"
    assert result.steps[-1].failure_message == "RuntimeError"
    assert "synthetic cleanup detail" not in result.model_dump_json()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "phase, expected_code",
    [
        ("reset", "RESET_FAILURE"),
        ("capture_before", "CAPTURE_BEFORE_FAILURE"),
        ("execute", "EXECUTE_FAILURE"),
        ("capture_after", "CAPTURE_AFTER_FAILURE"),
    ],
)
async def test_boundary_failures_are_localized_cleanup_is_reentrant_and_reset_recovers(
    phase: str,
    expected_code: str,
) -> None:
    environment = BoundaryFailingEnvironment(phase)
    result = await ReplayKernel(environment, {}).replay(
        run_id=f"run.failure.{phase}",
        plan=_plan(_action(1)),
        root=_root(),
    )

    failed = next(step for step in result.steps if step.status is ReplayStepStatus.FAILED)
    assert failed.failure_code == expected_code
    assert "synthetic boundary detail" not in result.model_dump_json()
    await environment.cleanup()
    await environment.cleanup()
    recovered = await environment.reset(_root())
    assert recovered.fingerprint == _root().capture.fingerprint


@pytest.mark.asyncio
async def test_oracle_failure_is_localized_and_preserves_runtime_observation() -> None:
    action = _action(1)
    plan = ReplayPlan(
        plan_id="plan.oracle-failure",
        root_seed_id="root.001",
        steps=(
            ReplayStep(
                step_id="step.oracle",
                action=action,
                oracle_expectations=(
                    OracleExpectation(
                        oracle_id="oracle.synthetic",
                        allowed_results=frozenset({OracleOutcome.SATISFIED}),
                    ),
                ),
            ),
        ),
    )
    result = await ReplayKernel(FakeEnvironment(), {"oracle.synthetic": FailingOracle()}).replay(
        run_id="run.oracle-failure", plan=plan, root=_root()
    )

    failed = result.steps[0]
    assert failed.failure_code == "ORACLE_FAILURE"
    assert len(failed.observations) == 1
    assert failed.after_fingerprint is not None
    assert "synthetic oracle detail" not in result.model_dump_json()


@pytest.mark.asyncio
async def test_reset_is_bounded_and_cleanup_still_runs() -> None:
    environment = NeverResetEnvironment()
    result = await ReplayKernel(environment, {}, reset_timeout_seconds=0.01).replay(
        run_id="run.reset-timeout",
        plan=_plan(_action(1)),
        root=_root(),
    )

    assert result.steps[0].failure_code == "RESET_TIMEOUT"
    assert result.failed_step_id == "environment"
    assert environment.cleanup_calls == 1


def test_duplicate_idempotency_key_is_rejected_before_execution() -> None:
    first = _action(1)
    duplicate = _action(2).model_copy(update={"idempotency_key": first.idempotency_key})

    with pytest.raises(ValidationError, match="idempotency_key"):
        _plan(first, duplicate)


@pytest.mark.parametrize("reserved", ["root", "preflight", "environment", "cleanup"])
def test_plan_rejects_reserved_boundary_step_ids(reserved: str) -> None:
    with pytest.raises(ValidationError, match="reserved boundary"):
        ReplayPlan(
            plan_id="plan.reserved",
            root_seed_id="root.001",
            steps=(ReplayStep(step_id=reserved, action=_action(1)),),
        )


def test_canonical_hash_is_independent_of_mapping_insertion_order() -> None:
    assert canonical_sha256({"a": 1, "b": 2}) == canonical_sha256({"b": 2, "a": 1})


def test_canonical_hash_sorts_unordered_containers_recursively() -> None:
    unordered = {"results": frozenset({"VIOLATED", "SATISFIED", "INCONCLUSIVE"})}
    canonical = {"results": ["INCONCLUSIVE", "SATISFIED", "VIOLATED"]}

    assert canonical_sha256(unordered) == canonical_sha256(canonical)
