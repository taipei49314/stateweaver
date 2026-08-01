"""Clean-root, fail-closed deterministic replay orchestration."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence

from stateweaver.contracts import HttpRequestAction, OracleResult
from stateweaver.replay.models import (
    DeterminismClassification,
    DeterminismReport,
    ReplayActionLogEntry,
    ReplayObservation,
    ReplayPlan,
    ReplayRunResult,
    ReplayRunStatus,
    ReplayStep,
    ReplayStepResult,
    ReplayStepStatus,
    RootSeed,
    StateCapture,
    canonical_sha256,
)
from stateweaver.replay.ports import ReplayEnvironment, ReplayOracle


class ReplayKernel:
    """Execute typed plans from a pinned clean state with precise failure attribution."""

    def __init__(
        self,
        environment: ReplayEnvironment,
        oracles: Mapping[str, ReplayOracle],
        *,
        reset_timeout_seconds: float = 10.0,
        cleanup_timeout_seconds: float = 10.0,
    ) -> None:
        if reset_timeout_seconds <= 0 or reset_timeout_seconds > 60:
            raise ValueError("reset_timeout_seconds must be in (0, 60]")
        if cleanup_timeout_seconds <= 0 or cleanup_timeout_seconds > 60:
            raise ValueError("cleanup_timeout_seconds must be in (0, 60]")
        self._environment = environment
        self._oracles = dict(oracles)
        self._reset_timeout_seconds = reset_timeout_seconds
        self._cleanup_timeout_seconds = cleanup_timeout_seconds

    async def replay(
        self,
        *,
        run_id: str,
        plan: ReplayPlan,
        root: RootSeed,
    ) -> ReplayRunResult:
        """Replay once, stopping at and recording the first failing step."""

        results: list[ReplayStepResult] = []
        root_capture: StateCapture | None = None
        final_capture: StateCapture | None = None
        run_status = ReplayRunStatus.FAILED
        failed_step_id: str | None = None
        cleanup_failure: str | None = None
        environment_phase = "preflight"

        try:
            if plan.root_seed_id != root.root_seed_id:
                failed_step_id = "preflight"
                results.append(
                    ReplayStepResult(
                        step_id="preflight",
                        status=ReplayStepStatus.FAILED,
                        failure_code="PLAN_ROOT_MISMATCH",
                        failure_message="plan and root identifiers do not match",
                    )
                )
            else:
                environment_phase = "reset"
                async with asyncio.timeout(self._reset_timeout_seconds):
                    root_capture = await self._environment.reset(root)
                final_capture = root_capture
                environment_phase = "replay"
                if root_capture.fingerprint != root.capture.fingerprint:
                    run_status = ReplayRunStatus.ROOT_DIVERGED
                    failed_step_id = "root"
                    results.append(
                        ReplayStepResult(
                            step_id="root",
                            status=ReplayStepStatus.FAILED,
                            before_fingerprint=root_capture.fingerprint,
                            failure_code="ROOT_FINGERPRINT_MISMATCH",
                            failure_message="restored root did not match the pinned fingerprint",
                        )
                    )
                else:
                    for index, step in enumerate(plan.steps):
                        result, final_capture = await self._execute_step(step, final_capture)
                        results.append(result)
                        if result.status is ReplayStepStatus.FAILED:
                            failed_step_id = step.step_id
                            results.extend(self._skipped_results(plan.steps[index + 1 :]))
                            break
                    else:
                        run_status = ReplayRunStatus.SUCCEEDED
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            results.append(
                ReplayStepResult(
                    step_id="environment",
                    status=ReplayStepStatus.FAILED,
                    failure_code=f"{environment_phase.upper()}_TIMEOUT",
                    failure_message="environment boundary exceeded its bounded timeout",
                )
            )
            failed_step_id = "environment"
        except Exception as exc:  # adapters are untrusted boundaries; convert to typed failure
            failure_code = type(exc).__name__
            results.append(
                ReplayStepResult(
                    step_id="environment",
                    status=ReplayStepStatus.FAILED,
                    failure_code=f"{environment_phase.upper()}_FAILURE",
                    failure_message=failure_code,
                )
            )
            failed_step_id = "environment"
        finally:
            try:
                async with asyncio.timeout(self._cleanup_timeout_seconds):
                    await self._environment.cleanup()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # cleanup outcome must be visible but sanitized
                cleanup_failure = type(exc).__name__

        if cleanup_failure is not None:
            run_status = ReplayRunStatus.CLEANUP_FAILED
            results.append(
                ReplayStepResult(
                    step_id="cleanup",
                    status=ReplayStepStatus.FAILED,
                    failure_code="CLEANUP_FAILURE",
                    failure_message=cleanup_failure,
                )
            )
            failed_step_id = failed_step_id or "cleanup"

        action_log = self._build_action_log(plan, results)
        trace_hash = canonical_sha256(
            {
                "plan_id": plan.plan_id,
                "status": run_status,
                "root_fingerprint": root_capture.fingerprint if root_capture else None,
                "final_fingerprint": final_capture.fingerprint if final_capture else None,
                "steps": results,
                "action_log": action_log,
                "failed_step_id": failed_step_id,
            }
        )
        return ReplayRunResult(
            run_id=run_id,
            plan_id=plan.plan_id,
            status=run_status,
            root_fingerprint=root_capture.fingerprint if root_capture else None,
            final_fingerprint=final_capture.fingerprint if final_capture else None,
            steps=tuple(results),
            action_log=action_log,
            failed_step_id=failed_step_id,
            trace_hash=trace_hash,
        )

    async def verify_determinism(
        self,
        *,
        plan: ReplayPlan,
        root: RootSeed,
        run_ids: Sequence[str],
    ) -> DeterminismReport:
        """Replay serially from the same root and compare semantic signatures."""

        if len(run_ids) < 2:
            raise ValueError("determinism verification requires at least two runs")
        if len(run_ids) != len(set(run_ids)):
            raise ValueError("run_ids must be unique")

        runs = [await self.replay(run_id=run_id, plan=plan, root=root) for run_id in run_ids]
        signatures = tuple(run.deterministic_signature() for run in runs)
        reference = signatures[0]
        divergent_index = next(
            (index for index, signature in enumerate(signatures) if signature != reference), None
        )
        return DeterminismReport(
            plan_id=plan.plan_id,
            run_ids=tuple(run_ids),
            run_statuses=tuple(run.status for run in runs),
            signatures=signatures,
            deterministic=divergent_index is None,
            all_runs_succeeded=all(run.status is ReplayRunStatus.SUCCEEDED for run in runs),
            classification=(
                DeterminismClassification.DETERMINISTIC
                if divergent_index is None
                else DeterminismClassification.NONDETERMINISTIC
            ),
            divergent_run_id=None if divergent_index is None else run_ids[divergent_index],
        )

    async def _execute_step(
        self,
        step: ReplayStep,
        fallback_capture: StateCapture,
    ) -> tuple[ReplayStepResult, StateCapture]:
        before: StateCapture | None = None
        observations: tuple[ReplayObservation, ...] = ()
        after: StateCapture | None = None
        oracle_results: tuple[OracleResult, ...] = ()
        phase = "capture_before"
        try:
            async with asyncio.timeout(step.timeout_seconds):
                before = await self._environment.capture()
                phase = "execute"
                observations = await self._environment.execute(step.action)
                phase = "capture_after"
                after = await self._environment.capture()
                phase = "oracle"
                oracle_results = await self._evaluate_oracles(step, before, after, observations)
                if not self._expectations_match(step, oracle_results):
                    return (
                        ReplayStepResult(
                            step_id=step.step_id,
                            status=ReplayStepStatus.FAILED,
                            before_fingerprint=before.fingerprint,
                            after_fingerprint=after.fingerprint,
                            observations=observations,
                            oracle_results=oracle_results,
                            failure_code="ORACLE_EXPECTATION_MISMATCH",
                            failure_message="oracle result was outside the allowed result set",
                        ),
                        after,
                    )
        except TimeoutError:
            recovered = after or await self._best_effort_capture(step.timeout_seconds)
            stable = recovered or before or fallback_capture
            return (
                ReplayStepResult(
                    step_id=step.step_id,
                    status=ReplayStepStatus.FAILED,
                    before_fingerprint=(before or fallback_capture).fingerprint,
                    after_fingerprint=recovered.fingerprint if recovered else None,
                    observations=observations,
                    oracle_results=oracle_results,
                    failure_code=f"{phase.upper()}_TIMEOUT",
                    failure_message="replay boundary exceeded its bounded timeout",
                ),
                stable,
            )
        except Exception as exc:
            recovered = after or await self._best_effort_capture(step.timeout_seconds)
            stable = recovered or before or fallback_capture
            return (
                ReplayStepResult(
                    step_id=step.step_id,
                    status=ReplayStepStatus.FAILED,
                    before_fingerprint=(before or fallback_capture).fingerprint,
                    after_fingerprint=recovered.fingerprint if recovered else None,
                    observations=observations,
                    oracle_results=oracle_results,
                    failure_code=f"{phase.upper()}_FAILURE",
                    failure_message=type(exc).__name__,
                ),
                stable,
            )

        assert before is not None
        assert after is not None
        return (
            ReplayStepResult(
                step_id=step.step_id,
                status=ReplayStepStatus.PASSED,
                before_fingerprint=before.fingerprint,
                after_fingerprint=after.fingerprint,
                observations=observations,
                oracle_results=oracle_results,
            ),
            after,
        )

    async def _best_effort_capture(self, step_timeout_seconds: float) -> StateCapture | None:
        try:
            async with asyncio.timeout(min(step_timeout_seconds, 2.0)):
                return await self._environment.capture()
        except asyncio.CancelledError:
            raise
        except Exception:
            return None

    async def _evaluate_oracles(
        self,
        step: ReplayStep,
        before: StateCapture,
        after: StateCapture,
        observations: tuple[ReplayObservation, ...],
    ) -> tuple[OracleResult, ...]:
        results: list[OracleResult] = []
        for expectation in step.oracle_expectations:
            oracle = self._oracles.get(expectation.oracle_id)
            if oracle is None:
                raise LookupError(f"oracle is not registered: {expectation.oracle_id}")
            result = await oracle.evaluate(before, step.action, after, observations)
            results.append(result)
        return tuple(results)

    @staticmethod
    def _expectations_match(step: ReplayStep, results: tuple[OracleResult, ...]) -> bool:
        if len(step.oracle_expectations) != len(results):
            return False
        for expectation, result in zip(step.oracle_expectations, results, strict=True):
            verdict = str(result.result)
            if verdict not in expectation.allowed_results:
                return False
        return True

    @staticmethod
    def _skipped_results(steps: Sequence[ReplayStep]) -> list[ReplayStepResult]:
        return [
            ReplayStepResult(step_id=step.step_id, status=ReplayStepStatus.SKIPPED)
            for step in steps
        ]

    @staticmethod
    def _build_action_log(
        plan: ReplayPlan,
        results: Sequence[ReplayStepResult],
    ) -> tuple[ReplayActionLogEntry, ...]:
        result_by_step = {result.step_id: result for result in results}
        entries: list[ReplayActionLogEntry] = []
        for step in plan.steps:
            result = result_by_step.get(step.step_id)
            if result is None:
                continue
            envelope_hash = canonical_sha256(step.action)
            trace_id = canonical_sha256(
                {
                    "plan_id": plan.plan_id,
                    "step_id": step.step_id,
                    "envelope_hash": envelope_hash,
                }
            ).removeprefix("sha256:")[:32]
            action = step.action.action
            parameter_artifact = (
                action.body_artifact if isinstance(action, HttpRequestAction) else None
            )
            evidence_ids = tuple(
                dict.fromkeys(
                    evidence_id
                    for evidence_group in (
                        *(item.evidence_ids for item in result.observations),
                        *(item.evidence_ids for item in result.oracle_results),
                    )
                    for evidence_id in evidence_group
                )
            )
            entries.append(
                ReplayActionLogEntry(
                    step_id=step.step_id,
                    action=step.action,
                    action_id=step.action.action_id,
                    action_type=step.action.action_type,
                    sequence=step.action.sequence,
                    status=result.status,
                    idempotency_key=step.action.idempotency_key,
                    policy_decision_ref=step.action.policy_decision_ref,
                    trace_id=trace_id,
                    parameter_artifact=parameter_artifact,
                    envelope_hash=envelope_hash,
                    request_template_hash=canonical_sha256(action),
                    before_fingerprint=result.before_fingerprint,
                    after_fingerprint=result.after_fingerprint,
                    observation_hash=canonical_sha256(result.observations),
                    oracle_results_hash=canonical_sha256(result.oracle_results),
                    evidence_ids=evidence_ids,
                )
            )
        return tuple(entries)
