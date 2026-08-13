"""Bind process-local M5 semantics to closed Docker provider witnesses."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from pathlib import Path
from typing import ClassVar, Literal, Protocol, cast

from pydantic import BaseModel, ConfigDict, ValidationError, model_validator
from stateweaver.adapters.docker_compose import (
    M5MaterializedProviderRunReceipt,
    M5MaterializedProviderRunRequest,
    RealDockerComposeEnvironmentAdapter,
)
from stateweaver.contracts import (
    ActionEnvelope,
    OracleOutcome,
    Sha256Digest,
    WorldTier,
    canonical_json_bytes,
    sha256_digest,
)
from stateweaver.replay import ReplayActionLogEntry, ReplayPlan, ReplayRunResult, RootSeed

from .materialized_search_qualification import MaterializedSearchQualificationReceipt
from .observed_chain_qualification import (
    M5ControlName,
    ObservedChainQualificationReceipt,
)

_MARKER_RE = re.compile(r"^[0-9a-f]{40}$")
_PROVIDERS = ("cache", "clock", "database", "filesystem", "queue", "session")
_LIMITATIONS = (
    "This artifact retains bounded Docker executions over six real providers and exact process "
    "M5 action bytes as a prerequisite witness.",
    "The Docker provider bridge does not execute or trace FastAPI, so this artifact does not "
    "close SW-M5-CHAIN or prove one materialized application execution boundary.",
)


class MaterializedChainQualificationError(ValueError):
    """Value-safe rejection at the process-to-provider M5 boundary."""


class _M5Model(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)


class ProviderCaptureWitness(_M5Model):
    before: Sha256Digest
    after: Sha256Digest

    @model_validator(mode="after")
    def changed(self) -> ProviderCaptureWitness:
        if self.before == self.after:
            raise ValueError("M5 provider capture did not change")
        return self


class MaterializedStepWitness(_M5Model):
    step_id: str
    action: ActionEnvelope
    action_digest: Sha256Digest
    response_status: int
    oracle_outcome: OracleOutcome
    provider_captures: dict[str, ProviderCaptureWitness]

    @model_validator(mode="after")
    def content_bound(self) -> MaterializedStepWitness:
        if (
            self.action_digest != sha256_digest(self.action)
            or tuple(sorted(self.provider_captures)) != _PROVIDERS
        ):
            raise ValueError("M5 materialized step witness is invalid")
        return self


class MaterializedRunWitness(_M5Model):
    run_id: str
    root: RootSeed
    root_digest: Sha256Digest
    result: ReplayRunResult
    result_digest: Sha256Digest
    action_log: tuple[ReplayActionLogEntry, ...]
    action_log_digest: Sha256Digest
    steps: tuple[MaterializedStepWitness, ...]
    provider_run_receipt: M5MaterializedProviderRunReceipt
    provider_run_receipt_digest: Sha256Digest

    @model_validator(mode="after")
    def process_and_provider_are_exact(self) -> MaterializedRunWitness:
        provider = self.provider_run_receipt
        if (
            self.run_id != self.result.run_id
            or self.root_digest != sha256_digest(self.root)
            or self.result_digest != sha256_digest(self.result)
            or self.action_log != self.result.action_log
            or self.action_log_digest != sha256_digest(self.action_log)
            or self.provider_run_receipt_digest != provider.receipt_digest
            or self.run_id != provider.request.run_id
            or tuple(item.action for item in self.action_log) != provider.request.actions
            or tuple(item.step_id for item in self.steps)
            != tuple(item.step_id for item in provider.steps)
            or tuple(item.action for item in self.steps)
            != tuple(item.action for item in provider.steps)
            or tuple(item.action_digest for item in self.steps)
            != tuple(item.action_digest for item in provider.steps)
        ):
            raise ValueError("M5 materialized run witness is not cross-bound")
        for projected, retained in zip(self.steps, provider.steps, strict=True):
            expected = {
                before.provider: ProviderCaptureWitness(
                    before=before.sha256,
                    after=after.sha256,
                )
                for before, after in zip(retained.before, retained.after, strict=True)
            }
            if (
                projected.response_status != retained.response_status
                or projected.oracle_outcome.value != retained.oracle_outcome
                or projected.provider_captures != expected
            ):
                raise ValueError("M5 materialized provider projection is invalid")
        return self


class MaterializedControlWitness(MaterializedRunWitness):
    name: M5ControlName
    plan: ReplayPlan

    @model_validator(mode="after")
    def control_plan_is_exact(self) -> MaterializedControlWitness:
        if tuple(item.action for item in self.plan.steps) != tuple(
            item.action for item in self.action_log
        ):
            raise ValueError("M5 materialized control plan is substituted")
        return self


class MaterializedCleanupWitness(_M5Model):
    status: Literal["PASS"]
    destroyed: Literal[True]
    residual_containers: Literal[0]
    residual_networks: Literal[0]
    residual_volumes: Literal[0]


class MaterializedChainQualificationReceipt(_M5Model):
    """Prerequisite-only composite of process semantics and real-provider witnesses."""

    schema_version: Literal["stateweaver-m5-materialized-provider-qualification-v1"]
    status: Literal["M5_MATERIALIZED_PROVIDER_WITNESS_RETAINED"]
    repository_marker: str
    provider_runtime: Literal["docker-compose-real-providers@0.1.0"]
    provider_names: tuple[str, ...]
    m4_receipt_json: str
    m4_receipt_sha256: Sha256Digest
    m4_receipt_digest: Sha256Digest
    m4_winner_provider_state_digest: Sha256Digest
    process_receipt_json: str
    process_receipt_sha256: Sha256Digest
    process_receipt_digest: Sha256Digest
    plan: ReplayPlan
    plan_digest: Sha256Digest
    clean_root_runs: tuple[MaterializedRunWitness, ...]
    patched_run: MaterializedRunWitness
    negative_controls: tuple[MaterializedControlWitness, ...]
    cleanup_count: Literal[10]
    cleanup: MaterializedCleanupWitness
    limitations: tuple[str, ...]
    release_eligible: Literal[False]
    receipt_digest: Sha256Digest

    @model_validator(mode="after")
    def composite_is_closed(self) -> MaterializedChainQualificationReceipt:
        try:
            m4 = MaterializedSearchQualificationReceipt.model_validate_json(self.m4_receipt_json)
            process = ObservedChainQualificationReceipt.model_validate_json(
                self.process_receipt_json
            )
        except (ValidationError, TypeError, ValueError, RecursionError):
            raise ValueError("M5 materialized composite input is invalid") from None
        m4_bytes = self.m4_receipt_json.encode("utf-8")
        process_bytes = self.process_receipt_json.encode("utf-8")
        winner = tuple(
            item
            for item in m4.provider_receipts
            if item.request.candidate_id == m4.winner.candidate_id
            and item.request.target_tier is WorldTier.MATERIALIZED
        )

        def run_is_bound(
            witness: MaterializedRunWitness,
            *,
            result: ReplayRunResult,
            root: RootSeed,
            plan: ReplayPlan,
            scenario: str,
        ) -> bool:
            request = witness.provider_run_receipt.request
            outcome, response_status = _terminal(result)
            patched = scenario == "primary_patched"
            return (
                witness.result == result
                and witness.root == root
                and witness.action_log == result.action_log
                and tuple(item.action for item in witness.action_log)
                == tuple(item.action for item in plan.steps)
                and request.repository_marker == self.repository_marker
                and request.m4_provider_receipt == winner[0]
                and request.m4_receipt_sha256 == self.m4_receipt_sha256
                and request.m4_receipt_digest == self.m4_receipt_digest
                and request.process_receipt_sha256 == self.process_receipt_sha256
                and request.process_receipt_digest == self.process_receipt_digest
                and request.plan_id == plan.plan_id
                and request.root_seed_id == root.root_seed_id
                and request.root_digest == sha256_digest(root)
                and request.plan_digest == sha256_digest(plan)
                and request.run_id == result.run_id
                and request.scenario == scenario
                and request.mode == ("patched" if patched else "vulnerable")
                and request.actions == tuple(item.action for item in plan.steps)
                and request.expected_oracle_outcome == outcome.value
                and request.expected_response_status == response_status
                and request.expected_failed_step_id == (result.failed_step_id if patched else None)
                and request.expected_failure_code
                == ("ORACLE_EXPECTATION_MISMATCH" if patched else None)
            )

        runs_bound = len(winner) == 1 and all(
            run_is_bound(
                retained,
                result=result,
                root=process.clean_root,
                plan=process.replay_plan,
                scenario="primary_vulnerable",
            )
            for retained, result in zip(self.clean_root_runs, process.runs, strict=True)
        )
        patched_bound = len(winner) == 1 and run_is_bound(
            self.patched_run,
            result=process.patched_run,
            root=process.patched_root,
            plan=process.replay_plan,
            scenario="primary_patched",
        )
        controls_bound = len(winner) == 1 and all(
            retained.name == control.name
            and retained.plan == control.plan
            and run_is_bound(
                retained,
                result=control.result,
                root=control.root,
                plan=control.plan,
                scenario=control.name,
            )
            for retained, control in zip(
                self.negative_controls, process.negative_controls, strict=True
            )
        )
        if (
            _MARKER_RE.fullmatch(self.repository_marker) is None
            or self.provider_names != _PROVIDERS
            or canonical_json_bytes(json.loads(self.m4_receipt_json)) + b"\n" != m4_bytes
            or canonical_json_bytes(json.loads(self.process_receipt_json)) + b"\n" != process_bytes
            or self.m4_receipt_sha256 != f"sha256:{hashlib.sha256(m4_bytes).hexdigest()}"
            or self.process_receipt_sha256 != f"sha256:{hashlib.sha256(process_bytes).hexdigest()}"
            or m4.repository_marker != self.repository_marker
            or process.repository_marker != self.repository_marker
            or process.m4_receipt_json != self.m4_receipt_json
            or self.m4_receipt_digest != m4.receipt_digest
            or self.process_receipt_digest != process.receipt_digest
            or len(winner) != 1
            or not runs_bound
            or not patched_bound
            or not controls_bound
            or self.m4_winner_provider_state_digest != winner[0].provider_state_digest
            or self.plan != process.replay_plan
            or self.plan_digest != process.replay_plan_digest
            or tuple(item.run_id for item in self.clean_root_runs)
            != tuple(item.run_id for item in process.runs)
            or len(self.clean_root_runs) != 5
            or self.patched_run.run_id != process.patched_run.run_id
            or tuple(item.name for item in self.negative_controls)
            != tuple(item.name for item in process.negative_controls)
            or self.limitations != _LIMITATIONS
        ):
            raise ValueError("M5 materialized provider composite is incoherent")
        expected = sha256_digest(self.model_dump(mode="python", exclude={"receipt_digest"}))
        if self.receipt_digest != expected:
            raise ValueError("M5 materialized provider composite digest is invalid")
        return self


class _ProviderRunner(Protocol):
    async def run_m5_materialized_provider(
        self,
        request: M5MaterializedProviderRunRequest,
    ) -> M5MaterializedProviderRunReceipt: ...


def _terminal(result: ReplayRunResult) -> tuple[OracleOutcome, int]:
    if not result.steps or not result.steps[-1].oracle_results:
        raise MaterializedChainQualificationError("M5 process result lacks an oracle boundary")
    outcome = result.steps[-1].oracle_results[-1].result
    observations = result.steps[-1].observations
    status = observations[-1].payload.get("response_status") if observations else None
    if type(status) is not int:
        raise MaterializedChainQualificationError("M5 process result lacks a response boundary")
    return outcome, status


def _project_run(
    *,
    result: ReplayRunResult,
    root: RootSeed,
    provider: M5MaterializedProviderRunReceipt,
) -> MaterializedRunWitness:
    steps = tuple(
        MaterializedStepWitness(
            step_id=item.step_id,
            action=item.action,
            action_digest=item.action_digest,
            response_status=item.response_status,
            oracle_outcome=OracleOutcome(item.oracle_outcome),
            provider_captures={
                before.provider: ProviderCaptureWitness(
                    before=before.sha256,
                    after=after.sha256,
                )
                for before, after in zip(item.before, item.after, strict=True)
            },
        )
        for item in provider.steps
    )
    return MaterializedRunWitness(
        run_id=result.run_id,
        root=root,
        root_digest=sha256_digest(root),
        result=result,
        result_digest=sha256_digest(result),
        action_log=result.action_log,
        action_log_digest=sha256_digest(result.action_log),
        steps=steps,
        provider_run_receipt=provider,
        provider_run_receipt_digest=provider.receipt_digest,
    )


async def _qualify(
    *,
    m4_bytes: bytes,
    m4: MaterializedSearchQualificationReceipt,
    process_bytes: bytes,
    process: ObservedChainQualificationReceipt,
    adapter: _ProviderRunner,
) -> MaterializedChainQualificationReceipt:
    winner = tuple(
        item
        for item in m4.provider_receipts
        if item.request.candidate_id == m4.winner.candidate_id
        and item.request.target_tier is WorldTier.MATERIALIZED
    )
    if len(winner) != 1:
        raise MaterializedChainQualificationError("M5 materialized winner is ambiguous")
    m4_sha = f"sha256:{hashlib.sha256(m4_bytes).hexdigest()}"
    process_sha = f"sha256:{hashlib.sha256(process_bytes).hexdigest()}"

    async def execute(
        *,
        scenario: Literal[
            "primary_vulnerable",
            "primary_patched",
            "masked_response",
            "mock_only_response",
            "fresh_session",
            "same_tenant_document",
        ],
        plan: ReplayPlan,
        root: RootSeed,
        result: ReplayRunResult,
    ) -> MaterializedRunWitness:
        outcome, status = _terminal(result)
        patched = scenario == "primary_patched"
        if patched and (
            result.failed_step_id != "step.08"
            or result.steps[-1].failure_code != "ORACLE_EXPECTATION_MISMATCH"
        ):
            raise MaterializedChainQualificationError("M5 patched process boundary is not exact")
        request = M5MaterializedProviderRunRequest(
            repository_marker=m4.repository_marker,
            m4_provider_receipt=winner[0],
            m4_receipt_sha256=m4_sha,
            m4_receipt_digest=m4.receipt_digest,
            process_receipt_sha256=process_sha,
            process_receipt_digest=process.receipt_digest,
            plan_id=plan.plan_id,
            root_seed_id=root.root_seed_id,
            root_digest=sha256_digest(root),
            plan_digest=sha256_digest(plan),
            run_id=result.run_id,
            scenario=scenario,
            mode="patched" if patched else "vulnerable",
            actions=tuple(item.action for item in plan.steps),
            expected_oracle_outcome=cast(
                Literal["VIOLATED", "SATISFIED", "INCONCLUSIVE"], outcome.value
            ),
            expected_response_status=status,
            expected_failed_step_id=result.failed_step_id if patched else None,
            expected_failure_code="ORACLE_EXPECTATION_MISMATCH" if patched else None,
        )
        retained = await adapter.run_m5_materialized_provider(request)
        return _project_run(result=result, root=root, provider=retained)

    clean = tuple(
        [
            await execute(
                scenario="primary_vulnerable",
                plan=process.replay_plan,
                root=process.clean_root,
                result=result,
            )
            for result in process.runs
        ]
    )
    patched = await execute(
        scenario="primary_patched",
        plan=process.replay_plan,
        root=process.patched_root,
        result=process.patched_run,
    )
    controls: list[MaterializedControlWitness] = []
    for control in process.negative_controls:
        projected = await execute(
            scenario=control.name,
            plan=control.plan,
            root=control.root,
            result=control.result,
        )
        controls.append(
            MaterializedControlWitness(
                **projected.model_dump(mode="python"),
                name=control.name,
                plan=control.plan,
            )
        )
    values: dict[str, object] = {
        "schema_version": "stateweaver-m5-materialized-provider-qualification-v1",
        "status": "M5_MATERIALIZED_PROVIDER_WITNESS_RETAINED",
        "repository_marker": m4.repository_marker,
        "provider_runtime": "docker-compose-real-providers@0.1.0",
        "provider_names": _PROVIDERS,
        "m4_receipt_json": m4_bytes.decode("utf-8"),
        "m4_receipt_sha256": m4_sha,
        "m4_receipt_digest": m4.receipt_digest,
        "m4_winner_provider_state_digest": winner[0].provider_state_digest,
        "process_receipt_json": process_bytes.decode("utf-8"),
        "process_receipt_sha256": process_sha,
        "process_receipt_digest": process.receipt_digest,
        "plan": process.replay_plan,
        "plan_digest": process.replay_plan_digest,
        "clean_root_runs": clean,
        "patched_run": patched,
        "negative_controls": tuple(controls),
        "cleanup_count": 10,
        "cleanup": MaterializedCleanupWitness(
            status="PASS",
            destroyed=True,
            residual_containers=0,
            residual_networks=0,
            residual_volumes=0,
        ),
        "limitations": _LIMITATIONS,
        "release_eligible": False,
    }
    try:
        return MaterializedChainQualificationReceipt.model_validate(
            {**values, "receipt_digest": sha256_digest(values)}
        )
    except (ValidationError, TypeError, ValueError):
        raise MaterializedChainQualificationError(
            "M5 materialized provider witness construction failed"
        ) from None


def _read_exact(path: Path, *, limit: int) -> bytes:
    if path.is_symlink():
        raise MaterializedChainQualificationError("M5 input path is invalid")
    try:
        size = path.stat().st_size
        content = path.read_bytes()
    except OSError:
        raise MaterializedChainQualificationError("M5 input is unreadable") from None
    if size != len(content) or not 1 <= size <= limit:
        raise MaterializedChainQualificationError("M5 input size is invalid")
    return content


def qualify_materialized_chain(
    *,
    m4_receipt_path: Path,
    process_receipt_path: Path,
    repository_marker: str,
    adapter: _ProviderRunner | None = None,
) -> MaterializedChainQualificationReceipt:
    """Retain ten closed Docker provider witnesses without upgrading SW-M5."""

    if _MARKER_RE.fullmatch(repository_marker) is None:
        raise MaterializedChainQualificationError("repository marker must be an exact Git SHA")
    m4_bytes = _read_exact(m4_receipt_path, limit=4 * 1_048_576)
    process_bytes = _read_exact(process_receipt_path, limit=8 * 1_048_576)
    try:
        m4 = MaterializedSearchQualificationReceipt.model_validate_json(m4_bytes)
        process = ObservedChainQualificationReceipt.model_validate_json(process_bytes)
    except (ValidationError, TypeError, ValueError, RecursionError):
        raise MaterializedChainQualificationError("M5 retained inputs are invalid") from None
    if (
        canonical_json_bytes(m4) + b"\n" != m4_bytes
        or canonical_json_bytes(process) + b"\n" != process_bytes
        or m4.repository_marker != repository_marker
        or process.repository_marker != repository_marker
        or process.m4_receipt_json.encode("utf-8") != m4_bytes
    ):
        raise MaterializedChainQualificationError("M5 retained inputs are not exact")
    runner = RealDockerComposeEnvironmentAdapter() if adapter is None else adapter
    return asyncio.run(
        _qualify(
            m4_bytes=m4_bytes,
            m4=m4,
            process_bytes=process_bytes,
            process=process,
            adapter=runner,
        )
    )


def write_materialized_chain_qualification(
    output: Path,
    receipt: MaterializedChainQualificationReceipt,
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical_json_bytes(receipt) + b"\n")


__all__ = [
    "MaterializedChainQualificationError",
    "MaterializedChainQualificationReceipt",
    "qualify_materialized_chain",
    "write_materialized_chain_qualification",
]
