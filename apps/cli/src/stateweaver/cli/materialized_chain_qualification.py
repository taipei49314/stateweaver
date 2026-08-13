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
    ApplicationImageBinding,
    M4MaterializedStateBinding,
    M5MaterializedProviderRunReceipt,
    M5MaterializedProviderRunRequest,
    MaterializedLabRunReceipt,
    MaterializedLabRunRequest,
    RealDockerComposeEnvironmentAdapter,
)
from stateweaver.adapters.in_process_lab import FixedLabActionRegistry
from stateweaver.contracts import (
    ActionEnvelope,
    OracleOutcome,
    Sha256Digest,
    WorldTier,
    canonical_json_bytes,
    sha256_digest,
)
from stateweaver.policy import PolicyAuthorization, PolicyRequest
from stateweaver.replay import ReplayActionLogEntry, ReplayPlan, ReplayRunResult, RootSeed

from .m5_plan import M5ControlName, M5ExecutionPlan, compile_m5_plan
from .materialized_search_qualification import MaterializedSearchQualificationReceipt
from .observed_chain_qualification import ObservedChainQualificationReceipt

_MARKER_RE = re.compile(r"^[0-9a-f]{40}$")
_PROVIDERS = ("cache", "clock", "database", "filesystem", "queue", "session")
_LIMITATIONS = (
    "This artifact retains bounded Docker executions over six real providers and exact process "
    "M5 action bytes as a prerequisite witness.",
    "The Docker provider bridge does not execute or trace FastAPI, so this artifact does not "
    "close SW-M5-CHAIN or prove one materialized application execution boundary.",
)
_ACTUAL_RUNTIME = "docker-compose-fastapi-asgi-six-provider@0.1.0"
_CONTROL_NAMES: tuple[M5ControlName, ...] = (
    "masked_response",
    "mock_only_response",
    "fresh_session",
    "same_tenant_document",
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
        expected = sha256_digest(
            _json_compatible(self.model_dump(mode="python", exclude={"receipt_digest"}))
        )
        if self.receipt_digest != expected:
            raise ValueError("M5 materialized provider composite digest is invalid")
        return self


class ActualMaterializedRunWitness(_M5Model):
    """One actual-ASGI scenario projected against the exact shared M5 plan."""

    run_id: str
    process_result_digest: Sha256Digest
    root: RootSeed
    root_digest: Sha256Digest
    plan: ReplayPlan
    plan_digest: Sha256Digest
    expected_oracle_outcome: OracleOutcome
    expected_response_status: int
    materialized_run_receipt: MaterializedLabRunReceipt
    materialized_run_receipt_digest: Sha256Digest

    @model_validator(mode="after")
    def _exact_scenario(self) -> ActualMaterializedRunWitness:
        retained = self.materialized_run_receipt
        terminal = retained.steps[-1]
        if (
            self.root_digest != sha256_digest(self.root)
            or self.plan_digest != sha256_digest(self.plan)
            or retained.status != "M5_MATERIALIZED_APPLICATION_SCENARIO_EXECUTED"
            or self.materialized_run_receipt_digest != retained.receipt_digest
            or retained.request.run_id != self.run_id
            or retained.request.plan_id != self.plan.plan_id
            or retained.request.root_seed_id != self.root.root_seed_id
            or retained.request.root_digest != self.root_digest
            or retained.request.plan_digest != self.plan_digest
            or retained.request.actions != tuple(item.action for item in self.plan.steps)
            or tuple(item.step_id for item in retained.steps)
            != tuple(item.step_id for item in self.plan.steps)
            or terminal.oracle.verdict
            != (
                "VIOLATED"
                if self.expected_oracle_outcome is OracleOutcome.VIOLATED
                else "NOT_VIOLATED"
            )
            or terminal.trace.response_status != self.expected_response_status
        ):
            raise ValueError("M5 actual materialized scenario is not cross-bound")
        return self


class ActualMaterializedControlWitness(ActualMaterializedRunWitness):
    name: M5ControlName

    @model_validator(mode="after")
    def _named_control(self) -> ActualMaterializedControlWitness:
        if self.materialized_run_receipt.request.scenario != self.name:
            raise ValueError("M5 actual materialized control name was substituted")
        return self


class ActualMaterializedChainQualificationReceipt(_M5Model):
    """Closed ten-run actual FastAPI/ASGI M5 qualification composite."""

    schema_version: Literal["stateweaver-m5-materialized-actual-asgi-qualification-v1"]
    status: Literal["M5_MATERIALIZED_ACTUAL_ASGI_QUALIFIED"]
    repository_marker: str
    runtime: Literal["docker-compose-fastapi-asgi-six-provider@0.1.0"]
    m4_receipt_json: str
    m4_receipt_sha256: Sha256Digest
    m4_receipt_digest: Sha256Digest
    m4_winner_state_binding_digest: Sha256Digest
    m4_source_snapshot_digest: Sha256Digest
    m4_after_archive_digest: Sha256Digest
    m4_provider_state_digest: Sha256Digest
    process_receipt_json: str
    process_receipt_sha256: Sha256Digest
    process_receipt_digest: Sha256Digest
    execution_plan_digest: Sha256Digest
    primary_plan: ReplayPlan
    primary_plan_digest: Sha256Digest
    application_image_binding: ApplicationImageBinding
    clean_root_runs: tuple[ActualMaterializedRunWitness, ...]
    vulnerable_deterministic_signatures: tuple[Sha256Digest, ...]
    initial_checkpoint_bytes_digest: Sha256Digest
    patched_run: ActualMaterializedRunWitness
    negative_controls: tuple[ActualMaterializedControlWitness, ...]
    cleanup_count: Literal[10]
    all_cleanups_passed: Literal[True]
    all_projects_destroyed: Literal[True]
    receipt_digest: Sha256Digest

    @model_validator(mode="after")
    def _closed_actual_asgi_composite(self) -> ActualMaterializedChainQualificationReceipt:
        try:
            m4 = MaterializedSearchQualificationReceipt.model_validate_json(self.m4_receipt_json)
            process = ObservedChainQualificationReceipt.model_validate_json(
                self.process_receipt_json
            )
            execution = compile_m5_plan(m4)
        except (ValidationError, TypeError, ValueError, RecursionError):
            raise ValueError("M5 actual materialized inputs are invalid") from None
        m4_bytes = self.m4_receipt_json.encode("utf-8")
        process_bytes = self.process_receipt_json.encode("utf-8")
        lineage = m4.winner_materialized_state
        runs = self.clean_root_runs
        initial_bytes = tuple(
            item.materialized_run_receipt.initial_checkpoint.checkpoint_bytes for item in runs
        )
        expected_signatures = tuple(
            _actual_run_signature(item.materialized_run_receipt) for item in runs
        )
        primary_requests = tuple(item.materialized_run_receipt.request for item in runs)
        patched = self.patched_run.materialized_run_receipt
        controls = tuple(item.materialized_run_receipt for item in self.negative_controls)
        expected_control_boundaries = {
            item.name: (item.expected_outcome, item.expected_status)
            for item in execution.negative_controls
        }
        common = (*primary_requests, patched.request, *(item.request for item in controls))
        if (
            _MARKER_RE.fullmatch(self.repository_marker) is None
            or self.runtime != _ACTUAL_RUNTIME
            or canonical_json_bytes(json.loads(self.m4_receipt_json)) + b"\n" != m4_bytes
            or canonical_json_bytes(json.loads(self.process_receipt_json)) + b"\n" != process_bytes
            or self.m4_receipt_sha256 != _raw_sha256(m4_bytes)
            or self.process_receipt_sha256 != _raw_sha256(process_bytes)
            or m4.repository_marker != self.repository_marker
            or process.repository_marker != self.repository_marker
            or process.m4_receipt_json != self.m4_receipt_json
            or self.m4_receipt_digest != m4.receipt_digest
            or self.process_receipt_digest != process.receipt_digest
            or self.m4_winner_state_binding_digest != lineage.binding_digest
            or self.m4_source_snapshot_digest != lineage.source_snapshot_manifest_digest
            or self.m4_after_archive_digest != lineage.after_archive_digest
            or self.m4_provider_state_digest != lineage.provider_state_digest
            or self.execution_plan_digest != sha256_digest(_execution_plan_bytes(execution))
            or self.primary_plan != execution.replay_plan
            or self.primary_plan_digest != sha256_digest(execution.replay_plan)
            or any(
                item.image_binding != self.application_image_binding
                for item in (
                    *(run.materialized_run_receipt for run in runs),
                    patched,
                    *controls,
                )
            )
            or len(runs) != 5
            or tuple(item.run_id for item in runs) != tuple(item.run_id for item in process.runs)
            or tuple(item.process_result_digest for item in runs)
            != tuple(sha256_digest(item) for item in process.runs)
            or any(item.root != process.clean_root for item in runs)
            or any(item.plan != execution.replay_plan for item in runs)
            or any(item.expected_oracle_outcome is not OracleOutcome.VIOLATED for item in runs)
            or any(item.expected_response_status != 200 for item in runs)
            or any(
                item.materialized_run_receipt.request.scenario != "primary_vulnerable"
                for item in runs
            )
            or tuple(item.materialized_run_receipt.request.run_id for item in runs)
            != tuple(item.run_id for item in process.runs)
            or len(set(initial_bytes)) != 1
            or self.initial_checkpoint_bytes_digest != _raw_sha256(initial_bytes[0])
            or self.vulnerable_deterministic_signatures != expected_signatures
            or len(set(expected_signatures)) != 1
            or self.patched_run.root != process.patched_root
            or self.patched_run.process_result_digest != sha256_digest(process.patched_run)
            or self.patched_run.plan != execution.replay_plan
            or self.patched_run.expected_oracle_outcome is not OracleOutcome.SATISFIED
            or self.patched_run.expected_response_status != 403
            or patched.request.scenario != "primary_patched"
            or patched.request.run_id != process.patched_run.run_id
            or patched.request.mode != "patched"
            or patched.steps[-1].step_id != "step.08"
            or patched.steps[-1].oracle.verdict != "NOT_VIOLATED"
            or tuple(item.name for item in self.negative_controls) != _CONTROL_NAMES
            or tuple(
                item.materialized_run_receipt.request.run_id for item in self.negative_controls
            )
            != tuple(item.result.run_id for item in process.negative_controls)
            or any(
                (item.expected_oracle_outcome, item.expected_response_status)
                != expected_control_boundaries[item.name]
                for item in self.negative_controls
            )
            or any(
                item.plan != control.replay_plan
                for item, control in zip(
                    self.negative_controls, execution.negative_controls, strict=True
                )
            )
            or any(
                item.root != retained.root
                for item, retained in zip(
                    self.negative_controls, process.negative_controls, strict=True
                )
            )
            or any(
                item.process_result_digest != sha256_digest(retained.result)
                for item, retained in zip(
                    self.negative_controls, process.negative_controls, strict=True
                )
            )
            or any(request.repository_marker != self.repository_marker for request in common)
            or any(request.m4_state_binding_digest != lineage.binding_digest for request in common)
            or any(
                request.m4_source_snapshot_digest != lineage.source_snapshot_manifest_digest
                for request in common
            )
            or any(
                request.m4_after_archive_digest != lineage.after_archive_digest
                for request in common
            )
            or any(
                request.m4_provider_state_digest != lineage.provider_state_digest
                for request in common
            )
            or any(
                item.cleanup_status != "PASS" or not item.destroyed
                for item in (*[run.materialized_run_receipt for run in runs], patched, *controls)
            )
        ):
            raise ValueError("M5 actual materialized composite is incoherent")
        expected = sha256_digest(
            _json_compatible(self.model_dump(mode="python", exclude={"receipt_digest"}))
        )
        if self.receipt_digest != expected:
            raise ValueError("M5 actual materialized composite digest is invalid")
        return self


class _ApplicationRunner(Protocol):
    async def run_m5_materialized_application(
        self, request: MaterializedLabRunRequest
    ) -> MaterializedLabRunReceipt: ...


class _ProviderRunner(Protocol):
    async def run_m5_materialized_provider(
        self,
        request: M5MaterializedProviderRunRequest,
    ) -> M5MaterializedProviderRunReceipt: ...


def _raw_sha256(value: bytes) -> Sha256Digest:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _json_compatible(value: object) -> object:
    if isinstance(value, BaseModel):
        return _json_compatible(value.model_dump(mode="python"))
    if isinstance(value, bytes):
        return value.decode("utf-8")
    if isinstance(value, tuple | list):
        return [_json_compatible(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    return value


def _execution_plan_bytes(execution: M5ExecutionPlan) -> dict[str, object]:
    return {
        "m4_receipt_digest": execution.m4_receipt_digest,
        "observed_chain_digest": execution.observed_chain_digest,
        "compiler_admission": execution.compiler_admission,
        "scope_manifest": execution.scope_manifest,
        "replay_plan": execution.replay_plan,
        "policy_requests": execution.policy_requests,
        "policy_authorizations": execution.policy_authorizations,
        "negative_controls": tuple(
            {
                "name": item.name,
                "expected_outcome": item.expected_outcome,
                "expected_status": item.expected_status,
                "replay_plan": item.replay_plan,
                "policy_requests": item.policy_requests,
                "policy_authorizations": item.policy_authorizations,
            }
            for item in execution.negative_controls
        ),
    }


def _actual_run_signature(receipt: MaterializedLabRunReceipt) -> Sha256Digest:
    """Hash deterministic application semantics while excluding monotonic timings."""

    request_semantics = receipt.request.model_dump(mode="json", exclude={"run_id"})
    return sha256_digest(
        {
            "request": request_semantics,
            "application_schema_digest": receipt.application_schema_digest,
            "initial_checkpoint": receipt.initial_checkpoint.model_dump(mode="json"),
            "steps": tuple(
                {
                    "step_id": item.step_id,
                    "before": item.before.model_dump(mode="json"),
                    "route": item.trace.route,
                    "method": item.trace.method,
                    "response_status": item.trace.response_status,
                    "response_body_digest": item.trace.response_body_digest,
                    "response_evidence_id": item.trace.response_evidence_id,
                    "response_action_id": item.trace.response_action_id,
                    "after": item.after.model_dump(mode="json"),
                    "evidence_digest": item.evidence_digest,
                    "appended_evidence": item.appended_evidence.model_dump(mode="json"),
                    "oracle": item.oracle.model_dump(mode="json"),
                    "oracle_digest": item.oracle_digest,
                    "visibility_commit": item.visibility_commit,
                }
                for item in receipt.steps
            ),
            "final_checkpoint": receipt.final_checkpoint.model_dump(mode="json"),
        }
    )


def _materialized_request(
    *,
    repository_marker: str,
    lineage: M4MaterializedStateBinding,
    scenario: Literal[
        "primary_vulnerable",
        "primary_patched",
        "masked_response",
        "mock_only_response",
        "fresh_session",
        "same_tenant_document",
    ],
    run_id: str,
    root: RootSeed,
    plan: ReplayPlan,
    policy_requests: tuple[PolicyRequest, ...],
    policy_authorizations: tuple[PolicyAuthorization, ...],
    registry: FixedLabActionRegistry,
) -> MaterializedLabRunRequest:
    actions = tuple(item.action for item in plan.steps)
    lab_actions = tuple(registry.by_action_id[item.action_id] for item in actions)
    return MaterializedLabRunRequest(
        repository_marker=repository_marker,
        mode="patched" if scenario == "primary_patched" else "vulnerable",
        scenario=scenario,
        run_id=run_id,
        plan_id=plan.plan_id,
        root_seed_id=root.root_seed_id,
        root_digest=sha256_digest(root),
        plan_digest=sha256_digest(plan),
        m4_state_binding_digest=lineage.binding_digest,
        m4_source_snapshot_digest=lineage.source_snapshot_manifest_digest,
        m4_after_archive_digest=lineage.after_archive_digest,
        m4_provider_state_digest=lineage.provider_state_digest,
        actions=actions,
        action_bytes=tuple(canonical_json_bytes(item) for item in actions),
        lab_actions=lab_actions,
        lab_action_bytes=tuple(canonical_json_bytes(item) for item in lab_actions),
        policy_authorizations=policy_authorizations,
        policy_authorization_bytes=tuple(
            canonical_json_bytes(item) for item in policy_authorizations
        ),
        policy_requests=policy_requests,
        policy_request_bytes=tuple(canonical_json_bytes(item) for item in policy_requests),
    )


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
            {**values, "receipt_digest": sha256_digest(_json_compatible(values))}
        )
    except (ValidationError, TypeError, ValueError):
        raise MaterializedChainQualificationError(
            "M5 materialized provider witness construction failed"
        ) from None


def _actual_witness(
    *,
    run_id: str,
    process_result: ReplayRunResult,
    root: RootSeed,
    plan: ReplayPlan,
    outcome: OracleOutcome,
    status: int,
    receipt: MaterializedLabRunReceipt,
) -> ActualMaterializedRunWitness:
    return ActualMaterializedRunWitness(
        run_id=run_id,
        process_result_digest=sha256_digest(process_result),
        root=root,
        root_digest=sha256_digest(root),
        plan=plan,
        plan_digest=sha256_digest(plan),
        expected_oracle_outcome=outcome,
        expected_response_status=status,
        materialized_run_receipt=receipt,
        materialized_run_receipt_digest=receipt.receipt_digest,
    )


async def _qualify_actual(
    *,
    m4_bytes: bytes,
    m4: MaterializedSearchQualificationReceipt,
    process_bytes: bytes,
    process: ObservedChainQualificationReceipt,
    adapter: _ApplicationRunner,
) -> ActualMaterializedChainQualificationReceipt:
    execution = compile_m5_plan(m4)
    lineage = m4.winner_materialized_state

    async def execute_primary(
        *, mode: Literal["vulnerable", "patched"], result: ReplayRunResult, root: RootSeed
    ) -> ActualMaterializedRunWitness:
        scenario: Literal["primary_vulnerable", "primary_patched"] = (
            "primary_patched" if mode == "patched" else "primary_vulnerable"
        )
        request = _materialized_request(
            repository_marker=m4.repository_marker,
            lineage=lineage,
            scenario=scenario,
            run_id=result.run_id,
            root=root,
            plan=execution.replay_plan,
            policy_requests=execution.policy_requests,
            policy_authorizations=execution.policy_authorizations,
            registry=execution.registry,
        )
        receipt = await adapter.run_m5_materialized_application(request)
        return _actual_witness(
            run_id=result.run_id,
            process_result=result,
            root=root,
            plan=execution.replay_plan,
            outcome=(OracleOutcome.SATISFIED if mode == "patched" else OracleOutcome.VIOLATED),
            status=403 if mode == "patched" else 200,
            receipt=receipt,
        )

    clean = tuple(
        [
            await execute_primary(mode="vulnerable", result=item, root=process.clean_root)
            for item in process.runs
        ]
    )
    patched = await execute_primary(
        mode="patched", result=process.patched_run, root=process.patched_root
    )
    controls: list[ActualMaterializedControlWitness] = []
    for control, retained in zip(
        execution.negative_controls, process.negative_controls, strict=True
    ):
        request = _materialized_request(
            repository_marker=m4.repository_marker,
            lineage=lineage,
            scenario=control.name,
            run_id=retained.result.run_id,
            root=retained.root,
            plan=control.replay_plan,
            policy_requests=control.policy_requests,
            policy_authorizations=control.policy_authorizations,
            registry=control.registry,
        )
        receipt = await adapter.run_m5_materialized_application(request)
        projected = _actual_witness(
            run_id=retained.result.run_id,
            process_result=retained.result,
            root=retained.root,
            plan=control.replay_plan,
            outcome=control.expected_outcome,
            status=control.expected_status,
            receipt=receipt,
        )
        controls.append(
            ActualMaterializedControlWitness(
                **projected.model_dump(mode="python"), name=control.name
            )
        )
    if not clean:
        raise MaterializedChainQualificationError("M5 actual materialized runs are missing")
    signatures = tuple(_actual_run_signature(item.materialized_run_receipt) for item in clean)
    values: dict[str, object] = {
        "schema_version": "stateweaver-m5-materialized-actual-asgi-qualification-v1",
        "status": "M5_MATERIALIZED_ACTUAL_ASGI_QUALIFIED",
        "repository_marker": m4.repository_marker,
        "runtime": _ACTUAL_RUNTIME,
        "m4_receipt_json": m4_bytes.decode("utf-8"),
        "m4_receipt_sha256": _raw_sha256(m4_bytes),
        "m4_receipt_digest": m4.receipt_digest,
        "m4_winner_state_binding_digest": lineage.binding_digest,
        "m4_source_snapshot_digest": lineage.source_snapshot_manifest_digest,
        "m4_after_archive_digest": lineage.after_archive_digest,
        "m4_provider_state_digest": lineage.provider_state_digest,
        "process_receipt_json": process_bytes.decode("utf-8"),
        "process_receipt_sha256": _raw_sha256(process_bytes),
        "process_receipt_digest": process.receipt_digest,
        "execution_plan_digest": sha256_digest(_execution_plan_bytes(execution)),
        "primary_plan": execution.replay_plan,
        "primary_plan_digest": sha256_digest(execution.replay_plan),
        "application_image_binding": clean[0].materialized_run_receipt.image_binding,
        "clean_root_runs": clean,
        "vulnerable_deterministic_signatures": signatures,
        "initial_checkpoint_bytes_digest": _raw_sha256(
            clean[0].materialized_run_receipt.initial_checkpoint.checkpoint_bytes
        ),
        "patched_run": patched,
        "negative_controls": tuple(controls),
        "cleanup_count": 10,
        "all_cleanups_passed": True,
        "all_projects_destroyed": True,
    }
    try:
        return ActualMaterializedChainQualificationReceipt.model_validate(
            {**values, "receipt_digest": sha256_digest(_json_compatible(values))}
        )
    except (ValidationError, TypeError, ValueError):
        raise MaterializedChainQualificationError(
            "M5 actual materialized qualification construction failed"
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


def qualify_actual_materialized_chain(
    *,
    m4_receipt_path: Path,
    process_receipt_path: Path,
    repository_marker: str,
    adapter: _ApplicationRunner | None = None,
) -> ActualMaterializedChainQualificationReceipt:
    """Execute and independently qualify ten actual-ASGI Docker scenarios."""

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
        _qualify_actual(
            m4_bytes=m4_bytes,
            m4=m4,
            process_bytes=process_bytes,
            process=process,
            adapter=runner,
        )
    )


def write_materialized_chain_qualification(
    output: Path,
    receipt: MaterializedChainQualificationReceipt | ActualMaterializedChainQualificationReceipt,
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical_json_bytes(_json_compatible(receipt)) + b"\n")


__all__ = [
    "ActualMaterializedChainQualificationReceipt",
    "ActualMaterializedControlWitness",
    "ActualMaterializedRunWitness",
    "MaterializedChainQualificationError",
    "MaterializedChainQualificationReceipt",
    "qualify_actual_materialized_chain",
    "qualify_materialized_chain",
    "write_materialized_chain_qualification",
]
