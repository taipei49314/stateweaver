"""M5 exact-byte M4 admission, compilation, and five-clean-root replay."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict, ValidationError, model_validator
from stateweaver.adapters.in_process_lab import (
    ADAPTER_NAME as IN_PROCESS_ADAPTER_NAME,
)
from stateweaver.adapters.in_process_lab import (
    ADAPTER_VERSION as IN_PROCESS_ADAPTER_VERSION,
)
from stateweaver.adapters.in_process_lab import (
    CANONICAL_RANDOM_SEED,
    ORACLE_ID,
    FixedLabActionRegistry,
    InProcessLabEnvironment,
)
from stateweaver.contracts import (
    ActionEnvelope,
    EffectOperation,
    OracleOutcome,
    ScopeManifest,
    Sha256Digest,
    canonical_json_bytes,
    sha256_digest,
)
from stateweaver.replay import (
    DeterminismClassification,
    DeterminismReport,
    ReplayKernel,
    ReplayObservation,
    ReplayPlan,
    ReplayRunResult,
    ReplayRunStatus,
    RootSeed,
    StateCapture,
)
from stateweaver.workflows.world import ObservedChainAdmission
from stateweaver_lab import LabMode

from .m5_plan import (
    M5ControlName,
    M5ControlPlan,
    M5ExecutionPlan,
    compile_m5_plan,
    m5_scope,
)
from .m5_plan import (
    _compiler_admission as _compile_m5_admission,
)
from .m5_plan import (
    _fresh_plan as _compile_m5_fresh_plan,
)
from .m5_plan import (
    _fresh_plan_matches_admission as _m5_fresh_plan_matches_admission,
)
from .materialized_search_qualification import MaterializedSearchQualificationReceipt
from .network_guard import deny_network_egress
from .runtime_qualification import OBSERVED_CHAIN_LENGTH

M5_REPLAY_COUNT = 5
_MARKER_RE = re.compile(r"^[0-9a-f]{40}$")
_LIMITATIONS = (
    "This qualifies exact-byte hosted M4 materialization input, five vulnerable actual-ASGI "
    "clean-root replays, four negative controls, and the identical patched plan boundary.",
    "Execution is socket-free on the hosted Docker-Linux runner; it is not an external-trust "
    "or release receipt.",
)


class ObservedChainQualificationError(ValueError):
    """Value-safe rejection at the M4-to-M5 clean-root boundary."""


class _M5Model(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)


class M5NegativeControlReceipt(_M5Model):
    """One freshly authorized negative control with an explicit oracle boundary."""

    name: M5ControlName
    expected_outcome: OracleOutcome
    expected_status: int
    plan: ReplayPlan
    plan_digest: Sha256Digest
    root: RootSeed
    root_digest: Sha256Digest
    result: ReplayRunResult

    @model_validator(mode="after")
    def _validate_control(self) -> M5NegativeControlReceipt:
        outcome, status = _terminal_boundary(self.result)
        if (
            self.result.status is not ReplayRunStatus.SUCCEEDED
            or self.plan_digest != sha256_digest(self.plan)
            or self.root_digest != sha256_digest(self.root)
            or self.result.root_fingerprint != self.root.capture.fingerprint
            or not _run_matches_plan(self.result, self.plan)
            or outcome is not self.expected_outcome
            or status != self.expected_status
        ):
            raise ValueError("M5 negative control did not retain its expected boundary")
        return self


class ObservedChainQualificationReceipt(_M5Model):
    """Closed receipt for one exact retained M4 byte stream and five clean roots."""

    schema_version: Literal["stateweaver-m5-observed-chain-qualification-v2"]
    status: Literal["VULNERABLE_PATCHED_CONTROLS_QUALIFIED"]
    repository_marker: str
    m4_receipt_json: str
    m4_receipt_sha256: Sha256Digest
    m4_receipt_digest: Sha256Digest
    observed_chain_digest: Sha256Digest
    compiler_admission: ObservedChainAdmission
    replay_plan: ReplayPlan
    replay_plan_digest: Sha256Digest
    clean_root: RootSeed
    runs: tuple[ReplayRunResult, ...]
    determinism: DeterminismReport
    patched_root: RootSeed
    patched_run: ReplayRunResult
    patched_plan_digest: Sha256Digest
    negative_controls: tuple[M5NegativeControlReceipt, ...]
    negative_controls_digest: Sha256Digest
    cleanup_count: Literal[10]
    network_denied_attempts: Literal[0]
    limitations: tuple[str, ...]
    release_eligible: Literal[False]
    receipt_digest: Sha256Digest

    @model_validator(mode="after")
    def _validate_receipt(self) -> ObservedChainQualificationReceipt:
        try:
            raw: object = json.loads(self.m4_receipt_json)
            m4 = MaterializedSearchQualificationReceipt.model_validate_json(self.m4_receipt_json)
        except (json.JSONDecodeError, ValidationError, ValueError, RecursionError):
            raise ValueError("M5 retained M4 receipt is invalid") from None
        m4_bytes = self.m4_receipt_json.encode("utf-8")
        if (
            canonical_json_bytes(raw) + b"\n" != m4_bytes
            or f"sha256:{hashlib.sha256(m4_bytes).hexdigest()}" != self.m4_receipt_sha256
            or m4.receipt_digest != self.m4_receipt_digest
            or m4.observed_chain_digest != self.observed_chain_digest
            or m4.repository_marker != self.repository_marker
            or self.compiler_admission.candidate_id != m4.winner.candidate_id
            or self.compiler_admission.chain_fingerprint
            != sha256_digest(self.compiler_admission.compiled_chain)
            or self.replay_plan_digest != sha256_digest(self.replay_plan)
            or self.replay_plan.root_seed_id != self.clean_root.root_seed_id
            or self.clean_root.target_version != "lab-vulnerable"
            or self.clean_root.adapter_versions
            != {IN_PROCESS_ADAPTER_NAME: IN_PROCESS_ADAPTER_VERSION}
            or not _fresh_plan_matches_admission(
                self.replay_plan,
                self.compiler_admission,
            )
            or len(self.compiler_admission.compiled_chain.fragment_ids) != OBSERVED_CHAIN_LENGTH
            or len(self.runs) != M5_REPLAY_COUNT
            or tuple(item.run_id for item in self.runs)
            != tuple(f"run.m5.clean-root-{index:02d}" for index in range(1, 6))
            or any(item.status is not ReplayRunStatus.SUCCEEDED for item in self.runs)
            or any(
                item.root_fingerprint != self.clean_root.capture.fingerprint for item in self.runs
            )
            or any(not _run_matches_plan(item, self.replay_plan) for item in self.runs)
            or any(_terminal_boundary(item) != (OracleOutcome.VIOLATED, 200) for item in self.runs)
            or not self.determinism.deterministic
            or not self.determinism.all_runs_succeeded
            or self.determinism.run_ids != tuple(item.run_id for item in self.runs)
            or self.determinism.signatures
            != tuple(item.deterministic_signature() for item in self.runs)
            or self.patched_plan_digest != self.replay_plan_digest
            or self.patched_root.target_version != "lab-patched"
            or self.patched_root.adapter_versions
            != {IN_PROCESS_ADAPTER_NAME: IN_PROCESS_ADAPTER_VERSION}
            or self.patched_root.root_seed_id != self.clean_root.root_seed_id
            or self.patched_root.random_seed != self.clean_root.random_seed
            or self.patched_root.clock_epoch != self.clean_root.clock_epoch
            or self.patched_run.plan_id != self.replay_plan.plan_id
            or self.patched_run.root_fingerprint != self.patched_root.capture.fingerprint
            or not _run_matches_plan(self.patched_run, self.replay_plan)
            or self.patched_run.status is not ReplayRunStatus.FAILED
            or self.patched_run.failed_step_id != f"step.{OBSERVED_CHAIN_LENGTH:02d}"
            or self.patched_run.steps[-1].failure_code != "ORACLE_EXPECTATION_MISMATCH"
            or _terminal_boundary(self.patched_run) != (OracleOutcome.SATISFIED, 403)
            or tuple(item.name for item in self.negative_controls)
            != (
                "masked_response",
                "mock_only_response",
                "fresh_session",
                "same_tenant_document",
            )
            or self.negative_controls_digest != sha256_digest(self.negative_controls)
            or self.limitations != _LIMITATIONS
        ):
            raise ValueError("M5 exact-byte clean-root receipt is incoherent")
        expected = sha256_digest(self.model_dump(mode="python", exclude={"receipt_digest"}))
        if self.receipt_digest != expected:
            raise ValueError("M5 receipt digest is invalid")
        return self


def _terminal_boundary(result: ReplayRunResult) -> tuple[OracleOutcome | None, int | None]:
    if not result.steps:
        return None, None
    final = result.steps[-1]
    outcome = final.oracle_results[-1].result if final.oracle_results else None
    status: int | None = None
    if final.observations:
        candidate = final.observations[-1].payload.get("response_status")
        if type(candidate) is int:
            status = candidate
    return outcome, status


def _run_matches_plan(result: ReplayRunResult, plan: ReplayPlan) -> bool:
    return (
        result.plan_id == plan.plan_id
        and tuple(item.step_id for item in result.action_log)
        == tuple(item.step_id for item in plan.steps)
        and tuple(item.action for item in result.action_log)
        == tuple(item.action for item in plan.steps)
    )


def _fresh_plan_matches_admission(
    plan: ReplayPlan,
    admission: ObservedChainAdmission,
) -> bool:
    """Compatibility projection of the shared M5 plan validation."""

    return _m5_fresh_plan_matches_admission(plan, admission)


def _read_m4(path: Path) -> tuple[bytes, MaterializedSearchQualificationReceipt]:
    if path.is_symlink():
        raise ObservedChainQualificationError("M4 receipt path is invalid")
    try:
        size = path.stat().st_size
        content = path.read_bytes()
    except OSError:
        raise ObservedChainQualificationError("M4 receipt is unreadable") from None
    if size != len(content) or not 1 <= size <= 4 * 1_048_576:
        raise ObservedChainQualificationError("M4 receipt size is invalid")
    try:
        raw: object = json.loads(content.decode("utf-8"))
        if canonical_json_bytes(raw) + b"\n" != content:
            raise ValueError("M4 JSON is not canonical")
        receipt = MaterializedSearchQualificationReceipt.model_validate_json(content)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError, RecursionError):
        raise ObservedChainQualificationError("M4 receipt is invalid") from None
    return content, receipt


def _compiler_admission(m4: MaterializedSearchQualificationReceipt) -> ObservedChainAdmission:
    """Compatibility entrypoint retained for focused legacy regression tests."""

    return _compile_m5_admission(m4)


def _scope() -> ScopeManifest:
    """Compatibility entrypoint for the sole shared M5 policy scope."""

    return m5_scope()


def _fresh_plan(
    admission: ObservedChainAdmission,
) -> tuple[ReplayPlan, FixedLabActionRegistry]:
    """Compatibility projection of the shared fresh-plan compiler."""

    plan, _, registry = _compile_m5_fresh_plan(admission)
    return plan, registry


class _ExactObservedEnvironment:
    """Enforce compiled virtual guards before delegating one actual ASGI action."""

    def __init__(
        self,
        delegate: InProcessLabEnvironment,
        *,
        plan: ReplayPlan,
        root: RootSeed,
    ) -> None:
        self._delegate = delegate
        self._plan = plan
        self._root = root
        self._expected = {item.action.action_id: item.action for item in plan.steps}
        self.cleanup_count = 0

    async def reset(self, root: RootSeed) -> StateCapture:
        if sha256_digest(root) != sha256_digest(self._root):
            raise ValueError("M5 clean root identity changed")
        capture = await self._delegate.reset(root)
        if self._delegate.evidence_records:
            raise ValueError("M5 clean root retained evidence")
        return capture

    async def capture(self) -> StateCapture:
        return await self._delegate.capture()

    async def execute(self, action: ActionEnvelope) -> tuple[ReplayObservation, ...]:
        expected = self._expected.get(action.action_id)
        if expected is None or canonical_json_bytes(expected) != canonical_json_bytes(action):
            raise PermissionError("M5 action substitution was rejected")
        before_evidence_count = len(self._delegate.evidence_records)
        if any(
            item.path != f"chain.observed_step_{action.sequence:02d}"
            or item.expected != before_evidence_count
            for item in action.preconditions
        ):
            raise ValueError("M5 observed precondition was not met")
        observations = await self._delegate.execute(action)
        after_evidence_count = len(self._delegate.evidence_records)
        for effect in action.expected_effects:
            if (
                effect.operation is not EffectOperation.SET
                or effect.path != f"chain.observed_step_{action.sequence:02d}"
                or effect.value != after_evidence_count
            ):
                raise ValueError("M5 supports only observed SET effects")
        return observations

    async def cleanup(self) -> None:
        self.cleanup_count += 1
        await self._delegate.cleanup()


async def _run_exact_plan(
    *,
    mode: LabMode,
    plan: ReplayPlan,
    registry: FixedLabActionRegistry,
    run_ids: tuple[str, ...],
) -> tuple[RootSeed, tuple[ReplayRunResult, ...], int]:
    roots: list[RootSeed] = []
    runs: list[ReplayRunResult] = []
    cleanup_count = 0
    for run_id in run_ids:
        delegate = InProcessLabEnvironment(mode=mode, registry=registry)
        root = await delegate.create_root_seed(
            root_seed_id=plan.root_seed_id,
            random_seed=CANONICAL_RANDOM_SEED,
        )
        if roots and canonical_json_bytes(root) != canonical_json_bytes(roots[0]):
            raise ObservedChainQualificationError("M5 clean roots are not byte-identical")
        roots.append(root)
        environment = _ExactObservedEnvironment(delegate, plan=plan, root=root)
        kernel = ReplayKernel(environment, {ORACLE_ID: delegate.oracle})
        runs.append(await kernel.replay(run_id=run_id, plan=plan, root=root))
        cleanup_count += environment.cleanup_count
    if not roots:
        raise ObservedChainQualificationError("M5 replay requires at least one clean root")
    return roots[0], tuple(runs), cleanup_count


async def _run_negative_controls(
    controls: tuple[M5ControlPlan, ...],
) -> tuple[tuple[M5NegativeControlReceipt, ...], int]:
    receipts: list[M5NegativeControlReceipt] = []
    cleanup_count = 0
    for control in controls:
        root, results, cleaned = await _run_exact_plan(
            mode=LabMode.VULNERABLE,
            plan=control.replay_plan,
            registry=control.registry,
            run_ids=(f"run.m5.control-{control.name}",),
        )
        cleanup_count += cleaned
        receipts.append(
            M5NegativeControlReceipt(
                name=control.name,
                expected_outcome=control.expected_outcome,
                expected_status=control.expected_status,
                plan=control.replay_plan,
                plan_digest=sha256_digest(control.replay_plan),
                root=root,
                root_digest=sha256_digest(root),
                result=results[0],
            )
        )
    return tuple(receipts), cleanup_count


@dataclass(frozen=True)
class _M5Execution:
    plan: ReplayPlan
    root: RootSeed
    runs: tuple[ReplayRunResult, ...]
    determinism: DeterminismReport
    patched_root: RootSeed
    patched_run: ReplayRunResult
    negative_controls: tuple[M5NegativeControlReceipt, ...]
    cleanup_count: int


async def _execute(execution_plan: M5ExecutionPlan) -> _M5Execution:
    plan = execution_plan.replay_plan
    registry = execution_plan.registry
    root, runs, vulnerable_cleanup_count = await _run_exact_plan(
        mode=LabMode.VULNERABLE,
        plan=plan,
        registry=registry,
        run_ids=tuple(f"run.m5.clean-root-{index:02d}" for index in range(1, M5_REPLAY_COUNT + 1)),
    )
    patched_root, patched_runs, patched_cleanup_count = await _run_exact_plan(
        mode=LabMode.PATCHED,
        plan=plan,
        registry=registry,
        run_ids=("run.m5.patched-01",),
    )
    if (
        patched_root.root_seed_id != root.root_seed_id
        or patched_root.random_seed != root.random_seed
        or patched_root.clock_epoch != root.clock_epoch
    ):
        raise ObservedChainQualificationError("M5 patched root identity changed")
    negative_controls, control_cleanup_count = await _run_negative_controls(
        execution_plan.negative_controls
    )
    signatures = tuple(item.deterministic_signature() for item in runs)
    report = DeterminismReport(
        plan_id=plan.plan_id,
        run_ids=tuple(item.run_id for item in runs),
        run_statuses=tuple(item.status for item in runs),
        signatures=signatures,
        deterministic=len(set(signatures)) == 1,
        all_runs_succeeded=all(item.status is ReplayRunStatus.SUCCEEDED for item in runs),
        classification=(
            DeterminismClassification.DETERMINISTIC
            if len(set(signatures)) == 1
            else DeterminismClassification.NONDETERMINISTIC
        ),
        divergent_run_id=None,
    )
    return _M5Execution(
        plan=plan,
        root=root,
        runs=runs,
        determinism=report,
        patched_root=patched_root,
        patched_run=patched_runs[0],
        negative_controls=negative_controls,
        cleanup_count=(vulnerable_cleanup_count + patched_cleanup_count + control_cleanup_count),
    )


def qualify_observed_chain(
    *, m4_receipt_path: Path, repository_marker: str
) -> ObservedChainQualificationReceipt:
    """Compile exact retained M4 bytes and replay them across five clean roots."""

    if _MARKER_RE.fullmatch(repository_marker) is None:
        raise ObservedChainQualificationError("repository marker must be an exact Git SHA")
    m4_bytes, m4 = _read_m4(m4_receipt_path)
    if m4.repository_marker != repository_marker:
        raise ObservedChainQualificationError("M4 receipt source does not match")
    execution_plan = compile_m5_plan(m4)
    admission = execution_plan.compiler_admission

    async def guarded() -> tuple[_M5Execution, int]:
        with deny_network_egress() as guard:
            execution = await _execute(execution_plan)
        return execution, guard.denied_attempts

    execution, denied = asyncio.run(guarded())
    if (
        not execution.determinism.deterministic
        or not execution.determinism.all_runs_succeeded
        or execution.cleanup_count != 10
        or denied
    ):
        raise ObservedChainQualificationError("M5 clean-root replay did not qualify")
    values: dict[str, object] = {
        "schema_version": "stateweaver-m5-observed-chain-qualification-v2",
        "status": "VULNERABLE_PATCHED_CONTROLS_QUALIFIED",
        "repository_marker": repository_marker,
        "m4_receipt_json": m4_bytes.decode("utf-8"),
        "m4_receipt_sha256": f"sha256:{hashlib.sha256(m4_bytes).hexdigest()}",
        "m4_receipt_digest": m4.receipt_digest,
        "observed_chain_digest": m4.observed_chain_digest,
        "compiler_admission": admission,
        "replay_plan": execution.plan,
        "replay_plan_digest": sha256_digest(execution.plan),
        "clean_root": execution.root,
        "runs": execution.runs,
        "determinism": execution.determinism,
        "patched_root": execution.patched_root,
        "patched_run": execution.patched_run,
        "patched_plan_digest": sha256_digest(execution.plan),
        "negative_controls": execution.negative_controls,
        "negative_controls_digest": sha256_digest(execution.negative_controls),
        "cleanup_count": execution.cleanup_count,
        "network_denied_attempts": denied,
        "limitations": _LIMITATIONS,
        "release_eligible": False,
    }
    try:
        return ObservedChainQualificationReceipt.model_validate(
            {**values, "receipt_digest": sha256_digest(values)}
        )
    except (ValidationError, TypeError, ValueError):
        raise ObservedChainQualificationError("M5 receipt construction failed") from None


def write_observed_chain_qualification(
    output: Path, receipt: ObservedChainQualificationReceipt
) -> None:
    """Write one canonical M5 receipt."""

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical_json_bytes(receipt) + b"\n")


__all__ = [
    "M5_REPLAY_COUNT",
    "M5NegativeControlReceipt",
    "ObservedChainQualificationError",
    "ObservedChainQualificationReceipt",
    "qualify_observed_chain",
    "write_observed_chain_qualification",
]
