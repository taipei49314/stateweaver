"""M5 exact-byte M4 admission, compilation, and five-clean-root replay."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict, ValidationError, model_validator
from stateweaver.adapters.in_process_lab import (
    CANONICAL_RANDOM_SEED,
    FixedLabActionRegistry,
    InProcessLabEnvironment,
    LabAction,
    PolicyAuthorization,
    lab_action_artifact,
)
from stateweaver.compiler import CompilerFragment, TerminalGoal
from stateweaver.compiler.models import FragmentBinding
from stateweaver.contracts import (
    ActionEnvelope,
    ActionGuard,
    EffectOperation,
    EnvironmentMode,
    ExpectedEffect,
    HttpRequestAction,
    RequestedBy,
    RequesterType,
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
    canonical_json_bytes,
    sha256_digest,
)
from stateweaver.policy import BudgetSnapshot, PolicyRequest, evaluate_policy
from stateweaver.replay import (
    DeterminismClassification,
    DeterminismReport,
    ReplayKernel,
    ReplayObservation,
    ReplayPlan,
    ReplayRunResult,
    ReplayRunStatus,
    ReplayStep,
    RootSeed,
    StateCapture,
)
from stateweaver.workflows.world import ObservedChainAdmission, compile_observed_promotion
from stateweaver_lab import LabMode
from stateweaver_lab.models import (
    DocumentId,
    DowngradeRoleLabAction,
    PrimeAuthorizationCacheLabAction,
    PrimeAuthorizationCacheRequest,
    PrincipalId,
    RetainSessionLabAction,
    Role,
    RoleDowngradeRequest,
)

from .materialized_search_qualification import MaterializedSearchQualificationReceipt
from .network_guard import deny_network_egress

M5_REPLAY_COUNT = 5
_MARKER_RE = re.compile(r"^[0-9a-f]{40}$")
_EVALUATED_AT = datetime(2026, 7, 29, tzinfo=UTC)
_LIMITATIONS = (
    "This qualifies exact-byte M4-to-compiler admission and five actual-ASGI clean-root replays.",
    "It is socket-free and not yet the M5 Docker materialized-world exit or a release receipt.",
)
_LAB_ACTIONS: tuple[LabAction, ...] = (
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
)


class ObservedChainQualificationError(ValueError):
    """Value-safe rejection at the M4-to-M5 clean-root boundary."""


class _M5Model(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)


class ObservedChainQualificationReceipt(_M5Model):
    """Closed receipt for one exact retained M4 byte stream and five clean roots."""

    schema_version: Literal["stateweaver-m5-observed-chain-qualification-v1"]
    status: Literal["CLEAN_ROOT_REPLAY_QUALIFIED"]
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
    cleanup_count: Literal[5]
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
            or len(self.runs) != M5_REPLAY_COUNT
            or tuple(item.run_id for item in self.runs)
            != tuple(f"run.m5.clean-root-{index:02d}" for index in range(1, 6))
            or any(item.status is not ReplayRunStatus.SUCCEEDED for item in self.runs)
            or not self.determinism.deterministic
            or not self.determinism.all_runs_succeeded
            or self.determinism.run_ids != tuple(item.run_id for item in self.runs)
            or self.determinism.signatures
            != tuple(item.deterministic_signature() for item in self.runs)
            or self.limitations != _LIMITATIONS
        ):
            raise ValueError("M5 exact-byte clean-root receipt is incoherent")
        expected = sha256_digest(self.model_dump(mode="python", exclude={"receipt_digest"}))
        if self.receipt_digest != expected:
            raise ValueError("M5 receipt digest is invalid")
        return self


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
            raise ObservedChainQualificationError("M5 observed action is not HTTP")
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


def _scope() -> ScopeManifest:
    return ScopeManifest(
        metadata=ScopeMetadata(name="m5-clean-root"),
        spec=ScopeSpec(
            environmentMode=EnvironmentMode.SOURCE_BACKED,
            targets=ScopeTargets(
                include=(TargetSelector(host="localhost", ports=(80,), paths=("/v1/lab/**",)),)
            ),
            identities=ScopeIdentities(allowed=("test_user_a", "test_admin")),
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


def _fresh_plan(
    admission: ObservedChainAdmission,
) -> tuple[ReplayPlan, FixedLabActionRegistry]:
    compiled = admission.compiled_chain
    candidate = ReplayPlan(
        plan_id="plan.m5.clean-root",
        root_seed_id=compiled.root_seed_id,
        steps=tuple(
            ReplayStep(
                step_id=f"step.{index:02d}",
                action=action,
                timeout_seconds=action.timeout_ms / 1_000,
            )
            for index, action in enumerate(compiled.action_envelopes)
        ),
    )
    actions: list[ActionEnvelope] = []
    authorizations: dict[str, PolicyAuthorization] = {}
    for index, step in enumerate(candidate.steps, start=1):
        decision_ref = f"policy.m5.clean-root-{index:02d}"
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
            scope_manifest=_scope(),
            action_envelope=action,
            budget=BudgetSnapshot(
                requests_in_window=index - 1,
                request_window_seconds=1.0,
                write_requests_used=index - 1,
            ),
            evaluated_at=_EVALUATED_AT,
        )
        decision = evaluate_policy(request)
        if not decision.allowed:
            raise ObservedChainQualificationError("fresh M5 policy did not allow the plan")
        actions.append(action)
        authorizations[decision_ref] = PolicyAuthorization.bind(action, request, decision)
    return (
        ReplayPlan(
            plan_id=candidate.plan_id,
            root_seed_id=candidate.root_seed_id,
            steps=tuple(
                ReplayStep(
                    step_id=step.step_id,
                    action=action,
                    timeout_seconds=action.timeout_ms / 1_000,
                )
                for step, action in zip(candidate.steps, actions, strict=True)
            ),
        ),
        FixedLabActionRegistry(
            by_action_id={
                action.action_id: lab for action, lab in zip(actions, _LAB_ACTIONS, strict=True)
            },
            by_body_artifact={lab_action_artifact(item): item for item in _LAB_ACTIONS},
            policy_authorizations=authorizations,
        ),
    )


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
        self._initial = {
            guard.path: guard.expected for step in plan.steps for guard in step.action.preconditions
        }
        self._state: dict[str, object] = {}
        self._expected = {item.action.action_id: item.action for item in plan.steps}
        self.cleanup_count = 0

    async def reset(self, root: RootSeed) -> StateCapture:
        if sha256_digest(root) != sha256_digest(self._root):
            raise ValueError("M5 clean root identity changed")
        self._state = dict(self._initial)
        return await self._delegate.reset(root)

    async def capture(self) -> StateCapture:
        return await self._delegate.capture()

    async def execute(self, action: ActionEnvelope) -> tuple[ReplayObservation, ...]:
        expected = self._expected.get(action.action_id)
        if expected is None or canonical_json_bytes(expected) != canonical_json_bytes(action):
            raise PermissionError("M5 action substitution was rejected")
        if any(self._state.get(item.path) != item.expected for item in action.preconditions):
            raise ValueError("M5 observed precondition was not met")
        observations = await self._delegate.execute(action)
        for effect in action.expected_effects:
            if effect.operation is not EffectOperation.SET:
                raise ValueError("M5 supports only observed SET effects")
            self._state[effect.path] = effect.value
        return observations

    async def cleanup(self) -> None:
        self.cleanup_count += 1
        await self._delegate.cleanup()


async def _execute(
    admission: ObservedChainAdmission,
) -> tuple[ReplayPlan, RootSeed, tuple[ReplayRunResult, ...], DeterminismReport, int]:
    plan, registry = _fresh_plan(admission)
    delegate = InProcessLabEnvironment(mode=LabMode.VULNERABLE, registry=registry)
    root = await delegate.create_root_seed(
        root_seed_id=admission.compiled_chain.root_seed_id,
        random_seed=CANONICAL_RANDOM_SEED,
    )
    environment = _ExactObservedEnvironment(
        delegate,
        plan=plan,
        root=root,
    )
    kernel = ReplayKernel(environment, {})
    runs = tuple(
        [
            await kernel.replay(
                run_id=f"run.m5.clean-root-{index:02d}",
                plan=plan,
                root=root,
            )
            for index in range(1, M5_REPLAY_COUNT + 1)
        ]
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
    return plan, root, runs, report, environment.cleanup_count


def qualify_observed_chain(
    *, m4_receipt_path: Path, repository_marker: str
) -> ObservedChainQualificationReceipt:
    """Compile exact retained M4 bytes and replay them across five clean roots."""

    if _MARKER_RE.fullmatch(repository_marker) is None:
        raise ObservedChainQualificationError("repository marker must be an exact Git SHA")
    m4_bytes, m4 = _read_m4(m4_receipt_path)
    if m4.repository_marker != repository_marker:
        raise ObservedChainQualificationError("M4 receipt source does not match")
    admission = _compiler_admission(m4)

    async def guarded() -> tuple[
        ReplayPlan, RootSeed, tuple[ReplayRunResult, ...], DeterminismReport, int, int
    ]:
        with deny_network_egress() as guard:
            plan, root, runs, report, cleanup_count = await _execute(admission)
        return plan, root, runs, report, cleanup_count, guard.denied_attempts

    plan, root, runs, report, cleanup_count, denied = asyncio.run(guarded())
    if not report.deterministic or not report.all_runs_succeeded or cleanup_count != 5 or denied:
        raise ObservedChainQualificationError("M5 clean-root replay did not qualify")
    values: dict[str, object] = {
        "schema_version": "stateweaver-m5-observed-chain-qualification-v1",
        "status": "CLEAN_ROOT_REPLAY_QUALIFIED",
        "repository_marker": repository_marker,
        "m4_receipt_json": m4_bytes.decode("utf-8"),
        "m4_receipt_sha256": f"sha256:{hashlib.sha256(m4_bytes).hexdigest()}",
        "m4_receipt_digest": m4.receipt_digest,
        "observed_chain_digest": m4.observed_chain_digest,
        "compiler_admission": admission,
        "replay_plan": plan,
        "replay_plan_digest": sha256_digest(plan),
        "clean_root": root,
        "runs": runs,
        "determinism": report,
        "cleanup_count": cleanup_count,
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
    "ObservedChainQualificationError",
    "ObservedChainQualificationReceipt",
    "qualify_observed_chain",
    "write_observed_chain_qualification",
]
