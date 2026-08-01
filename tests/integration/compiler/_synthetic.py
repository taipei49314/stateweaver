"""Closed clean-room fixtures for compiler-to-replay integration tests."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import MappingProxyType

from stateweaver.compiler import (
    ChainCompiler,
    CompiledChain,
    CompilerFragment,
    RootState,
    TerminalGoal,
    TimeWindow,
)
from stateweaver.compiler.models import FragmentBinding
from stateweaver.contracts import (
    ActionEnvelope,
    ActionGuard,
    ComparisonOperator,
    EffectOperation,
    EnvironmentMode,
    ExpectedEffect,
    FidelityLevel,
    FidelityProfile,
    OracleOutcome,
    OracleResult,
    OracleType,
    ProvenanceKind,
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
    StateCondition,
    StateEffect,
    TargetSelector,
    TimeAdvanceAction,
    TransitionFragment,
    canonical_json_bytes,
    sha256_digest,
)
from stateweaver.policy import (
    BudgetSnapshot,
    DeterministicPolicyEvaluator,
    PolicyDecision,
    PolicyOutcome,
    PolicyRequest,
)
from stateweaver.replay import (
    CaptureLayer,
    OracleExpectation,
    ReplayObservation,
    ReplayPlan,
    ReplayStep,
    RootSeed,
    StateArtifact,
    StateCapture,
)

EPOCH = datetime(2026, 8, 1, tzinfo=UTC)
_AUTHORIZATION_LIFETIME = timedelta(seconds=1)
_WORLD_ID = "world.clean-room"
_ROOT_ID = "root.clean-room"


def condition(path: str, value: bool | str) -> StateCondition:
    return StateCondition(path=path, operator=ComparisonOperator.EQ, value=value)


def effect(path: str, value: bool | str) -> StateEffect:
    return StateEffect(path=path, operation=EffectOperation.SET, value=value)


def _action(
    identifier: str,
    policy_ref: str,
    *,
    preconditions: tuple[StateCondition, ...],
    effects: tuple[StateEffect, ...],
) -> ActionEnvelope:
    return ActionEnvelope(
        action_id=f"action.{identifier.rsplit('.', maxsplit=1)[-1]}",
        experiment_id="experiment.clean-room",
        world_id=_WORLD_ID,
        scope_action=ScopeAction.CONTROLLED_TIME,
        action=TimeAdvanceAction(milliseconds=1),
        preconditions=tuple(
            ActionGuard(path=item.path, expected=item.value) for item in preconditions
        ),
        expected_effects=tuple(
            ExpectedEffect(path=item.path, operation=item.operation, value=item.value)
            for item in effects
        ),
        risk_class=RiskClass.REVERSIBLE_STATE_CHANGE,
        idempotency_key=sha256_digest({"fragment": identifier}),
        requested_by=RequestedBy(type=RequesterType.WORKFLOW, role="compiler-integration"),
        policy_decision_ref=policy_ref,
    )


def fragment(
    identifier: str,
    *,
    preconditions: tuple[StateCondition, ...],
    effects: tuple[StateEffect, ...],
) -> CompilerFragment:
    typed_action = _action(
        identifier,
        f"policy.precompile.{identifier.rsplit('.', maxsplit=1)[-1]}",
        preconditions=preconditions,
        effects=effects,
    )
    transition = TransitionFragment(
        transition_id=identifier,
        name=identifier,
        source=ProvenanceKind.MOCKED,
        preconditions=preconditions,
        action=typed_action.action,
        effects=effects,
        observables=(condition("adapter.accepted", True),),
        evidence_ids=(f"evidence.synthetic.{identifier.rsplit('.', maxsplit=1)[-1]}",),
        fidelity=FidelityProfile(code=FidelityLevel.PARTIAL, timing=FidelityLevel.PARTIAL),
        consistent_replays=0,
    )
    return CompilerFragment(
        fragment=transition,
        envelope=typed_action,
        world_id=_WORLD_ID,
        binding=FragmentBinding(),
        window=TimeWindow(),
    )


def root_state() -> RootState:
    return RootState(
        root_seed_id=_ROOT_ID,
        world_id=_WORLD_ID,
        conditions=(condition("root.ready", True),),
    )


def goal() -> TerminalGoal:
    return TerminalGoal(
        goal_id="goal.clean-room-violation", conditions=(condition("violation.reached", True),)
    )


def chain_fragments() -> tuple[CompilerFragment, ...]:
    return (
        fragment(
            "fragment.prepare",
            preconditions=(condition("root.ready", True),),
            effects=(effect("session.prepared", True),),
        ),
        fragment(
            "fragment.cache",
            preconditions=(condition("session.prepared", True),),
            effects=(effect("cache.gate", "open"),),
        ),
        fragment(
            "fragment.terminal",
            preconditions=(condition("cache.gate", "open"),),
            effects=(effect("violation.reached", True),),
        ),
        fragment(
            "fragment.decoy",
            preconditions=(condition("root.ready", True),),
            effects=(effect("unused.flag", True),),
        ),
    )


def compile_chain() -> CompiledChain:
    return ChainCompiler().compile(
        chain_id="chain.clean-room", root=root_state(), fragments=chain_fragments(), goal=goal()
    )


def root_seed() -> RootSeed:
    return RootSeed(
        root_seed_id=_ROOT_ID,
        target_version="synthetic-clean-room-v1",
        random_seed=12345,
        clock_epoch=EPOCH,
        capture=capture({"root.ready": True}, 0),
        adapter_versions={"in_memory_effects": "1.0"},
    )


def capture(state: Mapping[str, bool | str], clock_ms: int) -> StateCapture:
    controlled_at = EPOCH + timedelta(milliseconds=clock_ms)
    artifacts = (
        StateArtifact.from_payload(layer=CaptureLayer.APPLICATION, payload={"state": dict(state)}),
        StateArtifact.from_payload(layer=CaptureLayer.CLOCK, payload={"milliseconds": clock_ms}),
    )
    return StateCapture.from_artifacts(
        capture_id=f"capture.clean-room.{clock_ms:03d}",
        controlled_at=controlled_at,
        artifacts=artifacts,
    )


def _action_subject_digest(action: ActionEnvelope) -> str:
    projection = action.model_dump(mode="python", by_alias=True, exclude_none=False)
    projection.pop("policy_decision_ref")
    return sha256_digest(projection)


def _policy_ref(
    *,
    chain_hash: str,
    effect_digest: str,
    root_digest: str,
    step_id: str,
    subject_digest: str,
    expires_at: datetime,
) -> str:
    material = sha256_digest(
        {
            "chain_hash": chain_hash,
            "effect_digest": effect_digest,
            "root_digest": root_digest,
            "step_id": step_id,
            "subject_digest": subject_digest,
            "expires_at": expires_at.isoformat(),
        }
    ).removeprefix("sha256:")
    return f"policy.fresh.{material[:24]}"


@dataclass(frozen=True)
class AuthorizationGrant:
    """Closed local capability binding one exact envelope to one root and typed effect."""

    plan_id: str
    step_id: str
    chain_hash: str
    decision_ref: str
    action_digest: str
    action_subject_digest: str
    root_digest: str
    fragment_digest: str
    effect_digest: str
    request_digest: str
    decision_digest: str
    expires_at: datetime
    fragment: TransitionFragment
    request: PolicyRequest
    decision: PolicyDecision


@dataclass(frozen=True)
class AuthorizedReplay:
    """Immutable result of fresh policy evaluation for a compiled plan."""

    plan: ReplayPlan
    root_digest: str
    chain_hash: str
    grants: Mapping[str, AuthorizationGrant]

    def __post_init__(self) -> None:
        object.__setattr__(self, "grants", MappingProxyType(dict(self.grants)))


def fresh_plan(chain: CompiledChain) -> AuthorizedReplay:
    """Evaluate each exact final envelope and retain its closed decision/request binding."""

    candidate = chain.to_replay_plan(plan_id="plan.clean-room")
    clean_root = root_seed()
    root_digest = sha256_digest(clean_root)
    selected = {
        item.envelope.action_id: item
        for item in chain_fragments()
        if item.fragment_id in chain.fragment_ids
    }
    fresh_steps: list[ReplayStep] = []
    grants: dict[str, AuthorizationGrant] = {}
    for index, step in enumerate(candidate.steps):
        compiled_fragment = selected[step.action.action_id]
        subject_digest = _action_subject_digest(step.action)
        effect_digest = sha256_digest(compiled_fragment.fragment.effects)
        expires_at = EPOCH + _AUTHORIZATION_LIFETIME
        decision_ref = _policy_ref(
            chain_hash=chain.causal_hash,
            effect_digest=effect_digest,
            root_digest=root_digest,
            step_id=step.step_id,
            subject_digest=subject_digest,
            expires_at=expires_at,
        )
        action = step.action.model_copy(update={"policy_decision_ref": decision_ref})
        request = PolicyRequest(
            scope_manifest=_scope_manifest(),
            action_envelope=action,
            budget=BudgetSnapshot(
                requests_in_window=index,
                request_window_seconds=1.0,
                write_requests_used=index,
            ),
            evaluated_at=EPOCH,
        )
        decision = DeterministicPolicyEvaluator().evaluate(request)
        if decision.outcome is not PolicyOutcome.ALLOW:
            raise AssertionError("synthetic fresh policy decision was not allowed")
        expectations = (
            (
                OracleExpectation(
                    oracle_id="oracle.terminal", allowed_results=frozenset({OracleOutcome.VIOLATED})
                ),
            )
            if index == len(candidate.steps) - 1
            else ()
        )
        fresh_step = ReplayStep(
            step_id=step.step_id, action=action, oracle_expectations=expectations
        )
        fresh_steps.append(fresh_step)
        grants[action.action_id] = AuthorizationGrant(
            plan_id=candidate.plan_id,
            step_id=step.step_id,
            chain_hash=chain.causal_hash,
            decision_ref=decision_ref,
            action_digest=sha256_digest(action),
            action_subject_digest=subject_digest,
            root_digest=root_digest,
            fragment_digest=sha256_digest(compiled_fragment.fragment),
            effect_digest=effect_digest,
            request_digest=request.fingerprint(),
            decision_digest=decision.fingerprint(),
            expires_at=expires_at,
            fragment=compiled_fragment.fragment,
            request=request,
            decision=decision,
        )
    plan = ReplayPlan(
        plan_id=candidate.plan_id,
        root_seed_id=candidate.root_seed_id,
        steps=tuple(fresh_steps),
    )
    return AuthorizedReplay(
        plan=plan,
        root_digest=root_digest,
        chain_hash=chain.causal_hash,
        grants=grants,
    )


def _scope_manifest() -> ScopeManifest:
    return ScopeManifest(
        metadata=ScopeMetadata(name="clean-room"),
        spec=ScopeSpec(
            environmentMode=EnvironmentMode.GRAY_BOX,
            targets=ScopeTargets(
                include=(TargetSelector(host="localhost", ports=(80,), paths=("/",)),)
            ),
            identities=ScopeIdentities(allowed=("synthetic",)),
            actions=ScopeActions(allow=(ScopeAction.CONTROLLED_TIME,)),
            limits=ScopeLimits(
                requestsPerSecond=10.0,
                concurrentMaterializedWorlds=1,
                maxWriteRequests=3,
            ),
            validity=ScopeValidity(expiresAt=EPOCH + timedelta(days=1)),
        ),
    )


class InMemoryEffectsEnvironment:
    """Closed interpreter for exact, root-bound, one-use synthetic capabilities."""

    def __init__(
        self,
        *,
        authorized: AuthorizedReplay,
        expected_root: RootSeed,
    ) -> None:
        if sha256_digest(expected_root) != authorized.root_digest:
            raise ValueError("authorized replay does not bind the supplied clean root")
        self._authorized = authorized
        self._expected_root = expected_root
        self._grants = MappingProxyType(dict(authorized.grants))
        self._validate_bundle()
        self._state: dict[str, bool | str] = {}
        self._clock_ms = 0
        self._active_root_digest: str | None = None
        self._consumed_idempotency_keys: set[str] = set()
        self.cleanup_calls = 0

    async def reset(self, root: RootSeed) -> StateCapture:
        candidate_digest = sha256_digest(root)
        if candidate_digest != self._authorized.root_digest or candidate_digest != sha256_digest(
            self._expected_root
        ):
            raise ValueError("unrecognized clean root")
        self._state = {"root.ready": True}
        self._clock_ms = 0
        self._active_root_digest = candidate_digest
        self._consumed_idempotency_keys.clear()
        return capture(self._state, self._clock_ms)

    async def capture(self) -> StateCapture:
        return capture(self._state, self._clock_ms)

    async def execute(self, action: ActionEnvelope) -> tuple[ReplayObservation, ...]:
        grant = self._grants.get(action.action_id)
        if self._active_root_digest is None or grant is None:
            raise PermissionError("closed replay requires a recognized active root and action")
        if (
            self._active_root_digest != grant.root_digest
            or action.policy_decision_ref != grant.decision_ref
            or sha256_digest(action) != grant.action_digest
            or _action_subject_digest(action) != grant.action_subject_digest
            or action.idempotency_key in self._consumed_idempotency_keys
            or action.scope_action is not ScopeAction.CONTROLLED_TIME
            or not isinstance(action.action, TimeAdvanceAction)
        ):
            raise PermissionError("exact fresh authorization was not accepted")
        current_time = self._expected_root.clock_epoch + timedelta(milliseconds=self._clock_ms)
        if current_time > grant.expires_at:
            raise PermissionError("fresh authorization has expired")
        if not all(self._matches(item) for item in action.preconditions):
            raise ValueError("typed fragment precondition was not met")
        self._consumed_idempotency_keys.add(action.idempotency_key)
        for item in action.expected_effects:
            if item.operation is not EffectOperation.SET:
                raise ValueError("only closed SET effects are supported by this synthetic adapter")
            if not isinstance(item.value, bool | str):
                raise ValueError("synthetic state only accepts boolean or string values")
            self._state[item.path] = item.value
        self._clock_ms += action.action.milliseconds
        return (
            ReplayObservation(
                observation_id=f"observation.clean-room.{action.sequence:02d}",
                kind="typed_effect_applied",
                payload={"action_id": action.action_id, "clock_ms": self._clock_ms},
                evidence_ids=grant.fragment.evidence_ids,
            ),
        )

    async def cleanup(self) -> None:
        self.cleanup_calls += 1

    def _matches(self, item: ActionGuard) -> bool:
        return self._state.get(item.path) == item.expected

    def _validate_bundle(self) -> None:
        plan = self._authorized.plan
        action_ids = tuple(step.action.action_id for step in plan.steps)
        if len(action_ids) != len(set(action_ids)) or set(action_ids) != set(self._grants):
            raise ValueError("authorized plan and grants must have the same unique actions")
        for step in plan.steps:
            action = step.action
            grant = self._grants[action.action_id]
            request_action = grant.request.action_envelope
            evaluated_at = grant.request.evaluated_at
            if request_action is None or evaluated_at is None:
                raise ValueError("authorization request must retain its complete evaluated input")
            expected_ref = _policy_ref(
                chain_hash=self._authorized.chain_hash,
                effect_digest=grant.effect_digest,
                root_digest=self._authorized.root_digest,
                step_id=step.step_id,
                subject_digest=grant.action_subject_digest,
                expires_at=grant.expires_at,
            )
            expected_guards = tuple(
                (item.path, item.operator, item.value, item.reference)
                for item in grant.fragment.preconditions
            )
            actual_guards = tuple(
                (item.path, ComparisonOperator.EQ, item.expected, None)
                for item in action.preconditions
            )
            expected_effects = tuple(
                ExpectedEffect(path=item.path, operation=item.operation, value=item.value)
                for item in grant.fragment.effects
            )
            reevaluated = DeterministicPolicyEvaluator().evaluate(grant.request)
            if (
                grant.plan_id != plan.plan_id
                or grant.step_id != step.step_id
                or grant.chain_hash != self._authorized.chain_hash
                or grant.root_digest != self._authorized.root_digest
                or grant.decision_ref != expected_ref
                or action.policy_decision_ref != expected_ref
                or grant.action_digest != sha256_digest(action)
                or grant.action_subject_digest != _action_subject_digest(action)
                or canonical_json_bytes(request_action) != canonical_json_bytes(action)
                or grant.request_digest != grant.request.fingerprint()
                or grant.decision_digest != grant.decision.fingerprint()
                or canonical_json_bytes(reevaluated) != canonical_json_bytes(grant.decision)
                or grant.decision.outcome is not PolicyOutcome.ALLOW
                or grant.fragment_digest != sha256_digest(grant.fragment)
                or grant.effect_digest != sha256_digest(grant.fragment.effects)
                or canonical_json_bytes(action.expected_effects)
                != canonical_json_bytes(expected_effects)
                or canonical_json_bytes(action.action)
                != canonical_json_bytes(grant.fragment.action)
                or actual_guards != expected_guards
                or grant.fragment.source is not ProvenanceKind.MOCKED
                or grant.expires_at != evaluated_at + _AUTHORIZATION_LIFETIME
                or grant.request.scope_manifest is None
                or canonical_json_bytes(grant.request.scope_manifest)
                != canonical_json_bytes(_scope_manifest())
            ):
                raise ValueError("authorization grant is not causally closed")


class TerminalStateOracle:
    id = "oracle.terminal"
    version = "1.0"

    async def evaluate(
        self,
        before: StateCapture,
        action: ActionEnvelope,
        after: StateCapture,
        observations: tuple[ReplayObservation, ...],
    ) -> OracleResult:
        del before, observations
        application = next(
            item for item in after.artifacts if item.layer is CaptureLayer.APPLICATION
        )
        state = application.payload["state"]
        reached = isinstance(state, Mapping) and state.get("violation.reached") is True
        return OracleResult(
            oracle_result_id="oracle.result.clean-room",
            oracle_type=OracleType.CUSTOM_DETERMINISTIC,
            world_id=action.world_id,
            invariant="synthetic authorization invariant forbids violation.reached",
            result=OracleOutcome.VIOLATED if reached else OracleOutcome.SATISFIED,
            observed={"goal_reached": reached, "final_fingerprint": after.fingerprint},
            evidence_ids=("evidence.synthetic.terminal",),
            deterministic=True,
        )
