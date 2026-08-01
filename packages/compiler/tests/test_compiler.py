from __future__ import annotations

import hashlib
from itertools import permutations

import pytest
from stateweaver.compiler import (
    ChainCompiler,
    CompilationError,
    CompilerFragment,
    RootState,
    TerminalGoal,
    TimeWindow,
)
from stateweaver.compiler.models import FragmentBinding
from stateweaver.contracts import (
    ActionEnvelope,
    ActionTarget,
    ComparisonOperator,
    EffectOperation,
    FidelityLevel,
    FidelityProfile,
    HttpMethod,
    HttpRequestAction,
    ProvenanceKind,
    RequestedBy,
    RequesterType,
    RiskClass,
    ScopeAction,
    StateCondition,
    StateEffect,
    TimeAdvanceAction,
    TransitionFragment,
)

JsonScalar = str | int | float | bool | None


def _condition(path: str, value: JsonScalar) -> StateCondition:
    return StateCondition(path=path, operator=ComparisonOperator.EQ, value=value)


def _http_action(*, identity: str = "identity:synthetic-user") -> HttpRequestAction:
    return HttpRequestAction(
        method=HttpMethod.POST,
        target=ActionTarget(scheme="http", host="localhost", port=80, path="/v1/lab/**"),
        identity_handle=identity,
        expected_statuses=(200,),
    )


def _fragment(
    identifier: str,
    *,
    preconditions: tuple[StateCondition, ...] = (),
    effects: tuple[StateEffect, ...],
    action: object | None = None,
    world_id: str = "world.synthetic",
    window: TimeWindow | None = None,
    after: tuple[str, ...] = (),
    identity: str = "identity:synthetic-user",
) -> CompilerFragment:
    typed_action = _http_action(identity=identity) if action is None else action
    assert isinstance(typed_action, HttpRequestAction | TimeAdvanceAction)
    envelope = ActionEnvelope(
        action_id=f"action.{identifier.rsplit('.', 1)[-1]}",
        experiment_id="experiment.synthetic",
        world_id=world_id,
        scope_action=(
            ScopeAction.CONTROLLED_TIME
            if isinstance(typed_action, TimeAdvanceAction)
            else ScopeAction.HTTP_REQUEST
        ),
        action=typed_action,
        risk_class=RiskClass.REVERSIBLE_STATE_CHANGE,
        idempotency_key="sha256:" + hashlib.sha256(identifier.encode("utf-8")).hexdigest(),
        requested_by=RequestedBy(type=RequesterType.WORKFLOW, role="compiler-test"),
        policy_decision_ref=f"policy.{identifier.rsplit('.', 1)[-1]}",
    )
    transition = TransitionFragment(
        transition_id=identifier,
        name=identifier,
        source=ProvenanceKind.OBSERVED,
        preconditions=preconditions or (_condition("root.ready", True),),
        action=typed_action,
        effects=effects,
        observables=(_condition("response.ok", True),),
        evidence_ids=("evidence.01",),
        fidelity=FidelityProfile(code=FidelityLevel.EXACT),
    )
    return CompilerFragment(
        fragment=transition,
        envelope=envelope,
        world_id=world_id,
        binding=FragmentBinding(
            identity_handle=identity if isinstance(typed_action, HttpRequestAction) else None
        ),
        window=window or TimeWindow(),
        after=after,
    )


def _effect(path: str, value: JsonScalar) -> StateEffect:
    return StateEffect(path=path, operation=EffectOperation.SET, value=value)


def _root() -> RootState:
    return RootState(
        root_seed_id="root.synthetic",
        world_id="world.synthetic",
        conditions=(_condition("root.ready", True),),
    )


def _goal() -> TerminalGoal:
    return TerminalGoal(goal_id="goal.violation", conditions=(_condition("violation.ready", True),))


def test_compiles_three_fragment_minimal_chain_and_replay_plan() -> None:
    fragments = (
        _fragment("fragment.prepare", effects=(_effect("session.old", True),)),
        _fragment(
            "fragment.cache",
            preconditions=(_condition("session.old", True),),
            effects=(_effect("cache.stale", True),),
        ),
        _fragment(
            "fragment.read",
            preconditions=(_condition("cache.stale", True),),
            effects=(_effect("violation.ready", True),),
        ),
        _fragment("fragment.decoy", effects=(_effect("unused.flag", True),)),
    )
    chain = ChainCompiler().compile(
        chain_id="chain.synthetic", root=_root(), fragments=fragments, goal=_goal()
    )

    assert chain.fragment_ids == ("fragment.prepare", "fragment.cache", "fragment.read")
    assert chain.requires_policy_reauthorization is True
    assert len(chain.fragment_semantic_hashes) == 3
    assert len(chain.to_replay_plan(plan_id="plan.synthetic").steps) == 3


def test_input_permutations_have_identical_order_and_causal_hash() -> None:
    fragments = (
        _fragment("fragment.prepare", effects=(_effect("session.old", True),)),
        _fragment(
            "fragment.cache",
            preconditions=(_condition("session.old", True),),
            effects=(_effect("cache.stale", True),),
        ),
        _fragment(
            "fragment.read",
            preconditions=(_condition("cache.stale", True),),
            effects=(_effect("violation.ready", True),),
        ),
    )
    compiled = [
        ChainCompiler().compile(
            chain_id="chain.synthetic", root=_root(), fragments=order, goal=_goal()
        )
        for order in permutations(fragments)
    ]
    assert {chain.fragment_ids for chain in compiled} == {compiled[0].fragment_ids}
    assert {chain.causal_hash for chain in compiled} == {compiled[0].causal_hash}


def test_causal_hash_binds_root_and_complete_fragment_semantics() -> None:
    fragment = _fragment("fragment.read", effects=(_effect("violation.ready", True),))
    baseline = ChainCompiler().compile(
        chain_id="chain.synthetic", root=_root(), fragments=(fragment,), goal=_goal()
    )
    changed_root = ChainCompiler().compile(
        chain_id="chain.synthetic",
        root=_root().model_copy(update={"clock_ms": 1}),
        fragments=(fragment,),
        goal=_goal(),
    )
    changed_fragment = ChainCompiler().compile(
        chain_id="chain.synthetic",
        root=_root(),
        fragments=(fragment.model_copy(update={"cost": 2}),),
        goal=_goal(),
    )

    assert len({baseline.causal_hash, changed_root.causal_hash, changed_fragment.causal_hash}) == 3


def test_mutually_exclusive_effects_are_rejected() -> None:
    fragments = (
        _fragment("fragment.one", effects=(_effect("state.flag", "one"),)),
        _fragment(
            "fragment.two",
            preconditions=(_condition("state.flag", "one"),),
            effects=(_effect("state.flag", "two"), _effect("violation.ready", True)),
        ),
    )
    with pytest.raises(CompilationError, match="MUTUALLY_EXCLUSIVE_EFFECT"):
        ChainCompiler().compile(
            chain_id="chain.conflict", root=_root(), fragments=fragments, goal=_goal()
        )


def test_missing_precondition_is_localized() -> None:
    fragment = _fragment(
        "fragment.read",
        preconditions=(_condition("cache.stale", True),),
        effects=(_effect("violation.ready", True),),
    )
    with pytest.raises(CompilationError, match=r"MISSING_PRECONDITION at fragment\.read"):
        ChainCompiler().compile(
            chain_id="chain.missing", root=_root(), fragments=(fragment,), goal=_goal()
        )


def test_identity_and_world_confusion_are_rejected() -> None:
    fragment = _fragment(
        "fragment.world", effects=(_effect("violation.ready", True),), world_id="world.other"
    )
    with pytest.raises(CompilationError, match="WORLD_MISMATCH"):
        ChainCompiler().compile(
            chain_id="chain.world", root=_root(), fragments=(fragment,), goal=_goal()
        )

    identity = _fragment("fragment.identity", effects=(_effect("violation.ready", True),))
    wrong_binding = identity.model_copy(
        update={"binding": FragmentBinding(identity_handle="identity:synthetic-other")}
    )
    with pytest.raises(CompilationError, match="IDENTITY_BINDING_MISMATCH"):
        ChainCompiler().compile(
            chain_id="chain.identity", root=_root(), fragments=(wrong_binding,), goal=_goal()
        )


def test_time_windows_and_dependency_cycles_fail_closed() -> None:
    advance = _fragment(
        "fragment.advance",
        action=TimeAdvanceAction(milliseconds=10),
        effects=(_effect("clock.advanced", True),),
    )
    window = _fragment(
        "fragment.window",
        preconditions=(_condition("clock.advanced", True),),
        effects=(_effect("violation.ready", True),),
        window=TimeWindow(opens_at_ms=10, closes_at_ms=20),
    )
    chain = ChainCompiler().compile(
        chain_id="chain.time", root=_root(), fragments=(window, advance), goal=_goal()
    )
    assert chain.fragment_ids == ("fragment.advance", "fragment.window")

    first = _fragment(
        "fragment.first",
        preconditions=(_condition("state.second", True),),
        effects=(_effect("state.first", True),),
    )
    second = _fragment(
        "fragment.second",
        preconditions=(_condition("state.first", True),),
        effects=(_effect("violation.ready", True), _effect("state.second", True)),
    )
    with pytest.raises(CompilationError, match="DEPENDENCY_CYCLE"):
        ChainCompiler().compile(
            chain_id="chain.cycle", root=_root(), fragments=(first, second), goal=_goal()
        )
