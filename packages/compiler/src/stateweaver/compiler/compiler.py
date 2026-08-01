"""A deterministic, bounded planner over typed synthetic transition fragments."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from itertools import combinations
from typing import Any, cast

from stateweaver.contracts import (
    ActionEnvelope,
    ArtifactHandle,
    ComparisonOperator,
    EffectOperation,
    HttpRequestAction,
    IdentityHandle,
    StateCondition,
    StateEffect,
    TimeAdvanceAction,
    TransitionFragment,
    sha256_digest,
)

from .models import CompiledChain, CompilerFragment, RootState, TerminalGoal


@dataclass
class CompilationError(ValueError):
    """Stable, value-safe failure localization for a rejected chain."""

    code: str
    fragment_id: str | None = None

    def __str__(self) -> str:
        suffix = "" if self.fragment_id is None else f" at {self.fragment_id}"
        return f"chain compilation failed: {self.code}{suffix}"


@dataclass(frozen=True)
class _Simulation:
    state: Mapping[str, object]
    clock_ms: int
    ordered: tuple[CompilerFragment, ...]


class ChainCompiler:
    """Compile only closed typed actions; it never opens targets or executes a plan."""

    def compile(
        self,
        *,
        chain_id: str,
        root: RootState,
        fragments: Iterable[CompilerFragment],
        goal: TerminalGoal,
    ) -> CompiledChain:
        nodes = tuple(sorted(fragments, key=lambda item: item.fragment_id))
        if not nodes:
            raise CompilationError("NO_FRAGMENTS")
        if len(nodes) != len({item.fragment_id for item in nodes}):
            raise CompilationError("DUPLICATE_FRAGMENT_ID")
        self._validate_nodes(root, nodes)
        initial = _state_from_conditions(root.conditions)
        relevant = tuple(
            node for node in nodes if _can_contribute(node.fragment, goal.conditions, nodes)
        )
        if not relevant:
            raise CompilationError("GOAL_UNREACHABLE")
        first_error: CompilationError | None = None
        conflict_error: CompilationError | None = None
        # Synthetic fragment sets are deliberately small, so exhaustive minimization is stable.
        for size in range(1, len(relevant) + 1):
            for selected in combinations(relevant, size):
                try:
                    self._assert_effects_compatible(selected)
                    simulation = _schedule(selected, initial, root.clock_ms, goal.conditions)
                except CompilationError as error:
                    first_error = first_error or error
                    if error.code == "MUTUALLY_EXCLUSIVE_EFFECT":
                        conflict_error = error
                    continue
                if _all_conditions(goal.conditions, simulation.state):
                    envelopes = tuple(
                        _resequenced_envelope(item.envelope, index)
                        for index, item in enumerate(simulation.ordered)
                    )
                    fragment_ids = tuple(item.fragment_id for item in simulation.ordered)
                    root_state_hash = sha256_digest(root)
                    fragment_semantic_hashes = tuple(
                        sha256_digest(item) for item in simulation.ordered
                    )
                    projection: dict[str, object] = {
                        "root_seed_id": root.root_seed_id,
                        "world_id": root.world_id,
                        "fragment_ids": fragment_ids,
                        "action_envelopes": envelopes,
                        "root_state_hash": root_state_hash,
                        "fragment_semantic_hashes": fragment_semantic_hashes,
                        "terminal_goal": goal,
                        "requires_policy_reauthorization": True,
                    }
                    return CompiledChain(
                        chain_id=chain_id,
                        root_seed_id=root.root_seed_id,
                        world_id=root.world_id,
                        fragment_ids=fragment_ids,
                        action_envelopes=envelopes,
                        root_state_hash=root_state_hash,
                        fragment_semantic_hashes=fragment_semantic_hashes,
                        terminal_goal=goal,
                        causal_hash=sha256_digest(projection),
                    )
        if _has_dependency_cycle(relevant, initial):
            raise CompilationError("DEPENDENCY_CYCLE")
        if conflict_error is not None:
            raise conflict_error
        raise first_error or CompilationError("GOAL_UNREACHABLE")

    def _validate_nodes(self, root: RootState, nodes: tuple[CompilerFragment, ...]) -> None:
        sessions: dict[str, str] = {}
        for node in nodes:
            if node.world_id != root.world_id:
                raise CompilationError("WORLD_MISMATCH", node.fragment_id)
            identity, artifact = _action_bindings(node.fragment)
            if node.binding.identity_handle != identity:
                raise CompilationError("IDENTITY_BINDING_MISMATCH", node.fragment_id)
            if node.binding.artifact_handle != artifact:
                raise CompilationError("ARTIFACT_BINDING_MISMATCH", node.fragment_id)
            if node.binding.session_handle is not None and node.binding.identity_handle is not None:
                existing = sessions.setdefault(
                    node.binding.session_handle, node.binding.identity_handle
                )
                if existing != node.binding.identity_handle:
                    raise CompilationError("SESSION_IDENTITY_CONFLICT", node.fragment_id)
            if any(parent not in {item.fragment_id for item in nodes} for parent in node.after):
                raise CompilationError("UNKNOWN_ORDERING_DEPENDENCY", node.fragment_id)

    @staticmethod
    def _assert_effects_compatible(selected: tuple[CompilerFragment, ...]) -> None:
        values: dict[str, object] = {}
        for node in selected:
            for effect in node.fragment.effects:
                if effect.operation is EffectOperation.SET:
                    previous = values.setdefault(effect.path, effect.value)
                    if previous != effect.value:
                        raise CompilationError("MUTUALLY_EXCLUSIVE_EFFECT", node.fragment_id)


def _resequenced_envelope(envelope: ActionEnvelope, sequence: int) -> ActionEnvelope:
    payload = {name: getattr(envelope, name) for name in type(envelope).model_fields}
    payload["sequence"] = sequence
    return ActionEnvelope.model_validate(payload)


def _action_bindings(
    fragment: TransitionFragment,
) -> tuple[IdentityHandle | None, ArtifactHandle | None]:
    action = fragment.action
    if isinstance(action, HttpRequestAction):
        return action.identity_handle, action.body_artifact
    identity = getattr(action, "identity_handle", None)
    artifact = getattr(action, "value_artifact", None)
    return identity, artifact


def _state_from_conditions(conditions: tuple[StateCondition, ...]) -> dict[str, object]:
    state: dict[str, object] = {}
    for condition in conditions:
        if condition.operator is ComparisonOperator.EQ and condition.reference is None:
            current = state.setdefault(condition.path, condition.value)
            if current != condition.value:
                raise CompilationError("ROOT_STATE_CONFLICT")
        elif condition.operator is ComparisonOperator.EXISTS:
            state.setdefault(condition.path, True)
        elif condition.operator is ComparisonOperator.NOT_EXISTS:
            state.pop(condition.path, None)
    if not _all_conditions(conditions, state):
        raise CompilationError("ROOT_STATE_CONFLICT")
    return state


def _can_contribute(
    fragment: TransitionFragment,
    goals: tuple[StateCondition, ...],
    all_nodes: tuple[CompilerFragment, ...],
) -> bool:
    needed = tuple(goals) + tuple(
        condition for node in all_nodes for condition in node.fragment.preconditions
    )
    return any(
        _effect_supports(effect, condition) for effect in fragment.effects for condition in needed
    )


def _effect_supports(effect: StateEffect, condition: StateCondition) -> bool:
    if effect.path != condition.path or condition.reference is not None:
        return False
    if effect.operation is EffectOperation.SET:
        return condition.operator is ComparisonOperator.EQ and effect.value == condition.value
    if effect.operation is EffectOperation.ADD:
        return condition.operator in {ComparisonOperator.CONTAINS, ComparisonOperator.EXISTS}
    if effect.operation is EffectOperation.REMOVE:
        return condition.operator in {
            ComparisonOperator.NOT_EXISTS,
            ComparisonOperator.NOT_CONTAINS,
        }
    return False


def _schedule(
    selected: tuple[CompilerFragment, ...],
    initial: Mapping[str, object],
    clock_ms: int,
    goal: tuple[StateCondition, ...],
) -> _Simulation:
    remaining = list(selected)
    ordered: list[CompilerFragment] = []
    state = dict(initial)
    current_clock = clock_ms
    while remaining:
        ready = [
            node
            for node in remaining
            if set(node.after).issubset({item.fragment_id for item in ordered})
            and _all_conditions(node.fragment.preconditions, state)
            and node.window.opens_at_ms <= current_clock <= node.window.closes_at_ms
        ]
        if not ready:
            candidate = min(remaining, key=lambda item: item.fragment_id)
            if not _all_conditions(candidate.fragment.preconditions, state):
                raise CompilationError("MISSING_PRECONDITION", candidate.fragment_id)
            if not set(candidate.after).issubset({item.fragment_id for item in ordered}):
                raise CompilationError("ORDERING_BLOCKED", candidate.fragment_id)
            raise CompilationError("TIME_WINDOW_MISSED", candidate.fragment_id)
        node = min(ready, key=lambda item: item.fragment_id)
        _apply_effects(state, node.fragment.effects)
        if isinstance(node.fragment.action, TimeAdvanceAction):
            current_clock += node.fragment.action.milliseconds
        ordered.append(node)
        remaining.remove(node)
    if not _all_conditions(goal, state):
        raise CompilationError("GOAL_UNREACHABLE")
    return _Simulation(state=state, clock_ms=current_clock, ordered=tuple(ordered))


def _all_conditions(conditions: tuple[StateCondition, ...], state: Mapping[str, object]) -> bool:
    return all(_condition_matches(condition, state) for condition in conditions)


def _condition_matches(condition: StateCondition, state: Mapping[str, object]) -> bool:
    exists = condition.path in state
    if condition.operator is ComparisonOperator.EXISTS:
        return exists
    if condition.operator is ComparisonOperator.NOT_EXISTS:
        return not exists
    if not exists:
        return False
    left = state[condition.path]
    right: object = (
        state.get(condition.reference) if condition.reference is not None else condition.value
    )
    try:
        if condition.operator is ComparisonOperator.EQ:
            return bool(left == right)
        if condition.operator is ComparisonOperator.NE:
            return bool(left != right)
        if condition.operator is ComparisonOperator.LT:
            return bool(cast(Any, left) < right)
        if condition.operator is ComparisonOperator.LE:
            return bool(cast(Any, left) <= right)
        if condition.operator is ComparisonOperator.GT:
            return bool(cast(Any, left) > right)
        if condition.operator is ComparisonOperator.GE:
            return bool(cast(Any, left) >= right)
        if condition.operator is ComparisonOperator.CONTAINS:
            return bool(cast(Any, right) in cast(Any, left))
        if condition.operator is ComparisonOperator.NOT_CONTAINS:
            return bool(cast(Any, right) not in cast(Any, left))
    except (KeyError, TypeError):
        return False


def _apply_effects(state: dict[str, object], effects: tuple[StateEffect, ...]) -> None:
    for effect in effects:
        if effect.operation is EffectOperation.SET:
            state[effect.path] = effect.value
        elif effect.operation is EffectOperation.ADD:
            current = state.get(effect.path, ())
            values = current if isinstance(current, tuple) else (current,)
            state[effect.path] = (*values, effect.value)
        elif effect.operation is EffectOperation.REMOVE:
            state.pop(effect.path, None)
        elif effect.operation is EffectOperation.INCREMENT:
            state[effect.path] = _number(state.get(effect.path, 0)) + _number(effect.value)
        elif effect.operation is EffectOperation.DECREMENT:
            state[effect.path] = _number(state.get(effect.path, 0)) - _number(effect.value)


def _number(value: object) -> int | float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise CompilationError("INVALID_NUMERIC_EFFECT")
    return value


def _has_dependency_cycle(
    nodes: tuple[CompilerFragment, ...], initial: Mapping[str, object]
) -> bool:
    identifiers = {node.fragment_id for node in nodes}
    edges: dict[str, set[str]] = {identifier: set() for identifier in identifiers}
    for node in nodes:
        for condition in node.fragment.preconditions:
            if _condition_matches(condition, initial):
                continue
            producers = {
                candidate.fragment_id
                for candidate in nodes
                if any(_effect_supports(effect, condition) for effect in candidate.fragment.effects)
            }
            edges[node.fragment_id].update(producers)
    visited: set[str] = set()
    active: set[str] = set()

    def visit(identifier: str) -> bool:
        if identifier in active:
            return True
        if identifier in visited:
            return False
        visited.add(identifier)
        active.add(identifier)
        cyclic = any(visit(child) for child in edges[identifier])
        active.remove(identifier)
        return cyclic

    return any(visit(identifier) for identifier in sorted(identifiers))
