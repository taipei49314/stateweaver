"""Deterministic baseline and StateWeaver tiered-search benchmark adapters."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Protocol

from stateweaver.contracts import (
    CanonicalSecurityState,
    EstimatedCost,
    Hypothesis,
    OracleType,
    PredictedBoundary,
    WorldTier,
    sha256_digest,
)
from stateweaver.search import (
    BeamSearchPolicy,
    PolicyGateOutcome,
    PositiveScoreSignal,
    PromotionCost,
    PromotionGates,
    ScoreSignal,
    ScoreSource,
    SearchBatch,
    SearchCandidate,
    SearchScores,
    TieredSearchController,
)
from stateweaver.search import (
    BudgetLedger as SearchBudgetLedger,
)
from stateweaver.search import (
    BudgetLimits as SearchBudgetLimits,
)

from .models import (
    AblationFeature,
    AblationSpec,
    BudgetAttemptKind,
    BudgetEventKind,
    BudgetExceededError,
    BudgetExhaustion,
    BudgetLedger,
    BudgetLimits,
    CandidateSubmission,
    PublicAction,
    PublicChallenge,
    StopReason,
    SystemRun,
    action_is_applicable,
    apply_action,
    goal_is_reached,
    state_fingerprint,
    tiered_system_config_digest,
)


class BenchmarkSystem(Protocol):
    @property
    def system_id(self) -> str: ...

    @property
    def system_config_digest(self) -> str: ...

    def solve(self, challenge: PublicChallenge, budget: BudgetLimits) -> SystemRun: ...


@dataclass(frozen=True, slots=True)
class _Path:
    state: tuple[tuple[str, bool], ...]
    action_tokens: tuple[str, ...]

    def mapping(self) -> dict[str, bool]:
        return dict(self.state)


@dataclass(frozen=True, slots=True)
class _Expansion:
    candidate: SearchCandidate
    path: _Path
    action: PublicAction
    quality: float


@dataclass(frozen=True, slots=True)
class LinearBaseline:
    """One-pass catalog-order baseline with no branching or backtracking."""

    @property
    def system_id(self) -> str:
        return "system.linear_baseline_v1"

    @property
    def system_config_digest(self) -> str:
        return sha256_digest({"solver": "linear_baseline", "version": 1})

    def solve(self, challenge: PublicChallenge, budget: BudgetLimits) -> SystemRun:
        challenge = PublicChallenge.model_validate(challenge.model_dump(mode="python"))
        budget = BudgetLimits.model_validate(budget.model_dump(mode="python"))
        ledger = BudgetLedger(limits=budget)
        state = challenge.initial_mapping()
        selected: list[str] = []
        stop = StopReason.NO_PROGRESS
        exhaustion: BudgetExhaustion | None = None
        for action in challenge.actions:
            try:
                ledger = ledger.reserve(
                    kind=BudgetEventKind.PLAN,
                    operation_key=_operation(
                        "plan",
                        challenge.challenge_id,
                        "linear",
                        state_fingerprint(state),
                        action.token,
                    ),
                    action_token=action.token,
                    latency_units=1,
                )
            except BudgetExceededError:
                stop = StopReason.BUDGET_EXHAUSTED
                exhaustion = BudgetExhaustion(
                    attempt_kind=BudgetAttemptKind.PLAN,
                    action_token=action.token,
                    base_usage=ledger.usage,
                    action_cost_delta=0,
                    world_cost_delta=0,
                    latency_units_delta=1,
                )
                break
            if not action_is_applicable(action, state):
                continue
            try:
                action_proposed = ledger.reserve(
                    kind=BudgetEventKind.ACTION,
                    operation_key=_operation(
                        "execute", challenge.challenge_id, "linear", action.token
                    ),
                    action_token=action.token,
                    action_cost=action.action_cost,
                    latency_units=action.action_cost,
                )
            except BudgetExceededError:
                stop = StopReason.BUDGET_EXHAUSTED
                exhaustion = BudgetExhaustion(
                    attempt_kind=BudgetAttemptKind.ACTION,
                    action_token=action.token,
                    base_usage=ledger.usage,
                    action_cost_delta=action.action_cost,
                    world_cost_delta=0,
                    latency_units_delta=action.action_cost,
                )
                break
            try:
                proposed = action_proposed.reserve(
                    kind=BudgetEventKind.WORLD,
                    operation_key=_operation(
                        "world", challenge.challenge_id, "linear", action.token
                    ),
                    action_token=action.token,
                    world_cost=1,
                    latency_units=2,
                )
            except BudgetExceededError:
                stop = StopReason.BUDGET_EXHAUSTED
                exhaustion = BudgetExhaustion(
                    attempt_kind=BudgetAttemptKind.ACTION_WORLD,
                    action_token=action.token,
                    base_usage=ledger.usage,
                    action_cost_delta=action.action_cost,
                    world_cost_delta=1,
                    latency_units_delta=action.action_cost + 2,
                )
                break
            ledger = proposed
            state = apply_action(action, state)
            selected.append(action.token)
            if goal_is_reached(challenge, state):
                stop = StopReason.GOAL_REACHED
                break
        return SystemRun(
            system_id=self.system_id,
            system_config_digest=self.system_config_digest,
            submission=CandidateSubmission(
                challenge_id=challenge.challenge_id,
                action_tokens=tuple(selected),
            ),
            ledger=ledger,
            anchor_requested=True,
            stop_reason=stop,
            budget_exhaustion=exhaustion,
        )


@dataclass(frozen=True, slots=True)
class StateWeaverTieredSystem:
    """Adapt public state branches to the real M4 ``TieredSearchController``."""

    seed: int = 0
    beam_width: int = 3
    ablation: AblationSpec = field(default_factory=lambda: AblationSpec(disabled=()))

    def __post_init__(self) -> None:
        if self.seed < 0 or not 1 <= self.beam_width <= 16:
            raise ValueError("tiered benchmark system configuration is outside bounds")
        object.__setattr__(
            self,
            "ablation",
            AblationSpec.model_validate(self.ablation.model_dump(mode="python")),
        )

    @property
    def system_id(self) -> str:
        suffix = self.system_config_digest.removeprefix("sha256:")[:12]
        return f"system.stateweaver_{suffix}"

    @property
    def system_config_digest(self) -> str:
        return tiered_system_config_digest(
            seed=self.seed,
            beam_width=self.beam_width,
            ablation=self.ablation,
        )

    def solve(self, challenge: PublicChallenge, budget: BudgetLimits) -> SystemRun:
        challenge = PublicChallenge.model_validate(challenge.model_dump(mode="python"))
        budget = BudgetLimits.model_validate(budget.model_dump(mode="python"))
        ledger = BudgetLedger(limits=budget)
        search_ledger = SearchBudgetLedger(
            limits=SearchBudgetLimits(
                max_llm_calls=0,
                max_target_requests=budget.max_action_cost,
                max_write_requests=0,
                max_cpu_seconds=budget.max_latency_units,
                max_ghost=max(1, budget.max_world_cost),
                max_replay=budget.max_world_cost,
                max_simulated=0,
                max_materialized=0,
            )
        )
        controller = TieredSearchController(
            BeamSearchPolicy(
                seed=self.seed,
                replay_width=self.beam_width,
                simulated_width=1,
                materialized_width=1,
            )
        )
        initial = _Path(
            state=tuple(sorted(challenge.initial_mapping().items())),
            action_tokens=(),
        )
        frontier = [initial]
        observed_paths = [initial]
        seen = {state_fingerprint(initial.mapping())}
        search_fingerprints: list[str] = []
        exhausted = False
        exhaustion: BudgetExhaustion | None = None
        depth_limit = (
            1 if self.ablation.has(AblationFeature.CHAIN_COMPILER) else challenge.max_chain_length
        )

        for _depth in range(depth_limit):
            expansions: list[_Expansion] = []
            for path in frontier:
                state = path.mapping()
                for action in challenge.actions:
                    if action.token in path.action_tokens or not action_is_applicable(
                        action, state
                    ):
                        continue
                    next_state = apply_action(action, state)
                    semantic_fingerprint = state_fingerprint(next_state)
                    if (
                        not self.ablation.has(AblationFeature.STATE_FINGERPRINT_DEDUP)
                        and semantic_fingerprint in seen
                    ):
                        continue
                    next_tokens = (*path.action_tokens, action.token)
                    try:
                        ledger = ledger.reserve(
                            kind=BudgetEventKind.PLAN,
                            operation_key=_operation(
                                "plan",
                                challenge.challenge_id,
                                *next_tokens,
                            ),
                            action_token=action.token,
                            latency_units=1,
                        )
                    except BudgetExceededError:
                        exhausted = True
                        exhaustion = BudgetExhaustion(
                            attempt_kind=BudgetAttemptKind.PLAN,
                            action_token=action.token,
                            base_usage=ledger.usage,
                            action_cost_delta=0,
                            world_cost_delta=0,
                            latency_units_delta=1,
                        )
                        break
                    remaining = _minimum_remaining_steps(
                        challenge,
                        next_state,
                        frozenset(next_tokens),
                    )
                    quality = _quality(challenge, remaining)
                    if self.ablation.has(AblationFeature.SEMANTIC_TWIN):
                        quality = 0.5
                    next_path = _Path(
                        state=tuple(sorted(next_state.items())),
                        action_tokens=next_tokens,
                    )
                    candidate = _search_candidate(
                        challenge=challenge,
                        path=next_path,
                        action=action,
                        quality=quality,
                        preserve_path_identity=self.ablation.has(
                            AblationFeature.STATE_FINGERPRINT_DEDUP
                        ),
                    )
                    expansions.append(
                        _Expansion(
                            candidate=candidate,
                            path=next_path,
                            action=action,
                            quality=quality,
                        )
                    )
                if exhausted:
                    break
            if not expansions:
                break

            by_id = {item.candidate.candidate_id: item for item in expansions}
            if self.ablation.has(AblationFeature.BUDGET_AWARE_SCHEDULER):
                promoted_ids = tuple(
                    item.candidate.candidate_id for item in expansions[: self.beam_width]
                )
            elif self.ablation.has(AblationFeature.WORLD_TIERS):
                promoted_ids = tuple(
                    item.candidate.candidate_id
                    for item in sorted(
                        expansions,
                        key=lambda item: (-item.quality, item.candidate.candidate_id),
                    )[: self.beam_width]
                )
            else:
                search_result = controller.advance(
                    SearchBatch(candidates=tuple(item.candidate for item in expansions)),
                    search_ledger,
                )
                search_ledger = search_result.ledger
                if search_result.fingerprint not in search_fingerprints:
                    search_fingerprints.append(search_result.fingerprint)
                promoted_ids = search_result.promoted_candidate_ids

            next_frontier: list[_Path] = []
            for candidate_id in promoted_ids:
                expansion = by_id[candidate_id]
                try:
                    action_proposed = ledger.reserve(
                        kind=BudgetEventKind.ACTION,
                        operation_key=_operation("execute", challenge.challenge_id, candidate_id),
                        action_token=expansion.action.token,
                        action_cost=expansion.action.action_cost,
                        latency_units=expansion.action.action_cost,
                    )
                except BudgetExceededError:
                    exhausted = True
                    exhaustion = BudgetExhaustion(
                        attempt_kind=BudgetAttemptKind.ACTION,
                        action_token=expansion.action.token,
                        base_usage=ledger.usage,
                        action_cost_delta=expansion.action.action_cost,
                        world_cost_delta=0,
                        latency_units_delta=expansion.action.action_cost,
                    )
                    break
                proposed = action_proposed
                if not self.ablation.has(AblationFeature.WORLD_TIERS):
                    try:
                        proposed = action_proposed.reserve(
                            kind=BudgetEventKind.WORLD,
                            operation_key=_operation("world", challenge.challenge_id, candidate_id),
                            action_token=expansion.action.token,
                            world_cost=1,
                            latency_units=2,
                        )
                    except BudgetExceededError:
                        exhausted = True
                        exhaustion = BudgetExhaustion(
                            attempt_kind=BudgetAttemptKind.ACTION_WORLD,
                            action_token=expansion.action.token,
                            base_usage=ledger.usage,
                            action_cost_delta=expansion.action.action_cost,
                            world_cost_delta=1,
                            latency_units_delta=expansion.action.action_cost + 2,
                        )
                        break
                ledger = proposed
                next_frontier.append(expansion.path)
                observed_paths.append(expansion.path)
                seen.add(state_fingerprint(expansion.path.mapping()))
            frontier = next_frontier
            successful = [path for path in frontier if goal_is_reached(challenge, path.mapping())]
            if successful:
                best = min(successful, key=_path_order)
                return self._run(
                    challenge,
                    ledger,
                    best,
                    StopReason.GOAL_REACHED,
                    tuple(search_fingerprints),
                    None,
                )
            if exhausted or not frontier:
                break

        best = min(
            observed_paths,
            key=lambda item: (
                _distance_order(
                    _minimum_remaining_steps(
                        challenge,
                        item.mapping(),
                        frozenset(item.action_tokens),
                    )
                ),
                _path_order(item),
            ),
        )
        if self.ablation.has(AblationFeature.CHAIN_COMPILER):
            stop = StopReason.CHAIN_COMPILER_DISABLED
        elif exhausted:
            stop = StopReason.BUDGET_EXHAUSTED
        elif len(best.action_tokens) >= depth_limit:
            stop = StopReason.DEPTH_LIMIT
        else:
            stop = StopReason.NO_PROGRESS
        return self._run(
            challenge,
            ledger,
            best,
            stop,
            tuple(search_fingerprints),
            exhaustion if stop is StopReason.BUDGET_EXHAUSTED else None,
        )

    def _run(
        self,
        challenge: PublicChallenge,
        ledger: BudgetLedger,
        path: _Path,
        stop: StopReason,
        search_fingerprints: tuple[str, ...],
        exhaustion: BudgetExhaustion | None,
    ) -> SystemRun:
        return SystemRun(
            system_id=self.system_id,
            system_config_digest=self.system_config_digest,
            submission=CandidateSubmission(
                challenge_id=challenge.challenge_id,
                action_tokens=path.action_tokens,
            ),
            ledger=ledger,
            anchor_requested=not self.ablation.has(AblationFeature.REALITY_ANCHOR),
            stop_reason=stop,
            budget_exhaustion=exhaustion,
            search_fingerprints=search_fingerprints,
        )


def _search_candidate(
    *,
    challenge: PublicChallenge,
    path: _Path,
    action: PublicAction,
    quality: float,
    preserve_path_identity: bool,
) -> SearchCandidate:
    suffix = sha256_digest((challenge.challenge_id, path.action_tokens)).removeprefix("sha256:")[
        :24
    ]
    state = path.mapping()
    capabilities = [key for key, value in state.items() if value]
    if preserve_path_identity:
        capabilities.append(f"path.{suffix[:16]}")
    canonical_state = CanonicalSecurityState(
        capabilities=tuple(sorted(capabilities)),
        controlled_time_bucket=0,
    )
    hypothesis = Hypothesis(
        hypothesis_id=f"hypothesis.{suffix}",
        claim="Synthetic state transition may advance the public goal condition",
        required_facts=("state_value",),
        predicted_boundary=PredictedBoundary(type=OracleType.WORKFLOW_INTEGRITY),
        novelty_score=quality,
        information_gain=quality,
        estimated_cost=EstimatedCost(
            llm_calls=0,
            target_requests=action.action_cost,
            materialized_worlds=0,
        ),
        suggested_mutations=("state.value",),
    )

    def signal(value: float, source: ScoreSource) -> ScoreSignal:
        return ScoreSignal(value=value, source=source)

    return SearchCandidate(
        candidate_id=f"candidate.{suffix}",
        hypothesis=hypothesis,
        tier=WorldTier.GHOST,
        state=canonical_state,
        state_fingerprint=canonical_state.fingerprint(),
        diversity_key=f"branch.{action.effects[0].key.removeprefix('state.')}",
        scores=SearchScores(
            boundary_impact=signal(quality, ScoreSource.DETERMINISTIC),
            information_gain=signal(quality, ScoreSource.DETERMINISTIC),
            novelty=signal(quality, ScoreSource.DETERMINISTIC),
            composability=signal(quality, ScoreSource.DETERMINISTIC),
            fidelity=signal(1.0, ScoreSource.MEASURED),
            reachability=signal(quality, ScoreSource.DETERMINISTIC),
            normalized_cost=PositiveScoreSignal(
                value=action.action_cost / 16,
                source=ScoreSource.DETERMINISTIC,
            ),
            operational_risk=PositiveScoreSignal(
                value=0.1,
                source=ScoreSource.POLICY,
            ),
        ),
        uncertainty=ScoreSignal(value=0.1, source=ScoreSource.MEASURED),
        gates=PromotionGates(
            in_scope=True,
            policy_outcome=PolicyGateOutcome.ALLOW,
            policy_decision_ref=f"policy.{suffix}",
            reversible=True,
            snapshot_capable=True,
            # The candidate state is post-transition; the typed action effects are the
            # facts learned by promoting this branch.
            new_fact_count=len(action.effects),
            calibration_path=True,
        ),
        promotion_cost=PromotionCost(
            target_requests=action.action_cost,
            cpu_seconds=1,
        ),
    )


def _minimum_remaining_steps(
    challenge: PublicChallenge,
    state: dict[str, bool],
    used: frozenset[str],
) -> int | None:
    if goal_is_reached(challenge, state):
        return 0
    pending: deque[tuple[dict[str, bool], frozenset[str], int]] = deque([(state, used, 0)])
    visited = {(state_fingerprint(state), used)}
    while pending:
        current, consumed, depth = pending.popleft()
        if depth >= challenge.max_chain_length:
            continue
        for action in challenge.actions:
            if action.token in consumed or not action_is_applicable(action, current):
                continue
            following = apply_action(action, current)
            if goal_is_reached(challenge, following):
                return depth + 1
            next_consumed = consumed | {action.token}
            key = (state_fingerprint(following), next_consumed)
            if key in visited:
                continue
            visited.add(key)
            pending.append((following, next_consumed, depth + 1))
    return None


def _quality(challenge: PublicChallenge, remaining: int | None) -> float:
    if remaining is None:
        return 0.05
    if remaining == 0:
        return 1.0
    return max(0.1, 1.0 - remaining / (challenge.max_chain_length + 1))


def _distance_order(distance: int | None) -> int:
    return 1_000_000 if distance is None else distance


def _path_order(path: _Path) -> tuple[int, tuple[str, ...]]:
    return (len(path.action_tokens), path.action_tokens)


def _operation(prefix: str, *parts: object) -> str:
    suffix = sha256_digest(parts).removeprefix("sha256:")[:24]
    return f"{prefix}.{suffix}"
