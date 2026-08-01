"""Unique, local-only fixtures for the search package tests."""

from __future__ import annotations

from stateweaver.contracts import (
    CanonicalSecurityState,
    ComparisonOperator,
    EffectOperation,
    EstimatedCost,
    FidelityLevel,
    FidelityProfile,
    Hypothesis,
    OracleType,
    PredictedBoundary,
    ProvenanceKind,
    StateCondition,
    StateEffect,
    TimeAdvanceAction,
    TransitionFragment,
    WorldTier,
)
from stateweaver.search import (
    BudgetLedger,
    BudgetLimits,
    PolicyGateOutcome,
    PositiveScoreSignal,
    PromotionCost,
    PromotionGates,
    ScoreSignal,
    ScoreSource,
    SearchCandidate,
    SearchScores,
)


def condition(path: str = "session.generation", value: int = 1) -> StateCondition:
    return StateCondition(path=path, operator=ComparisonOperator.EQ, value=value)


def fragment(index: int = 0) -> TransitionFragment:
    return TransitionFragment(
        transition_id=f"transition.synthetic.{index:03d}",
        name="synthetic controlled-time state transition",
        source=ProvenanceKind.OBSERVED,
        preconditions=(condition(),),
        action=TimeAdvanceAction(milliseconds=1_000),
        effects=(
            StateEffect(
                path="session.generation",
                operation=EffectOperation.SET,
                value=2,
            ),
        ),
        observables=(condition("response.status", 200),),
        evidence_ids=(f"ev.synthetic.{index:03d}",),
        fidelity=FidelityProfile(
            code=FidelityLevel.EXACT,
            identity=FidelityLevel.OBSERVED,
            timing=FidelityLevel.OBSERVED,
        ),
        consistent_replays=1,
    )


def gates(
    index: int = 0,
    *,
    policy: PolicyGateOutcome = PolicyGateOutcome.ALLOW,
    in_scope: bool = True,
    evidence: bool = True,
    complete: bool = True,
) -> PromotionGates:
    return PromotionGates(
        in_scope=in_scope,
        policy_outcome=policy,
        policy_decision_ref=f"policy.synthetic.{index:03d}",
        reversible=True,
        action_plan_refs=(f"plan.synthetic.{index:03d}",) if complete else (),
        expected_observations=(condition("response.status", 200),) if complete else (),
        oracle_refs=(f"oracle.synthetic.{index:03d}",) if complete else (),
        evidence_ids=(f"ev.synthetic.{index:03d}",) if evidence else (),
        required_capabilities=("synthetic_snapshot",),
        available_capabilities=("synthetic_snapshot",),
        snapshot_capable=complete,
        new_fact_count=1,
        calibration_path=False,
    )


def candidate(
    index: int,
    *,
    tier: WorldTier = WorldTier.GHOST,
    score: float = 0.7,
    uncertainty: float = 0.5,
    diversity: str | None = None,
    state_bucket: int | None = None,
    promotion_gates: PromotionGates | None = None,
    cost: PromotionCost | None = None,
    with_fragment: bool | None = None,
    score_source: ScoreSource = ScoreSource.DETERMINISTIC,
) -> SearchCandidate:
    novelty = min(1.0, score)
    information_gain = min(1.0, score)
    hypothesis = Hypothesis(
        hypothesis_id=f"hypothesis.synthetic.{index:03d}",
        claim=f"Synthetic state hypothesis number {index:03d}",
        required_facts=("session_generation",),
        predicted_boundary=PredictedBoundary(type=OracleType.AUTHORIZATION),
        novelty_score=novelty,
        information_gain=information_gain,
        estimated_cost=EstimatedCost(llm_calls=0, target_requests=1, materialized_worlds=0),
        suggested_mutations=("session.generation",),
    )

    def signal(value: float, source: ScoreSource) -> ScoreSignal:
        return ScoreSignal(value=value, source=source)

    include_fragment = tier is WorldTier.SIMULATED if with_fragment is None else with_fragment
    state = CanonicalSecurityState(
        controlled_time_bucket=(index + 1 if state_bucket is None else state_bucket)
    )
    return SearchCandidate(
        candidate_id=f"candidate.synthetic.{index:03d}",
        hypothesis=hypothesis,
        tier=tier,
        state=state,
        state_fingerprint=state.fingerprint(),
        diversity_key=diversity or f"family.synthetic.{index % 4}",
        scores=SearchScores(
            boundary_impact=signal(score, ScoreSource.DETERMINISTIC),
            information_gain=signal(information_gain, score_source),
            novelty=signal(novelty, score_source),
            composability=signal(score, ScoreSource.DETERMINISTIC),
            fidelity=signal(score, ScoreSource.MEASURED),
            reachability=signal(score, ScoreSource.DETERMINISTIC),
            normalized_cost=PositiveScoreSignal(value=0.5, source=ScoreSource.DETERMINISTIC),
            operational_risk=PositiveScoreSignal(value=0.5, source=ScoreSource.POLICY),
        ),
        uncertainty=ScoreSignal(value=uncertainty, source=ScoreSource.MEASURED),
        transition_fragments=(fragment(index),) if include_fragment else (),
        state_predicates=(condition(),),
        gates=promotion_gates or gates(index),
        promotion_cost=cost or PromotionCost(target_requests=1, write_requests=0, cpu_seconds=1),
    )


def ledger(
    *,
    max_target_requests: int = 100,
    max_replay: int = 16,
    max_simulated: int = 8,
    max_materialized: int = 4,
) -> BudgetLedger:
    return BudgetLedger(
        limits=BudgetLimits(
            max_llm_calls=10,
            max_target_requests=max_target_requests,
            max_write_requests=10,
            max_cpu_seconds=1_000,
            max_ghost=64,
            max_replay=max_replay,
            max_simulated=max_simulated,
            max_materialized=max_materialized,
        )
    )
