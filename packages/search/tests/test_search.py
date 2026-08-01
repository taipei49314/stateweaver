from __future__ import annotations

from itertools import permutations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError
from search_test_fixtures import candidate, fragment, gates, ledger
from stateweaver.contracts import (
    ActionTarget,
    HttpMethod,
    HttpRequestAction,
    WorldTier,
    canonical_json_bytes,
)
from stateweaver.search import (
    BeamSearchPolicy,
    BudgetLedger,
    BudgetLimits,
    DecisionDisposition,
    PolicyGateOutcome,
    PromotionCost,
    PromotionGates,
    ReasonCode,
    ScoreSource,
    SearchBatch,
    SearchCandidate,
    SearchDecision,
    SearchResult,
    TieredSearchController,
)


def _decision(result: SearchResult, candidate_id: str) -> SearchDecision:
    return next(item for item in result.decisions if item.candidate_id == candidate_id)


def test_twenty_four_ghosts_promote_only_the_bounded_beam() -> None:
    batch = SearchBatch(candidates=tuple(candidate(index) for index in range(24)))
    controller = TieredSearchController(BeamSearchPolicy(seed=17, replay_width=5))

    result = controller.advance(batch, ledger())

    assert result.source_tier is WorldTier.GHOST
    assert result.target_tier is WorldTier.REPLAY
    assert len(result.decisions) == 24
    assert len(result.promoted_candidate_ids) == 5
    assert sum(item.disposition is DecisionDisposition.PRUNE for item in result.decisions) == 19
    assert result.ledger.usage().replay_worlds == 5


def test_fixed_seed_and_input_permutation_are_byte_deterministic() -> None:
    candidates = tuple(candidate(index, score=0.8) for index in range(12))
    policy = BeamSearchPolicy(seed=23, replay_width=4)
    controller = TieredSearchController(policy)

    first = controller.advance(SearchBatch(candidates=candidates), ledger())
    second = controller.advance(SearchBatch(candidates=tuple(reversed(candidates))), ledger())

    assert canonical_json_bytes(first) == canonical_json_bytes(second)
    assert first.fingerprint == second.fingerprint


@given(st.sampled_from(tuple(permutations(range(6)))))
@settings(max_examples=20)
def test_candidate_permutations_have_one_canonical_result(order: tuple[int, ...]) -> None:
    candidates = tuple(candidate(index, score=0.75) for index in order)
    result = TieredSearchController(BeamSearchPolicy(seed=11, replay_width=3)).advance(
        SearchBatch(candidates=candidates), ledger()
    )
    canonical = TieredSearchController(BeamSearchPolicy(seed=11, replay_width=3)).advance(
        SearchBatch(candidates=tuple(candidate(index, score=0.75) for index in range(6))),
        ledger(),
    )
    assert canonical_json_bytes(result) == canonical_json_bytes(canonical)


@given(
    max_requests=st.integers(min_value=0, max_value=20),
    request_cost=st.integers(min_value=1, max_value=5),
    width=st.integers(min_value=1, max_value=16),
)
@settings(max_examples=40)
def test_budget_never_overspends(max_requests: int, request_cost: int, width: int) -> None:
    candidates = tuple(
        candidate(
            index,
            cost=PromotionCost(target_requests=request_cost, cpu_seconds=1),
        )
        for index in range(24)
    )
    initial = ledger(max_target_requests=max_requests, max_replay=16)
    result = TieredSearchController(BeamSearchPolicy(seed=5, replay_width=width)).advance(
        SearchBatch(candidates=candidates), initial
    )
    usage = result.ledger.usage()

    assert usage.target_requests <= max_requests
    assert usage.replay_worlds <= 16
    assert len(result.promoted_candidate_ids) <= width
    assert initial.reservations == ()


def test_budget_ledger_is_immutable_and_append_only() -> None:
    initial = ledger(max_target_requests=2)
    first = initial.reserve(
        "candidate.synthetic.001",
        WorldTier.REPLAY,
        PromotionCost(target_requests=1),
    )
    second = first.reserve(
        "candidate.synthetic.002",
        WorldTier.REPLAY,
        PromotionCost(target_requests=1),
    )

    assert initial.reservations == ()
    assert len(first.reservations) == 1
    assert len(second.reservations) == 2
    with pytest.raises(ValueError, match="exceeds"):
        second.reserve(
            "candidate.synthetic.003",
            WorldTier.REPLAY,
            PromotionCost(target_requests=1),
        )


def test_model_score_cannot_override_policy_gate() -> None:
    denied = candidate(
        0,
        score=1.0,
        score_source=ScoreSource.MODEL,
        promotion_gates=gates(0, policy=PolicyGateOutcome.DENY),
    )
    allowed = candidate(1, score=0.3)

    result = TieredSearchController(BeamSearchPolicy(replay_width=1)).advance(
        SearchBatch(candidates=(denied, allowed)), ledger()
    )

    denied_decision = _decision(result, denied.candidate_id)
    assert denied_decision.disposition is DecisionDisposition.PRUNE
    assert ReasonCode.POLICY_DENIED in denied_decision.reason_codes
    assert result.promoted_candidate_ids == (allowed.candidate_id,)


def test_model_score_cannot_override_materialization_evidence_gates() -> None:
    unsupported = candidate(
        0,
        tier=WorldTier.SIMULATED,
        score=1.0,
        score_source=ScoreSource.MODEL,
        promotion_gates=gates(0, evidence=False, complete=False),
        with_fragment=False,
    )
    evidence_bound = candidate(1, tier=WorldTier.SIMULATED, score=0.3)

    result = TieredSearchController(BeamSearchPolicy(materialized_width=1)).advance(
        SearchBatch(candidates=(unsupported, evidence_bound)), ledger()
    )

    blocked = _decision(result, unsupported.candidate_id)
    assert blocked.disposition is DecisionDisposition.PRUNE
    assert set(blocked.reason_codes) >= {
        ReasonCode.MISSING_EVIDENCE,
        ReasonCode.MISSING_ACTION_PLAN,
        ReasonCode.MISSING_EXPECTED_OBSERVATION,
        ReasonCode.MISSING_MACHINE_ORACLE,
        ReasonCode.MISSING_SNAPSHOT_CAPABILITY,
    }
    assert result.promoted_candidate_ids == (evidence_bound.candidate_id,)


def test_dedup_keeps_one_state_and_explains_cheaper_dominance() -> None:
    winner = candidate(
        0,
        score=0.9,
        state_bucket=99,
        cost=PromotionCost(target_requests=1, cpu_seconds=1),
    )
    duplicate = candidate(
        1,
        score=0.7,
        state_bucket=99,
        cost=PromotionCost(target_requests=2, cpu_seconds=2),
    )

    result = TieredSearchController(BeamSearchPolicy(replay_width=2)).advance(
        SearchBatch(candidates=(duplicate, winner)), ledger()
    )

    duplicate_decision = _decision(result, duplicate.candidate_id)
    assert result.promoted_candidate_ids == (winner.candidate_id,)
    assert duplicate_decision.reason_codes == (ReasonCode.DOMINATED_BY_CHEAPER_WORLD,)
    assert duplicate_decision.deduplicated_to == winner.candidate_id


def test_diversity_first_pass_avoids_single_family_collapse() -> None:
    first_family_best = candidate(0, score=0.95, diversity="family.synthetic.a")
    first_family_second = candidate(1, score=0.90, diversity="family.synthetic.a")
    second_family = candidate(2, score=0.80, diversity="family.synthetic.b")

    result = TieredSearchController(BeamSearchPolicy(replay_width=2)).advance(
        SearchBatch(candidates=(first_family_best, first_family_second, second_family)),
        ledger(),
    )

    assert result.promoted_candidate_ids == tuple(
        sorted((first_family_best.candidate_id, second_family.candidate_id))
    )
    assert _decision(result, first_family_second.candidate_id).reason_codes == (
        ReasonCode.BEAM_CAPACITY,
    )


def test_uncertainty_is_an_explicit_deterministic_tie_breaking_signal() -> None:
    low = candidate(0, score=0.7, uncertainty=0.0, diversity="family.synthetic.low")
    high = candidate(1, score=0.7, uncertainty=1.0, diversity="family.synthetic.high")

    result = TieredSearchController(BeamSearchPolicy(replay_width=1)).advance(
        SearchBatch(candidates=(low, high)), ledger()
    )

    assert result.promoted_candidate_ids == (high.candidate_id,)


def test_gate_reasons_are_complete_and_stable() -> None:
    blocked_gates = PromotionGates(
        in_scope=False,
        policy_outcome=PolicyGateOutcome.DENY,
        policy_decision_ref="policy.synthetic.blocked",
        reversible=True,
        required_capabilities=("missing_capability",),
        available_capabilities=(),
        snapshot_capable=False,
        new_fact_count=0,
        calibration_path=False,
        repeated_nondeterminism=2,
    )
    blocked = candidate(
        0,
        score=0.1,
        promotion_gates=blocked_gates,
    )

    result = TieredSearchController().advance(SearchBatch(candidates=(blocked,)), ledger())
    assert _decision(result, blocked.candidate_id).reason_codes == (
        ReasonCode.OUT_OF_SCOPE,
        ReasonCode.POLICY_DENIED,
        ReasonCode.UNSUPPORTED_ADAPTER_CAPABILITY,
        ReasonCode.NO_NEW_FACTS,
        ReasonCode.LOW_FIDELITY_WITHOUT_CALIBRATION_PATH,
        ReasonCode.REPEATED_NONDETERMINISM,
    )


def test_strict_models_reject_unknown_fields_bool_integers_and_duplicate_candidates() -> None:
    payload = SearchBatch(candidates=(candidate(0),)).model_dump(mode="python")
    payload["unexpected"] = True
    with pytest.raises(ValidationError):
        SearchBatch.model_validate(payload)
    with pytest.raises(ValidationError):
        BeamSearchPolicy(seed=True)
    with pytest.raises(ValidationError, match="unique"):
        SearchBatch(candidates=(candidate(0), candidate(0)))


def test_ledger_rejects_preconstructed_overspend() -> None:
    initial = ledger(max_target_requests=1)
    reservation = ledger(max_target_requests=10).reserve(
        "candidate.synthetic.001", WorldTier.REPLAY, PromotionCost(target_requests=2)
    )
    with pytest.raises(ValidationError, match="overspent"):
        BudgetLedger(limits=initial.limits, reservations=(reservation.reservations[0],))


def test_materialized_source_tier_is_not_promotable() -> None:
    with pytest.raises(ValidationError, match="promotable"):
        SearchBatch(candidates=(candidate(0, tier=WorldTier.MATERIALIZED),))


def test_controller_revalidates_forged_model_instances_at_boundary() -> None:
    forged_gates = PromotionGates.model_construct(
        in_scope=True,
        policy_outcome=PolicyGateOutcome.ALLOW,
        policy_decision_ref="bad",
        reversible=True,
        snapshot_capable=True,
        new_fact_count=1,
        calibration_path=True,
    )
    forged_candidate = candidate(0).model_copy(update={"gates": forged_gates})
    forged_batch = SearchBatch.model_construct(candidates=(forged_candidate,))

    with pytest.raises(ValidationError):
        TieredSearchController().advance(forged_batch, ledger())


def test_budget_limits_reject_boolean_counters() -> None:
    with pytest.raises(ValidationError):
        BudgetLimits(
            max_llm_calls=False,
            max_target_requests=1,
            max_write_requests=1,
            max_cpu_seconds=1,
        )


def test_state_fingerprint_must_bind_canonical_typed_state() -> None:
    payload = candidate(0).model_dump(mode="python")
    payload["state_fingerprint"] = "sha256:" + "0" * 64
    with pytest.raises(ValidationError, match="derive"):
        SearchCandidate.model_validate(payload)


def test_critical_score_dimensions_cannot_be_model_only() -> None:
    payload = candidate(0).model_dump(mode="python")
    scores = payload["scores"]
    assert isinstance(scores, dict)
    boundary = scores["boundary_impact"]
    assert isinstance(boundary, dict)
    boundary["source"] = ScoreSource.MODEL
    with pytest.raises(ValidationError, match="model-only"):
        SearchCandidate.model_validate(payload)


def test_materialization_requires_fragment_evidence_to_match_gate_evidence() -> None:
    mismatched = gates(0).model_dump(mode="python")
    mismatched["evidence_ids"] = ("ev.unrelated.001",)
    blocked = candidate(
        0,
        tier=WorldTier.SIMULATED,
        promotion_gates=PromotionGates.model_validate(mismatched),
    )
    result = TieredSearchController().advance(SearchBatch(candidates=(blocked,)), ledger())
    assert ReasonCode.MISSING_EVIDENCE in _decision(result, blocked.candidate_id).reason_codes


def test_repeated_controller_step_does_not_double_reserve_candidate() -> None:
    item = candidate(0)
    batch = SearchBatch(candidates=(item,))
    controller = TieredSearchController()
    first = controller.advance(batch, ledger())
    second = controller.advance(batch, first.ledger)

    assert len(second.ledger.reservations) == 1
    assert _decision(second, item.candidate_id).reason_codes == (ReasonCode.ALREADY_PROMOTED,)


def test_reservation_identifier_is_content_bound() -> None:
    accepted = ledger().reserve(
        "candidate.synthetic.001", WorldTier.REPLAY, PromotionCost(target_requests=1)
    )
    payload = accepted.reservations[0].model_dump(mode="python")
    payload["reservation_id"] = "reservation." + "0" * 24
    with pytest.raises(ValidationError, match="bind"):
        type(accepted.reservations[0]).model_validate(payload)


def test_candidate_cost_cannot_understate_typed_hypothesis_estimate() -> None:
    payload = candidate(0).model_dump(mode="python")
    payload["promotion_cost"] = PromotionCost(target_requests=0)
    with pytest.raises(ValidationError, match="understate"):
        SearchCandidate.model_validate(payload)


def test_search_fragment_rejects_nonlocal_concrete_target() -> None:
    external = fragment(0).model_copy(
        update={
            "action": HttpRequestAction(
                method=HttpMethod.GET,
                target=ActionTarget(
                    scheme="https", host="example.com", port=443, path="/synthetic"
                ),
            )
        }
    )
    payload = candidate(0).model_dump(mode="python")
    payload["transition_fragments"] = (external,)
    with pytest.raises(ValidationError, match="local synthetic"):
        SearchCandidate.model_validate(payload)
