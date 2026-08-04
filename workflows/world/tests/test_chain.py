from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

import pytest
from search_test_fixtures import candidate, ledger
from stateweaver.compiler import CompilerFragment, RootState, TerminalGoal
from stateweaver.contracts import (
    ActionEnvelope,
    ActionGuard,
    ComparisonOperator,
    EffectOperation,
    ExpectedEffect,
    FidelityLevel,
    FidelityProfile,
    ProvenanceKind,
    RequestedBy,
    RequesterType,
    RiskClass,
    ScopeAction,
    StateCondition,
    StateEffect,
    TimeAdvanceAction,
    TransitionFragment,
    WorldTier,
    sha256_digest,
)
from stateweaver.search import (
    BeamSearchPolicy,
    DecisionDisposition,
    PromotionCost,
    PromotionGates,
    ReasonCode,
    SearchBatch,
    SearchCandidate,
    SearchDecision,
    SearchResult,
    TieredSearchController,
)
from stateweaver.workflows.world import (
    AllocatedWorld,
    CaptureReceipt,
    ObservedChainAdmission,
    ObservedChainAdmissionError,
    PromotionRecord,
    WorkflowResult,
    compile_observed_promotion,
)

_CHAIN_ID = "chain.synthetic.observed-promotion"
_GOAL_CONDITION = "violation.reached"


@dataclass(frozen=True)
class _AdmissionCase:
    item: SearchCandidate
    batch: SearchBatch
    search: SearchResult
    promotion: PromotionRecord
    workflow: WorkflowResult
    fragments: tuple[CompilerFragment, ...]
    goal: TerminalGoal


def _condition(path: str, value: bool | str | int) -> StateCondition:
    return StateCondition(path=path, operator=ComparisonOperator.EQ, value=value)


def _effect(path: str, value: bool | str | int) -> StateEffect:
    return StateEffect(path=path, operation=EffectOperation.SET, value=value)


def _transition(
    index: int = 70,
    *,
    source: ProvenanceKind = ProvenanceKind.OBSERVED,
    evidence_ids: tuple[str, ...] | None = None,
    effects: tuple[StateEffect, ...] | None = None,
    name: str | None = None,
) -> TransitionFragment:
    identifier = f"transition.synthetic.{index:03d}"
    return TransitionFragment(
        transition_id=identifier,
        name=name or identifier,
        source=source,
        preconditions=(_condition("root.ready", True),),
        action=TimeAdvanceAction(milliseconds=1),
        effects=effects or (_effect(_GOAL_CONDITION, True),),
        observables=(_condition(_GOAL_CONDITION, True),),
        evidence_ids=evidence_ids or (f"ev.synthetic.{index:03d}",),
        fidelity=FidelityProfile(
            code=FidelityLevel.EXACT,
            timing=FidelityLevel.OBSERVED,
        ),
        consistent_replays=1,
    )


def _candidate(
    fragments: tuple[TransitionFragment, ...],
    *,
    index: int = 70,
    gate_evidence_ids: tuple[str, ...] | None = None,
) -> SearchCandidate:
    base = candidate(index, tier=WorldTier.SIMULATED, with_fragment=False)
    admitted_evidence = gate_evidence_ids
    if admitted_evidence is None:
        admitted_evidence = tuple(
            sorted(
                {evidence_id for transition in fragments for evidence_id in transition.evidence_ids}
            )
        )
    gates = PromotionGates.model_validate(
        {
            **base.gates.model_dump(mode="python"),
            "expected_observations": (_condition(_GOAL_CONDITION, True),),
            "evidence_ids": admitted_evidence,
        }
    )
    return SearchCandidate.model_validate(
        {
            **base.model_dump(mode="python"),
            "transition_fragments": fragments,
            "gates": gates,
        }
    )


def _allocation_id(item: SearchCandidate) -> str:
    return f"allocation.materialized.{item.candidate_id.removeprefix('candidate.')}"


def _root(allocation_id: str) -> RootState:
    return RootState(
        root_seed_id="root.synthetic.observed-chain",
        world_id=allocation_id,
        conditions=(_condition("root.ready", True),),
    )


def _promotion(
    item: SearchCandidate,
    *,
    reservation_id: str,
    allocation_id: str | None = None,
    state_fingerprint: str | None = None,
    compiler_root: RootState | None = None,
) -> PromotionRecord:
    admitted_allocation = allocation_id or _allocation_id(item)
    fingerprint = state_fingerprint or item.state_fingerprint
    allocation = AllocatedWorld(
        allocation_id=admitted_allocation,
        candidate_id=item.candidate_id,
        target_tier=WorldTier.MATERIALIZED,
        state_fingerprint=fingerprint,
        sibling_identity=f"identity:world.{item.candidate_id.removeprefix('candidate.')}",
    )
    capture = CaptureReceipt(
        allocation_id=admitted_allocation,
        candidate_id=item.candidate_id,
        state_fingerprint=fingerprint,
        compiler_root=compiler_root or _root(admitted_allocation),
        evidence_ref=item.gates.evidence_ids[0],
        oracle_ref=item.gates.oracle_refs[0],
        oracle_passed=True,
    )
    return PromotionRecord(
        candidate_id=item.candidate_id,
        target_tier=WorldTier.MATERIALIZED,
        reservation_id=reservation_id,
        allocation=allocation,
        capture=capture,
    )


def _guards(transition: TransitionFragment) -> tuple[ActionGuard, ...]:
    return tuple(
        ActionGuard(path=condition.path, expected=condition.value)
        for condition in transition.preconditions
    )


def _expected_effects(transition: TransitionFragment) -> tuple[ExpectedEffect, ...]:
    return tuple(
        ExpectedEffect(path=effect.path, operation=effect.operation, value=effect.value)
        for effect in transition.effects
    )


def _compiler_fragment(
    transition: TransitionFragment,
    *,
    world_id: str,
    policy_decision_ref: str,
    envelope_updates: dict[str, object] | None = None,
) -> CompilerFragment:
    suffix = transition.transition_id.rsplit(".", maxsplit=1)[-1]
    envelope = ActionEnvelope(
        action_id=f"action.synthetic.{suffix}",
        experiment_id="experiment.synthetic.observed-chain",
        world_id=world_id,
        scope_action=ScopeAction.CONTROLLED_TIME,
        action=transition.action,
        preconditions=_guards(transition),
        expected_effects=_expected_effects(transition),
        risk_class=RiskClass.REVERSIBLE_STATE_CHANGE,
        idempotency_key=sha256_digest(
            {"transition_id": transition.transition_id, "world_id": world_id}
        ),
        requested_by=RequestedBy(type=RequesterType.WORKFLOW, role="observed-chain-test"),
        policy_decision_ref=policy_decision_ref,
    )
    if envelope_updates:
        envelope = ActionEnvelope.model_validate(
            {**envelope.model_dump(mode="python"), **envelope_updates}
        )
    return CompilerFragment(fragment=transition, envelope=envelope, world_id=world_id)


def _goal(*, condition: StateCondition | None = None) -> TerminalGoal:
    return TerminalGoal(
        goal_id="goal.synthetic.observed-chain",
        conditions=(condition or _condition(_GOAL_CONDITION, True),),
    )


def _case(
    transitions: tuple[TransitionFragment, ...] | None = None,
    *,
    index: int = 70,
    gate_evidence_ids: tuple[str, ...] | None = None,
) -> _AdmissionCase:
    admitted = transitions or (_transition(index),)
    item = _candidate(admitted, index=index, gate_evidence_ids=gate_evidence_ids)
    batch = SearchBatch(candidates=(item,))
    input_ledger = ledger()
    search_policy = BeamSearchPolicy()
    search = TieredSearchController(search_policy).advance(batch, input_ledger)
    decision = search.decisions[0]
    assert decision.disposition is DecisionDisposition.PROMOTE
    reservation = next(
        reservation
        for reservation in search.ledger.reservations
        if reservation.candidate_id == item.candidate_id
    )
    promotion = _promotion(item, reservation_id=reservation.reservation_id)
    workflow = WorkflowResult(
        input_ledger=input_ledger,
        search_policy=search_policy,
        search=search,
        committed_ledger=search.ledger,
        promotions=(promotion,),
        events=(),
    )
    compiler_fragments = tuple(
        _compiler_fragment(
            transition,
            world_id=promotion.allocation.allocation_id,
            policy_decision_ref=item.gates.policy_decision_ref,
        )
        for transition in admitted
    )
    return _AdmissionCase(
        item=item,
        batch=batch,
        search=search,
        promotion=promotion,
        workflow=workflow,
        fragments=compiler_fragments,
        goal=_goal(),
    )


def _compile(
    case: _AdmissionCase,
    *,
    chain_id: str = _CHAIN_ID,
    batch: SearchBatch | None = None,
    workflow: WorkflowResult | None = None,
    candidate_id: str | None = None,
    fragments: Iterable[CompilerFragment] | None = None,
    goal: TerminalGoal | None = None,
) -> ObservedChainAdmission:
    return compile_observed_promotion(
        batch=batch or case.batch,
        workflow=workflow or case.workflow,
        candidate_id=candidate_id or case.item.candidate_id,
        chain_id=chain_id,
        fragments=case.fragments if fragments is None else fragments,
        goal=goal or case.goal,
    )


def _assert_rejected(code: str, operation: Callable[[], object]) -> None:
    with pytest.raises(ObservedChainAdmissionError) as caught:
        operation()
    assert caught.value.code == code


def test_success_uses_a_real_search_promotion_and_returns_a_content_bound_receipt() -> None:
    case = _case()
    decision = case.search.decisions[0]
    committed = case.workflow.committed_ledger.reservations[0]

    assert decision.disposition is DecisionDisposition.PROMOTE
    assert decision.reservation_id is not None
    assert case.promotion.reservation_id == committed.reservation_id
    assert committed.candidate_id == case.item.candidate_id
    assert committed.target_tier is WorldTier.MATERIALIZED
    assert committed.cost == case.item.promotion_cost

    admission = _compile(case)
    root = case.promotion.capture.compiler_root
    assert admission.candidate_id == case.item.candidate_id
    assert admission.reservation_id == case.promotion.reservation_id
    assert admission.allocation_id == case.promotion.allocation.allocation_id
    assert admission.search_batch_fingerprint == sha256_digest(case.batch)
    assert admission.workflow_fingerprint == sha256_digest(case.workflow)
    assert admission.candidate_fingerprint == sha256_digest(case.item)
    assert admission.promotion_fingerprint == sha256_digest(case.promotion)
    assert admission.compiler_input_fingerprint == sha256_digest(
        {
            "chain_id": _CHAIN_ID,
            "root": root,
            "fragments": case.fragments,
            "goal": case.goal,
        }
    )
    assert admission.compiled_chain.root_seed_id == root.root_seed_id
    assert admission.compiled_chain.world_id == root.world_id
    assert admission.compiled_chain.fragment_ids == (
        case.item.transition_fragments[0].transition_id,
    )
    assert admission.chain_fingerprint == sha256_digest(admission.compiled_chain)
    assert admission.admission_fingerprint == sha256_digest(admission.admission_projection())
    assert ObservedChainAdmission.model_validate_json(admission.canonical_bytes()) == admission


def test_nested_compiled_chain_model_copy_cannot_remint_the_outer_receipt() -> None:
    case = _case()
    admission = _compile(case)
    forged_chain = admission.compiled_chain.model_copy(
        update={
            "terminal_goal": TerminalGoal(
                goal_id="goal.synthetic.substituted",
                conditions=(_condition("violation.substituted", True),),
            )
        }
    )
    chain_fingerprint = sha256_digest(forged_chain)
    projection = admission.admission_projection()
    projection["chain_fingerprint"] = chain_fingerprint
    forged = admission.model_copy(
        update={
            "compiled_chain": forged_chain,
            "chain_fingerprint": chain_fingerprint,
            "admission_fingerprint": sha256_digest(projection),
        }
    )

    with pytest.raises(ValueError, match=r"causal_hash|closed-model validation"):
        ObservedChainAdmission.model_validate(forged)


def test_batch_fingerprint_substitution_is_rejected() -> None:
    case = _case()
    search = SearchResult.model_validate(
        {
            **case.search.model_dump(mode="python"),
            "input_fingerprint": sha256_digest({"substituted": "batch"}),
        }
    )
    workflow = WorkflowResult(
        input_ledger=case.workflow.input_ledger,
        search_policy=case.workflow.search_policy,
        search=search,
        committed_ledger=case.workflow.committed_ledger,
        promotions=case.workflow.promotions,
        events=(),
    )

    _assert_rejected(
        "SEARCH_BATCH_FINGERPRINT_MISMATCH",
        lambda: _compile(case, workflow=workflow),
    )


def test_invalid_chain_id_is_a_stable_admission_error() -> None:
    case = _case()

    _assert_rejected("MALFORMED_INPUT", lambda: _compile(case, chain_id="invalid chain id"))


def test_compiler_rejection_is_mapped_to_a_stable_admission_error() -> None:
    case = _case()
    blocked = CompilerFragment.model_validate(
        {
            **case.fragments[0].model_dump(mode="python"),
            "after": ("transition.synthetic.unknown",),
        }
    )

    _assert_rejected(
        "COMPILATION_UNKNOWN_ORDERING_DEPENDENCY",
        lambda: _compile(case, fragments=(blocked,)),
    )


def test_candidate_identifier_must_resolve_inside_the_bound_batch() -> None:
    case = _case()

    _assert_rejected(
        "CANDIDATE_NOT_IN_BATCH",
        lambda: _compile(case, candidate_id="candidate.synthetic.absent"),
    )


def test_search_promotion_without_a_committed_promotion_record_is_rejected() -> None:
    case = _case()
    workflow = WorkflowResult(
        input_ledger=case.workflow.input_ledger,
        search_policy=case.workflow.search_policy,
        search=case.search,
        committed_ledger=case.workflow.committed_ledger,
        promotions=(),
        events=(),
    )

    _assert_rejected(
        "PROMOTION_NOT_COMMITTED",
        lambda: _compile(case, workflow=workflow),
    )


def test_non_promote_search_decision_is_rejected_even_if_a_promotion_record_is_supplied() -> None:
    case = _case()
    original = case.search.decisions[0]
    decision = SearchDecision(
        candidate_id=case.item.candidate_id,
        source_tier=WorldTier.SIMULATED,
        target_tier=WorldTier.MATERIALIZED,
        disposition=DecisionDisposition.PRUNE,
        reason_codes=(ReasonCode.OUT_OF_SCOPE,),
        priority=original.priority,
    )
    search = SearchResult(
        source_tier=WorldTier.SIMULATED,
        target_tier=WorldTier.MATERIALIZED,
        decisions=(decision,),
        promoted_candidate_ids=(),
        ledger=ledger(),
        input_fingerprint=sha256_digest(case.batch),
    )
    workflow = WorkflowResult(
        input_ledger=case.workflow.input_ledger,
        search_policy=case.workflow.search_policy,
        search=search,
        committed_ledger=case.workflow.committed_ledger,
        promotions=(case.promotion,),
        events=(),
    )

    _assert_rejected("SEARCH_RESULT_MISMATCH", lambda: _compile(case, workflow=workflow))


def test_unchecked_promotion_reservation_substitution_is_revalidated_by_the_bridge() -> None:
    case = _case()
    promotion = case.promotion.model_copy(update={"reservation_id": "reservation.substituted"})
    workflow = case.workflow.model_copy(update={"promotions": (promotion,)})

    _assert_rejected("MALFORMED_INPUT", lambda: _compile(case, workflow=workflow))


def test_committed_ledger_reservation_must_bind_candidate_tier_and_exact_cost() -> None:
    case = _case()
    wrong_ledger = ledger().reserve(
        "candidate.synthetic.other",
        WorldTier.MATERIALIZED,
        case.item.promotion_cost,
    )
    wrong_reservation = wrong_ledger.reservations[-1]
    promotion = _promotion(case.item, reservation_id=wrong_reservation.reservation_id)
    workflow = WorkflowResult(
        input_ledger=case.workflow.input_ledger,
        search_policy=case.workflow.search_policy,
        search=case.search,
        committed_ledger=wrong_ledger,
        promotions=(promotion,),
        events=(),
    )

    _assert_rejected(
        "COMMITTED_RESERVATION_MISMATCH",
        lambda: _compile(case, workflow=workflow),
    )


def test_provisional_search_reservation_must_bind_exact_candidate_cost() -> None:
    case = _case()
    wrong_ledger = ledger().reserve(
        case.item.candidate_id,
        WorldTier.MATERIALIZED,
        PromotionCost(),
    )
    wrong_reservation = wrong_ledger.reservations[-1]
    original = case.search.decisions[0]
    decision = SearchDecision.model_validate(
        {
            **original.model_dump(mode="python"),
            "reservation_id": wrong_reservation.reservation_id,
        }
    )
    search = SearchResult(
        source_tier=case.search.source_tier,
        target_tier=case.search.target_tier,
        decisions=(decision,),
        promoted_candidate_ids=(case.item.candidate_id,),
        ledger=wrong_ledger,
        input_fingerprint=sha256_digest(case.batch),
    )
    workflow = WorkflowResult(
        input_ledger=case.workflow.input_ledger,
        search_policy=case.workflow.search_policy,
        search=search,
        committed_ledger=case.workflow.committed_ledger,
        promotions=case.workflow.promotions,
        events=(),
    )

    _assert_rejected("SEARCH_RESULT_MISMATCH", lambda: _compile(case, workflow=workflow))


def test_later_winner_can_admit_after_an_earlier_capture_rollback_changes_reservation_id() -> None:
    first = _candidate((_transition(70),), index=70)
    second = _candidate((_transition(71),), index=71)
    batch = SearchBatch(candidates=(first, second))
    input_ledger = ledger()
    search_policy = BeamSearchPolicy()
    search = TieredSearchController(search_policy).advance(batch, input_ledger)
    assert all(decision.disposition is DecisionDisposition.PROMOTE for decision in search.decisions)
    provisional = search.ledger.reservations[-1]
    selected = {item.candidate_id: item for item in batch.candidates}[provisional.candidate_id]
    committed_ledger = ledger().reserve(
        selected.candidate_id,
        WorldTier.MATERIALIZED,
        selected.promotion_cost,
    )
    committed = committed_ledger.reservations[-1]
    assert provisional.reservation_id != committed.reservation_id
    promotion = _promotion(selected, reservation_id=committed.reservation_id)
    workflow = WorkflowResult(
        input_ledger=input_ledger,
        search_policy=search_policy,
        search=search,
        committed_ledger=committed_ledger,
        promotions=(promotion,),
        events=(),
    )
    transition = selected.transition_fragments[0]
    compiler_fragment = _compiler_fragment(
        transition,
        world_id=promotion.allocation.allocation_id,
        policy_decision_ref=selected.gates.policy_decision_ref,
    )
    case = _AdmissionCase(
        item=selected,
        batch=batch,
        search=search,
        promotion=promotion,
        workflow=workflow,
        fragments=(compiler_fragment,),
        goal=_goal(),
    )

    admission = _compile(case)

    assert admission.candidate_id == selected.candidate_id
    assert admission.reservation_id == committed.reservation_id


def test_promotion_state_substitution_is_rejected() -> None:
    case = _case()
    promotion = _promotion(
        case.item,
        reservation_id=case.promotion.reservation_id,
        state_fingerprint=sha256_digest({"substituted": "state"}),
    )
    workflow = WorkflowResult(
        input_ledger=case.workflow.input_ledger,
        search_policy=case.workflow.search_policy,
        search=case.search,
        committed_ledger=case.workflow.committed_ledger,
        promotions=(promotion,),
        events=(),
    )

    _assert_rejected("STATE_FINGERPRINT_MISMATCH", lambda: _compile(case, workflow=workflow))


def test_malformed_captured_root_world_is_revalidated_by_the_bridge() -> None:
    case = _case()
    malformed_root = _root("allocation.materialized.substituted")
    capture = case.promotion.capture.model_copy(update={"compiler_root": malformed_root})
    promotion = case.promotion.model_copy(update={"capture": capture})
    workflow = case.workflow.model_copy(update={"promotions": (promotion,)})

    _assert_rejected("MALFORMED_INPUT", lambda: _compile(case, workflow=workflow))


def test_non_observed_candidate_fragment_is_rejected() -> None:
    case = _case((_transition(source=ProvenanceKind.DECLARED),))

    with pytest.raises(ObservedChainAdmissionError) as caught:
        _compile(case)

    assert caught.value.code == "FRAGMENT_NOT_OBSERVED"
    assert caught.value.fragment_id == case.item.transition_fragments[0].transition_id


def test_compiler_fragment_set_substitution_is_rejected() -> None:
    case = _case()

    _assert_rejected(
        "COMPILER_FRAGMENT_SET_MISMATCH",
        lambda: _compile(case, fragments=()),
    )


def test_same_id_fragment_content_substitution_is_rejected() -> None:
    case = _case()
    substituted = _transition(name="substituted semantics")
    compiler_fragment = _compiler_fragment(
        substituted,
        world_id=case.promotion.allocation.allocation_id,
        policy_decision_ref=case.item.gates.policy_decision_ref,
    )

    with pytest.raises(ObservedChainAdmissionError) as caught:
        _compile(case, fragments=(compiler_fragment,))

    assert caught.value.code == "COMPILER_FRAGMENT_SUBSTITUTION"
    assert caught.value.fragment_id == substituted.transition_id


def test_search_recomputation_rejects_fragment_evidence_outside_candidate_gates() -> None:
    baseline = _case()
    transition = _transition(evidence_ids=("ev.synthetic.unbound",))
    item = _candidate(
        (transition,),
        gate_evidence_ids=("ev.synthetic.070",),
    )
    batch = SearchBatch(candidates=(item,))
    search = SearchResult.model_validate(
        {
            **baseline.search.model_dump(mode="python"),
            "input_fingerprint": sha256_digest(batch),
        }
    )
    workflow = WorkflowResult(
        input_ledger=baseline.workflow.input_ledger,
        search_policy=baseline.workflow.search_policy,
        search=search,
        committed_ledger=baseline.workflow.committed_ledger,
        promotions=baseline.workflow.promotions,
        events=(),
    )
    compiler_fragment = _compiler_fragment(
        transition,
        world_id=baseline.promotion.allocation.allocation_id,
        policy_decision_ref=item.gates.policy_decision_ref,
    )
    case = _AdmissionCase(
        item=item,
        batch=batch,
        search=search,
        promotion=baseline.promotion,
        workflow=workflow,
        fragments=(compiler_fragment,),
        goal=_goal(),
    )

    with pytest.raises(ObservedChainAdmissionError) as caught:
        _compile(case)

    assert caught.value.code == "SEARCH_RESULT_MISMATCH"


def test_compiler_envelope_policy_decision_must_match_candidate_gate() -> None:
    case = _case()
    compiler_fragment = _compiler_fragment(
        case.item.transition_fragments[0],
        world_id=case.promotion.allocation.allocation_id,
        policy_decision_ref="policy.synthetic.substituted",
    )

    with pytest.raises(ObservedChainAdmissionError) as caught:
        _compile(case, fragments=(compiler_fragment,))

    assert caught.value.code == "POLICY_DECISION_MISMATCH"
    assert caught.value.fragment_id == compiler_fragment.fragment_id


def test_terminal_goal_must_be_an_expected_observation() -> None:
    case = _case()

    _assert_rejected(
        "GOAL_OBSERVATION_MISMATCH",
        lambda: _compile(
            case,
            goal=_goal(condition=_condition("violation.substituted", True)),
        ),
    )


@pytest.mark.parametrize(
    ("boundary", "updates", "expected_code"),
    (
        (
            "guard-omission",
            {"preconditions": ()},
            "ENVELOPE_PRECONDITION_MISMATCH",
        ),
        (
            "guard-substitution",
            {"preconditions": (ActionGuard(path="root.ready", expected=False),)},
            "ENVELOPE_PRECONDITION_MISMATCH",
        ),
        (
            "effect-omission",
            {"expected_effects": ()},
            "ENVELOPE_EFFECT_MISMATCH",
        ),
        (
            "effect-substitution",
            {
                "expected_effects": (
                    ExpectedEffect(
                        path=_GOAL_CONDITION,
                        operation=EffectOperation.SET,
                        value=False,
                    ),
                )
            },
            "ENVELOPE_EFFECT_MISMATCH",
        ),
    ),
)
def test_fragment_guards_and_expected_effects_are_exact_typed_projections(
    boundary: str, updates: dict[str, object], expected_code: str
) -> None:
    case = _case()
    compiler_fragment = _compiler_fragment(
        case.item.transition_fragments[0],
        world_id=case.promotion.allocation.allocation_id,
        policy_decision_ref=case.item.gates.policy_decision_ref,
        envelope_updates=updates,
    )

    with pytest.raises(ObservedChainAdmissionError) as caught:
        _compile(case, fragments=(compiler_fragment,))

    assert caught.value.code == expected_code, boundary
    assert caught.value.fragment_id == compiler_fragment.fragment_id


def test_compiler_minimization_cannot_discard_an_admitted_observed_fragment() -> None:
    required = _transition()
    decoy = _transition(
        71,
        effects=(_effect("unused.decoy", True),),
    )
    case = _case((required, decoy))

    _assert_rejected(
        "CHAIN_DROPPED_OBSERVED_FRAGMENT",
        lambda: _compile(case),
    )
