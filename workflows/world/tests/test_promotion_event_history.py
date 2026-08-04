from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

import pytest
from pydantic import JsonValue, ValidationError
from search_test_fixtures import candidate, condition, ledger
from stateweaver.compiler import RootState
from stateweaver.contracts import EventEnvelope, EventHistory, WorldTier, sha256_digest
from stateweaver.search import (
    BeamSearchPolicy,
    BudgetLedger,
    DecisionDisposition,
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
    PromotionLifecyclePhase,
    PromotionRecord,
    PromotionRunContext,
    WorkflowResult,
    promotion_lifecycle_payload,
)

RECORDED_AT = datetime(2026, 8, 4, 12, 0, tzinfo=UTC)
CONTEXT = PromotionRunContext(
    experiment_id="experiment.synthetic.lifecycle",
    run_id="run.synthetic.lifecycle",
    recorded_at=RECORDED_AT,
)


@dataclass(frozen=True)
class _WorkflowCase:
    context: PromotionRunContext
    item: SearchCandidate
    input_ledger: BudgetLedger
    policy: BeamSearchPolicy
    batch: SearchBatch
    search: SearchResult
    committed_ledger: BudgetLedger
    promotion: PromotionRecord

    def result(self) -> WorkflowResult:
        return WorkflowResult.create(
            context=self.context,
            input_ledger=self.input_ledger,
            search_policy=self.policy,
            search_batch=self.batch,
            search=self.search,
            committed_ledger=self.committed_ledger,
            promotions=(self.promotion,),
        )

    def not_committed_result(self) -> WorkflowResult:
        return WorkflowResult.create(
            context=self.context,
            input_ledger=self.input_ledger,
            search_policy=self.policy,
            search_batch=self.batch,
            search=self.search,
            committed_ledger=self.input_ledger,
            promotions=(),
        )


def _case(
    index: int = 70,
    *,
    input_ledger: BudgetLedger | None = None,
) -> _WorkflowCase:
    item = candidate(index)
    before = input_ledger or ledger(max_replay=4)
    policy = BeamSearchPolicy(seed=19, replay_width=4)
    batch = SearchBatch(candidates=(item,))
    search = TieredSearchController(policy).advance(batch, before)
    committed = before.reserve(item.candidate_id, search.target_tier, item.promotion_cost)
    reservation = committed.reservations[-1]
    suffix = item.candidate_id.rsplit(".", maxsplit=1)[-1]
    allocation = AllocatedWorld(
        allocation_id=f"allocation.{search.target_tier.value}.{suffix}",
        candidate_id=item.candidate_id,
        target_tier=search.target_tier,
        state_fingerprint=item.state_fingerprint,
        sibling_identity=f"identity:world.{search.target_tier.value}.{suffix}",
    )
    capture = CaptureReceipt(
        allocation_id=allocation.allocation_id,
        candidate_id=item.candidate_id,
        state_fingerprint=item.state_fingerprint,
        compiler_root=RootState(
            root_seed_id=f"root.synthetic.{suffix}",
            world_id=allocation.allocation_id,
            conditions=(condition(),),
        ),
        evidence_ref=item.gates.evidence_ids[0],
        oracle_ref=item.gates.oracle_refs[0],
        oracle_passed=True,
    )
    promotion = PromotionRecord(
        candidate_id=item.candidate_id,
        target_tier=search.target_tier,
        reservation_id=reservation.reservation_id,
        allocation=allocation,
        capture=capture,
    )
    return _WorkflowCase(
        context=CONTEXT,
        item=item,
        input_ledger=before,
        policy=policy,
        batch=batch,
        search=search,
        committed_ledger=committed,
        promotion=promotion,
    )


def _phase(event: EventEnvelope) -> PromotionLifecyclePhase:
    return promotion_lifecycle_payload(event).phase


def _remint_history(
    events: tuple[EventEnvelope, ...],
    *,
    payloads: tuple[Mapping[str, JsonValue], ...] | None = None,
) -> EventHistory:
    assert events
    assert payloads is None or len(payloads) == len(events)
    reminted: list[EventEnvelope] = []
    previous_hash = None
    for index, event in enumerate(events):
        payload = payloads[index] if payloads is not None else event.payload
        rebuilt = EventEnvelope.create(
            event_type=event.event_type,
            experiment_id=event.experiment_id,
            run_id=event.run_id,
            world_id=event.world_id,
            actor=event.actor,
            trace_id=event.trace_id,
            timestamp=event.timestamp,
            sequence=index + 1,
            prev_event_hash=previous_hash,
            payload=payload,
        )
        reminted.append(rebuilt)
        previous_hash = rebuilt.semantic_hash
    return EventHistory.create(
        experiment_id=events[0].experiment_id,
        run_id=events[0].run_id,
        events=tuple(reminted),
    )


def _validate_with_history(result: WorkflowResult, history: EventHistory) -> WorkflowResult:
    wire = result.model_dump(mode="python")
    wire["event_history"] = history.model_dump(mode="python")
    return WorkflowResult.model_validate(wire)


def test_create_builds_parseable_deterministic_success_history() -> None:
    case = _case()
    left = case.result()
    right = case.result()

    assert left.canonical_bytes() == right.canonical_bytes()
    assert left.event_history == right.event_history
    assert tuple(_phase(event) for event in left.event_history.events) == (
        PromotionLifecyclePhase.RESERVED,
        PromotionLifecyclePhase.ALLOCATED,
        PromotionLifecyclePhase.CAPTURED,
        PromotionLifecyclePhase.COMMITTED,
    )


def test_search_blocked_history_binds_exact_decision_reasons() -> None:
    item = candidate(69)
    before = ledger(max_replay=0)
    policy = BeamSearchPolicy(seed=19, replay_width=4)
    search = TieredSearchController(policy).advance(SearchBatch(candidates=(item,)), before)
    result = WorkflowResult.create(
        context=CONTEXT,
        input_ledger=before,
        search_policy=policy,
        search_batch=SearchBatch(candidates=(item,)),
        search=search,
        committed_ledger=before,
        promotions=(),
    )
    event = result.event_history.events[0]
    payload = promotion_lifecycle_payload(event)

    assert payload.phase is PromotionLifecyclePhase.SEARCH_BLOCKED
    assert payload.reason_codes == (ReasonCode.BUDGET_EXCEEDED,)
    assert result.blocked_candidate_ids == (item.candidate_id,)

    forged_payload = dict(event.payload)
    forged_payload["reason_codes"] = [ReasonCode.BEAM_CAPACITY.value]
    forged = _remint_history((event,), payloads=(forged_payload,))
    with pytest.raises(ValidationError):
        _validate_with_history(result, forged)


def test_successful_promotion_rejects_empty_history_after_wire_revalidation() -> None:
    result = _case().result()
    empty = result.event_history.model_copy(update={"events": ()})
    forged = result.model_copy(update={"event_history": empty})

    with pytest.raises(ValidationError):
        WorkflowResult.model_validate_json(forged.model_dump_json())


def test_reverse_and_resequence_with_all_integrity_fields_reminted_is_rejected() -> None:
    result = _case().result()
    reversed_history = _remint_history(tuple(reversed(result.event_history.events)))

    with pytest.raises(ValidationError):
        _validate_with_history(result, reversed_history)


def test_stale_candidate_with_fully_reminted_history_is_rejected() -> None:
    result = _case().result()
    payloads: list[dict[str, JsonValue]] = []
    for event in result.event_history.events:
        payload = dict(event.payload)
        assert "candidate_id" in payload
        payload["candidate_id"] = "candidate.synthetic.stale"
        payloads.append(payload)
    stale_history = _remint_history(result.event_history.events, payloads=tuple(payloads))

    with pytest.raises(ValidationError):
        _validate_with_history(result, stale_history)


def test_payload_v1_confusion_with_fully_reminted_history_is_rejected() -> None:
    result = _case().result()
    payloads: list[dict[str, JsonValue]] = []
    for event in result.event_history.events:
        payload = dict(event.payload)
        payload["schema_version"] = "world-promotion-lifecycle-v1"
        payloads.append(payload)
    downgraded = _remint_history(result.event_history.events, payloads=tuple(payloads))

    with pytest.raises(ValidationError):
        _validate_with_history(result, downgraded)


@pytest.mark.parametrize("mutation", ("drop", "duplicate"))
def test_drop_or_duplicate_with_fully_reminted_history_is_rejected(mutation: str) -> None:
    result = _case().result()
    events = result.event_history.events
    attacked = events[1:] if mutation == "drop" else (events[0], *events)
    attacked_history = _remint_history(tuple(attacked))

    with pytest.raises(ValidationError):
        _validate_with_history(result, attacked_history)


def test_committed_candidate_cannot_also_claim_not_committed() -> None:
    case = _case()
    committed = case.result()
    not_committed = case.not_committed_result()
    terminal = next(
        event
        for event in not_committed.event_history.events
        if _phase(event) is PromotionLifecyclePhase.NOT_COMMITTED
    )
    contradictory = _remint_history((*committed.event_history.events, terminal))

    with pytest.raises(ValidationError):
        _validate_with_history(committed, contradictory)


def test_committed_ledger_cannot_contain_an_extra_unpromoted_reservation() -> None:
    case = _case()
    result = case.result()
    extra = candidate(71)
    extra_ledger = case.committed_ledger.reserve(
        extra.candidate_id,
        case.search.target_tier,
        extra.promotion_cost,
    )
    wire = result.model_dump(mode="python")
    wire["committed_ledger"] = extra_ledger.model_dump(mode="python")

    with pytest.raises(ValidationError):
        WorkflowResult.model_validate(wire)


def test_committed_ledger_cannot_substitute_the_input_prefix() -> None:
    empty = ledger(max_replay=4)
    original_prefix = candidate(80)
    substituted_prefix = candidate(81)
    promoted = candidate(82)
    before = empty.reserve(
        original_prefix.candidate_id,
        WorldTier.REPLAY,
        original_prefix.promotion_cost,
    )
    case = _case(82, input_ledger=before)
    result = case.result()
    substituted = empty.reserve(
        substituted_prefix.candidate_id,
        WorldTier.REPLAY,
        substituted_prefix.promotion_cost,
    ).reserve(promoted.candidate_id, WorldTier.REPLAY, promoted.promotion_cost)
    wire = result.model_dump(mode="python")
    wire["committed_ledger"] = substituted.model_dump(mode="python")

    with pytest.raises(ValidationError):
        WorkflowResult.model_validate(wire)


def test_model_copy_cannot_remove_promotion_across_wire_revalidation() -> None:
    result = _case().result()
    forged = result.model_copy(update={"promotions": ()})

    with pytest.raises(ValidationError):
        WorkflowResult.model_validate_json(forged.model_dump_json())


def test_result_projection_hash_rejects_stale_history_after_policy_substitution() -> None:
    result = _case().result()
    substituted = result.search_policy.model_copy(update={"seed": result.search_policy.seed + 1})
    wire = result.model_dump(mode="python")
    wire["search_policy"] = substituted.model_dump(mode="python")

    with pytest.raises(ValidationError):
        WorkflowResult.model_validate(wire)


def test_create_rejects_search_generated_under_a_wider_policy() -> None:
    items = (candidate(72), candidate(73))
    batch = SearchBatch(candidates=items)
    before = ledger(max_replay=2)
    wide = BeamSearchPolicy(seed=19, replay_width=2)
    search = TieredSearchController(wide).advance(batch, before)
    assert len(search.promoted_candidate_ids) == 2

    with pytest.raises(ValueError, match="exactly replay"):
        WorkflowResult.create(
            context=CONTEXT,
            input_ledger=before,
            search_policy=BeamSearchPolicy(seed=19, replay_width=1),
            search_batch=batch,
            search=search,
            committed_ledger=before,
            promotions=(),
        )


def test_create_rejects_coherently_reminted_tier_jump() -> None:
    case = _case()
    wrong_ledger = case.input_ledger.reserve(
        case.item.candidate_id,
        WorldTier.MATERIALIZED,
        case.item.promotion_cost,
    )
    reservation = wrong_ledger.reservations[-1]
    decision = SearchDecision(
        candidate_id=case.item.candidate_id,
        source_tier=WorldTier.GHOST,
        target_tier=WorldTier.MATERIALIZED,
        disposition=DecisionDisposition.PROMOTE,
        reason_codes=(ReasonCode.PROMOTED,),
        priority=case.search.decisions[0].priority,
        reservation_id=reservation.reservation_id,
    )
    forged = SearchResult(
        source_tier=WorldTier.GHOST,
        target_tier=WorldTier.MATERIALIZED,
        decisions=(decision,),
        promoted_candidate_ids=(case.item.candidate_id,),
        ledger=wrong_ledger,
        input_fingerprint=sha256_digest(case.batch),
    )

    with pytest.raises(ValueError, match="exactly replay"):
        WorkflowResult.create(
            context=case.context,
            input_ledger=case.input_ledger,
            search_policy=case.policy,
            search_batch=case.batch,
            search=forged,
            committed_ledger=case.input_ledger,
            promotions=(),
        )


def test_create_rejects_promotion_state_substitution_outside_bound_batch() -> None:
    case = _case()
    substituted_state = sha256_digest({"substituted": "state"})
    allocation = case.promotion.allocation.model_copy(
        update={"state_fingerprint": substituted_state}
    )
    capture = case.promotion.capture.model_copy(update={"state_fingerprint": substituted_state})
    promotion = case.promotion.model_copy(update={"allocation": allocation, "capture": capture})

    with pytest.raises(ValueError, match="admitted search candidate"):
        WorkflowResult.create(
            context=case.context,
            input_ledger=case.input_ledger,
            search_policy=case.policy,
            search_batch=case.batch,
            search=case.search,
            committed_ledger=case.committed_ledger,
            promotions=(promotion,),
        )
