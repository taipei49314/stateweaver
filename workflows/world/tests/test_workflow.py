from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from search_test_fixtures import candidate, condition, fragment, gates, ledger
from stateweaver.compiler import RootState
from stateweaver.contracts import WorldTier
from stateweaver.search import (
    BeamSearchPolicy,
    BudgetLedger,
    BudgetLimits,
    PolicyGateOutcome,
    SearchBatch,
    SearchCandidate,
)
from stateweaver.workflows.world import (
    AllocatedWorld,
    AllocationRequest,
    CaptureReceipt,
    PromotionLifecyclePhase,
    PromotionRunContext,
    WorldPromotionWorkflow,
    promotion_lifecycle_payload,
)

_RECORDED_AT = datetime(2026, 8, 4, tzinfo=UTC)


def _context(index: int) -> PromotionRunContext:
    return PromotionRunContext(
        experiment_id="experiment.workflow.tests",
        run_id=f"run.workflow.{index:03d}",
        recorded_at=_RECORDED_AT + timedelta(seconds=index),
    )


@dataclass
class MemoryAllocator:
    fail_candidates: set[str] = field(default_factory=set)
    reused_identity: str | None = None
    reused_allocation: str | None = None
    unchecked_model: bool = False
    fail_release: bool = False
    cancel_release: bool = False
    allocated: list[AllocatedWorld] = field(default_factory=list)
    released: list[AllocatedWorld] = field(default_factory=list)

    async def allocate(self, request: AllocationRequest) -> AllocatedWorld:
        if request.candidate_id in self.fail_candidates:
            raise RuntimeError("synthetic allocation failure")
        suffix = request.candidate_id.removeprefix("candidate.")
        tier = request.target_tier.value
        allocation = AllocatedWorld(
            allocation_id=self.reused_allocation or f"allocation.{tier}.{suffix}",
            candidate_id=request.candidate_id,
            target_tier=request.target_tier,
            state_fingerprint=request.state_fingerprint,
            sibling_identity=self.reused_identity or f"identity:world.{tier}.{suffix}",
        )
        self.allocated.append(allocation)
        if self.unchecked_model:
            return allocation.model_copy(update={"allocation_id": "unchecked allocation"})
        return allocation

    async def release(self, allocation: AllocatedWorld) -> None:
        self.released.append(allocation)
        if self.cancel_release:
            raise asyncio.CancelledError()
        if self.fail_release:
            raise RuntimeError("synthetic release failure")


@dataclass
class MemoryCapture:
    fail_candidates: set[str] = field(default_factory=set)
    cancel_candidates: set[str] = field(default_factory=set)
    bad_oracle: bool = False
    unchecked_root: bool = False

    async def capture(
        self, request: AllocationRequest, allocation: AllocatedWorld
    ) -> CaptureReceipt:
        if request.candidate_id in self.fail_candidates:
            raise RuntimeError("synthetic capture failure")
        if request.candidate_id in self.cancel_candidates:
            raise asyncio.CancelledError()
        index = request.candidate_id.rsplit(".", maxsplit=1)[-1]
        receipt = CaptureReceipt(
            allocation_id=allocation.allocation_id,
            candidate_id=request.candidate_id,
            state_fingerprint=request.state_fingerprint,
            compiler_root=RootState(
                root_seed_id=f"root.synthetic.{index}",
                world_id=allocation.allocation_id,
                conditions=(condition(),),
            ),
            evidence_ref=f"ev.synthetic.{index}",
            oracle_ref=f"oracle.synthetic.{index}",
            oracle_passed=not self.bad_oracle,
        )
        if self.unchecked_root:
            bad_root = receipt.compiler_root.model_copy(
                update={"world_id": "allocation.synthetic.substituted"}
            )
            return receipt.model_copy(update={"compiler_root": bad_root})
        return receipt


def _workflow(
    allocator: MemoryAllocator | None = None,
    capture: MemoryCapture | None = None,
    *,
    initial_ledger: BudgetLedger | None = None,
    policy: BeamSearchPolicy | None = None,
) -> tuple[WorldPromotionWorkflow, MemoryAllocator, MemoryCapture]:
    memory_allocator = allocator or MemoryAllocator()
    memory_capture = capture or MemoryCapture()
    return (
        WorldPromotionWorkflow(
            allocator=memory_allocator,
            capture=memory_capture,
            ledger=initial_ledger or ledger(),
            policy=policy,
        ),
        memory_allocator,
        memory_capture,
    )


def _retier(item: SearchCandidate, tier: WorldTier) -> SearchCandidate:
    updates: dict[str, object] = {"tier": tier}
    if tier is WorldTier.SIMULATED:
        index = int(item.candidate_id.rsplit(".", maxsplit=1)[-1])
        updates["transition_fragments"] = (fragment(index),)
    return item.model_copy(update=updates)


@pytest.mark.asyncio
async def test_twenty_four_ghosts_flow_through_small_beams_to_materialized() -> None:
    initial = ledger(max_replay=4, max_simulated=2, max_materialized=1)
    policy = BeamSearchPolicy(seed=19, replay_width=4, simulated_width=2, materialized_width=1)
    workflow, allocator, _ = _workflow(initial_ledger=initial, policy=policy)
    ghosts = SearchBatch(
        candidates=tuple(candidate(index, score=0.4 + index / 100) for index in range(24))
    )

    replay = await workflow.advance(ghosts, context=_context(1))
    assert len(replay.promotions) == 4
    replay_by_id = {item.candidate_id: item for item in ghosts.candidates}
    replay_batch = SearchBatch(
        candidates=tuple(
            _retier(replay_by_id[item.candidate_id], WorldTier.REPLAY) for item in replay.promotions
        )
    )
    simulated = await workflow.advance(replay_batch, context=_context(2))
    assert len(simulated.promotions) == 2
    simulated_by_id = {item.candidate_id: item for item in replay_batch.candidates}
    simulated_batch = SearchBatch(
        candidates=tuple(
            _retier(simulated_by_id[item.candidate_id], WorldTier.SIMULATED)
            for item in simulated.promotions
        )
    )
    materialized = await workflow.advance(simulated_batch, context=_context(3))

    assert len(materialized.promotions) == 1
    usage = workflow.ledger.usage()
    assert (usage.replay_worlds, usage.simulated_worlds, usage.materialized_worlds) == (4, 2, 1)
    assert len({item.sibling_identity for item in allocator.allocated}) == 7
    assert all(item.capture.oracle_passed for item in materialized.promotions)


@pytest.mark.asyncio
async def test_callback_failure_does_not_commit_reservation_and_releases_allocation() -> None:
    first = candidate(0)
    second = candidate(1)
    allocator = MemoryAllocator()
    capture = MemoryCapture(fail_candidates={first.candidate_id})
    workflow, _, _ = _workflow(allocator, capture, initial_ledger=ledger(max_replay=2))

    result = await workflow.advance(SearchBatch(candidates=(first, second)), context=_context(4))

    assert [item.candidate_id for item in result.promotions] == [second.candidate_id]
    assert result.committed_ledger.usage().replay_worlds == 1
    assert allocator.released[0].candidate_id == first.candidate_id
    assert PromotionLifecyclePhase.NOT_COMMITTED in {
        promotion_lifecycle_payload(item).phase for item in result.events
    }


@pytest.mark.asyncio
async def test_release_failure_never_remints_not_committed_as_rollback() -> None:
    item = candidate(49)
    allocator = MemoryAllocator(fail_release=True)
    workflow, _, _ = _workflow(
        allocator,
        MemoryCapture(fail_candidates={item.candidate_id}),
        initial_ledger=ledger(max_replay=1),
    )

    result = await workflow.advance(SearchBatch(candidates=(item,)), context=_context(14))
    phases = tuple(promotion_lifecycle_payload(event).phase for event in result.events)

    assert phases == (
        PromotionLifecyclePhase.RESERVED,
        PromotionLifecyclePhase.NOT_COMMITTED,
    )
    assert not result.promotions
    assert result.committed_ledger == result.input_ledger
    assert allocator.released
    assert workflow.cleanup_pending_allocation_ids == (
        f"allocation.replay.{item.candidate_id.removeprefix('candidate.')}",
    )

    allocator.fail_release = False
    await workflow.close()

    assert not workflow.cleanup_pending_allocation_ids


@pytest.mark.asyncio
async def test_cancelled_release_retains_cleanup_ownership_before_propagating() -> None:
    item = candidate(50)
    allocator = MemoryAllocator(cancel_release=True)
    workflow, _, _ = _workflow(
        allocator,
        MemoryCapture(fail_candidates={item.candidate_id}),
        initial_ledger=ledger(max_replay=1),
    )

    with pytest.raises(asyncio.CancelledError):
        await workflow.advance(SearchBatch(candidates=(item,)), context=_context(15))

    allocation_id = f"allocation.replay.{item.candidate_id.removeprefix('candidate.')}"
    assert workflow.cleanup_pending_allocation_ids == (allocation_id,)
    assert workflow.ledger.usage().replay_worlds == 0

    allocator.cancel_release = False
    await workflow.close()

    assert not workflow.cleanup_pending_allocation_ids


@pytest.mark.asyncio
async def test_cancellation_releases_uncommitted_allocation_and_never_commits_budget() -> None:
    item = candidate(20)
    allocator = MemoryAllocator()
    workflow, _, _ = _workflow(
        allocator,
        MemoryCapture(cancel_candidates={item.candidate_id}),
        initial_ledger=ledger(max_replay=1),
    )

    with pytest.raises(asyncio.CancelledError):
        await workflow.advance(SearchBatch(candidates=(item,)), context=_context(5))

    assert workflow.ledger.usage().replay_worlds == 0
    assert [allocation.candidate_id for allocation in allocator.released] == [item.candidate_id]


@pytest.mark.asyncio
async def test_policy_evidence_and_oracle_gates_cannot_be_bypassed_by_model_score() -> None:
    denied = candidate(2, score=1.0, promotion_gates=gates(2, policy=PolicyGateOutcome.DENY))
    missing_evidence = candidate(3, score=1.0, promotion_gates=gates(3, evidence=False))
    bad_oracle = candidate(4, score=1.0)
    allocator = MemoryAllocator()
    workflow, _, _ = _workflow(
        allocator,
        MemoryCapture(bad_oracle=True),
        initial_ledger=ledger(max_replay=3),
    )

    result = await workflow.advance(
        SearchBatch(candidates=(denied, missing_evidence, bad_oracle)),
        context=_context(6),
    )

    assert not result.promotions
    assert not allocator.allocated or all(
        item in allocator.released for item in allocator.allocated
    )
    assert result.committed_ledger.usage().replay_worlds == 0
    assert missing_evidence.candidate_id in result.blocked_candidate_ids


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ("allocator", "capture"))
async def test_unchecked_callback_models_are_revalidated_before_commit(boundary: str) -> None:
    item = candidate(46)
    allocator = MemoryAllocator(unchecked_model=boundary == "allocator")
    capture = MemoryCapture(unchecked_root=boundary == "capture")
    workflow, _, _ = _workflow(
        allocator,
        capture,
        initial_ledger=ledger(max_replay=1),
    )

    result = await workflow.advance(SearchBatch(candidates=(item,)), context=_context(7))

    assert not result.promotions
    assert result.committed_ledger.usage().replay_worlds == 0
    if boundary == "capture":
        assert allocator.released == allocator.allocated


@pytest.mark.asyncio
async def test_fingerprint_dedup_and_reused_sibling_identity_fail_closed() -> None:
    duplicate_left = candidate(5, state_bucket=50)
    duplicate_right = candidate(6, state_bucket=50)
    workflow, allocator, _ = _workflow(initial_ledger=ledger(max_replay=2))
    deduped = await workflow.advance(
        SearchBatch(candidates=(duplicate_left, duplicate_right)), context=_context(8)
    )
    assert len(deduped.promotions) == 1
    assert len(allocator.allocated) == 1

    first = candidate(7)
    second = candidate(8)
    reused = "identity:world.reused"
    isolated, allocator, _ = _workflow(
        MemoryAllocator(reused_identity=reused), initial_ledger=ledger(max_replay=2)
    )
    result = await isolated.advance(SearchBatch(candidates=(first, second)), context=_context(9))
    assert len(result.promotions) == 1
    assert len(allocator.released) == 1
    assert result.committed_ledger.usage().replay_worlds == 1


@pytest.mark.asyncio
async def test_reused_allocation_id_fails_closed_with_distinct_sibling_identities() -> None:
    first = candidate(47)
    second = candidate(48)
    allocator = MemoryAllocator(reused_allocation="allocation.replay.reused")
    workflow, _, _ = _workflow(allocator, initial_ledger=ledger(max_replay=2))

    result = await workflow.advance(SearchBatch(candidates=(first, second)), context=_context(10))

    assert not result.promotions
    assert len(allocator.released) == 2
    assert not workflow.cleanup_pending_allocation_ids
    assert result.committed_ledger.usage().replay_worlds == 0


@pytest.mark.asyncio
async def test_collision_with_committed_id_is_quarantined_until_close() -> None:
    allocation_id = "allocation.replay.retained"
    allocator = MemoryAllocator(reused_allocation=allocation_id)
    workflow, _, _ = _workflow(allocator, initial_ledger=ledger(max_replay=2))

    first = await workflow.advance(SearchBatch(candidates=(candidate(51),)), context=_context(16))
    second = await workflow.advance(SearchBatch(candidates=(candidate(52),)), context=_context(17))

    assert len(first.promotions) == 1
    assert not second.promotions
    pending_before_close = workflow.cleanup_pending_allocation_ids
    assert pending_before_close == (allocation_id,)

    await workflow.close()

    pending_after_close = workflow.cleanup_pending_allocation_ids
    assert not pending_after_close
    assert len(allocator.released) == 2


@pytest.mark.asyncio
async def test_identical_failed_collision_releases_retain_distinct_ownership() -> None:
    allocation_id = "allocation.replay.identical"
    allocator = MemoryAllocator(
        reused_allocation=allocation_id,
        reused_identity="identity:world.replay.identical",
        fail_release=True,
    )
    workflow, _, _ = _workflow(allocator, initial_ledger=ledger(max_replay=2))

    result = await workflow.advance(
        SearchBatch(candidates=(candidate(53), candidate(54))), context=_context(18)
    )

    assert not result.promotions
    assert len(allocator.allocated) == 2
    released_before_close = tuple(allocator.released)
    pending_before_close = workflow.cleanup_pending_allocation_ids
    assert len(released_before_close) == 2
    assert pending_before_close == (allocation_id, allocation_id)

    allocator.fail_release = False
    await workflow.close()

    released_after_close = tuple(allocator.released)
    pending_after_close = workflow.cleanup_pending_allocation_ids
    assert not pending_after_close
    assert len(released_after_close) == 4


@pytest.mark.asyncio
async def test_concurrent_calls_share_one_hard_budget() -> None:
    tight = BudgetLedger(
        limits=BudgetLimits(
            max_llm_calls=10,
            max_target_requests=10,
            max_write_requests=10,
            max_cpu_seconds=10,
            max_ghost=64,
            max_replay=1,
            max_simulated=1,
            max_materialized=1,
        )
    )
    workflow, _, _ = _workflow(initial_ledger=tight)
    left, right = await asyncio.gather(
        workflow.advance(SearchBatch(candidates=(candidate(9),)), context=_context(11)),
        workflow.advance(SearchBatch(candidates=(candidate(10),)), context=_context(12)),
    )
    assert len(left.promotions) + len(right.promotions) == 1
    assert workflow.ledger.usage().replay_worlds == 1


@settings(max_examples=30, deadline=None)
@given(st.lists(st.integers(min_value=11, max_value=45), min_size=1, max_size=10, unique=True))
def test_property_budgets_and_sibling_identities_stay_bounded(indices: list[int]) -> None:
    async def run() -> None:
        workflow, _, _ = _workflow(initial_ledger=ledger(max_replay=2))
        result = await workflow.advance(
            SearchBatch(candidates=tuple(candidate(index) for index in indices)),
            context=_context(13),
        )
        assert len(result.promotions) <= 2
        assert result.committed_ledger.usage().replay_worlds <= 2
        assert len({item.allocation.sibling_identity for item in result.promotions}) == len(
            result.promotions
        )

    asyncio.run(run())
