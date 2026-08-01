from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from search_test_fixtures import candidate, fragment, gates, ledger
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
    PromotionEventKind,
    WorldPromotionWorkflow,
)


@dataclass
class MemoryAllocator:
    fail_candidates: set[str] = field(default_factory=set)
    reused_identity: str | None = None
    allocated: list[AllocatedWorld] = field(default_factory=list)
    released: list[AllocatedWorld] = field(default_factory=list)

    async def allocate(self, request: AllocationRequest) -> AllocatedWorld:
        if request.candidate_id in self.fail_candidates:
            raise RuntimeError("synthetic allocation failure")
        suffix = request.candidate_id.removeprefix("candidate.")
        tier = request.target_tier.value
        allocation = AllocatedWorld(
            allocation_id=f"allocation.{tier}.{suffix}",
            candidate_id=request.candidate_id,
            target_tier=request.target_tier,
            state_fingerprint=request.state_fingerprint,
            sibling_identity=self.reused_identity or f"identity:world.{tier}.{suffix}",
        )
        self.allocated.append(allocation)
        return allocation

    async def release(self, allocation: AllocatedWorld) -> None:
        self.released.append(allocation)


@dataclass
class MemoryCapture:
    fail_candidates: set[str] = field(default_factory=set)
    cancel_candidates: set[str] = field(default_factory=set)
    bad_oracle: bool = False

    async def capture(
        self, request: AllocationRequest, allocation: AllocatedWorld
    ) -> CaptureReceipt:
        if request.candidate_id in self.fail_candidates:
            raise RuntimeError("synthetic capture failure")
        if request.candidate_id in self.cancel_candidates:
            raise asyncio.CancelledError()
        index = request.candidate_id.rsplit(".", maxsplit=1)[-1]
        return CaptureReceipt(
            allocation_id=allocation.allocation_id,
            candidate_id=request.candidate_id,
            state_fingerprint=request.state_fingerprint,
            evidence_ref=f"ev.synthetic.{index}",
            oracle_ref=f"oracle.synthetic.{index}",
            oracle_passed=not self.bad_oracle,
        )


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

    replay = await workflow.advance(ghosts)
    assert len(replay.promotions) == 4
    replay_by_id = {item.candidate_id: item for item in ghosts.candidates}
    replay_batch = SearchBatch(
        candidates=tuple(
            _retier(replay_by_id[item.candidate_id], WorldTier.REPLAY) for item in replay.promotions
        )
    )
    simulated = await workflow.advance(replay_batch)
    assert len(simulated.promotions) == 2
    simulated_by_id = {item.candidate_id: item for item in replay_batch.candidates}
    simulated_batch = SearchBatch(
        candidates=tuple(
            _retier(simulated_by_id[item.candidate_id], WorldTier.SIMULATED)
            for item in simulated.promotions
        )
    )
    materialized = await workflow.advance(simulated_batch)

    assert len(materialized.promotions) == 1
    usage = workflow.ledger.usage()
    assert (usage.replay_worlds, usage.simulated_worlds, usage.materialized_worlds) == (4, 2, 1)
    assert len({item.sibling_identity for item in allocator.allocated}) == 7
    assert all(item.capture.oracle_passed for item in materialized.promotions)


@pytest.mark.asyncio
async def test_callback_failure_rolls_back_hard_reservation_and_releases_allocation() -> None:
    first = candidate(0)
    second = candidate(1)
    allocator = MemoryAllocator()
    capture = MemoryCapture(fail_candidates={first.candidate_id})
    workflow, _, _ = _workflow(allocator, capture, initial_ledger=ledger(max_replay=2))

    result = await workflow.advance(SearchBatch(candidates=(first, second)))

    assert [item.candidate_id for item in result.promotions] == [second.candidate_id]
    assert result.committed_ledger.usage().replay_worlds == 1
    assert allocator.released[0].candidate_id == first.candidate_id
    assert PromotionEventKind.ROLLED_BACK in {item.kind for item in result.events}


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
        await workflow.advance(SearchBatch(candidates=(item,)))

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

    result = await workflow.advance(SearchBatch(candidates=(denied, missing_evidence, bad_oracle)))

    assert not result.promotions
    assert not allocator.allocated or all(
        item in allocator.released for item in allocator.allocated
    )
    assert result.committed_ledger.usage().replay_worlds == 0
    assert missing_evidence.candidate_id in result.blocked_candidate_ids


@pytest.mark.asyncio
async def test_fingerprint_dedup_and_reused_sibling_identity_fail_closed() -> None:
    duplicate_left = candidate(5, state_bucket=50)
    duplicate_right = candidate(6, state_bucket=50)
    workflow, allocator, _ = _workflow(initial_ledger=ledger(max_replay=2))
    deduped = await workflow.advance(SearchBatch(candidates=(duplicate_left, duplicate_right)))
    assert len(deduped.promotions) == 1
    assert len(allocator.allocated) == 1

    first = candidate(7)
    second = candidate(8)
    reused = "identity:world.reused"
    isolated, allocator, _ = _workflow(
        MemoryAllocator(reused_identity=reused), initial_ledger=ledger(max_replay=2)
    )
    result = await isolated.advance(SearchBatch(candidates=(first, second)))
    assert len(result.promotions) == 1
    assert len(allocator.released) == 1
    assert result.committed_ledger.usage().replay_worlds == 1


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
        workflow.advance(SearchBatch(candidates=(candidate(9),))),
        workflow.advance(SearchBatch(candidates=(candidate(10),))),
    )
    assert len(left.promotions) + len(right.promotions) == 1
    assert workflow.ledger.usage().replay_worlds == 1


@settings(max_examples=30, deadline=None)
@given(st.lists(st.integers(min_value=11, max_value=45), min_size=1, max_size=10, unique=True))
def test_property_budgets_and_sibling_identities_stay_bounded(indices: list[int]) -> None:
    async def run() -> None:
        workflow, _, _ = _workflow(initial_ledger=ledger(max_replay=2))
        result = await workflow.advance(
            SearchBatch(candidates=tuple(candidate(index) for index in indices))
        )
        assert len(result.promotions) <= 2
        assert result.committed_ledger.usage().replay_worlds <= 2
        assert len({item.allocation.sibling_identity for item in result.promotions}) == len(
            result.promotions
        )

    asyncio.run(run())
