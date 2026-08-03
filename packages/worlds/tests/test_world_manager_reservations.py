from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass, field
from typing import Literal

import pytest
from stateweaver.worlds import (
    CleanupError,
    EnvironmentHandle,
    LifecycleError,
    SnapshotManifest,
    TargetSpec,
    WorldError,
    WorldManager,
    WorldNode,
    WorldPhase,
)
from worlds_test_adapter import InMemoryConformanceAdapter


@dataclass
class _Gate:
    entered: asyncio.Event = field(default_factory=asyncio.Event)
    release: asyncio.Event = field(default_factory=asyncio.Event)


class _ReservationAdversarialAdapter(InMemoryConformanceAdapter):
    """No-network adapter that deterministically returns colliding pending handles."""

    def __init__(self) -> None:
        super().__init__()
        self.prepare_mode: Literal["unique", "same", "namespace_overlap"] = "unique"
        self.same_child_forks = False
        self.prepare_calls = 0
        self.fork_calls = 0
        self.snapshot_calls = 0
        self.destroy_calls: list[str] = []
        self.prepared_ids: list[str] = []
        self.active_snapshots = 0
        self.max_active_snapshots = 0
        self._prepare_gates: deque[_Gate] = deque()
        self._snapshot_gates: deque[_Gate] = deque()
        self._destroy_gates: deque[_Gate] = deque()
        self._shared_prepare: EnvironmentHandle | None = None
        self._overlap_source: EnvironmentHandle | None = None
        self._shared_child: EnvironmentHandle | None = None

    def gate_next_prepare(self) -> _Gate:
        gate = _Gate()
        self._prepare_gates.append(gate)
        return gate

    def gate_next_snapshot(self) -> _Gate:
        gate = _Gate()
        self._snapshot_gates.append(gate)
        return gate

    def gate_next_destroy(self) -> _Gate:
        gate = _Gate()
        self._destroy_gates.append(gate)
        return gate

    async def prepare(self, target: TargetSpec) -> EnvironmentHandle:
        self.prepare_calls += 1
        if self._prepare_gates:
            gate = self._prepare_gates.popleft()
            gate.entered.set()
            await gate.release.wait()

        if self.prepare_mode == "same":
            if self._shared_prepare is None:
                self._shared_prepare = await super().prepare(target)
                self.prepared_ids.append(self._shared_prepare.environment_id)
            return self._shared_prepare

        handle = await super().prepare(target)
        self.prepared_ids.append(handle.environment_id)
        if self.prepare_mode == "namespace_overlap":
            if self._overlap_source is None:
                self._overlap_source = handle
            else:
                handle = handle.validated_copy(
                    namespace=handle.namespace.validated_copy(
                        network=self._overlap_source.namespace.network
                    )
                )
        return handle

    async def snapshot(self, env: EnvironmentHandle) -> SnapshotManifest:
        self.snapshot_calls += 1
        if self._snapshot_gates:
            gate = self._snapshot_gates.popleft()
            self.active_snapshots += 1
            self.max_active_snapshots = max(self.max_active_snapshots, self.active_snapshots)
            gate.entered.set()
            try:
                await gate.release.wait()
            finally:
                self.active_snapshots -= 1
        return await super().snapshot(env)

    async def fork(self, snapshot: SnapshotManifest) -> EnvironmentHandle:
        self.fork_calls += 1
        if self.same_child_forks:
            if self._shared_child is None:
                self._shared_child = await super().fork(snapshot)
            return self._shared_child
        return await super().fork(snapshot)

    async def destroy(self, env: EnvironmentHandle) -> None:
        self.destroy_calls.append(env.environment_id)
        if self._destroy_gates:
            gate = self._destroy_gates.popleft()
            gate.entered.set()
            await gate.release.wait()
        await super().destroy(env)


def _target() -> TargetSpec:
    return TargetSpec(target_id="target:local-reservation-lab", target_version="version:1")


async def _wait_entered(gate: _Gate) -> None:
    await asyncio.wait_for(gate.entered.wait(), timeout=1.0)


async def _advance_ready_tasks() -> None:
    for _ in range(3):
        await asyncio.sleep(0)


async def _prepare_collision(
    mode: Literal["same", "namespace_overlap"],
) -> tuple[_ReservationAdversarialAdapter, WorldNode]:
    adapter = _ReservationAdversarialAdapter()
    adapter.prepare_mode = mode
    manager = WorldManager(adapter)
    first_gate = adapter.gate_next_snapshot()
    second_gate = adapter.gate_next_snapshot()

    first = asyncio.create_task(manager.prepare(_target(), world_id=f"world:{mode}:first"))
    await _wait_entered(first_gate)
    second = asyncio.create_task(manager.prepare(_target(), world_id=f"world:{mode}:second"))

    outcomes: tuple[WorldNode | BaseException, WorldNode | BaseException]
    try:
        await _advance_ready_tasks()
        assert not second_gate.entered.is_set()
        assert adapter.snapshot_calls == 1
        assert second.done()
    finally:
        first_gate.release.set()
        second_gate.release.set()
        outcomes = await asyncio.wait_for(
            asyncio.gather(first, second, return_exceptions=True), timeout=1.0
        )

    winner, loser = outcomes
    assert isinstance(winner, WorldNode)
    assert isinstance(loser, LifecycleError)
    assert winner.environment is not None
    await manager.snapshot(winner.world_id)
    return adapter, winner


@pytest.mark.asyncio
async def test_concurrent_same_handle_prepare_rejects_loser_without_destroying_winner() -> None:
    adapter, winner = await _prepare_collision("same")

    assert winner.environment is not None
    assert adapter.destroy_calls == []
    assert adapter.destroyed.isdisjoint({winner.environment.environment_id})


@pytest.mark.asyncio
async def test_pending_namespace_overlap_rejects_snapshot_and_cleans_only_owned_loser() -> None:
    adapter, winner = await _prepare_collision("namespace_overlap")

    assert winner.environment is not None
    assert len(adapter.prepared_ids) == 2
    assert adapter.destroy_calls == [adapter.prepared_ids[1]]
    assert adapter.destroyed.isdisjoint({winner.environment.environment_id})


@pytest.mark.asyncio
async def test_pending_namespace_loser_cleanup_does_not_block_winner_commits() -> None:
    adapter = _ReservationAdversarialAdapter()
    adapter.prepare_mode = "namespace_overlap"
    manager = WorldManager(adapter)
    winner = await manager.prepare(_target(), world_id="world:published-winner")
    assert winner.environment is not None
    destroy_gate = adapter.gate_next_destroy()
    loser = asyncio.create_task(manager.prepare(_target(), world_id="world:pending-loser"))
    await _wait_entered(destroy_gate)

    snapshot = asyncio.create_task(manager.snapshot(winner.world_id))
    transition = asyncio.create_task(manager.transition(winner.world_id, WorldPhase.FROZEN))
    winner_outcomes: tuple[SnapshotManifest | BaseException, WorldNode | BaseException]
    loser_outcome: WorldNode | BaseException
    try:
        winner_outcomes = await asyncio.wait_for(
            asyncio.gather(snapshot, transition, return_exceptions=True), timeout=1.0
        )
        assert isinstance(winner_outcomes[0], SnapshotManifest)
        assert isinstance(winner_outcomes[1], WorldNode)
    finally:
        destroy_gate.release.set()
        loser_outcome = (
            await asyncio.wait_for(asyncio.gather(loser, return_exceptions=True), timeout=1.0)
        )[0]

    assert isinstance(loser_outcome, LifecycleError)
    current = manager.store.get(winner.world_id)
    assert current.phase is WorldPhase.FROZEN
    assert current.destroyed is False
    assert winner.environment.environment_id not in adapter.destroyed
    assert adapter.prepared_ids[1] in adapter.destroyed


@pytest.mark.asyncio
async def test_different_parent_forks_cannot_publish_or_cleanup_the_same_child_handle() -> None:
    adapter = _ReservationAdversarialAdapter()
    manager = WorldManager(adapter)
    left = await manager.prepare(_target(), world_id="world:parent:left")
    right = await manager.prepare(_target(), world_id="world:parent:right")
    adapter.same_child_forks = True
    first_gate = adapter.gate_next_snapshot()
    second_gate = adapter.gate_next_snapshot()

    first = asyncio.create_task(
        manager.fork(
            left.world_id,
            lineage_transition="transition:left-child",
            world_id="world:child:left",
        )
    )
    await _wait_entered(first_gate)
    second = asyncio.create_task(
        manager.fork(
            right.world_id,
            lineage_transition="transition:right-child",
            world_id="world:child:right",
        )
    )

    outcomes: tuple[WorldNode | BaseException, WorldNode | BaseException]
    try:
        await _advance_ready_tasks()
        assert not second_gate.entered.is_set()
        assert second.done()
    finally:
        first_gate.release.set()
        second_gate.release.set()
        outcomes = await asyncio.wait_for(
            asyncio.gather(first, second, return_exceptions=True), timeout=1.0
        )

    winner, loser = outcomes
    assert isinstance(winner, WorldNode)
    assert isinstance(loser, LifecycleError)
    assert adapter.destroy_calls == []
    assert winner.environment is not None
    await manager.snapshot(winner.world_id)


@pytest.mark.asyncio
async def test_duplicate_world_id_is_rejected_before_a_second_adapter_prepare() -> None:
    adapter = _ReservationAdversarialAdapter()
    manager = WorldManager(adapter)
    first_gate = adapter.gate_next_prepare()
    second_gate = adapter.gate_next_prepare()

    first = asyncio.create_task(manager.prepare(_target(), world_id="world:duplicate"))
    await _wait_entered(first_gate)
    second = asyncio.create_task(manager.prepare(_target(), world_id="world:duplicate"))

    outcomes: tuple[WorldNode | BaseException, WorldNode | BaseException]
    try:
        await _advance_ready_tasks()
        assert adapter.prepare_calls == 1
        assert not second_gate.entered.is_set()
        assert second.done()
    finally:
        first_gate.release.set()
        second_gate.release.set()
        outcomes = await asyncio.wait_for(
            asyncio.gather(first, second, return_exceptions=True), timeout=1.0
        )

    winner, loser = outcomes
    assert isinstance(winner, WorldNode)
    assert isinstance(loser, LifecycleError)


@pytest.mark.asyncio
async def test_bound_snapshot_failure_cleans_up_then_releases_world_id_for_retry() -> None:
    adapter = _ReservationAdversarialAdapter()
    adapter.fail_next_snapshot = True
    manager = WorldManager(adapter)

    with pytest.raises(WorldError, match="adapter operation failed"):
        await manager.prepare(_target(), world_id="world:retry-after-cleanup")

    assert adapter.prepare_calls == 1
    assert adapter.destroy_calls == [adapter.prepared_ids[0]]
    recovered = await manager.prepare(_target(), world_id="world:retry-after-cleanup")
    assert recovered.destroyed is False
    assert adapter.prepare_calls == 2


@pytest.mark.asyncio
async def test_cleanup_failure_quarantines_world_id_before_any_retry_adapter_call() -> None:
    adapter = _ReservationAdversarialAdapter()
    adapter.fail_next_snapshot = True
    adapter.fail_destroy = True
    manager = WorldManager(adapter)

    with pytest.raises(CleanupError):
        await manager.prepare(_target(), world_id="world:quarantined")

    calls_before_retry = adapter.prepare_calls
    with pytest.raises(LifecycleError):
        await manager.prepare(_target(), world_id="world:quarantined")
    assert adapter.prepare_calls == calls_before_retry == 1


@pytest.mark.asyncio
async def test_distinct_prepare_reservations_do_not_serialize_snapshot_operations() -> None:
    adapter = _ReservationAdversarialAdapter()
    manager = WorldManager(adapter)
    first_gate = adapter.gate_next_snapshot()
    second_gate = adapter.gate_next_snapshot()
    first = asyncio.create_task(manager.prepare(_target(), world_id="world:parallel:first"))
    second = asyncio.create_task(manager.prepare(_target(), world_id="world:parallel:second"))

    outcomes: tuple[WorldNode | BaseException, WorldNode | BaseException]
    try:
        await asyncio.gather(_wait_entered(first_gate), _wait_entered(second_gate))
        assert adapter.active_snapshots == 2
        assert adapter.max_active_snapshots == 2
    finally:
        first_gate.release.set()
        second_gate.release.set()
        outcomes = await asyncio.wait_for(
            asyncio.gather(first, second, return_exceptions=True), timeout=1.0
        )

    assert all(isinstance(outcome, WorldNode) for outcome in outcomes)


@pytest.mark.asyncio
async def test_read_only_world_store_has_no_materialization_authority() -> None:
    adapter = _ReservationAdversarialAdapter()
    manager = WorldManager(adapter)
    root = await manager.prepare(_target(), world_id="world:bypass-root")
    ghost = await manager.create_ghost(
        root.world_id,
        lineage_transition="transition:bypass-ghost",
        world_id="world:bypass-ghost",
    )

    assert manager.store is manager.worlds
    assert manager.worlds.get(ghost.world_id) == ghost
    assert ghost.environment is None
    assert ghost.snapshot is None
    assert not hasattr(manager.worlds, "add")
    assert not hasattr(manager.worlds, "replace")
