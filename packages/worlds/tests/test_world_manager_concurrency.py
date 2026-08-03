from __future__ import annotations

import asyncio
from collections import defaultdict, deque
from dataclasses import dataclass, field

import pytest
from stateweaver.worlds import (
    EnvironmentHandle,
    LifecycleError,
    RevisionConflict,
    SnapshotManifest,
    TargetSpec,
    WorldError,
    WorldManager,
    WorldPhase,
)
from worlds_test_adapter import InMemoryConformanceAdapter


@dataclass
class _OperationGate:
    entered: asyncio.Event = field(default_factory=asyncio.Event)
    release: asyncio.Event = field(default_factory=asyncio.Event)
    failure: BaseException | None = None


class _AdversarialAdapter(InMemoryConformanceAdapter):
    """Deterministic, in-process adapter whose awaits are controlled by the test."""

    def __init__(self) -> None:
        super().__init__()
        self._snapshot_gates: dict[str, deque[_OperationGate]] = defaultdict(deque)
        self._fork_gates: dict[str, deque[_OperationGate]] = defaultdict(deque)
        self._restore_gates: dict[str, deque[_OperationGate]] = defaultdict(deque)
        self.active_snapshots = 0
        self.max_active_snapshots = 0
        self.destroy_calls: dict[str, int] = defaultdict(int)

    def gate_snapshot(self, environment_id: str) -> _OperationGate:
        gate = _OperationGate()
        self._snapshot_gates[environment_id].append(gate)
        return gate

    def gate_fork(
        self, source_environment_id: str, *, failure: BaseException | None = None
    ) -> _OperationGate:
        gate = _OperationGate(failure=failure)
        self._fork_gates[source_environment_id].append(gate)
        return gate

    def gate_restore(self, environment_id: str) -> _OperationGate:
        gate = _OperationGate()
        self._restore_gates[environment_id].append(gate)
        return gate

    async def snapshot(self, env: EnvironmentHandle) -> SnapshotManifest:
        gates = self._snapshot_gates[env.environment_id]
        if gates:
            gate = gates.popleft()
            self.active_snapshots += 1
            self.max_active_snapshots = max(self.max_active_snapshots, self.active_snapshots)
            gate.entered.set()
            try:
                await gate.release.wait()
                if gate.failure is not None:
                    raise gate.failure
            finally:
                self.active_snapshots -= 1
        return await super().snapshot(env)

    async def fork(self, snapshot: SnapshotManifest) -> EnvironmentHandle:
        gates = self._fork_gates[snapshot.source_environment_id]
        if gates:
            gate = gates.popleft()
            gate.entered.set()
            await gate.release.wait()
            if gate.failure is not None:
                raise gate.failure
        return await super().fork(snapshot)

    async def restore(self, env: EnvironmentHandle, snapshot: SnapshotManifest) -> None:
        gates = self._restore_gates[env.environment_id]
        if gates:
            gate = gates.popleft()
            gate.entered.set()
            await gate.release.wait()
        await super().restore(env, snapshot)

    async def destroy(self, env: EnvironmentHandle) -> None:
        self.destroy_calls[env.environment_id] += 1
        await super().destroy(env)


def _target() -> TargetSpec:
    return TargetSpec(target_id="target:local-lab", target_version="version:1")


async def _wait_entered(gate: _OperationGate) -> None:
    await asyncio.wait_for(gate.entered.wait(), timeout=1.0)


@pytest.mark.asyncio
async def test_unknown_world_ids_do_not_allocate_retained_admission_gates() -> None:
    manager = WorldManager(_AdversarialAdapter())

    for index in range(32):
        with pytest.raises(LifecycleError, match="unknown world"):
            await manager.snapshot(f"world:unknown-{index}")

    assert not manager._world_gates


@pytest.mark.asyncio
async def test_snapshot_commit_never_overwrites_a_transition_made_while_adapter_awaits() -> None:
    adapter = _AdversarialAdapter()
    manager = WorldManager(adapter)
    world = await manager.prepare(_target(), world_id="world:race")
    assert world.environment is not None
    gate = adapter.gate_snapshot(world.environment.environment_id)

    snapshot_task = asyncio.create_task(manager.snapshot(world.world_id))
    await _wait_entered(gate)
    transition_task = asyncio.create_task(manager.transition(world.world_id, WorldPhase.FROZEN))
    await asyncio.sleep(0)

    try:
        assert not transition_task.done()
        assert manager.store.get(world.world_id).phase is WorldPhase.ACTIVE
    finally:
        gate.release.set()

    await asyncio.wait_for(asyncio.gather(snapshot_task, transition_task), timeout=1.0)
    assert manager.store.get(world.world_id).phase is WorldPhase.FROZEN


@pytest.mark.asyncio
async def test_parent_transition_waits_for_an_in_flight_fork() -> None:
    adapter = _AdversarialAdapter()
    manager = WorldManager(adapter)
    parent = await manager.prepare(_target(), world_id="world:fork-parent")
    assert parent.environment is not None
    gate = adapter.gate_fork(parent.environment.environment_id)

    fork_task = asyncio.create_task(
        manager.fork(
            parent.world_id,
            lineage_transition="transition:child",
            world_id="world:fork-child",
        )
    )
    await _wait_entered(gate)
    transition_task = asyncio.create_task(manager.transition(parent.world_id, WorldPhase.FROZEN))
    await asyncio.sleep(0)

    try:
        assert not transition_task.done()
        assert manager.store.get(parent.world_id).phase is WorldPhase.ACTIVE
    finally:
        gate.release.set()

    child, transitioned = await asyncio.wait_for(
        asyncio.gather(fork_task, transition_task), timeout=1.0
    )
    assert child.parent_world_id == parent.world_id
    assert transitioned.phase is WorldPhase.FROZEN
    assert manager.store.get(parent.world_id) == transitioned


@pytest.mark.asyncio
async def test_same_world_snapshot_operations_are_serialized() -> None:
    adapter = _AdversarialAdapter()
    manager = WorldManager(adapter)
    world = await manager.prepare(_target(), world_id="world:serialized")
    assert world.environment is not None
    first_gate = adapter.gate_snapshot(world.environment.environment_id)
    second_gate = adapter.gate_snapshot(world.environment.environment_id)

    first = asyncio.create_task(manager.snapshot(world.world_id))
    await _wait_entered(first_gate)
    second = asyncio.create_task(manager.snapshot(world.world_id))
    await asyncio.sleep(0)

    try:
        assert not second_gate.entered.is_set()
        assert adapter.active_snapshots == 1
    finally:
        first_gate.release.set()

    await _wait_entered(second_gate)
    second_gate.release.set()
    await asyncio.wait_for(asyncio.gather(first, second), timeout=1.0)


@pytest.mark.asyncio
async def test_distinct_world_snapshot_operations_remain_parallel() -> None:
    adapter = _AdversarialAdapter()
    manager = WorldManager(adapter)
    first_world = await manager.prepare(_target(), world_id="world:parallel-a")
    second_world = await manager.prepare(_target(), world_id="world:parallel-b")
    assert first_world.environment is not None
    assert second_world.environment is not None
    first_gate = adapter.gate_snapshot(first_world.environment.environment_id)
    second_gate = adapter.gate_snapshot(second_world.environment.environment_id)

    first = asyncio.create_task(manager.snapshot(first_world.world_id))
    second = asyncio.create_task(manager.snapshot(second_world.world_id))
    try:
        await asyncio.gather(_wait_entered(first_gate), _wait_entered(second_gate))
        assert adapter.active_snapshots == 2
        assert adapter.max_active_snapshots == 2
    finally:
        first_gate.release.set()
        second_gate.release.set()

    await asyncio.wait_for(asyncio.gather(first, second), timeout=1.0)


@pytest.mark.asyncio
async def test_destroy_waits_for_snapshot_and_cleans_the_environment_once() -> None:
    adapter = _AdversarialAdapter()
    manager = WorldManager(adapter)
    world = await manager.prepare(_target(), world_id="world:snapshot-destroy")
    assert world.environment is not None
    environment_id = world.environment.environment_id
    gate = adapter.gate_snapshot(environment_id)

    snapshot_task = asyncio.create_task(manager.snapshot(world.world_id))
    await _wait_entered(gate)
    destroy_task = asyncio.create_task(manager.destroy(world.world_id))
    await asyncio.sleep(0)

    try:
        assert not destroy_task.done()
        assert environment_id not in adapter.destroyed
    finally:
        gate.release.set()

    await asyncio.wait_for(asyncio.gather(snapshot_task, destroy_task), timeout=1.0)
    destroyed = manager.store.get(world.world_id)
    assert destroyed.destroyed
    assert destroyed.environment is None
    assert adapter.destroy_calls[environment_id] == 1

    assert (await manager.destroy(world.world_id)).destroyed
    assert adapter.destroy_calls[environment_id] == 1


@pytest.mark.asyncio
async def test_destroy_waits_for_restore_and_commits_after_the_latest_revision() -> None:
    adapter = _AdversarialAdapter()
    manager = WorldManager(adapter)
    world = await manager.prepare(_target(), world_id="world:restore-destroy")
    assert world.environment is not None
    assert world.snapshot is not None
    environment_id = world.environment.environment_id
    gate = adapter.gate_restore(environment_id)

    restore_task = asyncio.create_task(manager.restore(world.world_id, world.snapshot))
    await _wait_entered(gate)
    destroy_task = asyncio.create_task(manager.destroy(world.world_id))
    await asyncio.sleep(0)

    try:
        assert not destroy_task.done()
        assert environment_id not in adapter.destroyed
    finally:
        gate.release.set()

    restored, destroyed = await asyncio.wait_for(
        asyncio.gather(restore_task, destroy_task), timeout=1.0
    )
    assert destroyed.revision == restored.revision + 1
    assert destroyed.destroyed
    assert manager.store.get(world.world_id) == destroyed
    assert adapter.destroy_calls[environment_id] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True], ids=("failure", "cancellation"))
async def test_failed_or_cancelled_lifecycle_operation_releases_world_admission(
    cancel: bool,
) -> None:
    adapter = _AdversarialAdapter()
    manager = WorldManager(adapter)
    parent = await manager.prepare(_target(), world_id=f"world:release-{cancel}")
    assert parent.environment is not None
    gate = adapter.gate_fork(
        parent.environment.environment_id,
        failure=None if cancel else RuntimeError("synthetic gated fork failure"),
    )

    interrupted = asyncio.create_task(
        manager.fork(
            parent.world_id,
            lineage_transition=f"transition:interrupted-{cancel}",
            world_id=f"world:interrupted-{cancel}",
        )
    )
    await _wait_entered(gate)
    if cancel:
        interrupted.cancel()
    else:
        gate.release.set()

    expected = asyncio.CancelledError if cancel else WorldError
    with pytest.raises(expected):
        await interrupted

    recovered = await asyncio.wait_for(
        manager.fork(
            parent.world_id,
            lineage_transition=f"transition:recovered-{cancel}",
            world_id=f"world:recovered-{cancel}",
        ),
        timeout=1.0,
    )
    assert recovered.parent_world_id == parent.world_id


@pytest.mark.asyncio
async def test_store_rejects_a_stale_revision_without_overwriting_the_current_node() -> None:
    adapter = _AdversarialAdapter()
    manager = WorldManager(adapter)
    original = await manager.prepare(_target(), world_id="world:cas")

    committed = manager.store.replace(
        original.validated_copy(phase=WorldPhase.FROZEN),
        expected_revision=original.revision,
    )
    assert committed.revision == original.revision + 1

    with pytest.raises(RevisionConflict, match="revision"):
        manager.store.replace(original, expected_revision=original.revision)

    current = manager.store.get(original.world_id)
    assert current == committed
    assert current.phase is WorldPhase.FROZEN
