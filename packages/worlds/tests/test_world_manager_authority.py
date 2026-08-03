from __future__ import annotations

import asyncio

import pytest
from pydantic import ValidationError
from stateweaver.worlds import (
    AdapterPin,
    AdapterPinError,
    EnvironmentHandle,
    LifecycleError,
    SnapshotManifest,
    TargetSpec,
    WorldManager,
    WorldPhase,
)
from worlds_test_adapter import InMemoryConformanceAdapter


class _CountingAdapter(InMemoryConformanceAdapter):
    """Deterministic adapter that exposes only synthetic operation counts to tests."""

    def __init__(self) -> None:
        super().__init__()
        self.prepare_calls = 0
        self.snapshot_calls = 0
        self.fork_calls = 0
        self.destroy_calls: list[str] = []

    async def prepare(self, target: TargetSpec) -> EnvironmentHandle:
        self.prepare_calls += 1
        return await super().prepare(target)

    async def snapshot(self, env: EnvironmentHandle) -> SnapshotManifest:
        self.snapshot_calls += 1
        return await super().snapshot(env)

    async def fork(self, snapshot: SnapshotManifest) -> EnvironmentHandle:
        self.fork_calls += 1
        return await super().fork(snapshot)

    async def destroy(self, env: EnvironmentHandle) -> None:
        self.destroy_calls.append(env.environment_id)
        await super().destroy(env)


def _target() -> TargetSpec:
    return TargetSpec(target_id="target:local-authority-lab", target_version="version:1")


def test_public_world_catalog_exposes_queries_and_no_mutation_or_reservation_surface() -> None:
    manager = WorldManager(_CountingAdapter())

    assert manager.worlds is manager.store
    public_names = {name for name in dir(manager.worlds) if not name.startswith("_")}
    assert public_names == {"all", "canonical_world_id", "get"}
    for forbidden in (
        "add",
        "replace",
        "assert_environment_unassigned",
        "reserve",
        "claim",
        "release",
        "_reserve_world",
        "_claim_environment",
        "_release_world",
    ):
        assert not hasattr(manager.worlds, forbidden)


@pytest.mark.asyncio
async def test_forged_phase_and_metadata_destroy_cannot_bypass_manager_cleanup() -> None:
    adapter = _CountingAdapter()
    manager = WorldManager(adapter)
    world = await manager.prepare(_target(), world_id="world:authority-root")
    assert world.environment is not None
    environment_id = world.environment.environment_id

    illegal_phase = world.validated_copy(phase=WorldPhase.VERIFIED)
    metadata_destroy = world.validated_copy(destroyed=True, environment=None)
    assert illegal_phase.phase is WorldPhase.VERIFIED
    assert metadata_destroy.destroyed is True
    with pytest.raises(AttributeError):
        assert manager.worlds.replace is None  # type: ignore[attr-defined]

    before_snapshot = manager.worlds.get(world.world_id)
    refreshed = await manager.snapshot(world.world_id)
    after_snapshot = manager.worlds.get(world.world_id)
    assert refreshed.source_environment_id == environment_id
    assert before_snapshot.phase is after_snapshot.phase is WorldPhase.ACTIVE
    assert after_snapshot.destroyed is False
    assert environment_id not in adapter.destroyed

    first_destroy = await manager.destroy(world.world_id)
    second_destroy = await manager.destroy(world.world_id)
    assert first_destroy.destroyed and second_destroy.destroyed
    assert adapter.destroy_calls == [environment_id]
    assert environment_id in adapter.destroyed


@pytest.mark.asyncio
async def test_read_only_queries_return_frozen_nodes_without_adapter_or_revision_side_effects() -> (
    None
):
    adapter = _CountingAdapter()
    manager = WorldManager(adapter)
    world = await manager.prepare(_target(), world_id="world:query-root")
    call_counts = (
        adapter.prepare_calls,
        adapter.snapshot_calls,
        adapter.fork_calls,
        tuple(adapter.destroy_calls),
    )

    fetched = manager.worlds.get(world.world_id)
    listed = manager.worlds.all()
    canonical = manager.worlds.canonical_world_id(world.state_fingerprint)
    assert fetched == world
    assert listed == (world,)
    assert canonical == world.world_id
    assert manager.worlds.get(world.world_id).revision == world.revision
    with pytest.raises(ValidationError):
        fetched.phase = WorldPhase.FROZEN
    detached = fetched.model_copy(update={"phase": WorldPhase.VERIFIED})
    assert detached.phase is WorldPhase.VERIFIED
    assert manager.worlds.get(world.world_id).phase is WorldPhase.ACTIVE
    assert call_counts == (
        adapter.prepare_calls,
        adapter.snapshot_calls,
        adapter.fork_calls,
        tuple(adapter.destroy_calls),
    )


@pytest.mark.asyncio
async def test_create_ghost_derives_lineage_and_uses_only_manager_legal_transition() -> None:
    adapter = _CountingAdapter()
    manager = WorldManager(adapter)
    parent = await manager.prepare(_target(), world_id="world:ghost-parent")
    call_counts = (adapter.prepare_calls, adapter.snapshot_calls, adapter.fork_calls)

    ghost = await manager.create_ghost(
        parent.world_id,
        lineage_transition="transition:ghost-candidate",
        world_id="world:ghost-candidate",
    )

    assert ghost.parent_world_id == parent.world_id
    assert ghost.root_snapshot_id == parent.root_snapshot_id
    assert ghost.target == parent.target
    assert ghost.adapter == parent.adapter
    assert ghost.capability_manifest == parent.capability_manifest
    assert ghost.lineage == (*parent.lineage, "transition:ghost-candidate")
    assert ghost.phase is WorldPhase.GHOST
    assert ghost.environment is None
    assert ghost.snapshot is None
    assert call_counts == (adapter.prepare_calls, adapter.snapshot_calls, adapter.fork_calls)

    replay = await manager.transition(ghost.world_id, WorldPhase.REPLAY)
    assert replay.phase is WorldPhase.REPLAY
    assert replay.revision == ghost.revision + 1
    assert manager.worlds.get(parent.world_id) == parent


@pytest.mark.asyncio
async def test_create_ghost_revalidates_parent_adapter_pin_before_catalog_mutation() -> None:
    adapter = _CountingAdapter()
    manager = WorldManager(adapter)
    parent = await manager.prepare(_target(), world_id="world:pin-parent")
    call_counts = (
        adapter.prepare_calls,
        adapter.snapshot_calls,
        adapter.fork_calls,
        tuple(adapter.destroy_calls),
    )
    adapter.pin = AdapterPin(adapter=parent.adapter.adapter, version="2.0.0")

    with pytest.raises(AdapterPinError):
        await manager.create_ghost(
            parent.world_id,
            lineage_transition="transition:pin-drift",
            world_id="world:pin-drift-child",
        )

    assert manager.worlds.all() == (parent,)
    with pytest.raises(LifecycleError):
        manager.worlds.get("world:pin-drift-child")
    assert call_counts == (
        adapter.prepare_calls,
        adapter.snapshot_calls,
        adapter.fork_calls,
        tuple(adapter.destroy_calls),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("world_id", ["", "   ", "world/invalid", "x" * 161])
async def test_invalid_prepare_world_id_is_rejected_before_adapter(world_id: str) -> None:
    adapter = _CountingAdapter()
    manager = WorldManager(adapter)

    with pytest.raises(LifecycleError):
        await manager.prepare(_target(), world_id=world_id)

    assert adapter.prepare_calls == 0
    assert adapter.snapshot_calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("world_id", ["", "child invalid", "x" * 161])
async def test_invalid_fork_world_id_is_rejected_before_adapter(world_id: str) -> None:
    adapter = _CountingAdapter()
    manager = WorldManager(adapter)
    parent = await manager.prepare(_target(), world_id="world:valid-parent")
    calls_before = (adapter.fork_calls, adapter.snapshot_calls)

    with pytest.raises(LifecycleError):
        await manager.fork(
            parent.world_id,
            lineage_transition="transition:invalid-child",
            world_id=world_id,
        )

    assert (adapter.fork_calls, adapter.snapshot_calls) == calls_before


@pytest.mark.asyncio
async def test_foreign_event_loop_is_rejected_before_adapter_and_original_loop_recovers() -> None:
    adapter = _CountingAdapter()
    manager = WorldManager(adapter)
    world = await manager.prepare(_target(), world_id="world:loop-affinity")
    assert world.environment is not None
    snapshot_calls = adapter.snapshot_calls

    def run_in_foreign_loop() -> BaseException | None:
        try:
            asyncio.run(manager.snapshot(world.world_id))
        except BaseException as error:
            return error
        return None

    foreign_error = await asyncio.to_thread(run_in_foreign_loop)
    assert isinstance(foreign_error, LifecycleError)
    assert adapter.snapshot_calls == snapshot_calls

    restored = await manager.snapshot(world.world_id)
    assert restored.source_environment_id == world.environment.environment_id
    assert adapter.snapshot_calls == snapshot_calls + 1


@pytest.mark.asyncio
async def test_invalid_foreign_loop_attempt_does_not_claim_unbound_manager_ownership() -> None:
    adapter = _CountingAdapter()
    manager = WorldManager(adapter)

    def run_invalid_in_foreign_loop() -> BaseException | None:
        try:
            asyncio.run(manager.prepare(_target(), world_id=""))
        except BaseException as error:
            return error
        return None

    foreign_error = await asyncio.to_thread(run_invalid_in_foreign_loop)
    assert isinstance(foreign_error, LifecycleError)
    assert adapter.prepare_calls == 0
    assert adapter.snapshot_calls == 0

    world = await manager.prepare(_target(), world_id="world:original-loop-owner")
    assert world.destroyed is False
    assert adapter.prepare_calls == 1
    assert adapter.snapshot_calls == 1
