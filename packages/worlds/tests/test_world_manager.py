from __future__ import annotations

import asyncio

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError
from stateweaver.worlds import (
    AdapterPin,
    AdapterPinError,
    AdapterReturnError,
    CapabilityError,
    CapabilityLevel,
    CapabilityManifest,
    CleanupError,
    EgressPolicy,
    LifecycleError,
    OperationLimits,
    OperationTimeout,
    TargetSpec,
    WorldManager,
    WorldNode,
    WorldPhase,
)
from worlds_test_adapter import Component, InMemoryConformanceAdapter


def _target() -> TargetSpec:
    return TargetSpec(
        target_id="target:local-lab",
        target_version="version:1",
        secret_handles=("secret:synthetic",),
    )


@pytest.mark.asyncio
async def test_four_siblings_mutate_all_isolation_markers_without_root_contamination() -> None:
    adapter = InMemoryConformanceAdapter()
    manager = WorldManager(adapter)
    root = await manager.prepare(_target(), world_id="world:root")
    siblings = await asyncio.gather(
        *(
            manager.fork(
                root.world_id, lineage_transition=f"transition:{index}", world_id=f"world:{index}"
            )
            for index in range(4)
        )
    )
    components: tuple[Component, ...] = ("database", "cache", "queue", "session", "clock")
    for index, sibling in enumerate(siblings):
        assert sibling.environment is not None
        for component in components:
            adapter.mutate(sibling.environment, component, f"world-{index}-{component}")
    assert root.environment is not None
    for component in components:
        assert adapter.marker(root.environment, component) == "root"
    for index, sibling in enumerate(siblings):
        assert sibling.environment is not None
        for component in components:
            assert adapter.marker(sibling.environment, component) == f"world-{index}-{component}"
        assert sibling.environment.namespace != root.environment.namespace


@pytest.mark.asyncio
async def test_snapshot_restore_identity_and_fingerprint_dedup_preserves_lineage() -> None:
    adapter = InMemoryConformanceAdapter()
    manager = WorldManager(adapter)
    root = await manager.prepare(_target(), world_id="world:root")
    left, right = await asyncio.gather(
        manager.fork(root.world_id, lineage_transition="transition:left", world_id="world:left"),
        manager.fork(root.world_id, lineage_transition="transition:right", world_id="world:right"),
    )
    assert left.deduplicated_to == root.world_id
    assert right.deduplicated_to == root.world_id
    assert right.lineage != left.lineage
    assert left.environment is not None
    saved = await manager.snapshot(left.world_id)
    assert "synthetic-secret-value" not in saved.model_dump_json()
    assert "secret:synthetic" in saved.model_dump_json()
    adapter.mutate(left.environment, "database", "changed")
    restored = await manager.restore(left.world_id, saved)
    assert restored.snapshot is not None
    assert restored.snapshot.content_hashes == saved.content_hashes
    assert restored.state_fingerprint == saved.state_fingerprint


@pytest.mark.asyncio
async def test_restore_revalidates_manifest_before_adapter_call_without_destroying_world() -> None:
    adapter = InMemoryConformanceAdapter()
    manager = WorldManager(adapter)
    root = await manager.prepare(_target(), world_id="world:root")
    assert root.snapshot is not None
    forged = root.snapshot.model_copy(update={"state_fingerprint": "sha256:" + "0" * 64})

    with pytest.raises(AdapterReturnError, match="invalid snapshot manifest"):
        await manager.restore(root.world_id, forged)

    assert manager.store.get(root.world_id).destroyed is False
    assert root.environment is not None
    assert root.environment.environment_id not in adapter.destroyed


@pytest.mark.asyncio
async def test_world_node_binds_snapshot_source_to_live_environment() -> None:
    adapter = InMemoryConformanceAdapter()
    manager = WorldManager(adapter)
    root = await manager.prepare(_target(), world_id="world:root")
    assert root.snapshot is not None
    forged_snapshot = root.snapshot.model_copy(update={"source_environment_id": "env:forged"})
    with pytest.raises(ValidationError, match="source environment"):
        WorldNode(**(root.model_dump() | {"snapshot": forged_snapshot}))


@pytest.mark.asyncio
async def test_cleanup_after_failure_and_idempotent_destroy() -> None:
    adapter = InMemoryConformanceAdapter()
    manager = WorldManager(adapter)
    root = await manager.prepare(_target(), world_id="world:root")
    adapter.fail_next_snapshot = True
    with pytest.raises(Exception, match="adapter operation failed"):
        await manager.fork(root.world_id, lineage_transition="transition:broken")
    assert adapter.destroyed  # failed fork's ephemeral environment was cleaned up
    first = await manager.destroy(root.world_id)
    second = await manager.destroy(root.world_id)
    assert first.destroyed and second.destroyed


@pytest.mark.asyncio
async def test_timeout_cancels_adapter_and_fails_closed() -> None:
    adapter = InMemoryConformanceAdapter()
    manager = WorldManager(adapter, limits=OperationLimits(snapshot_seconds=0.01))
    adapter.sleep_snapshot = True
    with pytest.raises(OperationTimeout):
        await manager.prepare(_target())
    assert adapter.snapshot_cancelled
    assert adapter.destroyed


@pytest.mark.asyncio
async def test_version_pinning_pruned_unschedulable_and_default_egress_denied() -> None:
    adapter = InMemoryConformanceAdapter()
    manager = WorldManager(adapter)
    root = await manager.prepare(_target())
    assert root.capability_manifest.egress_policy.value == "deny"
    adapter.pin = AdapterPin(adapter="in-memory-conformance", version="2.0.0")
    with pytest.raises(AdapterPinError):
        await manager.fork(root.world_id, lineage_transition="transition:pin")
    # Lifecycle still observes its original pin and explicitly prohibits scheduling pruned worlds.
    adapter.pin = root.adapter
    ghost = await manager.create_ghost(
        root.world_id,
        lineage_transition="transition:ghost",
        world_id="world:ghost",
    )
    await manager.transition(ghost.world_id, WorldPhase.PRUNED)
    assert not manager.schedulable(ghost.world_id)
    with pytest.raises(LifecycleError):
        await manager.transition(ghost.world_id, WorldPhase.ACTIVE)


@pytest.mark.asyncio
async def test_untrusted_adapter_returns_and_reused_namespace_fail_closed() -> None:
    adapter = InMemoryConformanceAdapter()
    adapter.return_wrong_prepare = True
    with pytest.raises(AdapterReturnError):
        await WorldManager(adapter).prepare(_target())

    adapter = InMemoryConformanceAdapter()
    manager = WorldManager(adapter)
    root = await manager.prepare(_target())
    adapter.return_wrong_fork = True
    with pytest.raises(AdapterReturnError):
        await manager.fork(root.world_id, lineage_transition="transition:wrong-fork")
    adapter.return_wrong_fork = False
    adapter.reuse_parent_on_fork = True
    with pytest.raises(LifecycleError, match="environment identifier"):
        await manager.fork(root.world_id, lineage_transition="transition:reused")
    assert root.environment is not None
    assert root.environment.environment_id not in adapter.destroyed
    assert adapter.marker(root.environment, "database") == "root"


@pytest.mark.asyncio
async def test_snapshot_wrong_model_source_and_version_mismatches_clean_up() -> None:
    for fault in (
        "return_wrong_snapshot",
        "snapshot_source_mismatch",
        "snapshot_version_mismatch",
        "snapshot_fingerprint_mismatch",
    ):
        adapter = InMemoryConformanceAdapter()
        manager = WorldManager(adapter)
        root = await manager.prepare(_target())
        setattr(adapter, fault, True)
        expected = (
            AdapterReturnError
            if fault in {"return_wrong_snapshot", "snapshot_fingerprint_mismatch"}
            else (LifecycleError, AdapterPinError)
        )
        with pytest.raises(expected):
            await manager.snapshot(root.world_id)
        assert manager.store.get(root.world_id).destroyed
        assert root.environment is not None and root.environment.environment_id in adapter.destroyed

    adapter = InMemoryConformanceAdapter()
    manager = WorldManager(adapter)
    root = await manager.prepare(_target())
    assert root.snapshot is not None
    adapter.return_wrong_restore = True
    with pytest.raises(AdapterReturnError):
        await manager.restore(root.world_id, root.snapshot)
    assert manager.store.get(root.world_id).destroyed


@pytest.mark.asyncio
async def test_cleanup_failure_is_visible_and_preserves_primary_cause() -> None:
    adapter = InMemoryConformanceAdapter()
    manager = WorldManager(adapter)
    root = await manager.prepare(_target())
    adapter.fail_next_snapshot = True
    adapter.fail_destroy = True
    with pytest.raises(CleanupError) as raised:
        await manager.fork(root.world_id, lineage_transition="transition:cleanup-failure")
    assert isinstance(raised.value.primary_error, Exception)
    assert isinstance(raised.value.cleanup_error, Exception)


@pytest.mark.asyncio
async def test_dedup_index_rebuilds_after_fingerprint_change_and_destroy() -> None:
    adapter = InMemoryConformanceAdapter()
    manager = WorldManager(adapter)
    root = await manager.prepare(_target(), world_id="world:root")
    left, right = await asyncio.gather(
        manager.fork(root.world_id, lineage_transition="transition:left", world_id="world:left"),
        manager.fork(root.world_id, lineage_transition="transition:right", world_id="world:right"),
    )
    assert manager.store.canonical_world_id(root.state_fingerprint) == root.world_id
    await manager.destroy(root.world_id)
    assert manager.store.canonical_world_id(left.state_fingerprint) == left.world_id
    assert manager.store.get(right.world_id).deduplicated_to == left.world_id
    assert left.environment is not None
    adapter.mutate(left.environment, "database", "new")
    changed = await manager.snapshot(left.world_id)
    assert manager.store.canonical_world_id(changed.state_fingerprint) == left.world_id
    assert manager.store.get(left.world_id).deduplicated_to is None


@pytest.mark.asyncio
async def test_manifest_hash_binds_all_security_semantics_and_models_cohere() -> None:
    adapter = InMemoryConformanceAdapter()
    manager = WorldManager(adapter)
    root = await manager.prepare(_target())
    assert root.snapshot is not None
    snapshot = root.snapshot
    reordered = snapshot.model_copy(
        update={"content_hashes": dict(reversed(tuple(snapshot.content_hashes.items())))}
    )
    assert reordered.manifest_hash == snapshot.manifest_hash
    assert (
        snapshot.model_copy(update={"source_environment_id": "env:other"}).manifest_hash
        != snapshot.manifest_hash
    )
    assert (
        snapshot.model_copy(update={"state_fingerprint": "sha256:" + "0" * 64}).manifest_hash
        != snapshot.manifest_hash
    )
    with pytest.raises(ValidationError):
        WorldNode(**(root.model_dump() | {"destroyed": True}))
    with pytest.raises(ValidationError):
        WorldNode(**(root.model_dump() | {"deduplicated_to": root.world_id}))


def test_capability_mapping_is_canonical_and_m2_rejects_egress_allowlists() -> None:
    adapter = InMemoryConformanceAdapter()
    manifest = adapter.capabilities()
    assert tuple(manifest.capabilities) == tuple(sorted(manifest.capabilities))
    adapter.capabilities = lambda: CapabilityManifest(  # type: ignore[method-assign]
        pin=adapter.pin,
        egress_policy=EgressPolicy.ALLOWLIST,
        capabilities=dict.fromkeys(manifest.capabilities, CapabilityLevel.SUPPORTED),
    )
    with pytest.raises(CapabilityError):
        WorldManager(adapter)


def test_models_are_frozen_closed_and_secret_values_do_not_serialize() -> None:
    adapter = InMemoryConformanceAdapter()
    target = _target()
    with pytest.raises(ValidationError):
        TargetSpec(target_id="target:x", target_version="version:1", unexpected="no")  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        target.target_id = "target:changed"
    assert "synthetic-secret-value" not in target.model_dump_json()
    assert "secret:synthetic" in target.model_dump_json()
    assert adapter.synthetic_secret_values["secret:synthetic"] == "synthetic-secret-value"


@pytest.mark.asyncio
async def test_manager_derives_complete_ghost_lineage_and_models_revalidate() -> None:
    adapter = InMemoryConformanceAdapter()
    manager = WorldManager(adapter)
    root = await manager.prepare(_target(), world_id="world:root")
    child = await manager.fork(
        root.world_id, lineage_transition="transition:child", world_id="world:child"
    )
    ghost = await manager.create_ghost(
        child.world_id,
        lineage_transition="transition:ghost",
        world_id="world:derived-ghost",
    )

    assert ghost.parent_world_id == child.world_id
    assert ghost.lineage == (*child.lineage, "transition:ghost")
    with pytest.raises(ValidationError, match="active materialized"):
        child.model_copy(update={"environment": None}).revalidated()


@pytest.mark.asyncio
async def test_identical_fingerprint_across_distinct_roots_is_not_cross_deduplicated() -> None:
    adapter = InMemoryConformanceAdapter()
    manager = WorldManager(adapter)
    first = await manager.prepare(_target(), world_id="world:first-root")
    second = await manager.prepare(_target(), world_id="world:second-root")

    assert first.state_fingerprint == second.state_fingerprint
    assert first.deduplicated_to is None
    assert second.deduplicated_to is None
    assert manager.store.canonical_world_id(first.state_fingerprint) is None


def test_snapshot_state_fingerprint_is_derived_not_adapter_asserted() -> None:
    hashes = {
        component: "sha256:" + f"{index:x}" * 64
        for index, component in enumerate(
            ("filesystem", "database", "cache", "queue", "session", "clock"), start=1
        )
    }
    with pytest.raises(ValidationError, match="derive from component hashes"):
        from stateweaver.worlds import SnapshotManifest

        SnapshotManifest(
            snapshot_id="snap:forged",
            root_snapshot_id="root:forged",
            source_environment_id="env:forged",
            target=_target(),
            adapter=AdapterPin(adapter="in-memory-conformance", version="1.0.0"),
            content_hashes=hashes,
            state_fingerprint="sha256:" + "0" * 64,
        )


@given(st.lists(st.text(alphabet="abc123", min_size=1, max_size=8), min_size=1, max_size=12))
def test_content_hashes_are_deterministic_for_same_component_markers(markers: list[str]) -> None:
    # The hashing oracle used by the conformance adapter is deterministic by construction.
    from worlds_test_adapter import _hash

    assert _hash({"markers": markers}) == _hash({"markers": markers})
