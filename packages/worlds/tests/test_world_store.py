from __future__ import annotations

import pytest
from stateweaver.worlds import (
    LifecycleError,
    RevisionConflict,
    TargetSpec,
    WorldManager,
    WorldPhase,
)
from stateweaver.worlds.store import _WorldStore
from worlds_test_adapter import InMemoryConformanceAdapter


def _target() -> TargetSpec:
    return TargetSpec(target_id="target:store-unit", target_version="version:1")


@pytest.mark.asyncio
async def test_private_writer_authority_preserves_stale_revision_rejection() -> None:
    adapter = InMemoryConformanceAdapter()
    manager = WorldManager(adapter)
    root = await manager.prepare(_target(), world_id="world:store-source")
    assert root.environment is not None

    store = _WorldStore()
    writer = store._open_manager_writer()
    with pytest.raises(LifecycleError, match="already issued"):
        store._open_manager_writer()

    reservation = writer.reserve_world(root.world_id)
    writer.claim_environment(reservation, root.environment)
    writer.validate_reserved_namespace(reservation)
    original = writer.add(root, reservation=reservation)

    with pytest.raises(LifecycleError, match="mutation authority"):
        store._replace(
            original.validated_copy(phase=WorldPhase.FROZEN),
            expected_revision=original.revision,
            authority=object(),
        )

    committed = writer.replace(
        original.validated_copy(phase=WorldPhase.FROZEN),
        expected_revision=original.revision,
    )
    with pytest.raises(RevisionConflict, match="revision"):
        writer.replace(original, expected_revision=original.revision)

    assert store.get(original.world_id) == committed
    await manager.destroy(root.world_id)
