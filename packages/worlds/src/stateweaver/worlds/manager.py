"""Fail-closed, bounded orchestration over the EnvironmentAdapter port."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from uuid import uuid4

from .models import (
    FORKABLE_PHASES,
    LEGAL_TRANSITIONS,
    M2_REQUIRED_CAPABILITIES,
    AdapterPin,
    AdapterPinError,
    AdapterReturnError,
    CapabilityError,
    CapabilityManifest,
    CleanupError,
    EgressPolicy,
    EnvironmentHandle,
    LifecycleError,
    OperationLimits,
    OperationTimeout,
    SnapshotManifest,
    TargetSpec,
    WorldError,
    WorldNode,
    WorldPhase,
)
from .ports import EnvironmentAdapter
from .store import WorldStore


class WorldManager:
    """Owns lifecycle invariants; adapters only receive bounded primitive calls."""

    def __init__(
        self, adapter: EnvironmentAdapter, *, limits: OperationLimits | None = None
    ) -> None:
        self._adapter = adapter
        self._limits = limits or OperationLimits()
        self.store = WorldStore()
        self._capabilities = self._validated_capabilities(adapter.capabilities())

    @staticmethod
    def _validated_capabilities(manifest: object) -> CapabilityManifest:
        if not isinstance(manifest, CapabilityManifest):
            raise AdapterReturnError("adapter capabilities returned an invalid model")
        try:
            manifest = manifest.revalidated()
        except ValueError as error:
            raise AdapterReturnError("adapter capabilities returned an invalid model") from error
        if manifest.egress_policy is not EgressPolicy.DENY:
            raise CapabilityError("M2 adapters require default-deny network egress")
        missing = sorted(name for name in M2_REQUIRED_CAPABILITIES if not manifest.supports(name))
        if missing:
            raise CapabilityError("adapter lacks required M2 isolation capabilities")
        return manifest

    def _check_pin(self, pin: AdapterPin) -> None:
        current = self._validated_capabilities(self._adapter.capabilities())
        if current != self._capabilities or current.pin != pin:
            raise AdapterPinError("adapter version or identity no longer matches world pin")

    async def _bounded(self, operation: Awaitable[object], seconds: float) -> object:
        try:
            return await asyncio.wait_for(operation, timeout=seconds)
        except TimeoutError as error:
            raise OperationTimeout("adapter operation exceeded its authorized deadline") from error
        except asyncio.CancelledError:
            raise
        except WorldError:
            raise
        except Exception as error:
            raise WorldError("adapter operation failed") from error

    @staticmethod
    def _as_handle(value: object) -> EnvironmentHandle:
        if not isinstance(value, EnvironmentHandle):
            raise AdapterReturnError("adapter returned an invalid environment handle")
        try:
            return value.revalidated()
        except ValueError as error:
            raise AdapterReturnError("adapter returned an invalid environment handle") from error

    @staticmethod
    def _as_snapshot(value: object) -> SnapshotManifest:
        if not isinstance(value, SnapshotManifest):
            raise AdapterReturnError("adapter returned an invalid snapshot manifest")
        try:
            return value.revalidated()
        except ValueError as error:
            raise AdapterReturnError("adapter returned an invalid snapshot manifest") from error

    @staticmethod
    def _require_none(value: object) -> None:
        if value is not None:
            raise AdapterReturnError("adapter restore returned an invalid result")

    async def _cleanup(self, env: EnvironmentHandle) -> None:
        await self._bounded(self._adapter.destroy(env), self._limits.destroy_seconds)

    async def _cleanup_or_raise(self, env: EnvironmentHandle, primary: BaseException) -> None:
        try:
            await self._cleanup(env)
        except BaseException as cleanup_error:
            raise CleanupError(primary, cleanup_error) from primary

    def _validate_snapshot(
        self,
        snapshot: SnapshotManifest,
        target: TargetSpec,
        environment: EnvironmentHandle,
        root_snapshot_id: str | None = None,
    ) -> None:
        self._check_pin(snapshot.adapter)
        if snapshot.target != target:
            raise LifecycleError("snapshot target pin differs from world target")
        if snapshot.source_environment_id != environment.environment_id:
            raise LifecycleError("snapshot source environment differs from live environment")
        if root_snapshot_id is not None and snapshot.root_snapshot_id != root_snapshot_id:
            raise LifecycleError("snapshot root lineage differs from world root")

    async def prepare(self, target: TargetSpec, *, world_id: str | None = None) -> WorldNode:
        """Prepare and snapshot a clean root; no node escapes a failed setup."""
        raw_environment = await self._bounded(
            self._adapter.prepare(target), self._limits.prepare_seconds
        )
        environment: EnvironmentHandle | None = None
        admitted = False
        try:
            environment = self._as_handle(raw_environment)
            self._check_pin(environment.adapter)
            self.store.assert_environment_unassigned(environment)
            admitted = True
            raw_snapshot = await self._bounded(
                self._adapter.snapshot(environment), self._limits.snapshot_seconds
            )
            snapshot = self._as_snapshot(raw_snapshot)
            self._validate_snapshot(snapshot, target, environment)
            node = WorldNode(
                world_id=world_id or f"world:{uuid4().hex}",
                parent_world_id=None,
                root_snapshot_id=snapshot.root_snapshot_id,
                target=target,
                adapter=self._capabilities.pin,
                capability_manifest=self._capabilities,
                phase=WorldPhase.ACTIVE,
                state_fingerprint=snapshot.state_fingerprint,
                lineage=(),
                environment=environment,
                snapshot=snapshot,
            )
            return self.store.add(node)
        except BaseException as primary:
            if admitted and environment is not None:
                await self._cleanup_or_raise(environment, primary)
            raise

    async def snapshot(self, world_id: str) -> SnapshotManifest:
        node = self.store.get(world_id)
        if node.destroyed or node.environment is None:
            raise LifecycleError("world has no live environment")
        self._check_pin(node.adapter)
        try:
            raw_snapshot = await self._bounded(
                self._adapter.snapshot(node.environment), self._limits.snapshot_seconds
            )
            snapshot = self._as_snapshot(raw_snapshot)
            self._validate_snapshot(snapshot, node.target, node.environment, node.root_snapshot_id)
            self.store.replace(
                node.validated_copy(snapshot=snapshot, state_fingerprint=snapshot.state_fingerprint)
            )
            return snapshot
        except BaseException as primary:
            try:
                await self._cleanup(node.environment)
            except BaseException as cleanup_error:
                self.store.replace(node.validated_copy(phase=WorldPhase.BLOCKED))
                raise CleanupError(primary, cleanup_error) from primary
            self.store.replace(node.validated_copy(destroyed=True, environment=None))
            raise

    async def fork(
        self, parent_world_id: str, *, lineage_transition: str, world_id: str | None = None
    ) -> WorldNode:
        parent = self.store.get(parent_world_id)
        if parent.destroyed or parent.snapshot is None or parent.phase not in FORKABLE_PHASES:
            raise LifecycleError("parent lifecycle state cannot be forked")
        self._check_pin(parent.adapter)
        raw_environment = await self._bounded(
            self._adapter.fork(parent.snapshot), self._limits.fork_seconds
        )
        environment: EnvironmentHandle | None = None
        admitted = False
        try:
            environment = self._as_handle(raw_environment)
            self._check_pin(environment.adapter)
            self.store.assert_environment_unassigned(environment)
            admitted = True
            raw_snapshot = await self._bounded(
                self._adapter.snapshot(environment), self._limits.snapshot_seconds
            )
            snapshot = self._as_snapshot(raw_snapshot)
            self._validate_snapshot(snapshot, parent.target, environment, parent.root_snapshot_id)
            node = WorldNode(
                world_id=world_id or f"world:{uuid4().hex}",
                parent_world_id=parent.world_id,
                root_snapshot_id=parent.root_snapshot_id,
                target=parent.target,
                adapter=parent.adapter,
                capability_manifest=parent.capability_manifest,
                phase=WorldPhase.ACTIVE,
                state_fingerprint=snapshot.state_fingerprint,
                lineage=(*parent.lineage, lineage_transition),
                environment=environment,
                snapshot=snapshot,
            )
            return self.store.add(node)
        except BaseException as primary:
            if admitted and environment is not None:
                await self._cleanup_or_raise(environment, primary)
            raise

    async def restore(self, world_id: str, snapshot: SnapshotManifest) -> WorldNode:
        node = self.store.get(world_id)
        if node.destroyed or node.environment is None or node.phase is WorldPhase.PRUNED:
            raise LifecycleError("world is unavailable for restore")
        self._check_pin(node.adapter)
        self._validate_snapshot(snapshot, node.target, node.environment, node.root_snapshot_id)
        try:
            restore_result = await self._bounded(
                self._adapter.restore(node.environment, snapshot), self._limits.restore_seconds
            )
            self._require_none(restore_result)
            raw_restored = await self._bounded(
                self._adapter.snapshot(node.environment), self._limits.snapshot_seconds
            )
            restored = self._as_snapshot(raw_restored)
            self._validate_snapshot(restored, node.target, node.environment, node.root_snapshot_id)
            if restored.content_hashes != snapshot.content_hashes:
                raise LifecycleError("restore identity verification failed")
            return self.store.replace(
                node.validated_copy(snapshot=restored, state_fingerprint=restored.state_fingerprint)
            )
        except BaseException as primary:
            try:
                await self._cleanup(node.environment)
            except BaseException as cleanup_error:
                self.store.replace(node.validated_copy(phase=WorldPhase.BLOCKED))
                raise CleanupError(primary, cleanup_error) from primary
            self.store.replace(node.validated_copy(destroyed=True, environment=None))
            raise

    async def destroy(self, world_id: str) -> WorldNode:
        node = self.store.get(world_id)
        if node.destroyed:
            return node
        if node.environment is None:
            return self.store.replace(node.validated_copy(destroyed=True))
        self._check_pin(node.adapter)
        await self._cleanup(node.environment)
        return self.store.replace(node.validated_copy(destroyed=True, environment=None))

    def transition(self, world_id: str, destination: WorldPhase) -> WorldNode:
        node = self.store.get(world_id)
        if node.destroyed:
            raise LifecycleError("destroyed worlds cannot transition")
        if destination not in LEGAL_TRANSITIONS[node.phase]:
            raise LifecycleError("illegal world lifecycle transition")
        return self.store.replace(node.validated_copy(phase=destination))

    def schedulable(self, world_id: str) -> bool:
        node = self.store.get(world_id)
        return not node.destroyed and node.phase in {
            WorldPhase.GHOST,
            WorldPhase.REPLAY,
            WorldPhase.SIMULATED,
            WorldPhase.ACTIVE,
        }
