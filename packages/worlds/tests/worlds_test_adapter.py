"""Uniquely named deterministic adapter used only by the worlds test suite."""

from __future__ import annotations

import asyncio
import copy
import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Literal

from stateweaver.worlds import (
    AdapterPin,
    CapabilityLevel,
    CapabilityManifest,
    EgressPolicy,
    EnvironmentHandle,
    ResourceQuotas,
    SnapshotManifest,
    TargetSpec,
    WorldNamespace,
)

Component = Literal["database", "cache", "queue", "session", "clock"]


def _hash(value: object) -> str:
    serialized = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return f"sha256:{sha256(serialized.encode()).hexdigest()}"


@dataclass
class _State:
    target: TargetSpec
    root_snapshot_id: str
    markers: dict[str, str]


class InMemoryConformanceAdapter:
    """No-network reference adapter; its state never leaves Python memory."""

    def __init__(self) -> None:
        self.pin = AdapterPin(adapter="in-memory-conformance", version="1.0.0")
        self._states: dict[str, _State] = {}
        self._snapshots: dict[str, _State] = {}
        self.destroyed: set[str] = set()
        self.fail_next_snapshot = False
        self.sleep_snapshot = False
        self.snapshot_cancelled = False
        self.return_wrong_prepare = False
        self.return_wrong_fork = False
        self.return_wrong_snapshot = False
        self.snapshot_source_mismatch = False
        self.snapshot_version_mismatch = False
        self.snapshot_fingerprint_mismatch = False
        self.reuse_parent_on_fork = False
        self.fail_destroy = False
        self.return_wrong_restore = False
        self._counter = 0
        self.synthetic_secret_values = {"secret:synthetic": "synthetic-secret-value"}

    def capabilities(self) -> CapabilityManifest:
        return CapabilityManifest(
            pin=self.pin,
            egress_policy=EgressPolicy.DENY,
            capabilities={
                "filesystem_fork": CapabilityLevel.SUPPORTED,
                "postgres_snapshot": CapabilityLevel.SUPPORTED,
                "redis_snapshot": CapabilityLevel.SUPPORTED,
                "queue_snapshot": CapabilityLevel.SUPPORTED,
                "browser_session_fork": CapabilityLevel.SUPPORTED,
                "controlled_clock": CapabilityLevel.SUPPORTED,
            },
        )

    def _handle(self, environment_id: str) -> EnvironmentHandle:
        return EnvironmentHandle(
            adapter=self.pin,
            environment_id=environment_id,
            opaque_ref=f"opaque:{environment_id}",
            namespace=WorldNamespace(
                network=f"network:{environment_id}",
                database=f"database:{environment_id}",
                cache=f"cache:{environment_id}",
                queue=f"queue:{environment_id}",
                session=f"session:{environment_id}",
                storage=f"storage:{environment_id}",
            ),
            quotas=ResourceQuotas(
                cpu_seconds=30, memory_mb=128, pids=32, requests=100, concurrent_actions=2
            ),
        )

    async def prepare(self, target: TargetSpec) -> EnvironmentHandle:
        if self.return_wrong_prepare:
            return object()  # type: ignore[return-value]
        self._counter += 1
        env_id = f"env:{self._counter}"
        root = f"root:{env_id}"
        self._states[env_id] = _State(
            target, root, dict.fromkeys(("database", "cache", "queue", "session", "clock"), "root")
        )
        return self._handle(env_id)

    async def snapshot(self, env: EnvironmentHandle) -> SnapshotManifest:
        if self.sleep_snapshot:
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                self.snapshot_cancelled = True
                raise
        if self.fail_next_snapshot:
            self.fail_next_snapshot = False
            raise RuntimeError("synthetic snapshot failure")
        if self.return_wrong_snapshot:
            return object()  # type: ignore[return-value]
        state = self._live(env)
        self._counter += 1
        snapshot_id = f"snap:{self._counter}"
        copied = copy.deepcopy(state)
        self._snapshots[snapshot_id] = copied
        hashes = {"filesystem": _hash("immutable-image")}
        hashes.update({name: _hash(value) for name, value in state.markers.items()})
        manifest = SnapshotManifest(
            snapshot_id=snapshot_id,
            root_snapshot_id=state.root_snapshot_id,
            source_environment_id=env.environment_id,
            target=state.target,
            adapter=self.pin,
            content_hashes=hashes,
            state_fingerprint=SnapshotManifest.derive_state_fingerprint(hashes),
        )
        if self.snapshot_source_mismatch:
            return manifest.model_copy(update={"source_environment_id": "env:wrong"})
        if self.snapshot_version_mismatch:
            return manifest.model_copy(
                update={"adapter": AdapterPin(adapter=self.pin.adapter, version="9.9.9")}
            )
        if self.snapshot_fingerprint_mismatch:
            return manifest.model_copy(update={"state_fingerprint": "sha256:" + "0" * 64})
        return manifest

    async def fork(self, snapshot: SnapshotManifest) -> EnvironmentHandle:
        if self.return_wrong_fork:
            return object()  # type: ignore[return-value]
        if self.reuse_parent_on_fork:
            return self._handle(snapshot.source_environment_id)
        source = self._snapshots[snapshot.snapshot_id]
        self._counter += 1
        env_id = f"env:{self._counter}"
        self._states[env_id] = copy.deepcopy(source)
        return self._handle(env_id)

    async def restore(self, env: EnvironmentHandle, snapshot: SnapshotManifest) -> None:
        self._states[env.environment_id] = copy.deepcopy(self._snapshots[snapshot.snapshot_id])
        if self.return_wrong_restore:
            return object()  # type: ignore[return-value]

    async def destroy(self, env: EnvironmentHandle) -> None:
        if self.fail_destroy:
            raise RuntimeError("synthetic destroy failure")
        self.destroyed.add(env.environment_id)
        self._states.pop(env.environment_id, None)

    def mutate(self, env: EnvironmentHandle, component: Component, marker: str) -> None:
        self._live(env).markers[component] = marker

    def marker(self, env: EnvironmentHandle, component: Component) -> str:
        return self._live(env).markers[component]

    def _live(self, env: EnvironmentHandle) -> _State:
        if env.environment_id in self.destroyed:
            raise RuntimeError("destroyed environment")
        return self._states[env.environment_id]
