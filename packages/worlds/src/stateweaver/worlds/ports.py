"""Ports implemented by concrete environment adapters, never imported by the core."""

from __future__ import annotations

from typing import Protocol

from .models import CapabilityManifest, EnvironmentHandle, SnapshotManifest, TargetSpec


class EnvironmentAdapter(Protocol):
    def capabilities(self) -> CapabilityManifest: ...

    async def prepare(self, target: TargetSpec) -> EnvironmentHandle: ...

    async def snapshot(self, env: EnvironmentHandle) -> SnapshotManifest: ...

    async def fork(self, snapshot: SnapshotManifest) -> EnvironmentHandle: ...

    async def restore(self, env: EnvironmentHandle, snapshot: SnapshotManifest) -> None: ...

    async def destroy(self, env: EnvironmentHandle) -> None:
        """Idempotently release a per-world environment."""
        ...
