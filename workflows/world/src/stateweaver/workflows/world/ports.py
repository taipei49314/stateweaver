"""Pure typed ports; implementations must be supplied by the caller."""

from __future__ import annotations

from typing import Protocol

from .models import AllocatedWorld, AllocationRequest, CaptureReceipt


class WorldAllocator(Protocol):
    async def allocate(self, request: AllocationRequest) -> AllocatedWorld: ...

    async def release(self, allocation: AllocatedWorld) -> None: ...


class WorldCapture(Protocol):
    async def capture(
        self, request: AllocationRequest, allocation: AllocatedWorld
    ) -> CaptureReceipt: ...
