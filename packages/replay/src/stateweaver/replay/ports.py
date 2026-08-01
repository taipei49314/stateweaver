"""Ports consumed by the deterministic replay kernel."""

from __future__ import annotations

from typing import Protocol

from stateweaver.contracts import ActionEnvelope, OracleResult
from stateweaver.replay.models import ReplayObservation, RootSeed, StateCapture


class ReplayEnvironment(Protocol):
    """Bounded environment adapter; implementations must be safe to reset repeatedly."""

    async def reset(self, root: RootSeed) -> StateCapture:
        """Restore the clean root and return the state actually restored."""
        ...

    async def capture(self) -> StateCapture:
        """Capture normalized DB/cache/queue/browser/application state."""
        ...

    async def execute(self, action: ActionEnvelope) -> tuple[ReplayObservation, ...]:
        """Execute one already-authorized typed action."""
        ...

    async def cleanup(self) -> None:
        """Release all per-run resources; must be idempotent."""
        ...


class ReplayOracle(Protocol):
    id: str
    version: str

    async def evaluate(
        self,
        before: StateCapture,
        action: ActionEnvelope,
        after: StateCapture,
        observations: tuple[ReplayObservation, ...],
    ) -> OracleResult:
        """Return a deterministic machine verdict for one transition."""
        ...
