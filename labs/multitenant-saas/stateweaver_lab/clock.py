"""A clock that advances only through typed lab actions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

CANONICAL_EPOCH = datetime(2026, 7, 29, 12, 0, 0, tzinfo=UTC)


@dataclass
class ControlledClock:
    """In-memory deterministic clock; wall time is never consulted."""

    _now: datetime

    @classmethod
    def canonical(cls) -> ControlledClock:
        return cls(_now=CANONICAL_EPOCH)

    @property
    def now(self) -> datetime:
        return self._now

    def advance(self, seconds: int) -> datetime:
        self._now += timedelta(seconds=seconds)
        return self._now


def canonical_timestamp(value: datetime) -> str:
    """Return a stable UTC representation for hashes and JSON evidence."""

    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
