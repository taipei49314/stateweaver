"""Sealed, canonical checkpoints for the deterministic lab state.

The checkpoint is deliberately an in-memory provider port, not a general
serialization mechanism.  It accepts only the lab's closed JSON shape and
never carries fixture bearer values or document contents.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from threading import RLock
from typing import TYPE_CHECKING, Final, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .fixtures import CANONICAL_SEED
from .models import LabMode

if TYPE_CHECKING:
    from .state import LabState

_SCHEMA_VERSION: Final = "stateweaver-lab-checkpoint-v1"
_MAX_CHECKPOINT_BYTES: Final = 131_072
_MAX_DEPTH: Final = 16
_MAX_CONTAINER_ITEMS: Final = 256
_GENERATION_RE: Final = re.compile(r"^[0-9a-f]{64}$")
_SHA256_RE: Final = re.compile(r"^sha256:[0-9a-f]{64}$")


class CheckpointError(ValueError):
    """A checkpoint or generation failed its sealed trust boundary."""


class CheckpointConflictError(CheckpointError):
    """The active pointer changed before the caller's compare-and-swap."""


class CheckpointPoisonedError(CheckpointError):
    """A partial or inconsistent generation permanently poisoned this store."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CheckpointError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise CheckpointError(f"non-finite JSON constant is forbidden: {value}")


def _bound(value: object, depth: int = 0) -> None:
    if depth > _MAX_DEPTH:
        raise CheckpointError("checkpoint nesting exceeds fixed boundary")
    if isinstance(value, dict):
        if len(value) > _MAX_CONTAINER_ITEMS:
            raise CheckpointError("checkpoint object exceeds fixed boundary")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 128:
                raise CheckpointError("checkpoint key is invalid")
            _bound(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > _MAX_CONTAINER_ITEMS:
            raise CheckpointError("checkpoint array exceeds fixed boundary")
        for item in value:
            _bound(item, depth + 1)
    elif isinstance(value, str):
        if len(value) > 512:
            raise CheckpointError("checkpoint string exceeds fixed boundary")
    elif type(value) not in {int, bool, type(None)}:
        raise CheckpointError("checkpoint JSON type is invalid")


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise CheckpointError("checkpoint is not canonical JSON") from error


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _unsigned_payload(
    *, generation: str, mode: LabMode, state: Mapping[str, object], state_fingerprint: str
) -> dict[str, object]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "generation": generation,
        "mode": mode.value,
        "seed": CANONICAL_SEED,
        "state": dict(state),
        "state_fingerprint": state_fingerprint,
    }


def _generation_payload(
    *, mode: LabMode, state: Mapping[str, object], state_fingerprint: str
) -> dict[str, object]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "mode": mode.value,
        "seed": CANONICAL_SEED,
        "state": dict(state),
        "state_fingerprint": state_fingerprint,
    }


class LabStateCheckpoint(BaseModel):
    """A strictly parsed checkpoint of all mutable, security-relevant lab state."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)

    schema_version: Literal["stateweaver-lab-checkpoint-v1"] = _SCHEMA_VERSION
    generation: str = Field(pattern=r"^[0-9a-f]{64}$")
    mode: LabMode
    seed: Literal["m0-canonical-v1"] = CANONICAL_SEED
    state: dict[str, object]
    state_fingerprint: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    checkpoint_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _sealed(self) -> LabStateCheckpoint:
        _bound(self.state)
        payload = _unsigned_payload(
            generation=self.generation,
            mode=self.mode,
            state=self.state,
            state_fingerprint=self.state_fingerprint,
        )
        if self.checkpoint_digest != _digest(payload):
            raise ValueError("checkpoint digest does not bind its canonical payload")
        return self

    @classmethod
    def create(
        cls, *, mode: LabMode, state: Mapping[str, object], state_fingerprint: str
    ) -> LabStateCheckpoint:
        state_copy = dict(state)
        _bound(state_copy)
        generation = hashlib.sha256(
            _canonical(
                _generation_payload(
                    mode=mode,
                    state=state_copy,
                    state_fingerprint=state_fingerprint,
                )
            )
        ).hexdigest()
        payload = _unsigned_payload(
            generation=generation,
            mode=mode,
            state=state_copy,
            state_fingerprint=state_fingerprint,
        )
        return cls(
            generation=generation,
            mode=mode,
            state=state_copy,
            state_fingerprint=state_fingerprint,
            checkpoint_digest=_digest(payload),
        )

    def canonical_bytes(self) -> bytes:
        return _canonical(self.model_dump(mode="json"))

    @classmethod
    def from_canonical_bytes(cls, raw: bytes) -> LabStateCheckpoint:
        if not raw or len(raw) > _MAX_CHECKPOINT_BYTES:
            raise CheckpointError("checkpoint exceeds fixed byte boundary")
        try:
            value = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CheckpointError("checkpoint JSON is invalid") from error
        _bound(value)
        try:
            checkpoint = cls.model_validate_json(raw)
        except ValidationError as error:
            raise CheckpointError("checkpoint shape is invalid") from error
        if checkpoint.canonical_bytes() != raw:
            raise CheckpointError("checkpoint JSON must use its exact canonical bytes")
        return checkpoint


class LabStateStore(Protocol):
    """A small optimistic-concurrency port for whole LabState generations."""

    def load_active(self) -> LabStateCheckpoint: ...

    def stage(self, checkpoint: LabStateCheckpoint) -> None: ...

    def compare_and_swap(
        self, expected_generation: str | None, next_generation: str
    ) -> LabStateCheckpoint: ...


@dataclass(frozen=True)
class _StoredGeneration:
    bytes: bytes
    digest: str


class InMemoryLabStateStore:
    """A fail-closed test/provider store with atomic active-generation changes."""

    def __init__(self, initial: LabStateCheckpoint | None = None) -> None:
        self._lock = RLock()
        self._staged: dict[str, _StoredGeneration] = {}
        self._active_generation: str | None = None
        self._poisoned = False
        if initial is not None:
            self.stage(initial)
            self.compare_and_swap(None, initial.generation)

    @property
    def active_generation(self) -> str | None:
        with self._lock:
            return self._active_generation

    @property
    def poisoned(self) -> bool:
        with self._lock:
            return self._poisoned

    def stage(self, checkpoint: LabStateCheckpoint) -> None:
        with self._lock:
            self._require_healthy()
            raw = checkpoint.canonical_bytes()
            restored = LabStateCheckpoint.from_canonical_bytes(raw)
            if restored != checkpoint:
                self._poison("staged checkpoint failed identity verification")
            existing = self._staged.get(checkpoint.generation)
            stored = _StoredGeneration(raw, checkpoint.checkpoint_digest)
            if existing is not None and existing != stored:
                self._poison("generation collision has inconsistent checkpoint bytes")
            self._staged[checkpoint.generation] = stored

    def load_active(self) -> LabStateCheckpoint:
        with self._lock:
            self._require_healthy()
            generation = self._active_generation
            if generation is None:
                raise CheckpointError("active generation is absent")
            stored = self._staged.get(generation)
            if stored is None:
                self._poison("active generation is missing its sealed shard")
                raise AssertionError("unreachable")
            try:
                checkpoint = LabStateCheckpoint.from_canonical_bytes(stored.bytes)
            except CheckpointError as error:
                self._poison("active generation sealed shard is invalid")
                raise AssertionError("unreachable") from error
            if checkpoint.generation != generation or checkpoint.checkpoint_digest != stored.digest:
                self._poison("active generation does not bind its sealed shard")
            return checkpoint

    def compare_and_swap(
        self, expected_generation: str | None, next_generation: str
    ) -> LabStateCheckpoint:
        with self._lock:
            self._require_healthy()
            if not _GENERATION_RE.fullmatch(next_generation):
                raise CheckpointError("next generation is invalid")
            if self._active_generation != expected_generation:
                raise CheckpointConflictError("active generation compare-and-swap failed")
            if next_generation not in self._staged:
                self._poison("next active generation is missing its sealed shard")
            self._active_generation = next_generation
            return self.load_active()

    def commit(self, state: LabState, expected_generation: str | None) -> LabStateCheckpoint:
        checkpoint = state.export_checkpoint()
        self.stage(checkpoint)
        return self.compare_and_swap(expected_generation, checkpoint.generation)

    def restore_active(self) -> LabState:
        from .state import LabState

        return LabState.from_checkpoint(self.load_active())

    def _require_healthy(self) -> None:
        if self._poisoned:
            raise CheckpointPoisonedError("checkpoint store is poisoned")

    def _poison(self, message: str) -> None:
        self._poisoned = True
        raise CheckpointPoisonedError(message)


__all__ = [
    "CheckpointConflictError",
    "CheckpointError",
    "CheckpointPoisonedError",
    "InMemoryLabStateStore",
    "LabStateCheckpoint",
    "LabStateStore",
]
