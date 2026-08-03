"""Immutable, closed-shape domain models for materialized worlds."""

from __future__ import annotations

import json
from collections.abc import Mapping
from enum import StrEnum
from hashlib import sha256
from types import MappingProxyType
from typing import Annotated, Any, ClassVar, Literal, Self, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)

NonEmpty = Annotated[str, Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9._:-]+$")]
Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
PositiveSeconds = Annotated[float, Field(gt=0, le=60)]


class FrozenModel(BaseModel):
    """Trust-boundary model: immutable, strict and closed to unknown fields."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid", frozen=True, strict=True, validate_default=True
    )

    def validated_copy(self, **changes: object) -> Self:
        """Re-run every field and model validator after an immutable update."""

        payload = {name: getattr(self, name) for name in type(self).model_fields}
        payload.update(changes)
        return type(self).model_validate(payload)

    def revalidated(self) -> Self:
        """Re-establish the trust boundary for instances returned by adapters."""

        return self.validated_copy()


def _freeze_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType(dict(value))


def _digest(value: bytes) -> str:
    return f"sha256:{sha256(value).hexdigest()}"


class CapabilityLevel(StrEnum):
    UNSUPPORTED = "unsupported"
    PARTIAL = "partial"
    SUPPORTED = "supported"


class EgressPolicy(StrEnum):
    DENY = "deny"
    ALLOWLIST = "allowlist"


class WorldPhase(StrEnum):
    PROPOSED = "PROPOSED"
    GHOST = "GHOST"
    REPLAY = "REPLAY"
    SIMULATED = "SIMULATED"
    MATERIALIZING = "MATERIALIZING"
    ACTIVE = "ACTIVE"
    BLOCKED = "BLOCKED"
    FROZEN = "FROZEN"
    FRAGMENT_EXTRACTED = "FRAGMENT_EXTRACTED"
    COMPOSITION_CANDIDATE = "COMPOSITION_CANDIDATE"
    REPLAYED = "REPLAYED"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    PRUNED = "PRUNED"


LEGAL_TRANSITIONS: Mapping[WorldPhase, frozenset[WorldPhase]] = MappingProxyType(
    {
        WorldPhase.PROPOSED: frozenset({WorldPhase.GHOST}),
        WorldPhase.GHOST: frozenset({WorldPhase.PRUNED, WorldPhase.REPLAY}),
        WorldPhase.REPLAY: frozenset({WorldPhase.PRUNED, WorldPhase.SIMULATED}),
        WorldPhase.SIMULATED: frozenset({WorldPhase.PRUNED, WorldPhase.MATERIALIZING}),
        WorldPhase.MATERIALIZING: frozenset({WorldPhase.ACTIVE, WorldPhase.BLOCKED}),
        WorldPhase.ACTIVE: frozenset({WorldPhase.FROZEN}),
        WorldPhase.FROZEN: frozenset({WorldPhase.FRAGMENT_EXTRACTED}),
        WorldPhase.FRAGMENT_EXTRACTED: frozenset({WorldPhase.COMPOSITION_CANDIDATE}),
        WorldPhase.COMPOSITION_CANDIDATE: frozenset({WorldPhase.REPLAYED}),
        WorldPhase.REPLAYED: frozenset({WorldPhase.VERIFIED, WorldPhase.REJECTED}),
        WorldPhase.BLOCKED: frozenset(),
        WorldPhase.PRUNED: frozenset(),
        WorldPhase.VERIFIED: frozenset(),
        WorldPhase.REJECTED: frozenset(),
    }
)
FORKABLE_PHASES = frozenset({WorldPhase.ACTIVE, WorldPhase.FROZEN})
M2_REQUIRED_CAPABILITIES = frozenset(
    {
        "filesystem_fork",
        "postgres_snapshot",
        "redis_snapshot",
        "queue_snapshot",
        "browser_session_fork",
        "controlled_clock",
    }
)


class AdapterPin(FrozenModel):
    adapter: NonEmpty
    version: NonEmpty


class CapabilityManifest(FrozenModel):
    pin: AdapterPin
    capabilities: Mapping[NonEmpty, CapabilityLevel]
    egress_policy: EgressPolicy = EgressPolicy.DENY

    @field_validator("capabilities")
    @classmethod
    def freeze_capabilities(
        cls, value: Mapping[str, CapabilityLevel]
    ) -> Mapping[str, CapabilityLevel]:
        if not value:
            raise ValueError("capability manifest cannot be empty")
        return cast(Mapping[str, CapabilityLevel], _freeze_mapping(dict(sorted(value.items()))))

    @field_serializer("capabilities")
    def serialize_capabilities(
        self, value: Mapping[str, CapabilityLevel]
    ) -> dict[str, CapabilityLevel]:
        return dict(sorted(value.items()))

    def supports(self, name: str) -> bool:
        return self.capabilities.get(name) is CapabilityLevel.SUPPORTED


class WorldNamespace(FrozenModel):
    network: NonEmpty
    database: NonEmpty
    cache: NonEmpty
    queue: NonEmpty
    session: NonEmpty
    storage: NonEmpty

    @model_validator(mode="after")
    def namespace_values_are_unique(self) -> WorldNamespace:
        values = (self.network, self.database, self.cache, self.queue, self.session, self.storage)
        if len(values) != len(set(values)):
            raise ValueError("world namespace components must be unique")
        return self


class ResourceQuotas(FrozenModel):
    cpu_seconds: Annotated[int, Field(ge=1, le=86_400)]
    memory_mb: Annotated[int, Field(ge=16, le=1_048_576)]
    pids: Annotated[int, Field(ge=1, le=65_536)]
    requests: Annotated[int, Field(ge=0, le=1_000_000)]
    concurrent_actions: Annotated[int, Field(ge=1, le=64)]


class EnvironmentHandle(FrozenModel):
    """Opaque adapter reference: no endpoint, path, or secret may appear here."""

    adapter: AdapterPin
    environment_id: NonEmpty
    opaque_ref: NonEmpty
    namespace: WorldNamespace
    quotas: ResourceQuotas


class TargetSpec(FrozenModel):
    target_id: NonEmpty
    target_version: NonEmpty
    secret_handles: tuple[NonEmpty, ...] = ()

    @field_validator("secret_handles")
    @classmethod
    def secret_handles_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("secret handles must be unique")
        return value


class SnapshotManifest(FrozenModel):
    schema_version: Literal["1.0"] = "1.0"
    snapshot_id: NonEmpty
    root_snapshot_id: NonEmpty
    source_environment_id: NonEmpty
    target: TargetSpec
    adapter: AdapterPin
    content_hashes: Mapping[NonEmpty, Digest]
    state_fingerprint: Digest

    @field_validator("content_hashes")
    @classmethod
    def hashes_are_complete_and_immutable(cls, value: Mapping[str, str]) -> Mapping[str, str]:
        required = {"filesystem", "database", "cache", "queue", "session", "clock"}
        if not required.issubset(value):
            raise ValueError("snapshot content hashes must cover every isolated state component")
        return cast(Mapping[str, str], _freeze_mapping(value))

    @field_serializer("content_hashes")
    def serialize_hashes(self, value: Mapping[str, str]) -> dict[str, str]:
        return dict(value)

    @staticmethod
    def derive_state_fingerprint(content_hashes: Mapping[str, str]) -> str:
        """Derive state identity from the complete, canonical component digest map."""

        payload = json.dumps(
            dict(sorted(content_hashes.items())),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
        return _digest(payload)

    @model_validator(mode="after")
    def state_fingerprint_is_content_derived(self) -> SnapshotManifest:
        if self.state_fingerprint != self.derive_state_fingerprint(self.content_hashes):
            raise ValueError("snapshot state fingerprint must derive from component hashes")
        return self

    @property
    def manifest_hash(self) -> str:
        payload = {
            "schema_version": self.schema_version,
            "snapshot_id": self.snapshot_id,
            "root_snapshot_id": self.root_snapshot_id,
            "source_environment_id": self.source_environment_id,
            "target": self.target.model_dump(mode="json"),
            "adapter": self.adapter.model_dump(mode="json"),
            "state_fingerprint": self.state_fingerprint,
            "content_hashes": dict(sorted(self.content_hashes.items())),
        }
        return _digest(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        )


class WorldNode(FrozenModel):
    world_id: NonEmpty
    parent_world_id: NonEmpty | None
    root_snapshot_id: NonEmpty
    target: TargetSpec
    adapter: AdapterPin
    capability_manifest: CapabilityManifest
    phase: WorldPhase
    state_fingerprint: Digest
    lineage: tuple[NonEmpty, ...]
    environment: EnvironmentHandle | None = None
    snapshot: SnapshotManifest | None = None
    deduplicated_to: NonEmpty | None = None
    destroyed: bool = False
    revision: Annotated[int, Field(ge=0)] = 0

    @field_validator("lineage")
    @classmethod
    def lineage_is_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("lineage transitions must be unique")
        return value

    @model_validator(mode="after")
    def coherent_live_shape(self) -> WorldNode:
        if self.destroyed and self.environment is not None:
            raise ValueError("destroyed worlds cannot retain an environment handle")
        if self.parent_world_id == self.world_id:
            raise ValueError("a world cannot be its own parent")
        if self.deduplicated_to == self.world_id:
            raise ValueError("a world cannot be deduplicated to itself")
        if (
            self.phase is WorldPhase.ACTIVE
            and not self.destroyed
            and (self.environment is None or self.snapshot is None)
        ):
            raise ValueError("active materialized worlds require a live environment and snapshot")
        if self.environment is not None and self.environment.adapter != self.adapter:
            raise ValueError("environment adapter must match world adapter pin")
        if (
            self.environment is not None
            and self.snapshot is not None
            and self.snapshot.source_environment_id != self.environment.environment_id
        ):
            raise ValueError("snapshot source environment must match the live world")
        if self.snapshot is not None and (
            self.snapshot.adapter != self.adapter
            or self.snapshot.target != self.target
            or self.snapshot.root_snapshot_id != self.root_snapshot_id
            or self.snapshot.state_fingerprint != self.state_fingerprint
        ):
            raise ValueError("snapshot pins must match the world")
        return self


class OperationLimits(FrozenModel):
    prepare_seconds: PositiveSeconds = 10.0
    snapshot_seconds: PositiveSeconds = 10.0
    fork_seconds: PositiveSeconds = 10.0
    restore_seconds: PositiveSeconds = 10.0
    destroy_seconds: PositiveSeconds = 10.0


class WorldError(RuntimeError):
    """Fail-closed lifecycle failure whose text never includes secret material."""


class LifecycleError(WorldError):
    pass


class RevisionConflict(LifecycleError):
    """A world commit was based on a stale store revision."""


class AdapterPinError(WorldError):
    pass


class CapabilityError(WorldError):
    pass


class AdapterReturnError(WorldError):
    pass


class CleanupError(WorldError):
    """Stable cleanup failure with both causal errors available to callers."""

    def __init__(self, primary_error: BaseException, cleanup_error: BaseException) -> None:
        super().__init__("cleanup failed after lifecycle operation failure")
        self.primary_error = primary_error
        self.cleanup_error = cleanup_error


class OperationTimeout(WorldError):
    pass
