"""World lineage, snapshot pinning, and canonical security-state hashing."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Annotated, cast

from pydantic import Field, JsonValue, field_serializer, field_validator, model_validator

from .base import (
    AwareTimestampMixin,
    ContractId,
    ContractModel,
    Name,
    NonNegativeInt,
    Sha256Digest,
    VersionedContract,
    freeze_json,
    sha256_digest,
    thaw_json,
)
from .enums import ClockMode, FidelityLevel, WorldStatus, WorldTier


class TargetVersionPin(ContractModel):
    target_id: ContractId
    version: Name
    image_digest: Sha256Digest


class AdapterVersionPin(ContractModel):
    adapter: Name
    version: Name


class WorldClock(AwareTimestampMixin):
    mode: ClockMode
    epoch: datetime

    @field_validator("epoch")
    @classmethod
    def epoch_is_absolute(cls, value: datetime) -> datetime:
        checked = cls.timestamp_must_have_timezone(value)
        assert checked is not None
        return checked


class WorldCapabilities(ContractModel):
    postgres_restore: bool = False
    redis_restore: bool = False
    queue_reseed: bool = False
    browser_session_fork: bool = False
    timing_control: FidelityLevel = FidelityLevel.UNKNOWN


class SnapshotReferences(ContractModel):
    filesystem: ContractId | None = None
    postgres: ContractId | None = None
    redis: ContractId | None = None
    queue: ContractId | None = None
    browser: ContractId | None = None

    def is_empty(self) -> bool:
        return all(value is None for name, value in self if name != "schema_version")


class WorldLineage(ContractModel):
    transitions: tuple[ContractId, ...] = ()

    @field_validator("transitions")
    @classmethod
    def transitions_are_unique(cls, value: tuple[ContractId, ...]) -> tuple[ContractId, ...]:
        if len(value) != len(set(value)):
            raise ValueError("world lineage transitions must be unique")
        return value


class WorldManifest(VersionedContract):
    world_id: ContractId
    parent_world_id: ContractId | None = None
    root_snapshot_id: ContractId
    tier: WorldTier
    hypothesis_id: ContractId | None = None
    state_fingerprint: Sha256Digest
    seed: NonNegativeInt
    clock: WorldClock
    capabilities: WorldCapabilities
    snapshots: SnapshotReferences
    target_version: TargetVersionPin
    adapter_versions: tuple[AdapterVersionPin, ...]
    lineage: WorldLineage
    status: WorldStatus

    @field_validator("adapter_versions")
    @classmethod
    def adapters_are_pinned_once(
        cls, value: tuple[AdapterVersionPin, ...]
    ) -> tuple[AdapterVersionPin, ...]:
        if not value:
            raise ValueError("world snapshots require at least one pinned adapter version")
        names = [pin.adapter for pin in value]
        if len(names) != len(set(names)):
            raise ValueError("adapter version pins must be unique by adapter")
        return tuple(sorted(value, key=lambda pin: pin.adapter))

    @model_validator(mode="after")
    def lifecycle_matches_tier(self) -> WorldManifest:
        if self.parent_world_id == self.world_id:
            raise ValueError("a world cannot be its own parent")
        if self.tier is not WorldTier.GHOST and self.parent_world_id is None:
            raise ValueError("replay, simulated, and materialized worlds require a parent world")
        if self.status in {WorldStatus.PROPOSED, WorldStatus.GHOST} and self.hypothesis_id is None:
            raise ValueError("proposed and ghost worlds require a hypothesis")
        allowed_statuses = {
            WorldTier.GHOST: {
                WorldStatus.PROPOSED,
                WorldStatus.GHOST,
                WorldStatus.PRUNED,
                WorldStatus.REJECTED,
            },
            WorldTier.REPLAY: {
                WorldStatus.REPLAY,
                WorldStatus.PRUNED,
                WorldStatus.REJECTED,
            },
            WorldTier.SIMULATED: {
                WorldStatus.SIMULATED,
                WorldStatus.PRUNED,
                WorldStatus.REJECTED,
            },
            WorldTier.MATERIALIZED: {
                WorldStatus.MATERIALIZING,
                WorldStatus.ACTIVE,
                WorldStatus.BLOCKED,
                WorldStatus.FROZEN,
                WorldStatus.FRAGMENT_EXTRACTED,
                WorldStatus.COMPOSITION_CANDIDATE,
                WorldStatus.REPLAYED,
                WorldStatus.VERIFIED,
                WorldStatus.REJECTED,
            },
        }
        if self.status not in allowed_statuses[self.tier]:
            raise ValueError(
                f"world status {self.status.value} is not valid for tier {self.tier.value}"
            )
        if self.tier is WorldTier.MATERIALIZED and self.snapshots.is_empty():
            raise ValueError("materialized worlds require captured snapshot references")
        return self


def validate_world_parent(child: WorldManifest, parent: WorldManifest) -> None:
    """Validate links that require both manifests, not only child-local shape.

    A standalone manifest cannot prove a parent exists or that its lineage was
    actually executed. Callers that hold the DAG must perform this explicit
    cross-node validation.
    """

    if child.parent_world_id != parent.world_id:
        raise ValueError("child parent_world_id must reference the supplied parent")
    if child.root_snapshot_id != parent.root_snapshot_id:
        raise ValueError("child and parent must share a root snapshot")
    if (
        child.hypothesis_id is not None
        and parent.hypothesis_id is not None
        and child.hypothesis_id != parent.hypothesis_id
    ):
        raise ValueError("child and parent cannot claim different hypotheses")
    parent_lineage = parent.lineage.transitions
    child_prefix = child.lineage.transitions[: len(parent_lineage)]
    if child_prefix != parent_lineage:
        raise ValueError("child lineage must extend the supplied parent lineage")


class GenerationState(ContractModel):
    ref: ContractId
    generation: NonNegativeInt


class ResourceSecurityState(ContractModel):
    resource_ref: ContractId
    owner_ref: ContractId | None = None
    visible_to: tuple[ContractId, ...] = ()

    @field_validator("visible_to")
    @classmethod
    def visibility_is_sorted_unique(cls, value: tuple[ContractId, ...]) -> tuple[ContractId, ...]:
        if len(value) != len(set(value)):
            raise ValueError("visible_to must not contain duplicates")
        return tuple(sorted(value))


class FeatureFlagState(ContractModel):
    name: Name
    enabled: bool
    variant: Name | None = None


def _sorted_unique_strings(value: tuple[str, ...]) -> tuple[str, ...]:
    if len(value) != len(set(value)):
        raise ValueError("canonical state collections must not contain duplicates")
    return tuple(sorted(value))


class CanonicalSecurityState(VersionedContract):
    """Security state plus metadata explicitly excluded from fingerprints."""

    principals: tuple[ContractId, ...] = ()
    roles: tuple[ContractId, ...] = ()
    tenants: tuple[ContractId, ...] = ()
    credentials: tuple[GenerationState, ...] = ()
    sessions: tuple[GenerationState, ...] = ()
    resources: tuple[ResourceSecurityState, ...] = ()
    policy_generations: tuple[GenerationState, ...] = ()
    cache_generations: tuple[GenerationState, ...] = ()
    pending_jobs: tuple[ContractId, ...] = ()
    feature_flags: tuple[FeatureFlagState, ...] = ()
    capabilities: tuple[Name, ...] = ()
    controlled_time_bucket: Annotated[int, Field(ge=0)]
    display_metadata: Mapping[str, JsonValue] = Field(default_factory=dict)
    audit_metadata: Mapping[str, JsonValue] = Field(default_factory=dict)

    @field_validator("display_metadata", "audit_metadata")
    @classmethod
    def metadata_is_deeply_immutable(
        cls, value: Mapping[str, JsonValue]
    ) -> Mapping[str, JsonValue]:
        return cast(Mapping[str, JsonValue], freeze_json(value))

    @field_serializer("display_metadata", "audit_metadata")
    def serialize_metadata(self, value: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
        return cast(dict[str, JsonValue], thaw_json(value))

    @field_validator("principals", "roles", "tenants", "pending_jobs", "capabilities")
    @classmethod
    def references_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _sorted_unique_strings(value)

    @field_validator("credentials", "sessions", "policy_generations", "cache_generations")
    @classmethod
    def generations_are_canonical(
        cls, value: tuple[GenerationState, ...]
    ) -> tuple[GenerationState, ...]:
        refs = [item.ref for item in value]
        if len(refs) != len(set(refs)):
            raise ValueError("generation state references must be unique")
        return tuple(sorted(value, key=lambda item: item.ref))

    @field_validator("resources")
    @classmethod
    def resources_are_canonical(
        cls, value: tuple[ResourceSecurityState, ...]
    ) -> tuple[ResourceSecurityState, ...]:
        refs = [item.resource_ref for item in value]
        if len(refs) != len(set(refs)):
            raise ValueError("resource state references must be unique")
        return tuple(sorted(value, key=lambda item: item.resource_ref))

    @field_validator("feature_flags")
    @classmethod
    def feature_flags_are_canonical(
        cls, value: tuple[FeatureFlagState, ...]
    ) -> tuple[FeatureFlagState, ...]:
        names = [item.name for item in value]
        if len(names) != len(set(names)):
            raise ValueError("feature flag names must be unique")
        return tuple(sorted(value, key=lambda item: item.name))

    def fingerprint(self) -> str:
        """Hash only the Architecture 4.4 security-semantic projection."""

        return sha256_digest(self.security_semantic_projection())

    def security_semantic_projection(self) -> dict[str, object]:
        """Return the explicit whitelist of fields relevant to security state."""

        return {
            "principals": self.principals,
            "roles": self.roles,
            "tenants": self.tenants,
            "credentials": self.credentials,
            "sessions": self.sessions,
            "resources": self.resources,
            "policy_generations": self.policy_generations,
            "cache_generations": self.cache_generations,
            "pending_jobs": self.pending_jobs,
            "feature_flags": self.feature_flags,
            "capabilities": self.capabilities,
            "controlled_time_bucket": self.controlled_time_bucket,
        }


def canonical_state_fingerprint(state: CanonicalSecurityState) -> str:
    """Public functional form used by schedulers and persistence adapters."""

    return state.fingerprint()


def security_semantic_projection(state: CanonicalSecurityState) -> dict[str, object]:
    """Public projection API for callers that need semantic, not wire, state."""

    return state.security_semantic_projection()
