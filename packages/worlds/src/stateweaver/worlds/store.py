"""In-memory DAG store with globally unique live environment identities."""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import TypeAdapter, ValidationError

from .models import (
    EnvironmentHandle,
    LifecycleError,
    NonEmpty,
    RevisionConflict,
    WorldNode,
)

_WORLD_ID_ADAPTER = TypeAdapter(NonEmpty)


def _validated_world_id(world_id: object) -> str:
    try:
        return _WORLD_ID_ADAPTER.validate_python(world_id, strict=True)
    except ValidationError as error:
        raise LifecycleError("world identifier is invalid") from error


@dataclass(frozen=True, slots=True)
class _WorldReservation:
    """Opaque authority to publish one not-yet-visible world identity."""

    world_id: str


@dataclass(slots=True)
class _PendingWorld:
    reservation: _WorldReservation
    environment: EnvironmentHandle | None = None


class _WorldStore:
    """Manager-owned storage; mutation is available only through its issued writer."""

    def __init__(self) -> None:
        self._nodes: dict[str, WorldNode] = {}
        self._fingerprints: dict[tuple[str, str, str, str, str, str], str] = {}
        self._pending_worlds: dict[str, _PendingWorld] = {}
        self.__writer_authority = object()
        self.__writer_issued = False

    def _open_manager_writer(self) -> _WorldStoreWriter:
        if self.__writer_issued:
            raise LifecycleError("world store writer was already issued")
        self.__writer_issued = True
        return _WorldStoreWriter(self, self.__writer_authority)

    def _require_writer(self, authority: object) -> None:
        if authority is not self.__writer_authority:
            raise LifecycleError("world store mutation authority is invalid")

    @staticmethod
    def _fingerprint_key(node: WorldNode) -> tuple[str, str, str, str, str, str]:
        return (
            node.root_snapshot_id,
            node.target.target_id,
            node.target.target_version,
            node.adapter.adapter,
            node.adapter.version,
            node.state_fingerprint,
        )

    def get(self, world_id: str) -> WorldNode:
        try:
            return self._nodes[world_id]
        except KeyError as error:
            raise LifecycleError("unknown world") from error

    @staticmethod
    def _namespace_values(environment: EnvironmentHandle) -> tuple[str, ...]:
        namespace = environment.namespace
        return (
            namespace.network,
            namespace.database,
            namespace.cache,
            namespace.queue,
            namespace.session,
            namespace.storage,
        )

    def _assert_unique_live_environment(
        self, node: WorldNode, *, excluding: str | None = None
    ) -> None:
        if node.destroyed or node.environment is None:
            return
        self._assert_environment_unassigned(node.environment, excluding=excluding)

    @staticmethod
    def _assert_environment_identity_disjoint(
        candidate: EnvironmentHandle, existing: EnvironmentHandle
    ) -> None:
        if candidate.environment_id == existing.environment_id:
            raise LifecycleError("environment identifier is already assigned to another world")
        if candidate.opaque_ref == existing.opaque_ref:
            raise LifecycleError(
                "opaque environment reference is already assigned to another world"
            )

    @classmethod
    def _assert_environment_namespace_disjoint(
        cls, candidate: EnvironmentHandle, existing: EnvironmentHandle
    ) -> None:
        if set(cls._namespace_values(candidate)) & set(cls._namespace_values(existing)):
            raise LifecycleError("world namespace component is already assigned to another world")

    @classmethod
    def _assert_environment_disjoint(
        cls, candidate: EnvironmentHandle, existing: EnvironmentHandle
    ) -> None:
        cls._assert_environment_identity_disjoint(candidate, existing)
        cls._assert_environment_namespace_disjoint(candidate, existing)

    def _assert_environment_unassigned(
        self, candidate: EnvironmentHandle, *, excluding: str | None = None
    ) -> None:
        for existing_id, existing in self._nodes.items():
            if existing_id == excluding or existing.destroyed or existing.environment is None:
                continue
            self._assert_environment_disjoint(candidate, existing.environment)
        for pending_id, pending in self._pending_worlds.items():
            if pending_id == excluding or pending.environment is None:
                continue
            self._assert_environment_disjoint(candidate, pending.environment)

    def _reserve_world(self, world_id: object, *, authority: object) -> _WorldReservation:
        """Atomically reserve an unpublished identity before invoking an adapter."""

        self._require_writer(authority)
        world_id = _validated_world_id(world_id)
        if world_id in self._nodes or world_id in self._pending_worlds:
            raise LifecycleError("world identifier already exists or is reserved")
        reservation = _WorldReservation(world_id=world_id)
        self._pending_worlds[world_id] = _PendingWorld(reservation=reservation)
        return reservation

    def _pending_for(self, reservation: _WorldReservation) -> _PendingWorld:
        pending = self._pending_worlds.get(reservation.world_id)
        if pending is None or pending.reservation is not reservation:
            raise LifecycleError("world reservation is no longer active")
        return pending

    def _claim_environment(
        self,
        reservation: _WorldReservation,
        environment: EnvironmentHandle,
        *,
        authority: object,
    ) -> None:
        """Claim unique adapter ownership before any cleanup authority is granted."""

        self._require_writer(authority)
        pending = self._pending_for(reservation)
        if pending.environment is not None:
            raise LifecycleError("world reservation already owns an environment")
        for existing in self._nodes.values():
            if existing.destroyed or existing.environment is None:
                continue
            self._assert_environment_identity_disjoint(environment, existing.environment)
        for pending_id, other in self._pending_worlds.items():
            if pending_id == reservation.world_id or other.environment is None:
                continue
            self._assert_environment_identity_disjoint(environment, other.environment)
        pending.environment = environment

    def _validate_reserved_namespace(
        self, reservation: _WorldReservation, *, authority: object
    ) -> None:
        """Reject namespace overlap after the candidate has safe cleanup ownership."""

        self._require_writer(authority)
        pending = self._pending_for(reservation)
        if pending.environment is None:
            raise LifecycleError("world reservation has no environment")
        candidate = pending.environment
        for existing in self._nodes.values():
            if existing.destroyed or existing.environment is None:
                continue
            self._assert_environment_namespace_disjoint(candidate, existing.environment)
        for pending_id, other in self._pending_worlds.items():
            if pending_id == reservation.world_id or other.environment is None:
                continue
            self._assert_environment_namespace_disjoint(candidate, other.environment)

    def _release_world(self, reservation: _WorldReservation, *, authority: object) -> None:
        """Release after no handle was bound or after its cleanup succeeded."""

        self._require_writer(authority)
        self._pending_for(reservation)
        del self._pending_worlds[reservation.world_id]

    def _validate_parent(self, node: WorldNode, *, require_live: bool) -> None:
        if node.parent_world_id is None:
            if node.lineage:
                raise LifecycleError("root worlds cannot claim transition lineage")
            return
        parent = self.get(node.parent_world_id)
        if (
            (require_live and parent.destroyed)
            or parent.root_snapshot_id != node.root_snapshot_id
            or parent.target != node.target
            or parent.adapter != node.adapter
            or parent.capability_manifest != node.capability_manifest
        ):
            raise LifecycleError("invalid parent lineage")
        if len(node.lineage) != len(parent.lineage) + 1 or node.lineage[:-1] != parent.lineage:
            raise LifecycleError("world lineage must extend the complete parent transition prefix")

    def _rebuild_indexes(self) -> None:
        rebuilt: dict[str, WorldNode] = {}
        fingerprints: dict[tuple[str, str, str, str, str, str], str] = {}
        for world_id, node in self._nodes.items():
            key = self._fingerprint_key(node)
            canonical = None if node.destroyed else fingerprints.get(key)
            rebuilt[world_id] = node.validated_copy(deduplicated_to=canonical)
            if not node.destroyed:
                fingerprints.setdefault(key, world_id)
        self._nodes = rebuilt
        self._fingerprints = fingerprints

    def _add(
        self,
        node: WorldNode,
        *,
        reservation: _WorldReservation,
        authority: object,
    ) -> WorldNode:
        self._require_writer(authority)
        node = node.revalidated()
        if node.world_id in self._nodes:
            raise LifecycleError("world identifier already exists")
        pending = self._pending_for(reservation)
        if reservation.world_id != node.world_id:
            raise LifecycleError("world reservation does not match the published world")
        if node.environment is None:
            if pending.environment is not None:
                raise LifecycleError("a ghost world cannot consume an environment reservation")
        else:
            if pending.environment != node.environment:
                raise LifecycleError("world reservation does not own the published environment")
        if node.revision != 0:
            raise LifecycleError("new worlds must start at revision zero")
        self._validate_parent(node, require_live=True)
        self._assert_unique_live_environment(node, excluding=node.world_id)
        self._nodes[node.world_id] = node
        self._rebuild_indexes()
        del self._pending_worlds[reservation.world_id]
        return self._nodes[node.world_id]

    def _replace(
        self,
        node: WorldNode,
        *,
        expected_revision: int | None = None,
        authority: object,
    ) -> WorldNode:
        self._require_writer(authority)
        node = node.revalidated()
        if node.world_id not in self._nodes:
            raise LifecycleError("unknown world")
        existing = self._nodes[node.world_id]
        expected_revision = node.revision if expected_revision is None else expected_revision
        if node.revision != expected_revision or existing.revision != expected_revision:
            raise RevisionConflict("world revision changed before commit")
        immutable_identity = (
            "parent_world_id",
            "root_snapshot_id",
            "target",
            "adapter",
            "capability_manifest",
            "lineage",
        )
        if any(getattr(existing, field) != getattr(node, field) for field in immutable_identity):
            raise LifecycleError("world identity and lineage are immutable")
        if existing.destroyed and not node.destroyed:
            raise LifecycleError("destroyed worlds cannot be revived")
        if existing.environment is None and node.environment is not None:
            raise LifecycleError("an existing world cannot attach an environment")
        if existing.environment is not None and node.environment is None and not node.destroyed:
            raise LifecycleError("a live world cannot release its environment")
        if (
            existing.environment is not None
            and node.environment is not None
            and existing.environment != node.environment
        ):
            raise LifecycleError("a world cannot switch environment identity")
        self._validate_parent(node, require_live=False)
        self._nodes[node.world_id] = node.validated_copy(revision=expected_revision + 1)
        self._rebuild_indexes()
        return self._nodes[node.world_id]

    def canonical_world_id(self, fingerprint: str) -> str | None:
        candidates = {
            world_id for key, world_id in self._fingerprints.items() if key[-1] == fingerprint
        }
        if len(candidates) != 1:
            return None
        world_id = next(iter(candidates))
        node = self._nodes[world_id]
        return world_id if not node.destroyed and node.state_fingerprint == fingerprint else None

    def all(self) -> tuple[WorldNode, ...]:
        return tuple(self._nodes.values())


class _WorldStoreWriter:
    """Opaque manager capability for all mutable store operations."""

    __slots__ = ("__authority", "__store")

    def __init__(self, store: _WorldStore, authority: object) -> None:
        self.__store = store
        self.__authority = authority

    def reserve_world(self, world_id: object) -> _WorldReservation:
        return self.__store._reserve_world(world_id, authority=self.__authority)

    def claim_environment(
        self, reservation: _WorldReservation, environment: EnvironmentHandle
    ) -> None:
        self.__store._claim_environment(reservation, environment, authority=self.__authority)

    def validate_reserved_namespace(self, reservation: _WorldReservation) -> None:
        self.__store._validate_reserved_namespace(reservation, authority=self.__authority)

    def release_world(self, reservation: _WorldReservation) -> None:
        self.__store._release_world(reservation, authority=self.__authority)

    def add(self, node: WorldNode, *, reservation: _WorldReservation) -> WorldNode:
        return self.__store._add(node, reservation=reservation, authority=self.__authority)

    def replace(self, node: WorldNode, *, expected_revision: int | None = None) -> WorldNode:
        return self.__store._replace(
            node, expected_revision=expected_revision, authority=self.__authority
        )


class ReadOnlyWorldStore:
    """Live query facade that deliberately exposes no lifecycle mutation methods."""

    __slots__ = ("__store",)

    def __init__(self, store: _WorldStore) -> None:
        self.__store = store

    def get(self, world_id: str) -> WorldNode:
        return self.__store.get(world_id)

    def canonical_world_id(self, fingerprint: str) -> str | None:
        return self.__store.canonical_world_id(fingerprint)

    def all(self) -> tuple[WorldNode, ...]:
        return self.__store.all()
