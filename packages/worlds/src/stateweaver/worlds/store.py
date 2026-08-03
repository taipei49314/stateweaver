"""In-memory DAG store with globally unique live environment identities."""

from __future__ import annotations

from .models import EnvironmentHandle, LifecycleError, RevisionConflict, WorldNode


class WorldStore:
    """Store immutable nodes while deriving indexes from their current live shape."""

    def __init__(self) -> None:
        self._nodes: dict[str, WorldNode] = {}
        self._fingerprints: dict[tuple[str, str, str, str, str, str], str] = {}

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
        self.assert_environment_unassigned(node.environment, excluding=excluding)

    def assert_environment_unassigned(
        self, candidate: EnvironmentHandle, *, excluding: str | None = None
    ) -> None:
        for existing_id, existing in self._nodes.items():
            if existing_id == excluding or existing.destroyed or existing.environment is None:
                continue
            environment = existing.environment
            if candidate.environment_id == environment.environment_id:
                raise LifecycleError("environment identifier is already assigned to another world")
            if candidate.opaque_ref == environment.opaque_ref:
                raise LifecycleError(
                    "opaque environment reference is already assigned to another world"
                )
            if set(self._namespace_values(candidate)) & set(self._namespace_values(environment)):
                raise LifecycleError(
                    "world namespace component is already assigned to another world"
                )

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

    def add(self, node: WorldNode) -> WorldNode:
        node = node.revalidated()
        if node.world_id in self._nodes:
            raise LifecycleError("world identifier already exists")
        if node.revision != 0:
            raise LifecycleError("new worlds must start at revision zero")
        self._validate_parent(node, require_live=True)
        self._assert_unique_live_environment(node)
        self._nodes[node.world_id] = node
        self._rebuild_indexes()
        return self._nodes[node.world_id]

    def replace(self, node: WorldNode, *, expected_revision: int | None = None) -> WorldNode:
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
        if (
            existing.environment is not None
            and node.environment is not None
            and existing.environment != node.environment
        ):
            raise LifecycleError("a world cannot switch environment identity")
        self._validate_parent(node, require_live=False)
        self._assert_unique_live_environment(node, excluding=node.world_id)
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
