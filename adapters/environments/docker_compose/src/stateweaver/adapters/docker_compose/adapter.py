"""Local-only M2 adapter for one fixed internal-network synthetic Compose project."""

from __future__ import annotations

import asyncio
import json
import uuid
from hashlib import sha256
from pathlib import Path
from typing import Final

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

from .errors import ComposeAdapterError, ComposeUnavailableError
from .runner import ProcessResult, ProcessRunner, SubprocessRunner, require_exact_argv

ADAPTER_PIN: Final = AdapterPin(adapter="docker-compose-synthetic", version="0.1.0")
_FIXED_TARGET_ID: Final = "synthetic-demo"
_FIXED_TARGET_VERSION: Final = "1.0.0"
_COMPOSE_FILE: Final = Path(__file__).with_name("compose.yaml")
_COMPONENTS: Final = ("filesystem", "database", "cache", "queue", "session", "clock")
_QUOTAS: Final = ResourceQuotas(
    cpu_seconds=60, memory_mb=512, pids=64, requests=1_000, concurrent_actions=4
)


class DockerComposeEnvironmentAdapter:
    """Create per-world fixed-demo projects without arbitrary targets, commands, or egress."""

    def __init__(self, *, runner: ProcessRunner | None = None) -> None:
        self._runner = runner if runner is not None else SubprocessRunner()
        self._live: dict[str, _LiveWorld] = {}
        self._snapshots: dict[str, SnapshotManifest] = {}
        self._lock = asyncio.Lock()

    def capabilities(self) -> CapabilityManifest:
        return CapabilityManifest(
            pin=ADAPTER_PIN,
            egress_policy=EgressPolicy.DENY,
            capabilities={
                "filesystem_fork": CapabilityLevel.PARTIAL,
                "postgres_snapshot": CapabilityLevel.PARTIAL,
                "redis_snapshot": CapabilityLevel.PARTIAL,
                "queue_snapshot": CapabilityLevel.PARTIAL,
                "browser_session_fork": CapabilityLevel.PARTIAL,
                "controlled_clock": CapabilityLevel.PARTIAL,
            },
        )

    async def prepare(self, target: TargetSpec) -> EnvironmentHandle:
        self._validate_target(target)
        async with self._lock:
            await self._require_docker()
            return await self._create_world(target=target, root_snapshot_id=None)

    async def snapshot(self, env: EnvironmentHandle) -> SnapshotManifest:
        async with self._lock:
            live = self._require_live(env)
            health = await self._health(live.project)
            hashes = {
                component: _hash(
                    {
                        "target": live.target.model_dump(mode="json"),
                        "component": component,
                        "health": health,
                    }
                )
                for component in _COMPONENTS
            }
            manifest = SnapshotManifest(
                snapshot_id=f"snapshot:{uuid.uuid4().hex}",
                root_snapshot_id=live.root_snapshot_id,
                source_environment_id=env.environment_id,
                target=live.target,
                adapter=ADAPTER_PIN,
                content_hashes=hashes,
                state_fingerprint=SnapshotManifest.derive_state_fingerprint(hashes),
            )
            self._snapshots[manifest.snapshot_id] = manifest
            return manifest

    async def fork(self, snapshot: SnapshotManifest) -> EnvironmentHandle:
        self._validate_snapshot(snapshot)
        async with self._lock:
            if snapshot.snapshot_id not in self._snapshots:
                raise ComposeAdapterError("snapshot is not owned by this adapter")
            await self._require_docker()
            return await self._create_world(
                target=snapshot.target, root_snapshot_id=snapshot.root_snapshot_id
            )

    async def restore(self, env: EnvironmentHandle, snapshot: SnapshotManifest) -> None:
        self._validate_snapshot(snapshot)
        async with self._lock:
            live = self._require_live(env)
            if snapshot.snapshot_id not in self._snapshots or snapshot.target != live.target:
                raise ComposeAdapterError("snapshot is not owned by this adapter")
            await self._compose(live.project, "down", "--volumes", "--remove-orphans")
            await self._compose(live.project, "up", "--detach", "--wait", "--no-build")
            await self._health(live.project)

    async def destroy(self, env: EnvironmentHandle) -> None:
        if not isinstance(env, EnvironmentHandle) or env.adapter != ADAPTER_PIN:
            raise ComposeAdapterError("environment handle is invalid")
        async with self._lock:
            live = self._live.pop(env.environment_id, None)
            if live is None:
                return
            try:
                await self._compose(live.project, "down", "--volumes", "--remove-orphans")
            except ComposeAdapterError:
                self._live[env.environment_id] = live
                raise

    async def _create_world(
        self, *, target: TargetSpec, root_snapshot_id: str | None
    ) -> EnvironmentHandle:
        token = uuid.uuid4().hex
        project = f"swm2{token}"
        environment_id = f"environment:{token}"
        namespace = WorldNamespace(
            network=f"network:{project}",
            database=f"database:{project}",
            cache=f"cache:{project}",
            queue=f"queue:{project}",
            session=f"session:{project}",
            storage=f"storage:{project}",
        )
        handle = EnvironmentHandle(
            adapter=ADAPTER_PIN,
            environment_id=environment_id,
            opaque_ref=f"compose:{project}",
            namespace=namespace,
            quotas=_QUOTAS,
        )
        await self._compose(project, "up", "--detach", "--wait", "--no-build")
        try:
            await self._health(project)
        except BaseException:
            try:
                await self._compose(project, "down", "--volumes", "--remove-orphans")
            finally:
                raise
        self._live[environment_id] = _LiveWorld(
            project=project,
            target=target,
            root_snapshot_id=root_snapshot_id or f"root:{environment_id}",
            handle=handle,
        )
        return handle

    async def _require_docker(self) -> None:
        await self._run(("docker", "version", "--format", "{{.Server.Version}}"))

    async def _compose(self, project: str, *operation: str) -> None:
        await self._run(
            (
                "docker",
                "compose",
                "--project-name",
                project,
                "--file",
                str(_COMPOSE_FILE),
                *operation,
            )
        )

    async def _health(self, project: str) -> str:
        result = await self._run(
            (
                "docker",
                "compose",
                "--project-name",
                project,
                "--file",
                str(_COMPOSE_FILE),
                "ps",
                "--format",
                "json",
            )
        )
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise ComposeAdapterError(
                "fixed synthetic compose health response is invalid"
            ) from error
        rows = payload if isinstance(payload, list) else [payload]
        if not rows or any(
            not isinstance(row, dict) or str(row.get("State", "")).lower() != "running"
            for row in rows
        ):
            raise ComposeAdapterError("fixed synthetic compose health check failed")
        normalized = tuple(
            {
                "service": str(row.get("Service", "synthetic-demo")),
                "state": str(row["State"]).lower(),
            }
            for row in rows
        )
        return _hash(normalized)

    async def _run(self, argv: tuple[str, ...]) -> ProcessResult:
        try:
            result = await self._runner.run(require_exact_argv(argv))
        except FileNotFoundError as error:
            raise ComposeUnavailableError("docker executable is unavailable") from error
        if (
            not isinstance(result, ProcessResult)
            or not isinstance(result.returncode, int)
            or isinstance(result.returncode, bool)
            or not isinstance(result.stdout, str)
            or not isinstance(result.stderr, str)
        ):
            raise ComposeAdapterError("process runner returned an invalid result")
        if result.returncode != 0:
            raise ComposeUnavailableError("local Docker Compose command failed")
        return result

    @staticmethod
    def _validate_target(target: TargetSpec) -> None:
        if (
            not isinstance(target, TargetSpec)
            or target.target_id != _FIXED_TARGET_ID
            or target.target_version != _FIXED_TARGET_VERSION
            or target.secret_handles
        ):
            raise ComposeAdapterError("only the fixed synthetic demo target is supported")

    def _require_live(self, env: EnvironmentHandle) -> _LiveWorld:
        if not isinstance(env, EnvironmentHandle) or env.adapter != ADAPTER_PIN:
            raise ComposeAdapterError("environment handle is invalid")
        live = self._live.get(env.environment_id)
        if live is None or live.handle != env:
            raise ComposeAdapterError("environment is not owned by this adapter")
        return live

    @staticmethod
    def _validate_snapshot(snapshot: SnapshotManifest) -> None:
        if not isinstance(snapshot, SnapshotManifest) or snapshot.adapter != ADAPTER_PIN:
            raise ComposeAdapterError("snapshot is invalid")


class _LiveWorld:
    def __init__(
        self, *, project: str, target: TargetSpec, root_snapshot_id: str, handle: EnvironmentHandle
    ) -> None:
        self.project = project
        self.target = target
        self.root_snapshot_id = root_snapshot_id
        self.handle = handle


def _hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    return f"sha256:{sha256(encoded).hexdigest()}"
