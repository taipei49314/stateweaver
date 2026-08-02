"""Local-only M2 adapter for one fixed internal-network synthetic Compose project."""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from contextlib import suppress
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Final, cast

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
from .runner import (
    MAX_STATE_ARCHIVE_BYTES,
    ProcessResult,
    ProcessRunner,
    SubprocessRunner,
    require_exact_argv,
)

ADAPTER_PIN: Final = AdapterPin(adapter="docker-compose-synthetic", version="0.1.0")
_FIXED_TARGET_ID: Final = "synthetic-demo"
_FIXED_TARGET_VERSION: Final = "1.0.0"
_COMPOSE_FILE: Final = Path(__file__).with_name("compose.yaml")
_COMPONENTS: Final = ("filesystem", "database", "cache", "queue", "session", "clock")
_IMAGE: Final = "stateweaver-synthetic-demo:local"
_IMAGE_ID_PATTERN: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
_CONTAINER_ID_PATTERN: Final = re.compile(r"^[0-9a-f]{12,64}$")
_STATE_BRIDGE: Final = (
    "exec",
    "--no-TTY",
    "synthetic-demo",
    "python",
    "/opt/stateweaver/state_bridge.py",
)
_QUOTAS: Final = ResourceQuotas(
    cpu_seconds=60, memory_mb=512, pids=64, requests=1_000, concurrent_actions=4
)


class DockerComposeEnvironmentAdapter:
    """Create per-world fixed-demo projects without arbitrary targets, commands, or egress."""

    def __init__(self, *, runner: ProcessRunner | None = None) -> None:
        self._runner = runner if runner is not None else SubprocessRunner()
        self._live: dict[str, _LiveWorld] = {}
        self._snapshots: dict[str, _StoredSnapshot] = {}
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
            image_id = await self._require_image()
            return await self._create_world(
                target=target,
                root_snapshot_id=None,
                image_id=image_id,
            )

    async def snapshot(self, env: EnvironmentHandle) -> SnapshotManifest:
        async with self._lock:
            live = self._require_live(env)
            await self._health(live.project, expected_image_id=live.image_id)
            archive, hashes = await self._export_state(live)
            manifest = SnapshotManifest(
                snapshot_id=f"snapshot:{uuid.uuid4().hex}",
                root_snapshot_id=live.root_snapshot_id,
                source_environment_id=env.environment_id,
                target=live.target,
                adapter=ADAPTER_PIN,
                content_hashes=hashes,
                state_fingerprint=SnapshotManifest.derive_state_fingerprint(hashes),
            )
            self._snapshots[manifest.snapshot_id] = _StoredSnapshot(
                manifest=manifest,
                archive=archive,
                image_id=live.image_id,
            )
            return manifest

    async def fork(self, snapshot: SnapshotManifest) -> EnvironmentHandle:
        async with self._lock:
            stored = self._require_stored_snapshot(snapshot)
            await self._require_docker()
            image_id = await self._require_image()
            if image_id != stored.image_id:
                raise ComposeAdapterError("fixed synthetic image identity changed after snapshot")
            env = await self._create_world(
                target=stored.manifest.target,
                root_snapshot_id=stored.manifest.root_snapshot_id,
                image_id=image_id,
            )
            live = self._require_live(env)
            try:
                await self._import_state(live, stored)
            except BaseException:
                self._live.pop(env.environment_id, None)
                await self._compensating_down(live.project)
                raise
            return env

    async def restore(self, env: EnvironmentHandle, snapshot: SnapshotManifest) -> None:
        async with self._lock:
            live = self._require_live(env)
            stored = self._require_stored_snapshot(snapshot)
            if stored.manifest.target != live.target:
                raise ComposeAdapterError("snapshot is not owned by this adapter")
            if stored.manifest.root_snapshot_id != live.root_snapshot_id:
                raise ComposeAdapterError("snapshot root lineage differs from environment")
            if stored.image_id != live.image_id or await self._require_image() != live.image_id:
                raise ComposeAdapterError("fixed synthetic image identity changed after snapshot")
            await self._compose(live.project, "down", "--volumes", "--remove-orphans")
            try:
                await self._compose(live.project, "up", "--detach", "--wait", "--no-build")
                await self._health(live.project, expected_image_id=live.image_id)
                await self._import_state(live, stored)
            except BaseException:
                await self._compensating_down(live.project)
                raise

    async def destroy(self, env: EnvironmentHandle) -> None:
        if not isinstance(env, EnvironmentHandle) or env.adapter != ADAPTER_PIN:
            raise ComposeAdapterError("environment handle is invalid")
        async with self._lock:
            live = self._live.get(env.environment_id)
            if live is None:
                return
            if live.handle != env:
                raise ComposeAdapterError("environment is not owned by this adapter")
            try:
                await self._compose(live.project, "down", "--volumes", "--remove-orphans")
            except BaseException:
                raise
            self._live.pop(env.environment_id, None)

    async def _create_world(
        self,
        *,
        target: TargetSpec,
        root_snapshot_id: str | None,
        image_id: str,
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
        try:
            await self._compose(project, "up", "--detach", "--wait", "--no-build")
            await self._health(project, expected_image_id=image_id)
        except BaseException:
            await self._compensating_down(project)
            raise
        self._live[environment_id] = _LiveWorld(
            project=project,
            target=target,
            root_snapshot_id=root_snapshot_id or f"root:{environment_id}",
            handle=handle,
            image_id=image_id,
        )
        return handle

    async def _require_docker(self) -> None:
        await self._run(("docker", "version", "--format", "{{.Server.Version}}"))

    async def _require_image(self) -> str:
        result = await self._run(("docker", "image", "inspect", "--format", "{{.Id}}", _IMAGE))
        image_id = result.stdout.strip()
        if not _IMAGE_ID_PATTERN.fullmatch(image_id):
            raise ComposeAdapterError("fixed synthetic image identity is invalid")
        return image_id

    async def _compose(
        self,
        project: str,
        *operation: str,
        stdin: bytes | None = None,
    ) -> ProcessResult:
        return await self._run(
            (
                "docker",
                "compose",
                "--project-name",
                project,
                "--file",
                str(_COMPOSE_FILE),
                *operation,
            ),
            stdin=stdin,
        )

    async def _health(self, project: str, *, expected_image_id: str) -> None:
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
            payload = json.loads(
                result.stdout,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_json_constant,
            )
        except (json.JSONDecodeError, ValueError) as error:
            raise ComposeAdapterError(
                "fixed synthetic compose health response is invalid"
            ) from error
        if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
            raise ComposeAdapterError("fixed synthetic compose health check failed")
        row = payload[0]
        container_id = row.get("ID")
        if (
            row.get("Service") != "synthetic-demo"
            or row.get("Image") != _IMAGE
            or row.get("Project") != project
            or not isinstance(container_id, str)
            or not _CONTAINER_ID_PATTERN.fullmatch(container_id)
            or str(row.get("State", "")).lower() != "running"
            or str(row.get("Health", "")).lower() != "healthy"
        ):
            raise ComposeAdapterError("fixed synthetic compose health check failed")
        image = await self._run(("docker", "inspect", "--format", "{{.Image}}", container_id))
        if image.stdout.strip() != expected_image_id:
            raise ComposeAdapterError("running container image identity is invalid")

    async def _export_state(self, live: _LiveWorld) -> tuple[bytes, dict[str, str]]:
        result = await self._compose(live.project, *_STATE_BRIDGE, "export")
        return _decode_archive(result.stdout, image_id=live.image_id)

    async def _import_state(self, live: _LiveWorld, stored: _StoredSnapshot) -> None:
        archive, hashes = _decode_archive(
            stored.archive.decode("utf-8"),
            image_id=stored.image_id,
        )
        if archive != stored.archive or hashes != dict(stored.manifest.content_hashes):
            raise ComposeAdapterError("retained snapshot archive no longer matches its manifest")
        result = await self._compose(
            live.project,
            *_STATE_BRIDGE,
            "import",
            stdin=stored.archive,
        )
        try:
            acknowledgement = json.loads(
                result.stdout,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_json_constant,
            )
        except (json.JSONDecodeError, ValueError) as error:
            raise ComposeAdapterError("fixed state import response is invalid") from error
        if acknowledgement != {"accepted": True, "schema_version": "1.0"}:
            raise ComposeAdapterError("fixed state import was not acknowledged")
        restored_archive, restored_hashes = await self._export_state(live)
        if restored_archive != stored.archive or restored_hashes != dict(
            stored.manifest.content_hashes
        ):
            raise ComposeAdapterError("state import identity verification failed")

    def _require_stored_snapshot(self, snapshot: SnapshotManifest) -> _StoredSnapshot:
        self._validate_snapshot(snapshot)
        stored = self._snapshots.get(snapshot.snapshot_id)
        if stored is None or stored.manifest != snapshot:
            raise ComposeAdapterError("snapshot is not owned by this adapter")
        archive, hashes = _decode_archive(
            stored.archive.decode("utf-8"),
            image_id=stored.image_id,
        )
        if archive != stored.archive or hashes != dict(stored.manifest.content_hashes):
            raise ComposeAdapterError("retained snapshot archive no longer matches its manifest")
        return stored

    async def _compensating_down(self, project: str) -> None:
        # The original lifecycle failure remains the authoritative boundary. A later explicit
        # destroy remains possible for registered environments; failed creates never escape.
        with suppress(BaseException):
            await self._compose(project, "down", "--volumes", "--remove-orphans")

    async def _run(
        self,
        argv: tuple[str, ...],
        *,
        stdin: bytes | None = None,
    ) -> ProcessResult:
        try:
            result = await self._runner.run(require_exact_argv(argv), stdin=stdin)
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
        if len(result.stdout.encode("utf-8")) > MAX_STATE_ARCHIVE_BYTES:
            raise ComposeAdapterError("process output exceeds the fixed archive boundary")
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
        try:
            snapshot.revalidated()
        except ValueError as error:
            raise ComposeAdapterError("snapshot is invalid") from error


@dataclass(frozen=True)
class _LiveWorld:
    project: str
    target: TargetSpec
    root_snapshot_id: str
    handle: EnvironmentHandle
    image_id: str


@dataclass(frozen=True)
class _StoredSnapshot:
    manifest: SnapshotManifest
    archive: bytes
    image_id: str


def _decode_archive(raw: str, *, image_id: str) -> tuple[bytes, dict[str, str]]:
    encoded = raw.encode("utf-8")
    if not encoded or len(encoded) > MAX_STATE_ARCHIVE_BYTES:
        raise ComposeAdapterError("fixed state archive exceeds its size boundary")
    try:
        payload = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, ValueError) as error:
        raise ComposeAdapterError("fixed state archive is invalid") from error
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "target",
        "components",
    }:
        raise ComposeAdapterError("fixed state archive has an invalid shape")
    if payload["schema_version"] != "1.0" or payload["target"] != {
        "target_id": _FIXED_TARGET_ID,
        "target_version": _FIXED_TARGET_VERSION,
    }:
        raise ComposeAdapterError("fixed state archive target binding is invalid")
    components = payload["components"]
    if not isinstance(components, dict) or set(components) != set(_COMPONENTS):
        raise ComposeAdapterError("fixed state archive component coverage is invalid")
    if any(not isinstance(value, dict) for value in components.values()):
        raise ComposeAdapterError("fixed state archive components must be JSON objects")
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(canonical) > MAX_STATE_ARCHIVE_BYTES:
        raise ComposeAdapterError("fixed state archive exceeds its size boundary")
    typed_components = cast(dict[str, object], components)
    hashes = {
        component: _hash(
            {
                "component": component,
                "image_id": image_id,
                "state": typed_components[component],
            }
        )
        for component in _COMPONENTS
    }
    return canonical, hashes


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object key")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON constant is forbidden: {value}")


def _hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    return f"sha256:{sha256(encoded).hexdigest()}"
