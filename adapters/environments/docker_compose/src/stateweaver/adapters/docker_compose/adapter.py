"""Local-only M2 adapters for fixed internal-network Compose projects."""

from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from threading import Lock
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
from .materialization import MaterializedCandidateRequest, MaterializedProviderReceipt
from .runner import (
    MAX_PROCESS_STREAM_BYTES,
    MAX_STATE_ARCHIVE_BYTES,
    ProcessBoundaryError,
    ProcessResult,
    ProcessRunner,
    SubprocessRunner,
    require_exact_argv,
)

ADAPTER_PIN: Final = AdapterPin(adapter="docker-compose-synthetic", version="0.1.0")
REAL_ADAPTER_PIN: Final = AdapterPin(adapter="docker-compose-real-providers", version="0.1.0")
_FIXED_TARGET_ID: Final = "synthetic-demo"
_FIXED_TARGET_VERSION: Final = "1.0.0"
_COMPOSE_FILE: Final = Path(__file__).with_name("compose.yaml")
_COMPONENTS: Final = ("filesystem", "database", "cache", "queue", "session", "clock")
_IMAGE: Final = "stateweaver-synthetic-demo:local"
_REAL_TARGET_ID: Final = "real-provider-demo"
_REAL_TARGET_VERSION: Final = "1.0.0"
_REAL_COMPOSE_FILE: Final = Path(__file__).with_name("real_compose.yaml")
_REAL_IMAGE: Final = "stateweaver-real-provider-bridge:local"
_REAL_PROVIDER_IMAGE_REFS: Final = (
    "postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193",
    "rabbitmq:4-management-alpine@sha256:44bf7eb50fe1765885659e49ccfdc775f8e531964d979321aee380a071f49f94",
    "redis:8-alpine@sha256:978f0e01593e65eed801f2402944efcd936d43b5027e4908a7897baf88ed6241",
    "selenium/standalone-chromium@sha256:81c80050126f610675e40eeac529a821dc5a0d38acf26c6d44f792a6e7ea8ac5",
)
_PROJECT_INVENTORY_OPERATIONS: Final = (
    ("ps", "--all", "{{.ID}}"),
    ("network", "ls", "{{.ID}}"),
    ("volume", "ls", "{{.Name}}"),
)
_IMAGE_ID_PATTERN: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
_CONTAINER_ID_PATTERN: Final = re.compile(r"^[0-9a-f]{12,64}$")
_STATE_BRIDGE: Final = (
    "exec",
    "--no-TTY",
    "synthetic-demo",
    "python",
    "/opt/stateweaver/state_bridge.py",
)
_REAL_STATE_BRIDGE: Final = (
    "exec",
    "--no-TTY",
    "provider-bridge",
    "python",
    "/opt/stateweaver/real_provider_bridge.py",
)
_QUOTAS: Final = ResourceQuotas(
    cpu_seconds=60, memory_mb=512, pids=64, requests=1_000, concurrent_actions=4
)
_IDENTITY_ALLOCATION_ATTEMPTS: Final = 32
_MAX_ISSUED_ENVIRONMENTS: Final = 4_096
_MAX_ISSUED_SNAPSHOTS: Final = 256
# The admitted subprocess has its own 60-second deadline plus a bounded reap.
# Give compensating cleanup enough time to reach that boundary so a failed
# create/restore cannot silently strand provider volumes or networks.
_COMPENSATING_DOWN_SECONDS: Final = 70.0


@dataclass(frozen=True, slots=True)
class _AdapterProfile:
    pin: AdapterPin
    target_id: str
    target_version: str
    compose_file: Path
    components: tuple[str, ...]
    image: str
    service: str
    state_bridge: tuple[str, ...]
    archive_schema_version: str
    capability_level: CapabilityLevel
    provider_image_refs: tuple[str, ...] = ()


_SYNTHETIC_PROFILE: Final = _AdapterProfile(
    pin=ADAPTER_PIN,
    target_id=_FIXED_TARGET_ID,
    target_version=_FIXED_TARGET_VERSION,
    compose_file=_COMPOSE_FILE,
    components=_COMPONENTS,
    image=_IMAGE,
    service="synthetic-demo",
    state_bridge=_STATE_BRIDGE,
    archive_schema_version="1.0",
    capability_level=CapabilityLevel.PARTIAL,
)
_REAL_PROFILE: Final = _AdapterProfile(
    pin=REAL_ADAPTER_PIN,
    target_id=_REAL_TARGET_ID,
    target_version=_REAL_TARGET_VERSION,
    compose_file=_REAL_COMPOSE_FILE,
    components=_COMPONENTS,
    image=_REAL_IMAGE,
    service="provider-bridge",
    state_bridge=_REAL_STATE_BRIDGE,
    archive_schema_version="2.0",
    capability_level=CapabilityLevel.SUPPORTED,
    provider_image_refs=_REAL_PROVIDER_IMAGE_REFS,
)


@dataclass(frozen=True, slots=True)
class _ImageIdentity:
    binding: str
    bridge: str


class _FixedDockerComposeEnvironmentAdapter:
    """Create per-world fixed projects without arbitrary targets, commands, or egress."""

    def __init__(
        self,
        *,
        profile: _AdapterProfile,
        runner: ProcessRunner | None = None,
    ) -> None:
        self._profile = profile
        self._runner = runner if runner is not None else SubprocessRunner()
        self._live: dict[str, _LiveWorld] = {}
        self._snapshots: dict[str, _StoredSnapshot] = {}
        self._issued_environment_ids: set[str] = set()
        self._issued_snapshot_ids: set[str] = set()
        self._registry_lock = Lock()

    def capabilities(self) -> CapabilityManifest:
        return CapabilityManifest(
            pin=self._profile.pin,
            egress_policy=EgressPolicy.DENY,
            capabilities={
                "filesystem_fork": self._profile.capability_level,
                "postgres_snapshot": self._profile.capability_level,
                "redis_snapshot": self._profile.capability_level,
                "queue_snapshot": self._profile.capability_level,
                "browser_session_fork": self._profile.capability_level,
                "controlled_clock": self._profile.capability_level,
            },
        )

    async def prepare(self, target: TargetSpec) -> EnvironmentHandle:
        self._validate_target(target)
        await self._require_docker()
        image_identity = await self._require_image()
        return await self._create_world(
            target=target,
            root_snapshot_id=None,
            image_identity=image_identity,
        )

    async def snapshot(self, env: EnvironmentHandle) -> SnapshotManifest:
        live = self._require_live(env)
        async with live.operation_lock:
            live = self._require_same_live(env, live)
            snapshot_id = self._allocate_snapshot_id()
            await self._health(
                live.project,
                expected_image_identity=live.image_identity,
            )
            archive, hashes = await self._export_state(live)
            manifest = SnapshotManifest(
                snapshot_id=snapshot_id,
                root_snapshot_id=live.root_snapshot_id,
                source_environment_id=live.handle.environment_id,
                target=live.target,
                adapter=self._profile.pin,
                content_hashes=hashes,
                state_fingerprint=SnapshotManifest.derive_state_fingerprint(hashes),
            )
            self._store_snapshot(
                _StoredSnapshot(
                    manifest=manifest,
                    archive=archive,
                    image_identity=live.image_identity,
                )
            )
            return manifest

    async def fork(self, snapshot: SnapshotManifest) -> EnvironmentHandle:
        stored = self._require_stored_snapshot(snapshot)
        await self._require_docker()
        image_identity = await self._require_image()
        if image_identity != stored.image_identity:
            raise ComposeAdapterError("fixed Compose image identity changed after snapshot")
        env = await self._create_world(
            target=stored.manifest.target,
            root_snapshot_id=stored.manifest.root_snapshot_id,
            image_identity=image_identity,
        )
        live = self._require_live(env)
        try:
            await self._import_state(live, stored)
        except BaseException:
            self._discard_live(live)
            await self._compensating_down(live.project)
            raise
        return env

    async def restore(self, env: EnvironmentHandle, snapshot: SnapshotManifest) -> None:
        live = self._require_live(env)
        async with live.operation_lock:
            live = self._require_same_live(env, live)
            stored = self._require_stored_snapshot(snapshot)
            if stored.manifest.target != live.target:
                raise ComposeAdapterError("snapshot is not owned by this adapter")
            if stored.manifest.root_snapshot_id != live.root_snapshot_id:
                raise ComposeAdapterError("snapshot root lineage differs from environment")
            if stored.manifest.source_environment_id != live.handle.environment_id:
                raise ComposeAdapterError("snapshot source environment differs from environment")
            if (
                stored.image_identity != live.image_identity
                or await self._require_image() != live.image_identity
            ):
                raise ComposeAdapterError("fixed Compose image identity changed after snapshot")
            try:
                await self._compose(live.project, "down", "--volumes", "--remove-orphans")
                await self._compose(live.project, "up", "--detach", "--wait", "--no-build")
                await self._health(
                    live.project,
                    expected_image_identity=live.image_identity,
                )
                await self._import_state(live, stored)
            except BaseException:
                await self._compensating_down(live.project)
                raise

    async def destroy(self, env: EnvironmentHandle) -> None:
        if not isinstance(env, EnvironmentHandle) or env.adapter != self._profile.pin:
            raise ComposeAdapterError("environment handle is invalid")
        with self._registry_lock:
            live = self._live.get(env.environment_id)
        if live is None:
            return
        if live.handle != env:
            raise ComposeAdapterError("environment is not owned by this adapter")
        async with live.operation_lock:
            with self._registry_lock:
                current = self._live.get(env.environment_id)
            if current is None:
                return
            if current is not live or current.handle != env:
                raise ComposeAdapterError("environment is not owned by this adapter")
            await self._compose(live.project, "down", "--volumes", "--remove-orphans")
            if self._profile is _REAL_PROFILE:
                await self._assert_project_clean(live.project)
            if not self._discard_live(live):
                raise ComposeAdapterError("environment ownership changed during destroy")

    async def _materialize_observed_candidate(
        self,
        env: EnvironmentHandle,
        request: MaterializedCandidateRequest,
    ) -> MaterializedProviderReceipt:
        if self._profile is not _REAL_PROFILE:
            raise ComposeAdapterError("M4 materialization requires the fixed real-provider profile")
        try:
            closed_request = MaterializedCandidateRequest.model_validate(
                request.model_dump(mode="python")
            )
        except (AttributeError, TypeError, ValueError):
            raise ComposeAdapterError("materialization request is invalid") from None
        live = self._require_live(env)
        async with live.operation_lock:
            live = self._require_same_live(env, live)
            await self._health(live.project, expected_image_identity=live.image_identity)
            before_archive, before = await self._export_state(live)
            _require_materialized_archive(before_archive, marker="baseline", tick=0)
            payload = json.dumps(
                {"marker": closed_request.marker, "tick": closed_request.tick},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            started_ns = time.perf_counter_ns()
            result = await self._compose(
                live.project,
                *self._profile.state_bridge,
                "mutate",
                stdin=payload,
            )
            elapsed_ns = time.perf_counter_ns() - started_ns
            try:
                acknowledgement = json.loads(
                    result.stdout,
                    object_pairs_hook=_unique_object,
                    parse_constant=_reject_json_constant,
                )
            except (json.JSONDecodeError, ValueError):
                raise ComposeAdapterError("fixed candidate mutation response is invalid") from None
            if acknowledgement != {"accepted": True, "schema_version": "2.0"}:
                raise ComposeAdapterError("fixed candidate mutation was not acknowledged")
            await self._health(live.project, expected_image_identity=live.image_identity)
            after_archive, after = await self._export_state(live)
            _require_materialized_archive(
                after_archive,
                marker=closed_request.marker,
                tick=closed_request.tick,
            )
            try:
                return MaterializedProviderReceipt.create(
                    request=closed_request,
                    environment_id=live.handle.environment_id,
                    before=before,
                    after=after,
                    elapsed_ns=elapsed_ns,
                )
            except ValueError:
                raise ComposeAdapterError("materialized provider oracle failed") from None

    async def _create_world(
        self,
        *,
        target: TargetSpec,
        root_snapshot_id: str | None,
        image_identity: _ImageIdentity,
    ) -> EnvironmentHandle:
        project, environment_id = self._allocate_environment_identity()
        namespace = WorldNamespace(
            network=f"network:{project}",
            database=f"database:{project}",
            cache=f"cache:{project}",
            queue=f"queue:{project}",
            session=f"session:{project}",
            storage=f"storage:{project}",
        )
        handle = EnvironmentHandle(
            adapter=self._profile.pin,
            environment_id=environment_id,
            opaque_ref=f"compose:{project}",
            namespace=namespace,
            quotas=_QUOTAS,
        )
        live = _LiveWorld(
            project=project,
            target=target,
            root_snapshot_id=root_snapshot_id or f"root:{environment_id}",
            handle=handle,
            image_identity=image_identity,
        )
        try:
            await self._compose(project, "up", "--detach", "--wait", "--no-build")
            await self._health(project, expected_image_identity=image_identity)
            self._register_live(live)
        except BaseException:
            await self._compensating_down(project)
            raise
        return handle

    async def _require_docker(self) -> None:
        await self._run(("docker", "version", "--format", "{{.Server.Version}}"))

    async def _require_image(self) -> _ImageIdentity:
        result = await self._run(
            ("docker", "image", "inspect", "--format", "{{.Id}}", self._profile.image)
        )
        bridge_image_id = result.stdout.strip()
        if not _IMAGE_ID_PATTERN.fullmatch(bridge_image_id):
            raise ComposeAdapterError("fixed Compose image identity is invalid")
        if not self._profile.provider_image_refs:
            return _ImageIdentity(binding=bridge_image_id, bridge=bridge_image_id)
        binding = _hash(
            {
                "bridge_image_id": bridge_image_id,
                "provider_image_refs": self._profile.provider_image_refs,
            }
        )
        return _ImageIdentity(binding=binding, bridge=bridge_image_id)

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
                str(self._profile.compose_file),
                *operation,
            ),
            stdin=stdin,
        )

    async def _health(
        self,
        project: str,
        *,
        expected_image_identity: _ImageIdentity,
    ) -> None:
        operation = ["ps", "--format", "json"]
        if self._profile is _REAL_PROFILE:
            operation.append(self._profile.service)
        result = await self._run(
            (
                "docker",
                "compose",
                "--project-name",
                project,
                "--file",
                str(self._profile.compose_file),
                *operation,
            )
        )
        try:
            payload = json.loads(
                result.stdout,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_json_constant,
            )
        except (json.JSONDecodeError, ValueError) as error:
            raise ComposeAdapterError("fixed Compose health response is invalid") from error
        # Compose v2 serializes `ps --format json` as an array while Compose v5
        # serializes a single matching service as one object. Normalize only those
        # two closed shapes; multiple or non-object rows remain fail closed.
        rows = [payload] if isinstance(payload, dict) else payload
        if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
            raise ComposeAdapterError("fixed Compose health check failed")
        row = rows[0]
        container_id = row.get("ID")
        fixed_checks = (
            (row.get("Service") == self._profile.service, "service"),
            (row.get("Image") == self._profile.image, "image"),
            (row.get("Project") == project, "project"),
            (
                isinstance(container_id, str)
                and _CONTAINER_ID_PATTERN.fullmatch(container_id) is not None,
                "container-id",
            ),
            (str(row.get("State", "")).lower() == "running", "state"),
            (str(row.get("Health", "")).lower() == "healthy", "health"),
        )
        for accepted, check_name in fixed_checks:
            if not accepted:
                raise ComposeAdapterError(f"fixed Compose health check failed: {check_name}")
        assert isinstance(container_id, str)
        image = await self._run(("docker", "inspect", "--format", "{{.Image}}", container_id))
        if image.stdout.strip() != expected_image_identity.bridge:
            raise ComposeAdapterError("running container image identity is invalid")

    async def _export_state(self, live: _LiveWorld) -> tuple[bytes, dict[str, str]]:
        result = await self._compose(live.project, *self._profile.state_bridge, "export")
        return _decode_archive(
            result.stdout,
            image_id=live.image_identity.binding,
            profile=self._profile,
        )

    async def _import_state(self, live: _LiveWorld, stored: _StoredSnapshot) -> None:
        archive, hashes = _decode_archive(
            stored.archive.decode("utf-8"),
            image_id=stored.image_identity.binding,
            profile=self._profile,
        )
        if archive != stored.archive or hashes != dict(stored.manifest.content_hashes):
            raise ComposeAdapterError("retained snapshot archive no longer matches its manifest")
        result = await self._compose(
            live.project,
            *self._profile.state_bridge,
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
        if acknowledgement != {
            "accepted": True,
            "schema_version": self._profile.archive_schema_version,
        }:
            raise ComposeAdapterError("fixed state import was not acknowledged")
        restored_archive, restored_hashes = await self._export_state(live)
        if restored_archive != stored.archive or restored_hashes != dict(
            stored.manifest.content_hashes
        ):
            raise ComposeAdapterError("state import identity verification failed")

    def _require_stored_snapshot(self, snapshot: SnapshotManifest) -> _StoredSnapshot:
        self._validate_snapshot(snapshot)
        with self._registry_lock:
            stored = self._snapshots.get(snapshot.snapshot_id)
        if stored is None or stored.manifest != snapshot:
            raise ComposeAdapterError("snapshot is not owned by this adapter")
        archive, hashes = _decode_archive(
            stored.archive.decode("utf-8"),
            image_id=stored.image_identity.binding,
            profile=self._profile,
        )
        if archive != stored.archive or hashes != dict(stored.manifest.content_hashes):
            raise ComposeAdapterError("retained snapshot archive no longer matches its manifest")
        return stored

    async def _compensating_down(self, project: str) -> None:
        # The original lifecycle failure remains the authoritative boundary. A later explicit
        # destroy remains possible for registered environments; failed creates never escape.
        async def cleanup() -> None:
            await self._compose(project, "down", "--volumes", "--remove-orphans")
            if self._profile is _REAL_PROFILE:
                await self._assert_project_clean(project)

        with suppress(BaseException):
            await asyncio.wait_for(
                cleanup(),
                timeout=_COMPENSATING_DOWN_SECONDS,
            )

    async def _assert_project_clean(self, project: str) -> None:
        label = f"label=com.docker.compose.project={project}"
        for resource, operation, output_format in _PROJECT_INVENTORY_OPERATIONS:
            result = await self._run(
                (
                    "docker",
                    resource,
                    operation,
                    "--filter",
                    label,
                    "--format",
                    output_format,
                )
            )
            if result.stdout.strip():
                raise ComposeAdapterError("fixed Compose cleanup inventory is not empty")

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
        except ProcessBoundaryError as error:
            if error.code == "process-deadline-exceeded":
                raise ComposeUnavailableError(
                    "local Docker Compose command exceeded its fixed deadline"
                ) from None
            raise ComposeAdapterError(
                "local Docker Compose process exceeded its fixed output boundary"
            ) from None
        if (
            not isinstance(result, ProcessResult)
            or not isinstance(result.returncode, int)
            or isinstance(result.returncode, bool)
            or not isinstance(result.stdout, str)
            or not isinstance(result.stderr, str)
        ):
            raise ComposeAdapterError("process runner returned an invalid result")
        if (
            len(result.stdout.encode("utf-8")) > MAX_PROCESS_STREAM_BYTES
            or len(result.stderr.encode("utf-8")) > MAX_PROCESS_STREAM_BYTES
        ):
            raise ComposeAdapterError("process output exceeds the fixed archive boundary")
        if result.returncode != 0:
            raise ComposeUnavailableError("local Docker Compose command failed")
        return result

    def _validate_target(self, target: TargetSpec) -> None:
        if (
            not isinstance(target, TargetSpec)
            or target.target_id != self._profile.target_id
            or target.target_version != self._profile.target_version
            or target.secret_handles
        ):
            target_name = (
                "fixed synthetic demo"
                if self._profile is _SYNTHETIC_PROFILE
                else "fixed real-provider demo"
            )
            raise ComposeAdapterError(f"only the {target_name} target is supported")

    def _require_live(self, env: EnvironmentHandle) -> _LiveWorld:
        if not isinstance(env, EnvironmentHandle) or env.adapter != self._profile.pin:
            raise ComposeAdapterError("environment handle is invalid")
        with self._registry_lock:
            live = self._live.get(env.environment_id)
        if live is None or live.handle != env:
            raise ComposeAdapterError("environment is not owned by this adapter")
        return live

    def _require_same_live(
        self,
        env: EnvironmentHandle,
        expected: _LiveWorld,
    ) -> _LiveWorld:
        live = self._require_live(env)
        if live is not expected:
            raise ComposeAdapterError("environment ownership changed while waiting")
        return live

    def _allocate_environment_identity(self) -> tuple[str, str]:
        for _ in range(_IDENTITY_ALLOCATION_ATTEMPTS):
            token = uuid.uuid4().hex
            if not re.fullmatch(r"[0-9a-f]{32}", token):
                continue
            environment_id = f"environment:{token}"
            with self._registry_lock:
                if len(self._issued_environment_ids) >= _MAX_ISSUED_ENVIRONMENTS:
                    raise ComposeAdapterError("environment identity capacity is exhausted")
                if environment_id in self._issued_environment_ids:
                    continue
                self._issued_environment_ids.add(environment_id)
            return f"swm2{token}", environment_id
        raise ComposeAdapterError("unable to allocate a unique environment identity")

    def _allocate_snapshot_id(self) -> str:
        for _ in range(_IDENTITY_ALLOCATION_ATTEMPTS):
            token = uuid.uuid4().hex
            if not re.fullmatch(r"[0-9a-f]{32}", token):
                continue
            snapshot_id = f"snapshot:{token}"
            with self._registry_lock:
                if len(self._issued_snapshot_ids) >= _MAX_ISSUED_SNAPSHOTS:
                    raise ComposeAdapterError("snapshot retention capacity is exhausted")
                if snapshot_id in self._issued_snapshot_ids:
                    continue
                self._issued_snapshot_ids.add(snapshot_id)
            return snapshot_id
        raise ComposeAdapterError("unable to allocate a unique snapshot identity")

    def _register_live(self, live: _LiveWorld) -> None:
        environment_id = live.handle.environment_id
        with self._registry_lock:
            if environment_id in self._live:
                raise ComposeAdapterError("environment identity is already registered")
            self._live[environment_id] = live

    def _discard_live(self, live: _LiveWorld) -> bool:
        environment_id = live.handle.environment_id
        with self._registry_lock:
            if self._live.get(environment_id) is not live:
                return False
            self._live.pop(environment_id)
            return True

    def _store_snapshot(self, stored: _StoredSnapshot) -> None:
        snapshot_id = stored.manifest.snapshot_id
        with self._registry_lock:
            if snapshot_id in self._snapshots:
                raise ComposeAdapterError("snapshot identity is already registered")
            self._snapshots[snapshot_id] = stored

    def _validate_snapshot(self, snapshot: SnapshotManifest) -> None:
        if not isinstance(snapshot, SnapshotManifest) or snapshot.adapter != self._profile.pin:
            raise ComposeAdapterError("snapshot is invalid")
        try:
            snapshot.revalidated()
        except ValueError as error:
            raise ComposeAdapterError("snapshot is invalid") from error


class DockerComposeEnvironmentAdapter(_FixedDockerComposeEnvironmentAdapter):
    """Fixed synthetic archive adapter retained for compatibility and diagnostics."""

    def __init__(self, *, runner: ProcessRunner | None = None) -> None:
        super().__init__(profile=_SYNTHETIC_PROFILE, runner=runner)


class RealDockerComposeEnvironmentAdapter(_FixedDockerComposeEnvironmentAdapter):
    """Fixed six-provider adapter for materialized M2 qualification worlds."""

    def __init__(self, *, runner: ProcessRunner | None = None) -> None:
        super().__init__(profile=_REAL_PROFILE, runner=runner)

    async def materialize_observed_candidate(
        self,
        env: EnvironmentHandle,
        request: MaterializedCandidateRequest,
    ) -> MaterializedProviderReceipt:
        """Apply one fixed request and atomically attest six provider changes."""

        return await self._materialize_observed_candidate(env, request)


@dataclass(frozen=True)
class _LiveWorld:
    project: str
    target: TargetSpec
    root_snapshot_id: str
    handle: EnvironmentHandle
    image_identity: _ImageIdentity
    operation_lock: asyncio.Lock = field(default_factory=asyncio.Lock, compare=False, repr=False)


@dataclass(frozen=True)
class _StoredSnapshot:
    manifest: SnapshotManifest
    archive: bytes
    image_identity: _ImageIdentity


def _decode_archive(
    raw: str,
    *,
    image_id: str,
    profile: _AdapterProfile = _SYNTHETIC_PROFILE,
) -> tuple[bytes, dict[str, str]]:
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
    if payload["schema_version"] != profile.archive_schema_version or payload["target"] != {
        "target_id": profile.target_id,
        "target_version": profile.target_version,
    }:
        raise ComposeAdapterError("fixed state archive target binding is invalid")
    components = payload["components"]
    if not isinstance(components, dict) or set(components) != set(profile.components):
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
        for component in profile.components
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


def _require_materialized_archive(archive: bytes, *, marker: str, tick: int) -> None:
    """Require the exact six-provider semantic state promised by an M4 mutation."""

    try:
        document = json.loads(
            archive,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ComposeAdapterError("materialized provider oracle failed") from None
    expected_clock = (
        (datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=tick))
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )
    expected = {
        "cache": {"entries": {"sw:marker": marker}},
        "clock": {"iso8601": expected_clock, "tick": tick},
        "database": {"rows": [{"id": 1, "tenant": "alpha", "value": marker}]},
        "filesystem": {"files": {"marker.txt": marker, "tenant.txt": "alpha"}},
        "queue": {"messages": [marker]},
        "session": {
            "cookies": [{"name": "sw_marker", "path": "/", "value": marker}],
            "local_storage": {"sw.marker": marker},
        },
    }
    if not isinstance(document, dict) or document.get("components") != expected:
        raise ComposeAdapterError("materialized provider oracle failed")
