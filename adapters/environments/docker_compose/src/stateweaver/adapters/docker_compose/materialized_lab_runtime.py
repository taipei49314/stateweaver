"""Fixed-argv Docker boundary for the M5 FastAPI application witness.

This module is intentionally only an execution *scaffold*.  It retains the
application-side bytes needed to prove a future M5 run, but reports an
unqualified result until the lab has atomically checkpointed all six providers.
It accepts neither a command, URL, filesystem path, nor a caller-selected
Compose project.
"""

from __future__ import annotations

import json
import re
import sys
import uuid
from collections.abc import Sequence
from hashlib import sha256
from pathlib import Path
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from stateweaver.contracts import (
    ActionEnvelope,
    HttpRequestAction,
    canonical_json_bytes,
    sha256_digest,
)

from .errors import ComposeAdapterError
from .runner import ProcessBoundaryError, ProcessResult, ProcessRunner

_COMPOSE_FILE: Final = Path(__file__).with_name("real_compose.yaml")
_APPLICATION_IMAGE: Final = "stateweaver-materialized-lab:local"
_BRIDGE_IMAGE: Final = "stateweaver-real-provider-bridge:local"
_PROVIDER_IMAGE_REFS: Final = (
    "postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193",
    "rabbitmq:4-management-alpine@sha256:44bf7eb50fe1765885659e49ccfdc775f8e531964d979321aee380a071f49f94",
    "redis:8-alpine@sha256:978f0e01593e65eed801f2402944efcd936d43b5027e4908a7897baf88ed6241",
    "selenium/standalone-chromium@sha256:81c80050126f610675e40eeac529a821dc5a0d38acf26c6d44f792a6e7ea8ac5",
)
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_PROJECT = re.compile(r"^swm2[0-9a-f]{32}$")
_MAX_WITNESS_BYTES: Final = 1_048_576
_RUNTIME_PREFIX: Final = (
    "exec",
    "--no-TTY",
    "materialized-lab",
    "python",
    "-m",
    "stateweaver.adapters.docker_compose.materialized_lab_runtime",
    "execute",
)


class _RuntimeModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class MaterializedLabRunRequest(_RuntimeModel):
    """Closed application replay input; all executable facts are typed bytes."""

    repository_marker: str = Field(pattern=r"^[0-9a-f]{40}$")
    mode: Literal["vulnerable", "patched"]
    plan_id: str = Field(pattern=r"^plan\.m5\.[a-z0-9.-]+$")
    root_seed_id: str = Field(pattern=r"^root\.m5\.[a-z0-9.-]+$")
    root_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    plan_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    actions: tuple[ActionEnvelope, ...] = Field(min_length=1, max_length=8)
    action_bytes: tuple[bytes, ...] = Field(min_length=1, max_length=8)
    policy_authorization_bytes: tuple[bytes, ...] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def _closed_bytes(self) -> MaterializedLabRunRequest:
        if len(self.actions) != len(self.action_bytes) or len(self.actions) != len(
            self.policy_authorization_bytes
        ):
            raise ValueError("M5 application request byte cardinality is invalid")
        if len({item.action_id for item in self.actions}) != len(self.actions):
            raise ValueError("M5 application actions must be unique")
        for action, exact in zip(self.actions, self.action_bytes, strict=True):
            typed = action.action
            if (
                not isinstance(typed, HttpRequestAction)
                or typed.target is None
                or typed.method is None
                or typed.target.scheme != "http"
                or typed.target.host != "localhost"
                or typed.target.port != 80
                or typed.query
                or typed.headers
                or typed.body_artifact is None
                or not typed.body_artifact.startswith("artifact:lab-action/")
                or exact != canonical_json_bytes(action)
            ):
                raise ValueError("M5 application action is not an exact admitted HTTP envelope")
        for value in self.policy_authorization_bytes:
            if not value or len(value) > _MAX_WITNESS_BYTES or _canonical_json(value) != value:
                raise ValueError("M5 application policy bytes are not canonical")
        return self


class ApplicationImageBinding(_RuntimeModel):
    application_image_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    bridge_image_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    provider_image_set_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    binding_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _bound(self) -> ApplicationImageBinding:
        expected = _digest(self.model_dump(mode="json", exclude={"binding_digest"}))
        if self.binding_digest != expected:
            raise ValueError("M5 application image binding digest is invalid")
        return self


class ApplicationRouteTrace(_RuntimeModel):
    action_id: str
    action_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    method: Literal["GET", "POST"]
    path: str = Field(pattern=r"^/v1/lab/(?:[a-z0-9-]+/?)+$")
    response_status: int = Field(ge=100, le=599)
    trace_id: str = Field(pattern=r"^trace-[a-z0-9-]{8,128}$")


class MaterializedLabRunReceipt(_RuntimeModel):
    """A fail-closed application witness, never an SW-M5 admission."""

    schema_version: Literal["stateweaver-m5-materialized-application-run-v1"]
    status: Literal["M5_MATERIALIZED_APPLICATION_UNQUALIFIED"]
    request: MaterializedLabRunRequest
    request_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    image_binding: ApplicationImageBinding
    execution_backend: Literal["fastapi-asgi"]
    provider_checkpoint_status: Literal["UNAVAILABLE", "PARTIAL"]
    route_traces: tuple[ApplicationRouteTrace, ...]
    cleanup_status: Literal["PASS"]
    destroyed: Literal[True]
    limitations: tuple[Literal["PROVIDER_CHECKPOINT_NOT_ATOMIC"], ...]
    receipt_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _closed(self) -> MaterializedLabRunReceipt:
        if (
            self.request_digest != _digest(self.request)
            or len(self.route_traces) != len(self.request.actions)
            or tuple(item.action_id for item in self.route_traces)
            != tuple(item.action_id for item in self.request.actions)
            or tuple(item.action_digest for item in self.route_traces)
            != tuple(sha256_digest(item) for item in self.request.actions)
            or not self.limitations
        ):
            raise ValueError("M5 application receipt is not content bound")
        expected = _digest(self.model_dump(mode="json", exclude={"receipt_digest"}))
        if self.receipt_digest != expected:
            raise ValueError("M5 application receipt digest is invalid")
        return self


class MaterializedLabDockerRuntime:
    """One isolated compose project per application witness, always torn down."""

    def __init__(self, *, runner: ProcessRunner) -> None:
        self._runner = runner

    async def run(self, request: MaterializedLabRunRequest) -> MaterializedLabRunReceipt:
        try:
            closed = MaterializedLabRunRequest.model_validate(request.model_dump(mode="python"))
        except (AttributeError, TypeError, ValueError):
            raise ComposeAdapterError("M5 application runtime request is invalid") from None
        project = "swm2" + uuid.uuid4().hex
        result: MaterializedLabRunReceipt | None = None
        cleanup_error: BaseException | None = None
        try:
            binding = await self._image_binding()
            await self._run(_compose(project, "up", "--detach", "--wait", "--no-build"))
            process = await self._run(
                _compose(project, *_RUNTIME_PREFIX),
                stdin=_runtime_payload(closed, binding),
            )
            result = _parse_runtime_result(process, closed, binding)
        except (ProcessBoundaryError, ValueError, json.JSONDecodeError, TypeError):
            raise ComposeAdapterError("M5 application runtime failed closed") from None
        finally:
            try:
                await self._run(_compose(project, "down", "--volumes", "--remove-orphans"))
            except BaseException as error:
                cleanup_error = error
        if cleanup_error is not None:
            raise ComposeAdapterError("M5 application runtime cleanup failed") from cleanup_error
        if result is None:
            raise ComposeAdapterError("M5 application runtime produced no receipt")
        return result

    async def _image_binding(self) -> ApplicationImageBinding:
        application = (
            await self._run(
                ("docker", "image", "inspect", "--format", "{{.Id}}", _APPLICATION_IMAGE)
            )
        ).stdout.strip()
        bridge = (
            await self._run(("docker", "image", "inspect", "--format", "{{.Id}}", _BRIDGE_IMAGE))
        ).stdout.strip()
        if _IMAGE_ID.fullmatch(application) is None or _IMAGE_ID.fullmatch(bridge) is None:
            raise ComposeAdapterError("M5 application image identity is invalid")
        # Provider image provenance is fixed in the checked-in Compose manifest;
        # this digest is deliberately supplied by the application boundary later.
        provider_set = sha256_digest(_PROVIDER_IMAGE_REFS)
        values: dict[str, object] = {
            "application_image_id": application,
            "bridge_image_id": bridge,
            "provider_image_set_digest": provider_set,
        }
        return ApplicationImageBinding.model_validate({**values, "binding_digest": _digest(values)})

    async def _run(self, argv: tuple[str, ...], *, stdin: bytes | None = None) -> ProcessResult:
        result = await self._runner.run(argv, stdin=stdin)
        if result.returncode != 0:
            raise ComposeAdapterError("fixed M5 application Docker command failed")
        return result


def _compose(project: str, *operation: str) -> tuple[str, ...]:
    if _PROJECT.fullmatch(project) is None:
        raise ValueError("M5 application Compose project is invalid")
    return (
        "docker",
        "compose",
        "--project-name",
        project,
        "--file",
        str(_COMPOSE_FILE),
        *operation,
    )


def _runtime_payload(request: MaterializedLabRunRequest, binding: ApplicationImageBinding) -> bytes:
    return canonical_json_bytes(
        {
            "schema_version": "stateweaver-m5-materialized-application-input-v1",
            "request": request.model_dump(mode="json"),
            "image_binding": binding.model_dump(mode="json"),
        }
    )


def _parse_runtime_result(
    result: ProcessResult,
    request: MaterializedLabRunRequest,
    binding: ApplicationImageBinding,
) -> MaterializedLabRunReceipt:
    raw = result.stdout.encode("utf-8")
    if not raw or len(raw) > _MAX_WITNESS_BYTES:
        raise ComposeAdapterError("M5 application runtime output is invalid")
    payload = json.loads(raw, object_pairs_hook=_unique_object)
    if not isinstance(payload, dict):
        raise ComposeAdapterError("M5 application runtime output is invalid")
    # The container must prove it used the admitted app boundary.  A provider-only
    # bridge, static response, or missing route trace has no representable shape.
    values = {
        "schema_version": "stateweaver-m5-materialized-application-run-v1",
        "status": "M5_MATERIALIZED_APPLICATION_UNQUALIFIED",
        "request": request,
        "request_digest": _digest(request),
        "image_binding": binding,
        "execution_backend": payload.get("execution_backend"),
        "provider_checkpoint_status": payload.get("provider_checkpoint_status"),
        "route_traces": tuple(payload.get("route_traces", ())),
        "cleanup_status": "PASS",
        "destroyed": True,
        "limitations": ("PROVIDER_CHECKPOINT_NOT_ATOMIC",),
    }
    return MaterializedLabRunReceipt.model_validate({**values, "receipt_digest": _digest(values)})


def _unique_object(items: Sequence[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _canonical_json(value: bytes) -> bytes:
    try:
        decoded = json.loads(value, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return b""
    return canonical_json_bytes(decoded)


def _digest(value: object) -> str:
    """Digest typed receipts including exact byte fields deterministically."""

    return "sha256:" + sha256(canonical_json_bytes(_json_compatible(value))).hexdigest()


def _json_compatible(value: object) -> object:
    if isinstance(value, BaseModel):
        return _json_compatible(value.model_dump(mode="python"))
    if isinstance(value, bytes):
        return value.decode("utf-8")
    if isinstance(value, tuple):
        return [_json_compatible(item) for item in value]
    if isinstance(value, list):
        return [_json_compatible(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    return value


def _container_main(argv: Sequence[str]) -> int:
    """Container-only fixed entrypoint.

    Until the lab's checkpoint API is available in the built image this returns
    no route witness.  The host parser rejects that shape, which is deliberate:
    an application container that cannot atomically bind provider persistence is
    not evidence.  ``serve``/``health`` do import and instantiate the actual
    FastAPI app, so the image cannot silently be replaced by a static service.
    """

    if len(argv) != 2 or argv[1] not in {"serve", "health", "execute"}:
        return 64
    try:
        sys.path.insert(0, "/opt/stateweaver/contracts")
        sys.path.insert(0, "/opt/stateweaver/lab")
        from stateweaver_lab import InMemoryLabStateStore, create_app

        app = create_app("vulnerable")
        if not getattr(app, "routes", None):
            return 70
        # This proves the actual FastAPI application's canonical state can move
        # through its sealed CAS port.  The adapter does not call this a provider
        # checkpoint: no real provider bridge has accepted the generation yet.
        store = InMemoryLabStateStore(app.state.lab.export_checkpoint())
        if store.load_active().generation != app.state.lab.export_checkpoint().generation:
            return 70
    except Exception:
        return 70
    if argv[1] == "health":
        return 0
    if argv[1] == "serve":
        # Compose needs a fixed, inert process for health checks.  It exposes no
        # socket and accepts no runtime command; execution is docker-exec only.
        import time

        while True:
            time.sleep(60)
    try:
        raw = sys.stdin.buffer.read(_MAX_WITNESS_BYTES + 1)
        if not raw or len(raw) > _MAX_WITNESS_BYTES:
            return 65
        payload = json.loads(raw, object_pairs_hook=_unique_object)
        if (
            not isinstance(payload, dict)
            or payload.get("schema_version") != "stateweaver-m5-materialized-application-input-v1"
        ):
            return 65
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return 65
    # This explicit, trace-less result is fail-closed until LabStateStore can
    # load/stage/compare-and-swap a real six-provider checkpoint.
    sys.stdout.write(
        json.dumps(
            {
                "execution_backend": "fastapi-asgi",
                "provider_checkpoint_status": "PARTIAL",
                "route_traces": [],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


__all__ = [
    "ApplicationImageBinding",
    "ApplicationRouteTrace",
    "MaterializedLabDockerRuntime",
    "MaterializedLabRunReceipt",
    "MaterializedLabRunRequest",
]


if __name__ == "__main__":  # pragma: no cover - Docker entrypoint only.
    raise SystemExit(_container_main(sys.argv))
