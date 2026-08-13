"""Closed Docker boundary for actual-ASGI execution over six retained providers.

The application container owns one clean checkpoint lineage.  Every generation is
stored as six immutable, exact-byte shards and becomes visible only through the
PostgreSQL compare-and-swap pointer.  This is atomic *visibility*, not a claim of
distributed transactions across the six providers.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
import time
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
from stateweaver.policy import (
    PolicyAuthorization,
    PolicyAuthorizationDeniedError,
    PolicyRequest,
    evaluate_policy,
    verify_policy_authorization,
)
from stateweaver_lab import LabStateCheckpoint, TypedLabAction, create_app
from stateweaver_lab.asgi import (
    LabAsgiExecutionError,
    execute_lab_action_asgi,
    lab_action_artifact,
    resolve_lab_http_action,
    seal_lab_asgi_app,
)
from stateweaver_lab.models import EvidenceRecordResponse, OracleResultResponse
from stateweaver_lab.state import LabState

from .errors import ComposeAdapterError
from .real_provider_bridge import (
    ProviderCheckpointCapture,
    ProviderCheckpointError,
    RealProviderLabStateStore,
)
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
_PROVIDERS: Final = ("postgres", "redis", "rabbitmq", "selenium", "filesystem", "clock")


class _RuntimeModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)


class MaterializedLabRunRequest(_RuntimeModel):
    """Exact admitted inputs for one clean scenario."""

    repository_marker: str = Field(pattern=r"^[0-9a-f]{40}$")
    mode: Literal["vulnerable", "patched"]
    scenario: Literal[
        "primary_vulnerable",
        "primary_patched",
        "masked_response",
        "mock_only_response",
        "fresh_session",
        "same_tenant_document",
    ]
    plan_id: str = Field(pattern=r"^plan\.m5\.[a-z0-9.-]+$")
    root_seed_id: str = Field(pattern=r"^root\.m5\.[a-z0-9.-]+$")
    root_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    plan_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    m4_state_binding_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    m4_source_snapshot_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    m4_after_archive_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    m4_provider_state_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    actions: tuple[ActionEnvelope, ...] = Field(min_length=1, max_length=8)
    action_bytes: tuple[bytes, ...] = Field(min_length=1, max_length=8)
    lab_actions: tuple[TypedLabAction, ...] = Field(min_length=1, max_length=8)
    lab_action_bytes: tuple[bytes, ...] = Field(min_length=1, max_length=8)
    policy_authorizations: tuple[PolicyAuthorization, ...] = Field(min_length=1, max_length=8)
    policy_authorization_bytes: tuple[bytes, ...] = Field(min_length=1, max_length=8)
    policy_requests: tuple[PolicyRequest, ...] = Field(min_length=1, max_length=8)
    policy_request_bytes: tuple[bytes, ...] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def _closed_bytes(self) -> MaterializedLabRunRequest:
        groups = (
            self.action_bytes,
            self.lab_actions,
            self.lab_action_bytes,
            self.policy_authorizations,
            self.policy_authorization_bytes,
            self.policy_requests,
            self.policy_request_bytes,
        )
        if any(len(group) != len(self.actions) for group in groups):
            raise ValueError("M5 application request byte cardinality is invalid")
        if len({item.action_id for item in self.actions}) != len(self.actions):
            raise ValueError("M5 application actions must be unique")
        first_scope = self.policy_requests[0].scope_manifest
        first_evaluated_at = self.policy_requests[0].evaluated_at
        writes_before = 0
        for index, (envelope, lab_action, authorization, request) in enumerate(
            zip(
                self.actions,
                self.lab_actions,
                self.policy_authorizations,
                self.policy_requests,
                strict=True,
            )
        ):
            action = envelope.action
            spec = resolve_lab_http_action(lab_action)
            exact_values = (
                (self.action_bytes[index], canonical_json_bytes(envelope)),
                (self.lab_action_bytes[index], canonical_json_bytes(lab_action)),
                (self.policy_authorization_bytes[index], canonical_json_bytes(authorization)),
                (self.policy_request_bytes[index], canonical_json_bytes(request)),
            )
            if any(actual != expected for actual, expected in exact_values):
                raise ValueError("M5 application retained bytes are not exact canonical values")
            if (
                not isinstance(action, HttpRequestAction)
                or action.target is None
                or action.method is None
                or envelope.sequence != index + 1
                or action.target.scheme != "http"
                or action.target.host != "localhost"
                or action.target.port != 80
                or action.method.value != spec.method.value
                or action.target.path != spec.path
                or action.identity_handle != spec.identity_handle
                or action.expected_statuses != spec.expected_statuses
                or action.body_artifact != lab_action_artifact(lab_action)
                or action.query
                or action.headers
                or action.template_ref is not None
                or request.action_envelope != envelope
                or request.scope_manifest != first_scope
                or request.evaluated_at != first_evaluated_at
                or request.budget is None
                or request.budget.requests_in_window != index
                or request.budget.write_requests_used != writes_before
                or authorization.policy_decision_ref != envelope.policy_decision_ref
            ):
                raise ValueError("M5 application action is outside the closed lab registry")
            try:
                expected_authorization = PolicyAuthorization.bind(
                    envelope, request, evaluate_policy(request)
                )
            except ValueError:
                raise ValueError("M5 application policy binding is invalid") from None
            if authorization != expected_authorization:
                raise ValueError("M5 application policy binding is invalid")
            if action.method.value not in {"GET", "HEAD", "OPTIONS"}:
                writes_before += 1
        if (self.scenario == "primary_patched") != (self.mode == "patched"):
            raise ValueError("M5 scenario and lab mode are inconsistent")
        return self


class ApplicationImageBinding(_RuntimeModel):
    application_image_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    bridge_image_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    provider_image_refs: tuple[str, ...]
    provider_image_set_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    provider_image_provenance: Literal["PINNED_MANIFEST_REFS_NOT_RUNTIME_IMAGE_IDS"]
    binding_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _bound(self) -> ApplicationImageBinding:
        if (
            self.provider_image_refs != _PROVIDER_IMAGE_REFS
            or self.provider_image_set_digest != sha256_digest(_PROVIDER_IMAGE_REFS)
            or self.provider_image_provenance != "PINNED_MANIFEST_REFS_NOT_RUNTIME_IMAGE_IDS"
            or self.binding_digest
            != _digest(self.model_dump(mode="json", exclude={"binding_digest"}))
        ):
            raise ValueError("M5 application image binding digest is invalid")
        return self


class ProviderCheckpointWitness(_RuntimeModel):
    provider: Literal["postgres", "redis", "rabbitmq", "selenium", "filesystem", "clock"]
    generation: str = Field(pattern=r"^[0-9a-f]{64}$")
    checkpoint_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    storage_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class CheckpointWitness(_RuntimeModel):
    generation: str = Field(pattern=r"^[0-9a-f]{64}$")
    checkpoint_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    checkpoint_bytes: bytes = Field(min_length=1, max_length=131_072)
    checkpoint_bytes_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    observations: tuple[ProviderCheckpointWitness, ...]

    @model_validator(mode="after")
    def _six_exact_shards(self) -> CheckpointWitness:
        try:
            checkpoint = LabStateCheckpoint.from_canonical_bytes(self.checkpoint_bytes)
        except ValueError:
            raise ValueError("checkpoint witness bytes are invalid") from None
        if (
            checkpoint.generation != self.generation
            or checkpoint.checkpoint_digest != self.checkpoint_digest
            or _raw_digest(self.checkpoint_bytes) != self.checkpoint_bytes_digest
            or tuple(item.provider for item in self.observations) != _PROVIDERS
            or any(item.generation != self.generation for item in self.observations)
            or any(item.checkpoint_digest != self.checkpoint_digest for item in self.observations)
            or any(
                item.storage_digest != self.checkpoint_bytes_digest for item in self.observations
            )
        ):
            raise ValueError("checkpoint witness does not retain six exact shards")
        return self


class ApplicationRouteTrace(_RuntimeModel):
    action_id: str
    action_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    lab_action_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    policy_authorization_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    policy_request_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    method: Literal["GET", "POST"]
    path: str = Field(pattern=r"^/v1/lab/(?:[A-Za-z0-9_.{}-]+/?)+$")
    route: str = Field(pattern=r"^/v1/lab/(?:[A-Za-z0-9_.{}-]+/?)+$")
    response_status: int = Field(ge=100, le=599)
    response_body_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    response_evidence_id: str | None = Field(default=None, pattern=r"^ev-[0-9]{3}$")
    response_action_id: str | None = Field(default=None, pattern=r"^act-[0-9]{3}$")
    started_ns: int = Field(ge=1)
    ended_ns: int = Field(ge=1)
    observation_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _timing(self) -> ApplicationRouteTrace:
        if self.ended_ns < self.started_ns:
            raise ValueError("application route timing is invalid")
        expected = _digest(self.model_dump(mode="json", exclude={"observation_digest"}))
        if self.observation_digest != expected:
            raise ValueError("application route observation digest is invalid")
        return self


class MaterializedLabStepReceipt(_RuntimeModel):
    step_id: str = Field(pattern=r"^step\.[0-9]{2}$")
    before: CheckpointWitness
    trace: ApplicationRouteTrace
    after: CheckpointWitness
    evidence_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    appended_evidence: EvidenceRecordResponse
    oracle: OracleResultResponse
    oracle_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    visibility_commit: Literal["POSTGRES_CAS"]
    step_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _bound(self) -> MaterializedLabStepReceipt:
        try:
            restored = LabState.from_checkpoint(
                LabStateCheckpoint.from_canonical_bytes(self.after.checkpoint_bytes)
            )
        except ValueError:
            raise ValueError("M5 application step checkpoint is invalid") from None
        evidence = restored.evidence()
        checkpoint = LabStateCheckpoint.from_canonical_bytes(self.after.checkpoint_bytes)
        raw_evidence = checkpoint.state.get("evidence")
        last_raw = raw_evidence[-1] if isinstance(raw_evidence, list) and raw_evidence else None
        if (
            self.oracle_digest != _digest(self.oracle)
            or restored.oracle_result() != self.oracle
            or not evidence.records
            or evidence.records[-1] != self.appended_evidence
            or self.evidence_digest != _digest(evidence)
            or not isinstance(last_raw, dict)
            or (
                self.trace.response_evidence_id is not None
                and self.trace.response_evidence_id != last_raw.get("evidence_id")
            )
            or (
                self.trace.response_action_id is not None
                and self.trace.response_action_id != last_raw.get("action_id")
            )
            or self.step_digest != _digest(self.model_dump(mode="json", exclude={"step_digest"}))
        ):
            raise ValueError("M5 application step is not content bound")
        return self


class MaterializedLabRunReceipt(_RuntimeModel):
    """Per-scenario Docker receipt; hosted SW-M5 admission remains a later gate."""

    schema_version: Literal["stateweaver-m5-materialized-application-run-v2"]
    status: Literal["M5_MATERIALIZED_APPLICATION_SCENARIO_EXECUTED"]
    request: MaterializedLabRunRequest
    request_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    image_binding: ApplicationImageBinding
    execution_backend: Literal["fastapi-asgi"]
    application_schema_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    checkpoint_visibility: Literal["SIX_IMMUTABLE_SHARDS_POSTGRES_CAS"]
    initial_checkpoint: CheckpointWitness
    steps: tuple[MaterializedLabStepReceipt, ...]
    final_checkpoint: CheckpointWitness
    cleanup_status: Literal["PASS"]
    destroyed: Literal[True]
    receipt_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _closed(self) -> MaterializedLabRunReceipt:
        if (
            self.request_digest != _digest(self.request)
            or self.application_schema_digest
            != sha256_digest(create_app(self.request.mode).openapi())
            or len(self.steps) != len(self.request.actions)
            or tuple(item.step_id for item in self.steps)
            != tuple(f"step.{index:02d}" for index in range(1, len(self.steps) + 1))
            or self.steps[0].before != self.initial_checkpoint
            or any(
                prior.after != following.before
                for prior, following in zip(self.steps, self.steps[1:], strict=False)
            )
            or self.steps[-1].after != self.final_checkpoint
            or tuple(item.trace.action_id for item in self.steps)
            != tuple(item.action_id for item in self.request.actions)
            or tuple(item.trace.action_digest for item in self.steps)
            != tuple(sha256_digest(item) for item in self.request.actions)
        ):
            raise ValueError("M5 application receipt is not content bound")
        expected = _digest(self.model_dump(mode="json", exclude={"receipt_digest"}))
        if self.receipt_digest != expected:
            raise ValueError("M5 application receipt digest is invalid")
        return self


class MaterializedLabDockerRuntime:
    """One isolated Compose project per application witness, always torn down."""

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
                _compose(project, *_RUNTIME_PREFIX), stdin=_runtime_payload(closed, binding)
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
        values: dict[str, object] = {
            "application_image_id": application,
            "bridge_image_id": bridge,
            "provider_image_refs": _PROVIDER_IMAGE_REFS,
            "provider_image_set_digest": sha256_digest(_PROVIDER_IMAGE_REFS),
            "provider_image_provenance": "PINNED_MANIFEST_REFS_NOT_RUNTIME_IMAGE_IDS",
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
            "schema_version": "stateweaver-m5-materialized-application-input-v2",
            "request": request.model_dump(mode="json"),
            "image_binding": binding.model_dump(mode="json"),
        }
    )


def _parse_runtime_result(
    result: ProcessResult, request: MaterializedLabRunRequest, binding: ApplicationImageBinding
) -> MaterializedLabRunReceipt:
    raw = result.stdout.encode("utf-8")
    if not raw or len(raw) > _MAX_WITNESS_BYTES:
        raise ComposeAdapterError("M5 application runtime output is invalid")
    payload = json.loads(raw, object_pairs_hook=_unique_object)
    if not isinstance(payload, dict):
        raise ComposeAdapterError("M5 application runtime output is invalid")
    values = {
        "schema_version": "stateweaver-m5-materialized-application-run-v2",
        "status": "M5_MATERIALIZED_APPLICATION_SCENARIO_EXECUTED",
        "request": request,
        "request_digest": _digest(request),
        "image_binding": binding,
        "execution_backend": payload.get("execution_backend"),
        "application_schema_digest": payload.get("application_schema_digest"),
        "checkpoint_visibility": payload.get("checkpoint_visibility"),
        "initial_checkpoint": payload.get("initial_checkpoint"),
        "steps": tuple(payload.get("steps", ())),
        "final_checkpoint": payload.get("final_checkpoint"),
        "cleanup_status": "PASS",
        "destroyed": True,
    }
    return MaterializedLabRunReceipt.model_validate_json(
        canonical_json_bytes(_json_compatible({**values, "receipt_digest": _digest(values)}))
    )


def _checkpoint_witness(capture: ProviderCheckpointCapture) -> dict[str, object]:
    return {
        "generation": capture.generation,
        "checkpoint_digest": capture.checkpoint_digest,
        "checkpoint_bytes": capture.checkpoint_bytes,
        "checkpoint_bytes_digest": _raw_digest(capture.checkpoint_bytes),
        "observations": [
            {
                "provider": item.provider,
                "generation": item.generation,
                "checkpoint_digest": item.checkpoint_digest,
                "storage_digest": item.storage_digest,
            }
            for item in capture.observations
        ],
    }


def _require_exact_envelope(envelope: ActionEnvelope, lab_action: TypedLabAction) -> None:
    action = envelope.action
    spec = resolve_lab_http_action(lab_action)
    if (
        not isinstance(action, HttpRequestAction)
        or action.target is None
        or action.method is None
        or action.method.value != spec.method.value
        or action.target.path != spec.path
        or action.identity_handle != spec.identity_handle
        or action.expected_statuses != spec.expected_statuses
        or action.body_artifact != lab_action_artifact(lab_action)
    ):
        raise ValueError("runtime action no longer matches its lab binding")


async def _execute_in_container(request: MaterializedLabRunRequest) -> dict[str, object]:
    app = create_app(request.mode)
    seal_lab_asgi_app(app)
    store = RealProviderLabStateStore()
    initial_checkpoint = app.state.lab.export_checkpoint()
    initial_staged = store.stage(initial_checkpoint.canonical_bytes())
    active = store.compare_and_swap(None, initial_checkpoint.generation)
    if initial_staged != active:
        raise ProviderCheckpointError("initial-checkpoint-readback-invalid")
    steps: list[dict[str, object]] = []
    current = active
    write_requests_used = 0
    for index, (envelope, lab_action, authorization, policy_request) in enumerate(
        zip(
            request.actions,
            request.lab_actions,
            request.policy_authorizations,
            request.policy_requests,
            strict=True,
        ),
        start=1,
    ):
        before = store.load_active()
        if before != current:
            raise ProviderCheckpointError("active-checkpoint-substitution")
        checkpoint = LabStateCheckpoint.from_canonical_bytes(before.checkpoint_bytes)
        retained_state = LabState.from_checkpoint(checkpoint)
        app.state.lab = retained_state
        _require_exact_envelope(envelope, lab_action)
        if policy_request.budget is None or policy_request.evaluated_at is None:
            raise ValueError("runtime policy request is incomplete")
        if (
            policy_request.budget.requests_in_window != index - 1
            or policy_request.budget.write_requests_used != write_requests_used
        ):
            raise ValueError("runtime policy budget order is invalid")
        controlled_now = retained_state.state_digest().now
        try:
            verify_policy_authorization(
                authorization,
                envelope,
                at=controlled_now,
                requests_used=index - 1,
                write_requests_used=write_requests_used,
                request=policy_request,
            )
        except PolicyAuthorizationDeniedError:
            raise ValueError("runtime policy authorization was denied") from None
        before_evidence = retained_state.evidence().records
        started = time.monotonic_ns()
        try:
            execution = await asyncio.wait_for(
                execute_lab_action_asgi(app, lab_action),
                timeout=envelope.timeout_ms / 1_000,
            )
        except TimeoutError:
            raise ValueError("actual ASGI action exceeded its admitted timeout") from None
        ended = time.monotonic_ns()
        action = envelope.action
        assert isinstance(action, HttpRequestAction)
        assert action.method is not None
        if execution.status not in action.expected_statuses:
            raise ValueError("actual ASGI status was not admitted")
        if app.state.lab is not retained_state:
            raise ValueError("actual ASGI application replaced retained state")
        after_evidence = retained_state.evidence().records
        if (
            len(after_evidence) != len(before_evidence) + 1
            or after_evidence[:-1] != before_evidence
        ):
            raise ValueError("actual ASGI action did not append exactly one evidence record")
        response = json.loads(execution.body, object_pairs_hook=_unique_object)
        if not isinstance(response, dict):
            raise ValueError("actual ASGI response is not a JSON object")
        if "evidence_id" in response and response["evidence_id"] != after_evidence[-1].evidence_id:
            raise ValueError("actual ASGI response does not bind its appended evidence")
        expected_action_id = f"act-{len(after_evidence):03d}"
        if "action_id" in response and response["action_id"] != expected_action_id:
            raise ValueError("actual ASGI response does not bind its appended evidence")
        oracle = retained_state.oracle_result().model_dump(mode="json")
        evidence = retained_state.evidence().model_dump(mode="json")
        next_checkpoint = retained_state.export_checkpoint()
        staged = store.stage(next_checkpoint.canonical_bytes())
        if staged.generation != next_checkpoint.generation:
            raise ProviderCheckpointError("next-checkpoint-stage-invalid")
        after = store.compare_and_swap(before.generation, next_checkpoint.generation)
        if after != store.load_active():
            raise ProviderCheckpointError("next-checkpoint-readback-invalid")
        trace_values: dict[str, object] = {
            "action_id": envelope.action_id,
            "action_digest": sha256_digest(envelope),
            "lab_action_digest": sha256_digest(lab_action),
            "policy_authorization_digest": sha256_digest(authorization),
            "policy_request_digest": sha256_digest(policy_request),
            "method": execution.method.value,
            "path": execution.path,
            "route": execution.route,
            "response_status": execution.status,
            "response_body_digest": _raw_digest(execution.body),
            "response_evidence_id": response.get("evidence_id"),
            "response_action_id": response.get("action_id"),
            "started_ns": started,
            "ended_ns": ended,
        }
        trace = {**trace_values, "observation_digest": _digest(trace_values)}
        step_values: dict[str, object] = {
            "step_id": f"step.{index:02d}",
            "before": _checkpoint_witness(before),
            "trace": trace,
            "after": _checkpoint_witness(after),
            "evidence_digest": _digest(evidence),
            "appended_evidence": after_evidence[-1].model_dump(mode="json"),
            "oracle": oracle,
            "oracle_digest": _digest(oracle),
            "visibility_commit": "POSTGRES_CAS",
        }
        steps.append({**step_values, "step_digest": _digest(step_values)})
        current = after
        if action.method.value not in {"GET", "HEAD", "OPTIONS"}:
            write_requests_used += 1
    return {
        "execution_backend": "fastapi-asgi",
        "application_schema_digest": sha256_digest(app.openapi()),
        "checkpoint_visibility": "SIX_IMMUTABLE_SHARDS_POSTGRES_CAS",
        "initial_checkpoint": _checkpoint_witness(active),
        "steps": steps,
        "final_checkpoint": _checkpoint_witness(current),
    }


def _unique_object(items: Sequence[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _digest(value: object) -> str:
    return "sha256:" + sha256(canonical_json_bytes(_json_compatible(value))).hexdigest()


def _raw_digest(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


def _json_compatible(value: object) -> object:
    if isinstance(value, BaseModel):
        return _json_compatible(value.model_dump(mode="python"))
    if isinstance(value, bytes):
        return value.decode("utf-8")
    if isinstance(value, tuple | list):
        return [_json_compatible(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    return value


def _container_main(argv: Sequence[str]) -> int:
    if len(argv) != 2 or argv[1] not in {"serve", "health", "execute"}:
        return 64
    if argv[1] == "health":
        app = create_app("vulnerable")
        seal_lab_asgi_app(app)
        return 0 if getattr(app, "routes", None) else 70
    if argv[1] == "serve":
        while True:
            time.sleep(60)
    try:
        raw = sys.stdin.buffer.read(_MAX_WITNESS_BYTES + 1)
        if not raw or len(raw) > _MAX_WITNESS_BYTES:
            return 65
        payload = json.loads(raw, object_pairs_hook=_unique_object)
        if (
            not isinstance(payload, dict)
            or set(payload) != {"schema_version", "request", "image_binding"}
            or payload.get("schema_version") != "stateweaver-m5-materialized-application-input-v2"
        ):
            return 65
        request = MaterializedLabRunRequest.model_validate_json(
            canonical_json_bytes(payload["request"])
        )
        ApplicationImageBinding.model_validate_json(canonical_json_bytes(payload["image_binding"]))
        output = __import__("asyncio").run(_execute_in_container(request))
        sys.stdout.buffer.write(canonical_json_bytes(_json_compatible(output)))
        return 0
    except (LabAsgiExecutionError, ProviderCheckpointError, TypeError, ValueError):
        return 70


__all__ = [
    "ApplicationImageBinding",
    "ApplicationRouteTrace",
    "CheckpointWitness",
    "MaterializedLabDockerRuntime",
    "MaterializedLabRunReceipt",
    "MaterializedLabRunRequest",
    "MaterializedLabStepReceipt",
    "ProviderCheckpointWitness",
]


if __name__ == "__main__":  # pragma: no cover - Docker entrypoint only.
    raise SystemExit(_container_main(sys.argv))
