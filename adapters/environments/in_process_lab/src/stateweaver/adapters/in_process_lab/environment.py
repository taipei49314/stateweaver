"""Deterministic, socket-free ReplayEnvironment implementation."""

from __future__ import annotations

import asyncio
import json
import re
import secrets
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Annotated, Final, Literal, cast

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator
from starlette.types import ASGIApp, Message, Scope
from stateweaver.contracts import ActionEnvelope, HttpMethod, HttpRequestAction, Sha256Digest
from stateweaver.contracts.base import ContractId
from stateweaver.replay import (
    CaptureLayer,
    ReplayObservation,
    RootSeed,
    StateArtifact,
    StateCapture,
    canonical_sha256,
)
from stateweaver_lab import (
    DeterministicLabService,
    LabActionResult,
    LabMode,
    LayeredStateCapture,
)
from stateweaver_lab.app import create_app as _TRUSTED_CREATE_APP
from stateweaver_lab.fixtures import CANONICAL_SEED, FixtureBearer
from stateweaver_lab.models import (
    ActionReceipt,
    AdvanceClockLabAction,
    ClaimReferenceLabAction,
    ClockResponse,
    DeferQueueLabAction,
    DocumentResponse,
    DowngradeRoleLabAction,
    EvidenceRecordResponse,
    MaskedDocumentResponse,
    MaskedReadLabAction,
    MockPolicyLabAction,
    MockPolicyResponse,
    PrimeAuthorizationCacheLabAction,
    PublishReferenceLabAction,
    ReadDocumentLabAction,
    ReferenceResponse,
    RetainSessionLabAction,
    RoleDowngradeResponse,
)

from .errors import (
    AdapterConfigurationError,
    LabCaptureRejectedError,
    LabEvidenceRejectedError,
    LabExecutionRejectedError,
    LabExecutionTimeoutError,
    LabIdempotencyConflictError,
)
from .registry import (
    FixedLabActionRegistry,
    LabAction,
    PolicyAuthorization,
    lab_http_action_spec,
    validate_fixed_http_envelope,
)

if TYPE_CHECKING:
    from .oracle import InProcessLabReplayOracle

ADAPTER_NAME: Final = "in_process_lab"
ADAPTER_VERSION: Final = "0.1.0"
CANONICAL_RANDOM_SEED: Final = 982_341

_SHA256_PATTERN: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
_LAYER_FIELDS: Final = (
    (CaptureLayer.APPLICATION, "application"),
    (CaptureLayer.DATABASE, "database"),
    (CaptureLayer.CACHE, "cache"),
    (CaptureLayer.QUEUE, "queue"),
    (CaptureLayer.BROWSER, "browser"),
    (CaptureLayer.CONFIGURATION, "configuration"),
    (CaptureLayer.CLOCK, "clock"),
)
_EXPECTED_LAYERS: Final = frozenset(layer for layer, _ in _LAYER_FIELDS)
_FORBIDDEN_CAPTURE_KEYS: Final = frozenset(
    {
        "authorization",
        "bearer",
        "bearer_value",
        "body",
        "cookie",
        "document_body",
        "password",
        "proxy_authorization",
        "refresh_token",
        "secret",
        "set_cookie",
        "token",
        "access_token",
        "x_api_key",
    }
)
_FIXTURE_BEARERS: Final = frozenset(item.value for item in FixtureBearer)
_MAX_ASGI_RESPONSE_BYTES: Final = 65_536


class InProcessLabRuntimeExecution(BaseModel):
    """Immutable receipt for the one actual repository ASGI lifecycle."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)

    execution_id: ContractId
    execution_digest: Sha256Digest
    envelope_digest: Sha256Digest
    source_digest: Sha256Digest
    authorization: PolicyAuthorization
    method: HttpMethod
    route: Annotated[str, Field(min_length=1, max_length=256, pattern=r"^/")]
    status: Annotated[int, Field(ge=100, le=599)]
    started_at_unix_nano: Annotated[int, Field(ge=0)]
    ended_at_unix_nano: Annotated[int, Field(gt=0)]
    before_captured_at_unix_nano: Annotated[int, Field(ge=0)]
    after_captured_at_unix_nano: Annotated[int, Field(gt=0)]
    before_capture: StateCapture
    after_capture: StateCapture
    observations: tuple[ReplayObservation, ...]

    @model_validator(mode="after")
    def execution_is_coherent(self) -> InProcessLabRuntimeExecution:
        if not (
            self.before_captured_at_unix_nano
            <= self.started_at_unix_nano
            < self.ended_at_unix_nano
            <= self.after_captured_at_unix_nano
        ):
            raise ValueError("runtime execution timestamps are out of order")
        if len(self.observations) != 1:
            raise ValueError("runtime execution requires exactly one observation")
        if self.before_capture == self.after_capture:
            raise ValueError("runtime execution did not produce a state change")
        expected_digest = canonical_sha256(
            self.model_dump(mode="python", exclude={"execution_digest"})
        )
        if self.execution_digest != expected_digest:
            raise ValueError("runtime execution digest does not match its contents")
        return self


@dataclass(frozen=True, slots=True)
class _AsgiResponse:
    route: str
    status: int
    body: bytes


@dataclass(frozen=True, slots=True)
class _AuthorizedAsgiExecution:
    envelope_digest: Sha256Digest
    source_digest: Sha256Digest
    authorization: PolicyAuthorization
    method: HttpMethod
    route: str
    status: int
    started_at_unix_nano: int
    ended_at_unix_nano: int
    observations: tuple[ReplayObservation, ...]


def _target_version(mode: LabMode) -> str:
    return f"lab-{mode.value}"


def _json_value(value: object) -> JsonValue:
    if isinstance(value, Enum):
        return cast(JsonValue, value.value)
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_value(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise LabCaptureRejectedError("capture contains a non-JSON value")


def _model_payload(model: BaseModel) -> dict[str, JsonValue]:
    dumped = model.model_dump(mode="json", by_alias=True, exclude_none=False)
    converted = _json_value(dumped)
    if not isinstance(converted, dict):
        raise LabCaptureRejectedError("capture layer is not an object")
    return converted


def _assert_redacted(value: JsonValue, *, key: str = "") -> None:
    normalized_key = key.lower().replace("-", "_")
    if normalized_key in _FORBIDDEN_CAPTURE_KEYS:
        raise LabCaptureRejectedError("capture contains a credential or protected-data field")
    if isinstance(value, str):
        lowered = value.lower()
        if (
            value in _FIXTURE_BEARERS
            or lowered.startswith("bearer ")
            or "synthetic_tenant_b_marker" in lowered
            or "synthetic_tenant_a_document" in lowered
        ):
            raise LabCaptureRejectedError("capture contains an unredacted value")
    elif isinstance(value, dict):
        for child_key, child in value.items():
            _assert_redacted(child, key=child_key)
    elif isinstance(value, list):
        for child in value:
            _assert_redacted(child, key=key)


class InProcessLabEnvironment:
    """Execute only fixed typed actions against one isolated synthetic lab state."""

    adapter_name = ADAPTER_NAME
    adapter_version = ADAPTER_VERSION

    def __init__(self, *, mode: LabMode, registry: FixedLabActionRegistry) -> None:
        if not isinstance(mode, LabMode):
            raise AdapterConfigurationError("mode must be an explicit LabMode")
        if not isinstance(registry, FixedLabActionRegistry):
            raise AdapterConfigurationError("a fixed action registry is required")
        self._service = DeterministicLabService(mode)
        self._registry = registry
        app = _TRUSTED_CREATE_APP(mode)
        if type(app) is not FastAPI:
            raise AdapterConfigurationError("the repository app factory returned an unknown type")
        self._app = app
        InProcessLabEnvironment._bind_app_state(self)
        self._source_digest = canonical_sha256(self._app.openapi())
        self._route_signature = _app_route_signature(self._app)
        self._middleware_signature = _app_middleware_signature(self._app)
        self._middleware_stack: ASGIApp = self._app.build_middleware_stack()
        self._app.middleware_stack = self._middleware_stack
        self._lock = asyncio.Lock()
        self._active = False
        self._inflight_task: asyncio.Task[_AuthorizedAsgiExecution] | None = None
        self._inflight_phase: Literal["executing", "settling"] | None = None
        self._idempotency_cache: dict[str, tuple[str, InProcessLabRuntimeExecution]] = {}
        self._observation_claims: dict[Sha256Digest, Sha256Digest] = {}
        self._last_observations: tuple[ReplayObservation, ...] = ()
        self._requests_used = 0
        self._write_requests_used = 0
        self._environment_nonce = secrets.token_hex(16)
        self._run_sequence = 0
        self._run_digest = canonical_sha256(
            {"environment_nonce": self._environment_nonce, "run_sequence": self._run_sequence}
        )

        from .oracle import InProcessLabReplayOracle

        self._oracle = InProcessLabReplayOracle(self._service)

    @property
    def mode(self) -> LabMode:
        InProcessLabEnvironment._assert_no_inflight(self)
        return self._service.mode

    @property
    def oracle(self) -> InProcessLabReplayOracle:
        from .oracle import InProcessLabReplayOracle

        InProcessLabEnvironment._assert_no_inflight(self)
        assert isinstance(self._oracle, InProcessLabReplayOracle)
        return self._oracle

    @property
    def last_observations(self) -> tuple[ReplayObservation, ...]:
        InProcessLabEnvironment._assert_no_inflight(self)
        return self._last_observations

    @property
    def runtime_source_digest(self) -> Sha256Digest:
        """Return only the digest of the fixed repository app source schema."""

        InProcessLabEnvironment._assert_no_inflight(self)
        InProcessLabEnvironment._assert_runtime_binding(self)
        return self._source_digest

    @property
    def evidence_records(self) -> tuple[EvidenceRecordResponse, ...]:
        """Return the synthetic, body-free audit records for the current run."""

        InProcessLabEnvironment._assert_no_inflight(self)
        records = DeterministicLabService.evidence(self._service).records
        for record in records:
            _assert_redacted(_model_payload(record))
        return records

    async def create_root_seed(self, *, root_seed_id: str, random_seed: int) -> RootSeed:
        """Reset and pin the only canonical seed supported by the synthetic lab."""

        if random_seed != CANONICAL_RANDOM_SEED:
            raise AdapterConfigurationError("the requested random seed is unsupported")
        async with self._lock:
            InProcessLabEnvironment._recover_settled_inflight(self)
            DeterministicLabService.reset(self._service)
            InProcessLabEnvironment._bind_app_state(self)
            InProcessLabEnvironment._assert_runtime_binding(self)
            InProcessLabEnvironment._activate_clean_run(self)
            capture = InProcessLabEnvironment._capture_unlocked(self)
            return RootSeed(
                root_seed_id=root_seed_id,
                target_version=_target_version(self.mode),
                random_seed=random_seed,
                clock_epoch=capture.controlled_at,
                capture=capture,
                adapter_versions={ADAPTER_NAME: ADAPTER_VERSION},
            )

    async def reset(self, root: RootSeed) -> StateCapture:
        """Restore the canonical clean root after validating every version pin."""

        InProcessLabEnvironment._validate_root(self, root)
        async with self._lock:
            InProcessLabEnvironment._recover_settled_inflight(self)
            DeterministicLabService.reset(self._service)
            InProcessLabEnvironment._bind_app_state(self)
            InProcessLabEnvironment._assert_runtime_binding(self)
            InProcessLabEnvironment._activate_clean_run(self)
            return InProcessLabEnvironment._capture_unlocked(self)

    async def capture(self) -> StateCapture:
        """Capture all seven real, redacted lab layers without private-state access."""

        async with self._lock:
            InProcessLabEnvironment._assert_no_inflight(self)
            InProcessLabEnvironment._assert_runtime_binding(self)
            return InProcessLabEnvironment._capture_unlocked(self)

    async def execute(self, action: ActionEnvelope) -> tuple[ReplayObservation, ...]:
        """Execute one authorized repository ASGI lifecycle and return its observations."""

        execution = await InProcessLabEnvironment.execute_observed(self, action)
        return execution.observations

    def resolve_runtime_route(self, action: ActionEnvelope) -> str:
        """Resolve an envelope to the fixed app route without executing its action."""

        if not isinstance(action, ActionEnvelope):
            raise LabExecutionRejectedError("execution requires an ActionEnvelope")
        InProcessLabEnvironment._assert_no_inflight(self)
        InProcessLabEnvironment._assert_runtime_binding(self)
        lab_action = self._registry.resolve(action)
        validate_fixed_http_envelope(action, lab_action)
        return InProcessLabEnvironment._resolve_app_route(self, action)

    async def claim_runtime_observation(
        self,
        execution: InProcessLabRuntimeExecution,
    ) -> Sha256Digest:
        """Claim the sole trusted observation issuance for one committed execution."""

        if type(execution) is not InProcessLabRuntimeExecution:
            raise LabExecutionRejectedError("runtime observation claim requires an exact receipt")
        async with self._lock:
            InProcessLabEnvironment._assert_no_inflight(self)
            InProcessLabEnvironment._assert_runtime_binding(self)
            if not self._active:
                raise LabExecutionRejectedError("the environment must be active to claim execution")
            cached = self._idempotency_cache.get(execution.authorization.idempotency_key)
            if cached is None or cached[1] != execution:
                raise LabExecutionRejectedError(
                    "runtime observation claim does not match a committed execution"
                )
            if execution.execution_digest in self._observation_claims:
                raise LabExecutionRejectedError(
                    "runtime execution observation issuance was already claimed"
                )
            claim_digest = canonical_sha256(
                {
                    "purpose": "runtime-observation-claim-v1",
                    "execution_id": execution.execution_id,
                    "execution_digest": execution.execution_digest,
                }
            )
            self._observation_claims[execution.execution_digest] = claim_digest
            return claim_digest

    async def execute_observed(
        self,
        action: ActionEnvelope,
    ) -> InProcessLabRuntimeExecution:
        """Authorize, execute, observe, and commit one actual ASGI lifecycle."""

        if not isinstance(action, ActionEnvelope):
            raise LabExecutionRejectedError("execution requires an ActionEnvelope")
        async with self._lock:
            InProcessLabEnvironment._assert_no_inflight(self)
            InProcessLabEnvironment._assert_runtime_binding(self)
            if not self._active:
                raise LabExecutionRejectedError("the environment must be reset before execution")

            envelope_hash = canonical_sha256(action)
            cached = self._idempotency_cache.get(action.idempotency_key)
            if cached is not None:
                cached_hash, cached_execution = cached
                if cached_hash != envelope_hash:
                    raise LabIdempotencyConflictError("idempotency key semantics changed")
                self._last_observations = cached_execution.observations
                return cached_execution

            lab_action = self._registry.resolve(action)
            validate_fixed_http_envelope(action, lab_action)
            authorization = self._registry.require_policy_allows(
                action,
                at=DeterministicLabService.capture(self._service).now,
                requests_used=self._requests_used,
                write_requests_used=self._write_requests_used,
            )
            before_capture = InProcessLabEnvironment._capture_unlocked(self)
            before_captured_at_unix_nano = time.time_ns()
            self._requests_used += 1
            if authorization.is_write:
                self._write_requests_used += 1
            task = asyncio.create_task(
                InProcessLabEnvironment._execute_uncached(
                    self,
                    action,
                    lab_action,
                    authorization,
                )
            )
            self._inflight_task = task
            self._inflight_phase = "executing"
            execution: InProcessLabRuntimeExecution | None = None
            execution_failed = False
            try:
                completed, _ = await asyncio.wait(
                    (task,),
                    timeout=action.timeout_ms / 1_000,
                )
                if not completed:
                    task.cancel()
                    self._inflight_phase = "settling"
                    self._active = False
                    raise LabExecutionTimeoutError(
                        "repository ASGI execution exceeded its deadline"
                    )
                outcome = task.result()
                after_capture = InProcessLabEnvironment._capture_unlocked(self)
                after_captured_at_unix_nano = max(
                    time.time_ns(),
                    outcome.ended_at_unix_nano,
                )
                execution_id_digest = canonical_sha256(
                    {
                        "run_digest": self._run_digest,
                        "envelope_digest": outcome.envelope_digest,
                        "started_at_unix_nano": outcome.started_at_unix_nano,
                    }
                ).removeprefix("sha256:")
                execution_fields: dict[str, object] = {
                    "execution_id": f"execution.{execution_id_digest[:24]}",
                    "envelope_digest": outcome.envelope_digest,
                    "source_digest": outcome.source_digest,
                    "authorization": outcome.authorization,
                    "method": outcome.method,
                    "route": outcome.route,
                    "status": outcome.status,
                    "started_at_unix_nano": outcome.started_at_unix_nano,
                    "ended_at_unix_nano": outcome.ended_at_unix_nano,
                    "before_captured_at_unix_nano": before_captured_at_unix_nano,
                    "after_captured_at_unix_nano": after_captured_at_unix_nano,
                    "before_capture": before_capture,
                    "after_capture": after_capture,
                    "observations": outcome.observations,
                }
                execution = InProcessLabRuntimeExecution.model_validate(
                    {
                        **execution_fields,
                        "execution_digest": canonical_sha256(execution_fields),
                    }
                )
            except LabExecutionTimeoutError:
                raise LabExecutionTimeoutError(
                    "repository ASGI execution exceeded its deadline"
                ) from None
            except asyncio.CancelledError:
                self._active = False
                if not task.done():
                    task.cancel()
                self._inflight_phase = "settling"
                raise
            except Exception:
                # A reservation is irreversible. Unknown post-reservation state poisons this run.
                self._active = False
                if not task.done():
                    task.cancel()
                self._inflight_phase = "settling"
                execution_failed = True
            if execution_failed or execution is None:
                del task
                raise LabExecutionRejectedError("repository ASGI execution failed") from None
            self._idempotency_cache[action.idempotency_key] = (envelope_hash, execution)
            self._last_observations = execution.observations
            InProcessLabEnvironment._clear_owned_inflight(self, task)
            return execution

    async def cleanup(self) -> None:
        """Close the run boundary; repeated cleanup calls are safe."""

        async with self._lock:
            InProcessLabEnvironment._recover_settled_inflight(self)
            self._active = False
            self._idempotency_cache.clear()
            self._observation_claims.clear()

    def _bind_app_state(self) -> None:
        self._app.state.lab = self._service._state

    def _assert_no_inflight(self) -> None:
        task = self._inflight_task
        if task is None:
            if self._inflight_phase is not None:
                raise LabExecutionRejectedError("repository ASGI execution state is invalid")
            return
        if self._inflight_phase == "executing":
            raise LabExecutionRejectedError("a repository ASGI execution is in progress")
        if self._inflight_phase == "settling":
            raise LabExecutionRejectedError(
                "a timed-out repository ASGI execution is still settling or requires cleanup/reset"
            )
        raise LabExecutionRejectedError("repository ASGI execution state is invalid")

    def _recover_settled_inflight(self) -> None:
        task = self._inflight_task
        if task is None:
            if self._inflight_phase is not None:
                raise LabExecutionRejectedError("repository ASGI execution state is invalid")
            return
        if self._inflight_phase == "executing":
            raise LabExecutionRejectedError("a repository ASGI execution is in progress")
        if self._inflight_phase != "settling" or not task.done():
            raise LabExecutionRejectedError(
                "a timed-out repository ASGI execution is still settling"
            )
        if not task.cancelled():
            task.exception()
        self._inflight_task = None
        self._inflight_phase = None

    def _clear_owned_inflight(self, task: asyncio.Task[_AuthorizedAsgiExecution]) -> None:
        if self._inflight_task is not task or self._inflight_phase != "executing":
            raise LabExecutionRejectedError("repository ASGI execution ownership changed")
        self._inflight_task = None
        self._inflight_phase = None

    def _assert_runtime_binding(self) -> None:
        if (
            any(
                name in vars(self)
                for name in (
                    "_assert_runtime_binding",
                    "_capture_unlocked",
                    "_execute_uncached",
                    "_invoke_asgi",
                    "_parse_asgi_result",
                    "_resolve_app_route",
                    "_validate_source_capture",
                )
            )
            or type(self._service) is not DeterministicLabService
            or any(
                name in vars(self._service)
                for name in ("capture", "capture_layers", "evidence", "reset")
            )
            or type(self._app) is not FastAPI
            or self._app.state.lab is not self._service._state
            or canonical_sha256(self._app.openapi()) != self._source_digest
            or bool(self._app.dependency_overrides)
            or _app_route_signature(self._app) != self._route_signature
            or _app_middleware_signature(self._app) != self._middleware_signature
            or self._app.middleware_stack is not self._middleware_stack
        ):
            raise LabExecutionRejectedError("repository ASGI app binding changed")

    def _resolve_app_route(self, envelope: ActionEnvelope) -> str:
        action = _http_action(envelope)
        if action.target is None or action.method is None:
            raise LabExecutionRejectedError("runtime route requires a concrete HTTP target")
        matches: list[str] = []
        for route in self._app.routes:
            pattern = getattr(route, "path_regex", None)
            methods = getattr(route, "methods", None)
            template = getattr(route, "path", None)
            if (
                pattern is not None
                and isinstance(methods, set)
                and isinstance(template, str)
                and action.method.value in methods
                and pattern.fullmatch(action.target.path) is not None
            ):
                matches.append(template)
        if len(matches) != 1:
            raise LabExecutionRejectedError("runtime route is not uniquely declared by the app")
        return matches[0]

    def _activate_clean_run(self) -> None:
        self._active = True
        self._idempotency_cache.clear()
        self._observation_claims.clear()
        self._last_observations = ()
        self._requests_used = 0
        self._write_requests_used = 0
        self._run_sequence += 1
        self._run_digest = canonical_sha256(
            {
                "environment_nonce": self._environment_nonce,
                "run_sequence": self._run_sequence,
            }
        )
        self._oracle.reset_diagnostics()

    def _validate_root(self, root: RootSeed) -> None:
        if not isinstance(root, RootSeed):
            raise AdapterConfigurationError("reset requires a RootSeed")
        if root.target_version != _target_version(self._service.mode):
            raise AdapterConfigurationError("root target version does not match the lab mode")
        if root.random_seed != CANONICAL_RANDOM_SEED:
            raise AdapterConfigurationError("root random seed is unsupported")
        if root.adapter_versions != {ADAPTER_NAME: ADAPTER_VERSION}:
            raise AdapterConfigurationError("root adapter version pins are missing or unknown")
        if {artifact.layer for artifact in root.capture.artifacts} != _EXPECTED_LAYERS:
            raise AdapterConfigurationError("root capture does not contain exactly seven layers")

    def _capture_unlocked(self) -> StateCapture:
        raw = DeterministicLabService.capture_layers(self._service)
        InProcessLabEnvironment._validate_source_capture(self, raw)
        artifacts: list[StateArtifact] = []
        for layer, field_name in _LAYER_FIELDS:
            payload = _model_payload(getattr(raw, field_name))
            if layer is CaptureLayer.APPLICATION:
                payload["source_state_fingerprint"] = raw.fingerprint
            _assert_redacted(payload)
            artifacts.append(StateArtifact.from_payload(layer=layer, payload=payload))

        capture_hash = canonical_sha256(
            {
                "source_fingerprint": raw.fingerprint,
                "artifact_hashes": [artifact.content_hash for artifact in artifacts],
            }
        ).removeprefix("sha256:")
        return StateCapture.from_artifacts(
            capture_id=f"capture.{capture_hash[:24]}",
            controlled_at=raw.clock.now,
            artifacts=tuple(artifacts),
        )

    def _validate_source_capture(self, raw: object) -> None:
        if not isinstance(raw, LayeredStateCapture):
            raise LabCaptureRejectedError("lab returned an unknown capture type")
        digest = DeterministicLabService.capture(self._service)
        if _SHA256_PATTERN.fullmatch(raw.fingerprint) is None:
            raise LabCaptureRejectedError("lab capture fingerprint is malformed")
        if (
            raw.fingerprint != digest.fingerprint
            or raw.configuration.mode is not digest.mode
            or raw.clock.now != digest.now
            or raw.database.policy_generation != digest.policy_generation
            or raw.application.evidence_count != digest.evidence_count
        ):
            raise LabCaptureRejectedError("layered capture disagrees with the authoritative digest")
        if raw.configuration.seed != CANONICAL_SEED:
            raise LabCaptureRejectedError("lab capture seed is unsupported")
        if raw.configuration.mode is not self._service.mode:
            raise LabCaptureRejectedError("lab capture mode changed")
        if (
            raw.configuration.network_scope != "in-process-only"
            or raw.configuration.external_egress_enabled
            or raw.configuration.arbitrary_actions_enabled
            or raw.clock.mode != "controlled"
        ):
            raise LabCaptureRejectedError("lab capture crossed the in-process safety boundary")

    async def _execute_uncached(
        self,
        envelope: ActionEnvelope,
        lab_action: LabAction,
        authorization: PolicyAuthorization,
    ) -> _AuthorizedAsgiExecution:
        before_records = DeterministicLabService.evidence(self._service).records
        started_at_unix_nano = time.time_ns()
        response = await InProcessLabEnvironment._invoke_asgi(self, envelope, lab_action)
        ended_at_unix_nano = max(time.time_ns(), started_at_unix_nano + 1_000)
        spec = lab_http_action_spec(lab_action)
        if response.status not in spec.expected_statuses:
            raise LabExecutionRejectedError("lab outcome was outside the registered status set")
        if response.route != InProcessLabEnvironment._resolve_app_route(self, envelope):
            raise LabExecutionRejectedError("executed ASGI route does not match the fixed route")
        result, error_code = InProcessLabEnvironment._parse_asgi_result(
            lab_action,
            status=response.status,
            body=response.body,
        )

        after_records = DeterministicLabService.evidence(self._service).records
        evidence = InProcessLabEnvironment._correlate_new_evidence(
            before_records,
            after_records,
        )
        observation = InProcessLabEnvironment._build_observation(
            envelope=envelope,
            lab_action=lab_action,
            result=result,
            evidence=evidence,
            status_code=response.status,
            error_code=error_code,
        )
        return _AuthorizedAsgiExecution(
            envelope_digest=canonical_sha256(envelope),
            source_digest=self._source_digest,
            authorization=authorization,
            method=spec.method,
            route=response.route,
            status=response.status,
            started_at_unix_nano=started_at_unix_nano,
            ended_at_unix_nano=ended_at_unix_nano,
            observations=(observation,),
        )

    async def _invoke_asgi(
        self,
        envelope: ActionEnvelope,
        lab_action: LabAction,
    ) -> _AsgiResponse:
        action = _http_action(envelope)
        if action.target is None or action.method is None:
            raise LabExecutionRejectedError("ASGI execution requires a concrete HTTP action")
        payload = lab_action.payload.model_dump(mode="json", by_alias=True, exclude_none=False)
        body = (
            b""
            if action.method in {HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS}
            else json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        )
        headers = {
            "host": action.target.host,
            "authorization": f"Bearer {lab_action.actor.value}",
        }
        if body:
            headers["content-type"] = "application/json"
            headers["content-length"] = str(len(body))
        scope: Scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.5"},
            "http_version": "1.1",
            "method": action.method.value,
            "scheme": action.target.scheme,
            "path": action.target.path,
            "raw_path": action.target.path.encode("ascii"),
            "query_string": b"",
            "root_path": "",
            "headers": [
                (name.encode("ascii"), value.encode("latin-1")) for name, value in headers.items()
            ],
            "client": ("127.0.0.1", 1),
            "server": (action.target.host, action.target.port),
            "state": {},
            "extensions": {},
        }
        request_sent = False
        status: int | None = None
        response_body = bytearray()
        response_complete = False

        async def receive() -> Message:
            nonlocal request_sent
            if not request_sent:
                request_sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        async def send(message: Message) -> None:
            nonlocal response_complete, status
            message_type = message.get("type")
            if message_type == "http.response.start":
                candidate = message.get("status")
                if (
                    status is not None
                    or isinstance(candidate, bool)
                    or not isinstance(candidate, int)
                ):
                    raise LabExecutionRejectedError("ASGI response status is invalid")
                status = candidate
                return
            if message_type == "http.response.body":
                if status is None or response_complete:
                    raise LabExecutionRejectedError("ASGI response body order is invalid")
                chunk = message.get("body", b"")
                if not isinstance(chunk, bytes):
                    raise LabExecutionRejectedError("ASGI response body is invalid")
                response_body.extend(chunk)
                if len(response_body) > _MAX_ASGI_RESPONSE_BYTES:
                    raise LabExecutionRejectedError("ASGI response exceeded the byte limit")
                response_complete = not bool(message.get("more_body", False))

        await FastAPI.__call__(self._app, scope, receive, send)
        if self._app.middleware_stack is not self._middleware_stack:
            raise LabExecutionRejectedError("repository ASGI middleware binding changed")
        route = getattr(scope.get("route"), "path", None)
        if status is None or not response_complete or not isinstance(route, str):
            raise LabExecutionRejectedError("ASGI response lifecycle was incomplete")
        return _AsgiResponse(route=route, status=status, body=bytes(response_body))

    @staticmethod
    def _parse_asgi_result(
        lab_action: LabAction,
        *,
        status: int,
        body: bytes,
    ) -> tuple[LabActionResult | None, str | None]:
        if status >= 400:
            try:
                document = json.loads(body)
                detail = document.get("detail") if isinstance(document, dict) else None
                error_code = detail.get("code") if isinstance(detail, dict) else None
            except (UnicodeDecodeError, json.JSONDecodeError):
                error_code = None
            if not isinstance(error_code, str) or not error_code:
                raise LabExecutionRejectedError("ASGI error response is malformed")
            return None, error_code
        response_model = _response_model_for(lab_action)
        try:
            result = response_model.model_validate_json(body)
        except (ValueError, TypeError):
            raise LabExecutionRejectedError("ASGI success response is malformed") from None
        return cast(LabActionResult, result), None

    @staticmethod
    def _correlate_new_evidence(
        before: tuple[EvidenceRecordResponse, ...],
        after: tuple[EvidenceRecordResponse, ...],
    ) -> EvidenceRecordResponse:
        if len(after) != len(before) + 1 or after[: len(before)] != before:
            raise LabEvidenceRejectedError("one action must append exactly one evidence record")
        return after[-1]

    @staticmethod
    def _build_observation(
        *,
        envelope: ActionEnvelope,
        lab_action: LabAction,
        result: LabActionResult | None,
        evidence: EvidenceRecordResponse,
        status_code: int,
        error_code: str | None,
    ) -> ReplayObservation:
        payload: dict[str, JsonValue] = {
            "action_type": lab_action.action_type,
            "actor_principal_id": evidence.actor_principal_id.value,
            "response_status": status_code,
            "response_schema": "lab.error" if result is None else type(result).__name__,
            "outcome": evidence.outcome,
            "resource_id": evidence.resource_id,
            "provenance": evidence.provenance.value,
            "controlled_at": evidence.at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "evidence_record_hash": canonical_sha256(evidence.model_dump(mode="json")),
            "protected_field_present": isinstance(result, DocumentResponse),
        }
        if error_code is not None:
            payload["error_code"] = error_code
        if isinstance(result, (DocumentResponse, MaskedDocumentResponse, MockPolicyResponse)):
            if result.evidence_id != evidence.evidence_id:
                raise LabEvidenceRejectedError("response evidence does not match action evidence")
            payload["document_id"] = result.document_id.value
        if isinstance(result, DocumentResponse):
            payload["owner_tenant"] = result.owner_tenant.value
        elif isinstance(result, MaskedDocumentResponse):
            payload["masked"] = True
        elif isinstance(result, MockPolicyResponse):
            payload["mock_only"] = True
        elif isinstance(result, RoleDowngradeResponse):
            payload["principal_id"] = result.principal_id.value
            payload["queue_job_id"] = result.queue_job_id.value
        elif isinstance(result, ReferenceResponse):
            payload["reference_id"] = result.reference_id.value
            payload["document_id"] = result.document_id.value
        elif isinstance(result, ClockResponse):
            payload["clock_now"] = result.now.astimezone(UTC).isoformat().replace("+00:00", "Z")

        # No result body is ever copied. Audit this adapter-created payload as well.
        _assert_redacted(payload)
        observation_hash = canonical_sha256(
            {
                "action_id": envelope.action_id,
                "idempotency_key": envelope.idempotency_key,
                "evidence_id": evidence.evidence_id,
                "payload": payload,
            }
        ).removeprefix("sha256:")
        return ReplayObservation(
            observation_id=f"observation.{observation_hash[:24]}",
            kind=f"lab.{lab_action.action_type}",
            payload=payload,
            evidence_ids=(evidence.evidence_id,),
        )


def _response_model_for(lab_action: LabAction) -> type[BaseModel]:
    if isinstance(
        lab_action,
        (RetainSessionLabAction, PrimeAuthorizationCacheLabAction, DeferQueueLabAction),
    ):
        return ActionReceipt
    if isinstance(lab_action, DowngradeRoleLabAction):
        return RoleDowngradeResponse
    if isinstance(lab_action, (PublishReferenceLabAction, ClaimReferenceLabAction)):
        return ReferenceResponse
    if isinstance(lab_action, AdvanceClockLabAction):
        return ClockResponse
    if isinstance(lab_action, ReadDocumentLabAction):
        return DocumentResponse
    if isinstance(lab_action, MaskedReadLabAction):
        return MaskedDocumentResponse
    if isinstance(lab_action, MockPolicyLabAction):
        return MockPolicyResponse
    raise LabExecutionRejectedError("registered lab action has no ASGI response model")


def _http_action(envelope: ActionEnvelope) -> HttpRequestAction:
    action = envelope.action
    if not isinstance(action, HttpRequestAction):
        raise LabExecutionRejectedError("runtime execution requires an HTTP action")
    return action


def _app_route_signature(
    app: FastAPI,
) -> tuple[tuple[str, str, tuple[str, ...], int, int], ...]:
    signature: list[tuple[str, str, tuple[str, ...], int, int]] = []
    for route in app.routes:
        path = getattr(route, "path", "")
        pattern = getattr(getattr(route, "path_regex", None), "pattern", "")
        methods = getattr(route, "methods", None)
        endpoint = getattr(route, "endpoint", None)
        dependent_call = getattr(getattr(route, "dependant", None), "call", None)
        signature.append(
            (
                str(path),
                str(pattern),
                tuple(sorted(methods)) if isinstance(methods, set) else (),
                id(endpoint),
                id(dependent_call),
            )
        )
    return tuple(signature)


def _app_middleware_signature(
    app: FastAPI,
) -> tuple[tuple[str, tuple[tuple[str, str], ...]], ...]:
    signature: list[tuple[str, tuple[tuple[str, str], ...]]] = []
    for middleware in app.user_middleware:
        middleware_type = middleware.cls
        middleware_module = getattr(middleware_type, "__module__", "unknown")
        middleware_qualname = getattr(middleware_type, "__qualname__", "unknown")
        values: list[tuple[str, str]] = []
        for key, value in middleware.kwargs.items():
            encoded = f"callable:{id(value)}" if callable(value) else canonical_sha256(value)
            values.append((key, encoded))
        signature.append(
            (
                f"{middleware_module}.{middleware_qualname}",
                tuple(sorted(values)),
            )
        )
    return tuple(signature)


__all__ = [
    "ADAPTER_NAME",
    "ADAPTER_VERSION",
    "CANONICAL_RANDOM_SEED",
    "InProcessLabEnvironment",
    "InProcessLabRuntimeExecution",
]
