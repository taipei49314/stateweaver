"""Deterministic, socket-free ReplayEnvironment implementation."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Final, cast

from pydantic import BaseModel, JsonValue
from stateweaver.contracts import ActionEnvelope
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
    LabActionError,
    LabActionResult,
    LabMode,
    LayeredStateCapture,
)
from stateweaver_lab.fixtures import CANONICAL_SEED, FixtureBearer
from stateweaver_lab.models import (
    ClockResponse,
    DocumentResponse,
    EvidenceRecordResponse,
    MaskedDocumentResponse,
    MockPolicyResponse,
    ReferenceResponse,
    RoleDowngradeResponse,
)

from .errors import (
    AdapterConfigurationError,
    LabCaptureRejectedError,
    LabEvidenceRejectedError,
    LabExecutionRejectedError,
    LabIdempotencyConflictError,
)
from .registry import (
    FixedLabActionRegistry,
    LabAction,
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
        self._service = DeterministicLabService.seed(mode)
        self._registry = registry
        self._lock = asyncio.Lock()
        self._active = False
        self._idempotency_cache: dict[str, tuple[str, tuple[ReplayObservation, ...]]] = {}
        self._last_observations: tuple[ReplayObservation, ...] = ()
        self._requests_used = 0
        self._write_requests_used = 0

        from .oracle import InProcessLabReplayOracle

        self._oracle = InProcessLabReplayOracle(self._service)

    @property
    def mode(self) -> LabMode:
        return self._service.mode

    @property
    def oracle(self) -> InProcessLabReplayOracle:
        from .oracle import InProcessLabReplayOracle

        assert isinstance(self._oracle, InProcessLabReplayOracle)
        return self._oracle

    @property
    def last_observations(self) -> tuple[ReplayObservation, ...]:
        return self._last_observations

    @property
    def evidence_records(self) -> tuple[EvidenceRecordResponse, ...]:
        """Return the synthetic, body-free audit records for the current run."""

        records = self._service.evidence().records
        for record in records:
            _assert_redacted(_model_payload(record))
        return records

    async def create_root_seed(self, *, root_seed_id: str, random_seed: int) -> RootSeed:
        """Reset and pin the only canonical seed supported by the synthetic lab."""

        if random_seed != CANONICAL_RANDOM_SEED:
            raise AdapterConfigurationError("the requested random seed is unsupported")
        async with self._lock:
            self._service.reset()
            self._activate_clean_run()
            capture = self._capture_unlocked()
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

        self._validate_root(root)
        async with self._lock:
            self._service.reset()
            self._activate_clean_run()
            return self._capture_unlocked()

    async def capture(self) -> StateCapture:
        """Capture all seven real, redacted lab layers without private-state access."""

        async with self._lock:
            return self._capture_unlocked()

    async def execute(self, action: ActionEnvelope) -> tuple[ReplayObservation, ...]:
        """Translate through a fixed registry, enforce policy, and execute in memory."""

        if not isinstance(action, ActionEnvelope):
            raise LabExecutionRejectedError("execution requires an ActionEnvelope")
        async with self._lock:
            if not self._active:
                raise LabExecutionRejectedError("the environment must be reset before execution")

            envelope_hash = canonical_sha256(action)
            cached = self._idempotency_cache.get(action.idempotency_key)
            if cached is not None:
                cached_hash, observations = cached
                if cached_hash != envelope_hash:
                    raise LabIdempotencyConflictError("idempotency key semantics changed")
                self._last_observations = observations
                return observations

            lab_action = self._registry.resolve(action)
            validate_fixed_http_envelope(action, lab_action)
            authorization = self._registry.require_policy_allows(
                action,
                at=self._service.capture().now,
                requests_used=self._requests_used,
                write_requests_used=self._write_requests_used,
            )
            self._requests_used += 1
            if authorization.is_write:
                self._write_requests_used += 1
            try:
                observations = self._execute_uncached(action, lab_action)
            except Exception:
                # A reservation is irreversible. Unknown post-reservation state poisons this run.
                self._active = False
                raise
            self._idempotency_cache[action.idempotency_key] = (envelope_hash, observations)
            self._last_observations = observations
            return observations

    async def cleanup(self) -> None:
        """Close the run boundary; repeated cleanup calls are safe."""

        async with self._lock:
            self._active = False
            self._idempotency_cache.clear()

    def _activate_clean_run(self) -> None:
        self._active = True
        self._idempotency_cache.clear()
        self._last_observations = ()
        self._requests_used = 0
        self._write_requests_used = 0
        self._oracle.reset_diagnostics()

    def _validate_root(self, root: RootSeed) -> None:
        if not isinstance(root, RootSeed):
            raise AdapterConfigurationError("reset requires a RootSeed")
        if root.target_version != _target_version(self.mode):
            raise AdapterConfigurationError("root target version does not match the lab mode")
        if root.random_seed != CANONICAL_RANDOM_SEED:
            raise AdapterConfigurationError("root random seed is unsupported")
        if root.adapter_versions != {ADAPTER_NAME: ADAPTER_VERSION}:
            raise AdapterConfigurationError("root adapter version pins are missing or unknown")
        if {artifact.layer for artifact in root.capture.artifacts} != _EXPECTED_LAYERS:
            raise AdapterConfigurationError("root capture does not contain exactly seven layers")

    def _capture_unlocked(self) -> StateCapture:
        raw = self._service.capture_layers()
        self._validate_source_capture(raw)
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
        digest = self._service.capture()
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
        if raw.configuration.mode is not self.mode:
            raise LabCaptureRejectedError("lab capture mode changed")
        if (
            raw.configuration.network_scope != "in-process-only"
            or raw.configuration.external_egress_enabled
            or raw.configuration.arbitrary_actions_enabled
            or raw.clock.mode != "controlled"
        ):
            raise LabCaptureRejectedError("lab capture crossed the in-process safety boundary")

    def _execute_uncached(
        self,
        envelope: ActionEnvelope,
        lab_action: LabAction,
    ) -> tuple[ReplayObservation, ...]:
        before_records = self._service.evidence().records
        result: LabActionResult | None
        error_code: str | None = None
        try:
            result = self._service.execute(lab_action)
            status_code = 200
        except LabActionError as exc:
            result = None
            status_code = exc.status_code
            error_code = exc.code

        spec = lab_http_action_spec(lab_action)
        if status_code not in spec.expected_statuses:
            raise LabExecutionRejectedError("lab outcome was outside the registered status set")

        after_records = self._service.evidence().records
        evidence = self._correlate_new_evidence(before_records, after_records)
        observation = self._build_observation(
            envelope=envelope,
            lab_action=lab_action,
            result=result,
            evidence=evidence,
            status_code=status_code,
            error_code=error_code,
        )
        return (observation,)

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


__all__ = [
    "ADAPTER_NAME",
    "ADAPTER_VERSION",
    "CANONICAL_RANDOM_SEED",
    "InProcessLabEnvironment",
]
