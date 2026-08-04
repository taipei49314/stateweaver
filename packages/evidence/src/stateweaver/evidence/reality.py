"""Immutable-byte resolution for non-authoritative M6 pre-receipt bundles.

This module deliberately stops before issuer authentication or Finding promotion.  It accepts
only serialized claims plus an in-memory byte mapping, snapshots every mapping value once, and
uses those exact bytes for both hashing and typed parsing.  A successful result is a candidate
for a future trusted attestation service, never an attestation itself.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    TypeAdapter,
    ValidationError,
    field_validator,
    model_validator,
)
from stateweaver.contracts import (
    ContractId,
    EnvironmentMode,
    NegativeControlKind,
    OracleResult,
    ProvenanceKind,
    RealityAnchorMode,
    RealityReplayReceipt,
    ScopeManifest,
    Sha256Digest,
    canonical_json_bytes,
    sha256_digest,
)
from stateweaver.replay import (
    ReplayActionLogEntry,
    ReplayPlan,
    ReplayRunResult,
    ReplayRunStatus,
    RootSeed,
)

from ._io import EvidenceInputError, assert_secret_free
from .semantic_trace import (
    RealityTraceArtifact,
    RealityTraceEvent,
    RealityTraceEventKind,
    RealityTraceEventType,
    RealityTraceFact,
    RealityTraceLane,
)

_PROFILE: Literal["source-backed-synthetic-v2"] = "source-backed-synthetic-v2"
_PATH_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)*$")
_FORBIDDEN_PATH_MARKERS = ("manifest", "receipt", "finding", "report", "attestation")

Token = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
]
SafeArtifactPath = Annotated[
    str,
    StringConstraints(min_length=3, max_length=240, pattern=_PATH_RE.pattern),
]
JsonScalar = str | int | float | bool | None


class _RealityModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
        str_strip_whitespace=True,
    )

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self)


class RealityArtifactRole(StrEnum):
    SCOPE = "scope"
    TARGET_LOCK = "target-lock"
    ADAPTER_LOCK = "adapter-lock"
    CHAIN = "chain"
    ROOT = "root"
    PLAN = "plan"
    PRIMARY_ORACLES = "primary-oracles"
    EVIDENCE_INDEX = "evidence-index"
    PRIMARY_RESULT = "primary-result"
    PRIMARY_ACTION_LOG = "primary-action-log"
    PRIMARY_TRACE = "primary-trace"
    CONTROL_PLAN = "control-plan"
    CONTROL_RESULT = "control-result"
    CONTROL_ACTION_LOG = "control-action-log"
    CONTROL_TRACE = "control-trace"
    CONTROL_ORACLES = "control-oracles"
    CONTROL_DELTA = "control-delta"
    PATCH_TARGET_LOCK = "patch-target-lock"
    PATCH_ROOT = "patch-root"
    PATCH_RESULT = "patch-result"
    PATCH_ACTION_LOG = "patch-action-log"
    PATCH_TRACE = "patch-trace"
    PATCH_ORACLES = "patch-oracles"


_PRIMARY_RUN_ROLES = frozenset(
    {
        RealityArtifactRole.PRIMARY_RESULT,
        RealityArtifactRole.PRIMARY_ACTION_LOG,
        RealityArtifactRole.PRIMARY_TRACE,
    }
)
_CONTROL_ROLES = frozenset(
    {
        RealityArtifactRole.CONTROL_PLAN,
        RealityArtifactRole.CONTROL_RESULT,
        RealityArtifactRole.CONTROL_ACTION_LOG,
        RealityArtifactRole.CONTROL_TRACE,
        RealityArtifactRole.CONTROL_ORACLES,
        RealityArtifactRole.CONTROL_DELTA,
    }
)
_PATCH_ROLES = frozenset(
    {
        RealityArtifactRole.PATCH_TARGET_LOCK,
        RealityArtifactRole.PATCH_ROOT,
        RealityArtifactRole.PATCH_RESULT,
        RealityArtifactRole.PATCH_ACTION_LOG,
        RealityArtifactRole.PATCH_TRACE,
        RealityArtifactRole.PATCH_ORACLES,
    }
)


class RealityManifestEntry(_RealityModel):
    role: RealityArtifactRole
    path: SafeArtifactPath
    sha256: Sha256Digest
    run_id: ContractId | None = None
    control_name: Token | None = None

    @model_validator(mode="after")
    def role_has_exact_identity_shape(self) -> RealityManifestEntry:
        if self.role in _PRIMARY_RUN_ROLES | _PATCH_ROLES:
            if self.run_id is None or self.control_name is not None:
                raise ValueError("replay artifact role requires only a run id")
        elif self.role in _CONTROL_ROLES:
            if self.run_id is None or self.control_name is None:
                raise ValueError("control artifact role requires run id and control name")
        elif self.run_id is not None or self.control_name is not None:
            raise ValueError("static artifact role cannot carry replay identity")
        return self


class RealityEvidenceManifestV2(_RealityModel):
    schema_version: Literal["reality-pre-receipt-v2"] = "reality-pre-receipt-v2"
    profile: Literal["source-backed-synthetic-v2"] = _PROFILE
    entries: Annotated[tuple[RealityManifestEntry, ...], Field(min_length=1)]

    @field_validator("entries")
    @classmethod
    def entries_are_canonical_and_unique(
        cls, value: tuple[RealityManifestEntry, ...]
    ) -> tuple[RealityManifestEntry, ...]:
        paths = tuple(entry.path for entry in value)
        if paths != tuple(sorted(paths)):
            raise ValueError("manifest entries must use canonical path order")
        if len(paths) != len(set(paths)):
            raise ValueError("manifest entry paths must be unique")
        return value


class RealityScopeArtifact(_RealityModel):
    schema_version: Literal["1.0"] = "1.0"
    scope_id: ContractId
    manifest: ScopeManifest


class RealityTargetLock(_RealityModel):
    schema_version: Literal["1.0"] = "1.0"
    target_id: ContractId
    target_version: Token
    source_sha256: Sha256Digest


class RealityAdapterComponent(_RealityModel):
    adapter_id: Token
    version: Token
    source_sha256: Sha256Digest


class RealityAdapterLock(_RealityModel):
    schema_version: Literal["1.0"] = "1.0"
    entries: Annotated[tuple[RealityAdapterComponent, ...], Field(min_length=1)]

    @field_validator("entries")
    @classmethod
    def entries_are_canonical_and_unique(
        cls, value: tuple[RealityAdapterComponent, ...]
    ) -> tuple[RealityAdapterComponent, ...]:
        names = tuple(entry.adapter_id for entry in value)
        if names != tuple(sorted(names)) or len(names) != len(set(names)):
            raise ValueError("adapter lock entries must be unique and ordered")
        return value


class RealityChainBinding(_RealityModel):
    schema_version: Literal["1.0"] = "1.0"
    chain_id: ContractId
    plan_id: ContractId
    plan_hash: Sha256Digest


class RealityDeltaChange(_RealityModel):
    state_path: Token
    before_sha256: Sha256Digest
    after_sha256: Sha256Digest

    @model_validator(mode="after")
    def change_is_nonvacuous(self) -> RealityDeltaChange:
        if self.before_sha256 == self.after_sha256:
            raise ValueError("control delta must change the selected state")
        return self


class RealityControlDelta(_RealityModel):
    schema_version: Literal["1.0"] = "1.0"
    control_name: Token
    kind: NegativeControlKind
    changes: Annotated[tuple[RealityDeltaChange, ...], Field(min_length=1)]

    @field_validator("changes")
    @classmethod
    def changes_are_canonical_and_unique(
        cls, value: tuple[RealityDeltaChange, ...]
    ) -> tuple[RealityDeltaChange, ...]:
        paths = tuple(change.state_path for change in value)
        if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
            raise ValueError("control delta paths must be unique and ordered")
        return value


class RealityEvidenceFact(_RealityModel):
    name: Token
    value: JsonScalar

    @field_validator("value")
    @classmethod
    def scalar_is_finite(cls, value: JsonScalar) -> JsonScalar:
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("evidence values must be finite")
        return value


class RealityEvidenceItem(_RealityModel):
    evidence_id: ContractId
    provenance: Literal[ProvenanceKind.OBSERVED]
    facts: Annotated[tuple[RealityEvidenceFact, ...], Field(min_length=1)]
    payload_sha256: Sha256Digest

    @model_validator(mode="after")
    def payload_hash_and_facts_are_canonical(self) -> RealityEvidenceItem:
        names = tuple(fact.name for fact in self.facts)
        if names != tuple(sorted(names)) or len(names) != len(set(names)):
            raise ValueError("evidence fact names must be unique and ordered")
        if self.payload_sha256 != sha256_digest(self.facts):
            raise ValueError("evidence payload hash does not match its facts")
        return self


class RealityEvidenceIndex(_RealityModel):
    schema_version: Literal["1.0"] = "1.0"
    items: Annotated[tuple[RealityEvidenceItem, ...], Field(min_length=1)]

    @field_validator("items")
    @classmethod
    def items_are_canonical_and_unique(
        cls, value: tuple[RealityEvidenceItem, ...]
    ) -> tuple[RealityEvidenceItem, ...]:
        identities = tuple(item.evidence_id for item in value)
        if identities != tuple(sorted(identities)) or len(identities) != len(set(identities)):
            raise ValueError("evidence items must be unique and ordered")
        return value


@dataclass(frozen=True)
class RealityBundleVerificationResult:
    """Result of byte-level causal resolution; never a promotion credential."""

    valid: bool
    errors: tuple[str, ...]
    receipt_hash: str | None = None
    pre_receipt_manifest_sha256: str | None = None
    snapshot_sha256: str | None = None
    profile: str | None = None
    event_semantics_verified: bool = False
    primary_semantic_trace_hash: str | None = None

    @property
    def promotable(self) -> Literal[False]:
        return False

    @property
    def authoritative(self) -> Literal[False]:
        return False


class _RealityVerificationError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _EntryResolver:
    def __init__(self, entries: tuple[RealityManifestEntry, ...]) -> None:
        self._entries = entries
        self._used: set[str] = set()

    def one(
        self,
        role: RealityArtifactRole,
        *,
        run_id: str | None = None,
        control_name: str | None = None,
    ) -> RealityManifestEntry:
        matches = tuple(
            entry
            for entry in self._entries
            if entry.role is role and entry.run_id == run_id and entry.control_name == control_name
        )
        if len(matches) != 1:
            raise _RealityVerificationError("manifest-role-closure-invalid")
        entry = matches[0]
        if entry.path in self._used:
            raise _RealityVerificationError("manifest-role-closure-invalid")
        self._used.add(entry.path)
        return entry

    def require_complete(self) -> None:
        if self._used != {entry.path for entry in self._entries}:
            raise _RealityVerificationError("manifest-role-closure-invalid")


_ORACLE_VECTOR = TypeAdapter(tuple[OracleResult, ...])
_ACTION_LOG_VECTOR = TypeAdapter(tuple[ReplayActionLogEntry, ...])


def _tagged_sha256(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def _safe_artifact_path(path: object) -> bool:
    if type(path) is not str or not path.isascii() or _PATH_RE.fullmatch(path) is None:
        return False
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return False
    lowered = tuple(part.lower() for part in parts)
    return not any(marker in part for part in lowered for marker in _FORBIDDEN_PATH_MARKERS)


def _snapshot_artifacts(artifacts: Mapping[str, bytes]) -> dict[str, bytes]:
    try:
        keys = tuple(artifacts)
    except (RuntimeError, TypeError) as error:
        raise _RealityVerificationError("artifact-snapshot-invalid") from error
    if not keys or len(keys) != len(set(keys)):
        raise _RealityVerificationError("artifact-snapshot-invalid")
    snapshot: dict[str, bytes] = {}
    try:
        for path in keys:
            if not _safe_artifact_path(path):
                raise _RealityVerificationError("artifact-path-invalid")
            content = artifacts[path]
            if type(content) is not bytes:
                raise _RealityVerificationError("artifact-snapshot-invalid")
            snapshot[path] = content
    except (KeyError, RuntimeError, TypeError) as error:
        raise _RealityVerificationError("artifact-snapshot-invalid") from error
    return snapshot


def _snapshot_sha256(manifest_json: bytes, artifacts: Mapping[str, bytes]) -> str:
    digest = hashlib.sha256()
    components = (("@pre-receipt-manifest", manifest_json), *sorted(artifacts.items()))
    for path, content in components:
        encoded_path = path.encode("ascii")
        digest.update(len(encoded_path).to_bytes(4, "big"))
        digest.update(encoded_path)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return f"sha256:{digest.hexdigest()}"


def _assert_canonical_safe_json(content: bytes) -> object:
    try:
        value: object = json.loads(content.decode("utf-8"))
        assert_secret_free(value)
        if canonical_json_bytes(value) != content:
            raise _RealityVerificationError("artifact-json-not-canonical")
        return value
    except _RealityVerificationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, EvidenceInputError, ValueError) as error:
        raise _RealityVerificationError("artifact-json-invalid") from error


def _parse_model[ModelT: BaseModel](model_type: type[ModelT], content: bytes) -> ModelT:
    _assert_canonical_safe_json(content)
    try:
        return model_type.model_validate_json(content)
    except ValidationError as error:
        raise _RealityVerificationError("artifact-schema-invalid") from error


def _parse_vector[VectorT](adapter: TypeAdapter[VectorT], content: bytes) -> VectorT:
    _assert_canonical_safe_json(content)
    try:
        return adapter.validate_json(content)
    except ValidationError as error:
        raise _RealityVerificationError("artifact-schema-invalid") from error


def _artifact(
    entry: RealityManifestEntry,
    snapshot: Mapping[str, bytes],
    *,
    expected_sha256: str | None = None,
) -> bytes:
    content = snapshot[entry.path]
    if expected_sha256 is not None and entry.sha256 != expected_sha256:
        raise _RealityVerificationError("receipt-artifact-digest-mismatch")
    return content


def _root_matches(
    root: RootSeed,
    *,
    root_seed_id: str,
    target_version: str,
    root_fingerprint: str,
    adapter_lock: RealityAdapterLock,
) -> bool:
    versions = {entry.adapter_id: entry.version for entry in adapter_lock.entries}
    return (
        root.root_seed_id == root_seed_id
        and root.target_version == target_version
        and root.capture.fingerprint == root_fingerprint
        and dict(root.adapter_versions) == versions
    )


def _result_oracles(result: ReplayRunResult) -> tuple[OracleResult, ...]:
    return tuple(oracle for step in result.steps for oracle in step.oracle_results)


def _oracle_evidence(oracles: tuple[OracleResult, ...]) -> set[str]:
    return {evidence_id for oracle in oracles for evidence_id in oracle.evidence_ids}


def _verify_result_projection(
    *,
    plan: ReplayPlan,
    result: ReplayRunResult,
    action_log: tuple[ReplayActionLogEntry, ...],
    trace: RealityTraceArtifact,
    expected_lane: RealityTraceLane,
    expected_run_id: str,
    expected_plan_id: str,
    expected_root_fingerprint: str,
    expected_trace_hash: str,
    expected_signature: str,
    expected_oracles: tuple[OracleResult, ...],
    expected_evidence_ids: tuple[str, ...],
    expected_status: ReplayRunStatus,
) -> str:
    if (
        result.run_id != expected_run_id
        or result.plan_id != expected_plan_id
        or result.root_fingerprint != expected_root_fingerprint
        or result.trace_hash != expected_trace_hash
        or trace.replay_trace_hash != expected_trace_hash
        or result.deterministic_signature() != expected_signature
        or result.status is not expected_status
        or result.action_log != action_log
        or _result_oracles(result) != expected_oracles
        or set(expected_evidence_ids) != _oracle_evidence(expected_oracles)
    ):
        raise _RealityVerificationError("replay-causal-binding-mismatch")
    planned_step_ids = tuple(step.step_id for step in plan.steps)
    if (
        result.plan_id != plan.plan_id
        or tuple(step.step_id for step in result.steps) != planned_step_ids
        or tuple(entry.step_id for entry in result.action_log) != planned_step_ids
        or any(
            entry.action != planned.action
            for planned, entry in zip(plan.steps, result.action_log, strict=True)
        )
    ):
        raise _RealityVerificationError("replay-plan-execution-mismatch")
    expected_trace = RealityTraceArtifact.from_replay_result(result, lane=expected_lane)
    if trace != expected_trace:
        raise _RealityVerificationError("replay-trace-semantics-mismatch")
    return trace.semantic_trace_hash


def _verify_static_artifacts(
    *,
    receipt: RealityReplayReceipt,
    resolver: _EntryResolver,
    snapshot: Mapping[str, bytes],
) -> tuple[RealityAdapterLock, ReplayPlan, RootSeed]:
    scope_entry = resolver.one(RealityArtifactRole.SCOPE)
    scope_artifact = _parse_model(
        RealityScopeArtifact,
        _artifact(scope_entry, snapshot, expected_sha256=receipt.scope_manifest_sha256),
    )
    if (
        scope_artifact.scope_id != receipt.scope_id
        or scope_artifact.manifest.spec.environment_mode is not EnvironmentMode.SOURCE_BACKED
        or receipt.anchor_mode is not RealityAnchorMode.SOURCE_BACKED
    ):
        raise _RealityVerificationError("scope-binding-mismatch")

    target_entry = resolver.one(RealityArtifactRole.TARGET_LOCK)
    target = _parse_model(
        RealityTargetLock,
        _artifact(target_entry, snapshot, expected_sha256=receipt.target_lock_sha256),
    )
    if target.target_id != receipt.target_id or target.target_version != receipt.target_version:
        raise _RealityVerificationError("target-binding-mismatch")

    adapter_entry = resolver.one(RealityArtifactRole.ADAPTER_LOCK)
    adapter = _parse_model(
        RealityAdapterLock,
        _artifact(adapter_entry, snapshot, expected_sha256=receipt.adapter_lock_sha256),
    )

    root_entry = resolver.one(RealityArtifactRole.ROOT)
    root = _parse_model(RootSeed, _artifact(root_entry, snapshot))
    if not _root_matches(
        root,
        root_seed_id=receipt.root_seed_id,
        target_version=receipt.target_version,
        root_fingerprint=receipt.root_fingerprint,
        adapter_lock=adapter,
    ):
        raise _RealityVerificationError("root-binding-mismatch")

    plan_entry = resolver.one(RealityArtifactRole.PLAN)
    plan = _parse_model(
        ReplayPlan,
        _artifact(plan_entry, snapshot, expected_sha256=receipt.plan_hash),
    )
    if plan.plan_id != receipt.plan_id or plan.root_seed_id != receipt.root_seed_id:
        raise _RealityVerificationError("plan-binding-mismatch")

    chain_entry = resolver.one(RealityArtifactRole.CHAIN)
    chain = _parse_model(RealityChainBinding, _artifact(chain_entry, snapshot))
    if (
        chain.chain_id != receipt.chain_id
        or chain.plan_id != receipt.plan_id
        or chain.plan_hash != receipt.plan_hash
    ):
        raise _RealityVerificationError("chain-binding-mismatch")
    return adapter, plan, root


def _verify_primary_attempts(
    *,
    receipt: RealityReplayReceipt,
    plan: ReplayPlan,
    resolver: _EntryResolver,
    snapshot: Mapping[str, bytes],
) -> str:
    oracle_entry = resolver.one(RealityArtifactRole.PRIMARY_ORACLES)
    primary_oracles = _parse_vector(_ORACLE_VECTOR, _artifact(oracle_entry, snapshot))
    if primary_oracles != receipt.oracle_results:
        raise _RealityVerificationError("oracle-binding-mismatch")
    semantic_trace_hashes: set[str] = set()
    for attempt in receipt.attempts:
        result_entry = resolver.one(
            RealityArtifactRole.PRIMARY_RESULT, run_id=attempt.replay_run_id
        )
        log_entry = resolver.one(
            RealityArtifactRole.PRIMARY_ACTION_LOG, run_id=attempt.replay_run_id
        )
        trace_entry = resolver.one(RealityArtifactRole.PRIMARY_TRACE, run_id=attempt.replay_run_id)
        result = _parse_model(
            ReplayRunResult,
            _artifact(result_entry, snapshot, expected_sha256=attempt.replay_result_sha256),
        )
        action_log = _parse_vector(
            _ACTION_LOG_VECTOR,
            _artifact(log_entry, snapshot, expected_sha256=attempt.action_log_sha256),
        )
        trace = _parse_model(
            RealityTraceArtifact,
            _artifact(trace_entry, snapshot),
        )
        if oracle_entry.sha256 != attempt.oracle_results_hash:
            raise _RealityVerificationError("oracle-binding-mismatch")
        semantic_trace_hashes.add(
            _verify_result_projection(
                plan=plan,
                result=result,
                action_log=action_log,
                trace=trace,
                expected_lane=RealityTraceLane.PRIMARY,
                expected_run_id=attempt.replay_run_id,
                expected_plan_id=attempt.plan_id,
                expected_root_fingerprint=attempt.root_fingerprint,
                expected_trace_hash=attempt.trace_hash,
                expected_signature=attempt.semantic_signature,
                expected_oracles=primary_oracles,
                expected_evidence_ids=attempt.evidence_ids,
                expected_status=ReplayRunStatus.SUCCEEDED,
            )
        )
    if len(semantic_trace_hashes) != 1:
        raise _RealityVerificationError("replay-trace-semantics-mismatch")
    return semantic_trace_hashes.pop()


def _verify_controls(
    *,
    receipt: RealityReplayReceipt,
    resolver: _EntryResolver,
    snapshot: Mapping[str, bytes],
) -> None:
    for control in receipt.negative_controls:
        selector = {"run_id": control.replay_run_id, "control_name": control.name}
        plan_entry = resolver.one(RealityArtifactRole.CONTROL_PLAN, **selector)
        result_entry = resolver.one(RealityArtifactRole.CONTROL_RESULT, **selector)
        log_entry = resolver.one(RealityArtifactRole.CONTROL_ACTION_LOG, **selector)
        trace_entry = resolver.one(RealityArtifactRole.CONTROL_TRACE, **selector)
        oracle_entry = resolver.one(RealityArtifactRole.CONTROL_ORACLES, **selector)
        delta_entry = resolver.one(RealityArtifactRole.CONTROL_DELTA, **selector)

        plan = _parse_model(
            ReplayPlan,
            _artifact(plan_entry, snapshot, expected_sha256=control.plan_hash),
        )
        result = _parse_model(
            ReplayRunResult,
            _artifact(result_entry, snapshot, expected_sha256=control.replay_result_sha256),
        )
        action_log = _parse_vector(
            _ACTION_LOG_VECTOR,
            _artifact(log_entry, snapshot, expected_sha256=control.action_log_sha256),
        )
        trace = _parse_model(
            RealityTraceArtifact,
            _artifact(trace_entry, snapshot),
        )
        oracles = _parse_vector(
            _ORACLE_VECTOR,
            _artifact(oracle_entry, snapshot, expected_sha256=control.oracle_results_hash),
        )
        delta = _parse_model(
            RealityControlDelta,
            _artifact(delta_entry, snapshot, expected_sha256=control.control_delta_sha256),
        )
        if (
            plan.plan_id != control.plan_id
            or plan.root_seed_id != control.root_seed_id
            or oracles != control.oracle_results
            or delta.control_name != control.name
            or delta.kind is not control.kind
        ):
            raise _RealityVerificationError("control-binding-mismatch")
        _verify_result_projection(
            plan=plan,
            result=result,
            action_log=action_log,
            trace=trace,
            expected_lane=RealityTraceLane.CONTROL,
            expected_run_id=control.replay_run_id,
            expected_plan_id=control.plan_id,
            expected_root_fingerprint=control.root_fingerprint,
            expected_trace_hash=control.trace_hash,
            expected_signature=control.semantic_signature,
            expected_oracles=oracles,
            expected_evidence_ids=control.evidence_ids,
            expected_status=ReplayRunStatus.SUCCEEDED,
        )


def _verify_patch(
    *,
    receipt: RealityReplayReceipt,
    adapter_lock: RealityAdapterLock,
    plan: ReplayPlan,
    primary_root: RootSeed,
    resolver: _EntryResolver,
    snapshot: Mapping[str, bytes],
) -> None:
    patch = receipt.patched_version
    if patch is None:
        return
    selector = {"run_id": patch.replay_run_id}
    target_entry = resolver.one(RealityArtifactRole.PATCH_TARGET_LOCK, **selector)
    root_entry = resolver.one(RealityArtifactRole.PATCH_ROOT, **selector)
    result_entry = resolver.one(RealityArtifactRole.PATCH_RESULT, **selector)
    log_entry = resolver.one(RealityArtifactRole.PATCH_ACTION_LOG, **selector)
    trace_entry = resolver.one(RealityArtifactRole.PATCH_TRACE, **selector)
    oracle_entry = resolver.one(RealityArtifactRole.PATCH_ORACLES, **selector)

    target = _parse_model(
        RealityTargetLock,
        _artifact(target_entry, snapshot, expected_sha256=patch.target_lock_sha256),
    )
    root = _parse_model(RootSeed, _artifact(root_entry, snapshot))
    result = _parse_model(
        ReplayRunResult,
        _artifact(result_entry, snapshot, expected_sha256=patch.replay_result_sha256),
    )
    action_log = _parse_vector(
        _ACTION_LOG_VECTOR,
        _artifact(log_entry, snapshot, expected_sha256=patch.action_log_sha256),
    )
    trace = _parse_model(
        RealityTraceArtifact,
        _artifact(trace_entry, snapshot),
    )
    oracles = _parse_vector(
        _ORACLE_VECTOR,
        _artifact(oracle_entry, snapshot, expected_sha256=patch.oracle_results_hash),
    )
    failed = next((step for step in result.steps if step.step_id == patch.failed_step_id), None)
    if (
        target.target_id != patch.target_id
        or target.target_version != patch.target_version
        or not _root_matches(
            root,
            root_seed_id=patch.root_seed_id,
            target_version=patch.target_version,
            root_fingerprint=patch.root_fingerprint,
            adapter_lock=adapter_lock,
        )
        or patch.root_seed_id != primary_root.root_seed_id
        or root.random_seed != primary_root.random_seed
        or root.clock_epoch != primary_root.clock_epoch
        or root.capture != primary_root.capture
        or dict(root.adapter_versions) != dict(primary_root.adapter_versions)
        or plan.plan_id != patch.plan_id
        or oracles != patch.oracle_results
        or result.failed_step_id != patch.failed_step_id
        or failed is None
        or failed.failure_code != patch.failure_code
        or patch.failure_code != "ORACLE_EXPECTATION_MISMATCH"
    ):
        raise _RealityVerificationError("patch-binding-mismatch")
    _verify_result_projection(
        plan=plan,
        result=result,
        action_log=action_log,
        trace=trace,
        expected_lane=RealityTraceLane.PATCH,
        expected_run_id=patch.replay_run_id,
        expected_plan_id=patch.plan_id,
        expected_root_fingerprint=patch.root_fingerprint,
        expected_trace_hash=patch.trace_hash,
        expected_signature=patch.semantic_signature,
        expected_oracles=oracles,
        expected_evidence_ids=patch.evidence_ids,
        expected_status=ReplayRunStatus.FAILED,
    )


def _verify_evidence_index(
    *,
    receipt: RealityReplayReceipt,
    resolver: _EntryResolver,
    snapshot: Mapping[str, bytes],
) -> None:
    entry = resolver.one(RealityArtifactRole.EVIDENCE_INDEX)
    index = _parse_model(RealityEvidenceIndex, _artifact(entry, snapshot))
    expected = {evidence_id for attempt in receipt.attempts for evidence_id in attempt.evidence_ids}
    expected.update(
        evidence_id for control in receipt.negative_controls for evidence_id in control.evidence_ids
    )
    if receipt.patched_version is not None:
        expected.update(receipt.patched_version.evidence_ids)
    if {item.evidence_id for item in index.items} != expected:
        raise _RealityVerificationError("evidence-coverage-mismatch")


def verify_reality_pre_receipt_bundle(
    *,
    receipt_json: bytes,
    manifest_json: bytes,
    artifacts: Mapping[str, bytes],
) -> RealityBundleVerificationResult:
    """Resolve a synthetic source-backed candidate from one immutable byte snapshot.

    No filesystem path, model instance, issuer claim, signature string, or caller-supplied
    ``verified`` boolean is accepted.  The result is always ``promotable=False``.
    """

    try:
        if type(receipt_json) is not bytes or type(manifest_json) is not bytes:
            raise _RealityVerificationError("serialized-input-required")
        receipt = _parse_model(RealityReplayReceipt, receipt_json)
        manifest = _parse_model(RealityEvidenceManifestV2, manifest_json)
        manifest_sha256 = _tagged_sha256(manifest_json)
        if receipt.pre_receipt_evidence_manifest_sha256 != manifest_sha256:
            raise _RealityVerificationError("manifest-receipt-digest-mismatch")

        snapshot = _snapshot_artifacts(artifacts)
        if set(snapshot) != {entry.path for entry in manifest.entries}:
            raise _RealityVerificationError("artifact-coverage-mismatch")
        for entry in manifest.entries:
            if _tagged_sha256(snapshot[entry.path]) != entry.sha256:
                raise _RealityVerificationError("artifact-digest-mismatch")

        resolver = _EntryResolver(manifest.entries)
        adapter_lock, plan, primary_root = _verify_static_artifacts(
            receipt=receipt,
            resolver=resolver,
            snapshot=snapshot,
        )
        primary_semantic_trace_hash = _verify_primary_attempts(
            receipt=receipt,
            plan=plan,
            resolver=resolver,
            snapshot=snapshot,
        )
        _verify_controls(receipt=receipt, resolver=resolver, snapshot=snapshot)
        _verify_patch(
            receipt=receipt,
            adapter_lock=adapter_lock,
            plan=plan,
            primary_root=primary_root,
            resolver=resolver,
            snapshot=snapshot,
        )
        _verify_evidence_index(receipt=receipt, resolver=resolver, snapshot=snapshot)
        resolver.require_complete()
        return RealityBundleVerificationResult(
            valid=True,
            errors=(),
            receipt_hash=receipt.receipt_hash,
            pre_receipt_manifest_sha256=manifest_sha256,
            snapshot_sha256=_snapshot_sha256(manifest_json, snapshot),
            profile=manifest.profile,
            event_semantics_verified=True,
            primary_semantic_trace_hash=primary_semantic_trace_hash,
        )
    except _RealityVerificationError as error:
        return RealityBundleVerificationResult(valid=False, errors=(error.code,))
    except (ValidationError, KeyError, TypeError, ValueError):
        return RealityBundleVerificationResult(valid=False, errors=("bundle-resolution-failed",))


__all__ = [
    "RealityAdapterComponent",
    "RealityAdapterLock",
    "RealityArtifactRole",
    "RealityBundleVerificationResult",
    "RealityChainBinding",
    "RealityControlDelta",
    "RealityDeltaChange",
    "RealityEvidenceFact",
    "RealityEvidenceIndex",
    "RealityEvidenceItem",
    "RealityEvidenceManifestV2",
    "RealityManifestEntry",
    "RealityScopeArtifact",
    "RealityTargetLock",
    "RealityTraceArtifact",
    "RealityTraceEvent",
    "RealityTraceEventKind",
    "RealityTraceEventType",
    "RealityTraceFact",
    "RealityTraceLane",
    "verify_reality_pre_receipt_bundle",
]
