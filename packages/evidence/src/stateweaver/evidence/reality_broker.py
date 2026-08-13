"""Fail-closed resolution for candidate inputs to a producer-external M6 broker.

This module validates policy/request bytes and a single immutable object snapshot.  It
never authenticates the external authority, issues an attestation, or promotes a Finding.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime

from pydantic import ValidationError
from stateweaver.contracts import (
    BrokerReplayRequest,
    ExternalTrustPolicy,
    RealityReplayReceipt,
    canonical_json_bytes,
    sha256_digest,
)

from .reality import (
    RealityAdapterLock,
    RealityEvidenceManifestV2,
    RealityTargetLock,
    verify_reality_pre_receipt_bundle,
)

_MAX_POLICY_BYTES = 64 * 1024
_MAX_REQUEST_BYTES = 2 * 1_048_576
_MAX_SNAPSHOT_BYTES = 256 * 1_048_576


@dataclass(frozen=True)
class M6BrokerCandidateVerification:
    valid: bool
    errors: tuple[str, ...]
    request_digest: str | None = None
    policy_digest: str | None = None
    snapshot_sha256: str | None = None
    semantic_result_sha256: str | None = None

    @property
    def authoritative(self) -> bool:
        return False

    @property
    def promotable(self) -> bool:
        return False


class _BrokerInputError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _digest(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def _snapshot(objects: Mapping[str, bytes]) -> dict[str, bytes]:
    try:
        identities = tuple(objects)
    except (RuntimeError, TypeError):
        raise _BrokerInputError("m6-object-snapshot-invalid") from None
    if not identities or len(identities) != len(set(identities)):
        raise _BrokerInputError("m6-object-snapshot-invalid")
    snapshot: dict[str, bytes] = {}
    total_bytes = 0
    try:
        for identity in identities:
            if type(identity) is not str:
                raise _BrokerInputError("m6-object-snapshot-invalid")
            content = objects[identity]
            if type(content) is not bytes:
                raise _BrokerInputError("m6-object-snapshot-invalid")
            total_bytes += len(content)
            if total_bytes > _MAX_SNAPSHOT_BYTES:
                raise _BrokerInputError("m6-object-snapshot-too-large")
            snapshot[identity] = content
    except (KeyError, RuntimeError, TypeError):
        raise _BrokerInputError("m6-object-snapshot-invalid") from None
    return snapshot


def _object_snapshot_digest(snapshot: Mapping[str, bytes]) -> str:
    digest = hashlib.sha256()
    for identity, content in sorted(snapshot.items()):
        name = identity.encode("ascii")
        digest.update(len(name).to_bytes(4, "big"))
        digest.update(name)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return f"sha256:{digest.hexdigest()}"


def _parse_canonical[ModelT](model: type[ModelT], content: bytes) -> ModelT:
    if type(content) is not bytes:
        raise _BrokerInputError("m6-serialized-input-required")
    try:
        raw: object = json.loads(content.decode("utf-8"))
        if canonical_json_bytes(raw) != content:
            raise _BrokerInputError("m6-json-not-canonical")
        return model.model_validate_json(content)  # type: ignore[attr-defined,no-any-return]
    except _BrokerInputError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError):
        raise _BrokerInputError("m6-json-invalid") from None


def _require_policy(
    policy: ExternalTrustPolicy,
    request: BrokerReplayRequest,
    *,
    trusted_at: datetime,
    current_revocation_epoch: int,
) -> None:
    if trusted_at.tzinfo is None or trusted_at.utcoffset() is None:
        raise _BrokerInputError("m6-trusted-clock-invalid")
    if (
        request.policy_digest != policy.policy_digest
        or request.immutable_store_id != policy.immutable_store_id
        or request.scope_manifest_sha256 not in policy.allowed_scope_manifest_sha256
        or request.target_id not in policy.allowed_target_ids
        or request.approval_ids != policy.required_approval_ids
    ):
        raise _BrokerInputError("m6-policy-binding-invalid")
    if (
        trusted_at < policy.valid_from
        or trusted_at >= policy.expires_at
        or trusted_at < request.requested_at
        or (trusted_at - request.requested_at).total_seconds() > policy.max_receipt_age_seconds
    ):
        raise _BrokerInputError("m6-policy-stale")
    if current_revocation_epoch != policy.revocation_epoch:
        raise _BrokerInputError("m6-policy-revoked")


def _require_object(
    reference: object,
    snapshot: Mapping[str, bytes],
) -> bytes:
    object_id = reference.object_id  # type: ignore[attr-defined]
    try:
        content = snapshot[object_id]
    except KeyError:
        raise _BrokerInputError("m6-object-coverage-invalid") from None
    if len(content) != reference.size_bytes or _digest(content) != reference.content_sha256:  # type: ignore[attr-defined]
        raise _BrokerInputError("m6-object-digest-invalid")
    return content


def verify_m6_broker_candidate(
    *,
    policy_json: bytes,
    request_json: bytes,
    objects: Mapping[str, bytes],
    trusted_at: datetime,
    current_revocation_epoch: int,
) -> M6BrokerCandidateVerification:
    """Validate broker inputs without converting them into authority or promotion."""

    try:
        if len(policy_json) > _MAX_POLICY_BYTES or len(request_json) > _MAX_REQUEST_BYTES:
            raise _BrokerInputError("m6-serialized-input-too-large")
        policy = _parse_canonical(ExternalTrustPolicy, policy_json)
        request = _parse_canonical(BrokerReplayRequest, request_json)
        _require_policy(
            policy,
            request,
            trusted_at=trusted_at,
            current_revocation_epoch=current_revocation_epoch,
        )
        snapshot = _snapshot(objects)
        references = (
            request.payload_manifest_object,
            request.pre_receipt_manifest_object,
            request.reality_receipt_object,
            *(binding.object_ref for binding in request.manifest_objects),
            *(binding.object_ref for binding in request.source_objects),
        )
        if set(snapshot) != {reference.object_id for reference in references}:
            raise _BrokerInputError("m6-object-coverage-invalid")
        payload_manifest = _require_object(request.payload_manifest_object, snapshot)
        manifest_json = _require_object(request.pre_receipt_manifest_object, snapshot)
        receipt_json = _require_object(request.reality_receipt_object, snapshot)
        if _digest(payload_manifest) != request.payload_manifest_sha256:
            raise _BrokerInputError("m6-payload-binding-invalid")
        manifest = _parse_canonical(RealityEvidenceManifestV2, manifest_json)
        receipt = _parse_canonical(RealityReplayReceipt, receipt_json)
        if (
            receipt.scope_manifest_sha256 != request.scope_manifest_sha256
            or receipt.target_id != request.target_id
            or receipt.target_version != request.target_version
            or receipt.adapter_lock_sha256 != request.adapter_lock_sha256
            or receipt.pre_receipt_evidence_manifest_sha256 != request.pre_receipt_manifest_sha256
        ):
            raise _BrokerInputError("m6-reality-binding-invalid")
        entry_by_digest = {sha256_digest(entry): entry for entry in manifest.entries}
        if len(entry_by_digest) != len(manifest.entries):
            raise _BrokerInputError("m6-manifest-entry-invalid")
        if {binding.manifest_entry_sha256 for binding in request.manifest_objects} != set(
            entry_by_digest
        ):
            raise _BrokerInputError("m6-manifest-coverage-invalid")
        artifact_snapshot: dict[str, bytes] = {}
        for binding in request.manifest_objects:
            entry = entry_by_digest[binding.manifest_entry_sha256]
            content = _require_object(binding.object_ref, snapshot)
            if _digest(content) != entry.sha256:
                raise _BrokerInputError("m6-manifest-artifact-invalid")
            artifact_snapshot[entry.path] = content
        source_by_kind = {
            (
                binding.component_kind.value,
                binding.component_id,
                binding.component_version,
            ): _require_object(binding.object_ref, snapshot)
            for binding in request.source_objects
        }
        target_entries = tuple(
            entry
            for entry in manifest.entries
            if entry.role.value in {"target-lock", "patch-target-lock"}
        )
        adapter_entry = next(
            entry for entry in manifest.entries if entry.role.value == "adapter-lock"
        )
        targets = tuple(
            _parse_canonical(RealityTargetLock, artifact_snapshot[entry.path])
            for entry in target_entries
        )
        adapter = _parse_canonical(RealityAdapterLock, artifact_snapshot[adapter_entry.path])
        expected_target_keys = {
            ("target", target.target_id, target.target_version) for target in targets
        }
        actual_target_keys = {key for key in source_by_kind if key[0] == "target"}
        if expected_target_keys != actual_target_keys or any(
            _digest(source_by_kind[("target", target.target_id, target.target_version)])
            != target.source_sha256
            for target in targets
        ):
            raise _BrokerInputError("m6-target-source-coverage-invalid")
        primary_target = next(
            target for target in targets if target.target_version == receipt.target_version
        )
        if primary_target.source_sha256 != request.source_sha256:
            raise _BrokerInputError("m6-target-source-invalid")
        adapter_sources = {
            (component_id, component_version): content
            for (kind, component_id, component_version), content in source_by_kind.items()
            if kind == "adapter"
        }
        expected_adapter_keys = {
            (f"adapter.{item.adapter_id}.01", item.version) for item in adapter.entries
        }
        if set(adapter_sources) != expected_adapter_keys:
            raise _BrokerInputError("m6-adapter-source-coverage-invalid")
        if any(
            _digest(adapter_sources[(f"adapter.{item.adapter_id}.01", item.version)])
            != item.source_sha256
            for item in adapter.entries
        ):
            raise _BrokerInputError("m6-adapter-source-invalid")
        reality = verify_reality_pre_receipt_bundle(
            receipt_json=receipt_json,
            manifest_json=manifest_json,
            artifacts=artifact_snapshot,
        )
        if not reality.valid or reality.snapshot_sha256 is None:
            raise _BrokerInputError("m6-reality-candidate-invalid")
        semantic_result = sha256_digest(
            {
                "payload_manifest_sha256": request.payload_manifest_sha256,
                "receipt_hash": reality.receipt_hash,
                "reality_snapshot_sha256": reality.snapshot_sha256,
                "semantic_trace_hash": reality.primary_semantic_trace_hash,
            }
        )
        return M6BrokerCandidateVerification(
            valid=True,
            errors=(),
            request_digest=request.request_digest,
            policy_digest=policy.policy_digest,
            snapshot_sha256=_object_snapshot_digest(snapshot),
            semantic_result_sha256=semantic_result,
        )
    except _BrokerInputError as error:
        return M6BrokerCandidateVerification(valid=False, errors=(error.code,))
    except (KeyError, StopIteration, TypeError, ValueError):
        return M6BrokerCandidateVerification(valid=False, errors=("m6-broker-input-invalid",))


__all__ = ["M6BrokerCandidateVerification", "verify_m6_broker_candidate"]
