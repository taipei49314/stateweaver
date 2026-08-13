"""Adversarial verification of M6 broker inputs before external issuance."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
import stateweaver.evidence.reality_broker as broker_module
from reality_bundle_fixtures import _build_bundle, _Bundle
from stateweaver.contracts import (
    BrokerReplayRequest,
    ExternalTrustPolicy,
    ImmutableObjectRef,
    ImmutableObjectRole,
    ManifestObjectBinding,
    SourceComponentKind,
    SourceObjectBinding,
    canonical_json_bytes,
    sha256_digest,
)
from stateweaver.evidence import M6BrokerCandidateVerification, verify_m6_broker_candidate

NOW = datetime(2026, 8, 13, 12, tzinfo=UTC)


def _digest(raw: bytes) -> str:
    import hashlib

    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _ref(*, role: ImmutableObjectRole, object_id: str, content: bytes) -> ImmutableObjectRef:
    return ImmutableObjectRef(
        role=role,
        store_id="store.external.reality",
        object_id=object_id,
        content_sha256=_digest(content),
        size_bytes=len(content),
        media_type="application/json",
    )


def _policy(scope_digest: str) -> ExternalTrustPolicy:
    values: dict[str, object] = {
        "schema_version": "stateweaver-m6-trust-policy-v1",
        "policy_id": "policy.m6.external.01",
        "authority_id": "authority.external.01",
        "approval_authority_id": "authority.approval.01",
        "oidc_issuer": "https://token.actions.githubusercontent.com",
        "oidc_subject": "github.com/example/authority/workflows/issue@refs/heads/main",
        "separated_consumer_identity": "machine.external.consumer.01",
        "immutable_store_id": "store.external.reality",
        "repository": "taipei49314/stateweaver",
        "source_ref": "refs/heads/main",
        "allowed_target_ids": ("target.synthetic.lab",),
        "allowed_scope_manifest_sha256": (scope_digest,),
        "required_approval_ids": ("approval.external.01",),
        "max_requests": 1,
        "max_requests_per_minute": 1,
        "max_write_requests": 0,
        "max_replay_seconds": 300,
        "max_receipt_age_seconds": 900,
        "required_cleanup_residuals": 0,
        "revocation_epoch": 7,
        "rotation_epoch": 3,
        "valid_from": NOW,
        "expires_at": NOW + timedelta(hours=1),
    }
    return ExternalTrustPolicy.model_validate({**values, "policy_digest": sha256_digest(values)})


def _inputs(bundle: _Bundle) -> tuple[ExternalTrustPolicy, BrokerReplayRequest, dict[str, bytes]]:
    entries = tuple(
        ManifestObjectBinding(
            manifest_entry_sha256=sha256_digest(entry),
            object_ref=_ref(
                role=ImmutableObjectRole.PRE_RECEIPT_ARTIFACT,
                object_id=f"object.m6.artifact.{index:03d}",
                content=bundle.artifacts[entry.path],
            ),
        )
        for index, entry in enumerate(bundle.manifest.entries, start=1)
    )
    target = next(entry for entry in bundle.manifest.entries if entry.role.value == "target-lock")
    patch_target = next(
        entry for entry in bundle.manifest.entries if entry.role.value == "patch-target-lock"
    )
    adapter = next(entry for entry in bundle.manifest.entries if entry.role.value == "adapter-lock")
    target_lock = __import__("json").loads(bundle.artifacts[target.path])
    patch_target_lock = __import__("json").loads(bundle.artifacts[patch_target.path])
    adapter_lock = __import__("json").loads(bundle.artifacts[adapter.path])
    target_source = canonical_json_bytes({"target": "lab-vulnerable"})
    patch_target_source = canonical_json_bytes({"target": "lab-patched"})
    adapter_source = canonical_json_bytes({"adapter": "fixture", "version": "1.0.0"})
    assert _digest(target_source) == target_lock["source_sha256"]
    assert _digest(patch_target_source) == patch_target_lock["source_sha256"]
    assert _digest(adapter_source) == adapter_lock["entries"][0]["source_sha256"]
    sources = (
        SourceObjectBinding(
            component_kind=SourceComponentKind.ADAPTER,
            component_id="adapter.fixture.01",
            component_version="1.0.0",
            source_sha256=_digest(adapter_source),
            object_ref=_ref(
                role=ImmutableObjectRole.ADAPTER_SOURCE,
                object_id="object.m6.source.adapter",
                content=adapter_source,
            ),
        ),
        SourceObjectBinding(
            component_kind=SourceComponentKind.TARGET,
            component_id="target.synthetic.lab",
            component_version="lab-patched",
            source_sha256=_digest(patch_target_source),
            object_ref=_ref(
                role=ImmutableObjectRole.TARGET_SOURCE,
                object_id="object.m6.source.target-patched",
                content=patch_target_source,
            ),
        ),
        SourceObjectBinding(
            component_kind=SourceComponentKind.TARGET,
            component_id="target.synthetic.lab",
            component_version="lab-vulnerable",
            source_sha256=_digest(target_source),
            object_ref=_ref(
                role=ImmutableObjectRole.TARGET_SOURCE,
                object_id="object.m6.source.target",
                content=target_source,
            ),
        ),
    )
    payload_manifest = canonical_json_bytes(
        {"candidate": "payload", "reality_receipt_sha256": _digest(bundle.receipt_json)}
    )
    refs = {
        "object.m6.payload": payload_manifest,
        "object.m6.manifest": bundle.manifest_json,
        "object.m6.receipt": bundle.receipt_json,
        "object.m6.source.adapter": adapter_source,
        "object.m6.source.target": target_source,
        "object.m6.source.target-patched": patch_target_source,
        **{
            binding.object_ref.object_id: bundle.artifacts[entry.path]
            for binding, entry in zip(entries, bundle.manifest.entries, strict=True)
        },
    }
    scope_digest = bundle.receipt.scope_manifest_sha256
    policy = _policy(scope_digest)
    values: dict[str, object] = {
        "schema_version": "stateweaver-m6-broker-request-v1",
        "request_id": "request.m6.replay.01",
        "payload_manifest_sha256": _digest(payload_manifest),
        "policy_digest": policy.policy_digest,
        "immutable_store_id": policy.immutable_store_id,
        "scope_manifest_sha256": scope_digest,
        "target_id": "target.synthetic.lab",
        "target_version": "lab-vulnerable",
        "source_sha256": _digest(target_source),
        "adapter_lock_sha256": bundle.receipt.adapter_lock_sha256,
        "pre_receipt_manifest_sha256": _digest(bundle.manifest_json),
        "reality_receipt_sha256": _digest(bundle.receipt_json),
        "payload_manifest_object": _ref(
            role=ImmutableObjectRole.PAYLOAD_MANIFEST,
            object_id="object.m6.payload",
            content=payload_manifest,
        ),
        "pre_receipt_manifest_object": _ref(
            role=ImmutableObjectRole.PRE_RECEIPT_MANIFEST,
            object_id="object.m6.manifest",
            content=bundle.manifest_json,
        ),
        "reality_receipt_object": _ref(
            role=ImmutableObjectRole.REALITY_RECEIPT,
            object_id="object.m6.receipt",
            content=bundle.receipt_json,
        ),
        "manifest_objects": entries,
        "source_objects": sources,
        "approval_ids": policy.required_approval_ids,
        "requested_at": NOW + timedelta(minutes=1),
    }
    request = BrokerReplayRequest.model_validate(
        {**values, "request_digest": sha256_digest(values)}
    )
    return policy, request, refs


def _remint_policy(policy: ExternalTrustPolicy, **updates: object) -> ExternalTrustPolicy:
    values = policy.model_dump(mode="python", exclude={"policy_digest"})
    values.update(updates)
    return ExternalTrustPolicy.model_validate({**values, "policy_digest": sha256_digest(values)})


def _remint_request(request: BrokerReplayRequest, **updates: object) -> BrokerReplayRequest:
    values = request.model_dump(mode="python", exclude={"request_digest"})
    values.update(updates)
    return BrokerReplayRequest.model_validate({**values, "request_digest": sha256_digest(values)})


def _verify(
    policy: ExternalTrustPolicy,
    request: BrokerReplayRequest,
    objects: Any,
    *,
    trusted_at: datetime = NOW + timedelta(minutes=2),
    epoch: int = 7,
) -> M6BrokerCandidateVerification:
    return verify_m6_broker_candidate(
        policy_json=policy.canonical_bytes(),
        request_json=request.canonical_bytes(),
        objects=objects,
        trusted_at=trusted_at,
        current_revocation_epoch=epoch,
    )


def test_complete_candidate_is_resolved_but_remains_non_authoritative() -> None:
    bundle = _build_bundle()
    policy, request, objects = _inputs(bundle)
    result = verify_m6_broker_candidate(
        policy_json=policy.canonical_bytes(),
        request_json=request.canonical_bytes(),
        objects=objects,
        trusted_at=NOW + timedelta(minutes=2),
        current_revocation_epoch=7,
    )

    assert result.valid
    assert result.errors == ()
    assert result.authoritative is False
    assert result.promotable is False
    assert result.snapshot_sha256 is not None


@pytest.mark.parametrize(
    "mutation", ("artifact", "source", "policy", "stale", "expiry", "revoked", "target")
)
def test_candidate_rejects_substitution_staleness_and_revocation(mutation: str) -> None:
    bundle = _build_bundle()
    policy, request, objects = _inputs(bundle)
    policy_json = policy.canonical_bytes()
    trusted_at = NOW + timedelta(minutes=2)
    epoch = 7
    if mutation == "artifact":
        objects = {**objects, request.manifest_objects[0].object_ref.object_id: b"{}"}
    elif mutation == "source":
        objects = {**objects, "object.m6.source.target": b"{}"}
    elif mutation == "policy":
        policy_json = policy.canonical_bytes() + b"\n"
    elif mutation == "stale":
        trusted_at = NOW + timedelta(hours=2)
    elif mutation == "expiry":
        trusted_at = policy.expires_at
    elif mutation == "revoked":
        epoch = 8
    else:
        values = policy.model_dump(mode="python", exclude={"policy_digest"})
        values["allowed_target_ids"] = ("target.synthetic.other",)
        policy = ExternalTrustPolicy.model_validate(
            {**values, "policy_digest": sha256_digest(values)}
        )
        policy_json = policy.canonical_bytes()

    result = verify_m6_broker_candidate(
        policy_json=policy_json,
        request_json=request.canonical_bytes(),
        objects=objects,
        trusted_at=trusted_at,
        current_revocation_epoch=epoch,
    )
    assert not result.valid
    assert not result.promotable


def test_mapping_is_snapshotted_once() -> None:
    bundle = _build_bundle()
    policy, request, objects = _inputs(bundle)

    class ReadOnce(dict[str, bytes]):
        reads: dict[str, int]

        def __init__(self, value: dict[str, bytes]) -> None:
            super().__init__(value)
            self.reads = dict.fromkeys(value, 0)

        def __getitem__(self, key: str) -> bytes:
            self.reads[key] += 1
            return super().__getitem__(key) if self.reads[key] == 1 else b"poison"

    snapshot = ReadOnce(objects)
    result = verify_m6_broker_candidate(
        policy_json=policy.canonical_bytes(),
        request_json=request.canonical_bytes(),
        objects=snapshot,
        trusted_at=NOW + timedelta(minutes=2),
        current_revocation_epoch=7,
    )
    assert result.valid
    assert set(snapshot.reads.values()) == {1}


@pytest.mark.parametrize(
    ("policy_update", "expected"),
    (
        ({"immutable_store_id": "store.external.other"}, "m6-policy-binding-invalid"),
        ({"allowed_scope_manifest_sha256": ("sha256:" + "0" * 64,)}, "m6-policy-binding-invalid"),
        ({"required_approval_ids": ("approval.external.other",)}, "m6-policy-binding-invalid"),
    ),
)
def test_policy_binding_is_exact(policy_update: dict[str, object], expected: str) -> None:
    policy, request, objects = _inputs(_build_bundle())
    policy = _remint_policy(policy, **policy_update)

    result = _verify(policy, request, objects)

    assert result.errors == (expected,)


@pytest.mark.parametrize(
    ("trusted_at", "expected"),
    (
        (NOW.replace(tzinfo=None), "m6-trusted-clock-invalid"),
        (NOW - timedelta(seconds=1), "m6-policy-stale"),
        (NOW + timedelta(seconds=30), "m6-policy-stale"),
    ),
)
def test_trusted_time_must_be_absolute_current_and_after_request(
    trusted_at: datetime, expected: str
) -> None:
    policy, request, objects = _inputs(_build_bundle())

    result = _verify(policy, request, objects, trusted_at=trusted_at)

    assert result.errors == (expected,)


def test_serialized_inputs_reject_wrong_type_invalid_json_and_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy, request, objects = _inputs(_build_bundle())
    invalid_type = verify_m6_broker_candidate(
        policy_json="not-bytes",  # type: ignore[arg-type]
        request_json=request.canonical_bytes(),
        objects=objects,
        trusted_at=NOW + timedelta(minutes=2),
        current_revocation_epoch=7,
    )
    invalid_json = verify_m6_broker_candidate(
        policy_json=b"\xff",
        request_json=request.canonical_bytes(),
        objects=objects,
        trusted_at=NOW + timedelta(minutes=2),
        current_revocation_epoch=7,
    )
    monkeypatch.setattr(broker_module, "_MAX_POLICY_BYTES", 1)
    too_large = _verify(policy, request, objects)

    assert invalid_type.errors == ("m6-serialized-input-required",)
    assert invalid_json.errors == ("m6-json-invalid",)
    assert too_large.errors == ("m6-serialized-input-too-large",)


class _BrokenSnapshot(dict[str, bytes]):
    def __init__(self, values: dict[str, bytes], failure: str) -> None:
        super().__init__(values)
        self.failure = failure

    def __iter__(self) -> Iterator[str]:
        if self.failure == "iterate":
            raise RuntimeError("changed during iteration")
        return super().__iter__()

    def __getitem__(self, key: str) -> bytes:
        if self.failure == "read":
            raise RuntimeError("changed during read")
        return super().__getitem__(key)


@pytest.mark.parametrize("objects", ({}, {1: b"value"}, {"object": "not-bytes"}))
def test_snapshot_rejects_empty_non_string_and_non_bytes_mappings(objects: Any) -> None:
    policy, request, _ = _inputs(_build_bundle())

    result = _verify(policy, request, objects)

    assert result.errors == ("m6-object-snapshot-invalid",)


@pytest.mark.parametrize("failure", ("iterate", "read"))
def test_snapshot_rejects_concurrent_mapping_failures(failure: str) -> None:
    policy, request, objects = _inputs(_build_bundle())

    result = _verify(policy, request, _BrokenSnapshot(objects, failure))

    assert result.errors == ("m6-object-snapshot-invalid",)


def test_snapshot_rejects_aggregate_byte_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    policy, request, objects = _inputs(_build_bundle())
    monkeypatch.setattr(broker_module, "_MAX_SNAPSHOT_BYTES", 1)

    result = _verify(policy, request, objects)

    assert result.errors == ("m6-object-snapshot-too-large",)


@pytest.mark.parametrize("coverage", ("missing", "extra"))
def test_snapshot_requires_exact_object_coverage(coverage: str) -> None:
    policy, request, objects = _inputs(_build_bundle())
    if coverage == "missing":
        objects.pop(next(iter(objects)))
    else:
        objects["object.m6.unrequested"] = b"{}"

    result = _verify(policy, request, objects)

    assert result.errors == ("m6-object-coverage-invalid",)


def test_manifest_requires_exact_entry_coverage() -> None:
    policy, request, objects = _inputs(_build_bundle())
    removed = request.manifest_objects[-1]
    request = _remint_request(request, manifest_objects=request.manifest_objects[:-1])
    objects.pop(removed.object_ref.object_id)

    result = _verify(policy, request, objects)

    assert result.errors == ("m6-manifest-coverage-invalid",)


def test_manifest_entry_cannot_be_rebound_to_other_valid_artifact() -> None:
    policy, request, objects = _inputs(_build_bundle())
    first, second, *remaining = request.manifest_objects
    swapped = (
        ManifestObjectBinding(
            manifest_entry_sha256=first.manifest_entry_sha256,
            object_ref=second.object_ref,
        ),
        ManifestObjectBinding(
            manifest_entry_sha256=second.manifest_entry_sha256,
            object_ref=first.object_ref,
        ),
        *remaining,
    )
    request = _remint_request(
        request,
        manifest_objects=tuple(
            sorted(
                swapped,
                key=lambda binding: (
                    binding.object_ref.object_id,
                    binding.manifest_entry_sha256,
                ),
            )
        ),
    )

    result = _verify(policy, request, objects)

    assert result.errors == ("m6-manifest-artifact-invalid",)


@pytest.mark.parametrize(
    ("request_update", "expected"),
    (
        ({"target_version": "lab-patched"}, "m6-reality-binding-invalid"),
        ({"adapter_lock_sha256": "sha256:" + "0" * 64}, "m6-reality-binding-invalid"),
    ),
)
def test_reality_receipt_binding_is_exact(request_update: dict[str, object], expected: str) -> None:
    policy, request, objects = _inputs(_build_bundle())
    if "target_version" in request_update:
        request_update["source_sha256"] = request.source_objects[1].source_sha256
    request = _remint_request(request, **request_update)

    result = _verify(policy, request, objects)

    assert result.errors == (expected,)


@pytest.mark.parametrize(
    ("kind", "expected"),
    (
        (SourceComponentKind.TARGET, "m6-target-source-coverage-invalid"),
        (SourceComponentKind.ADAPTER, "m6-adapter-source-coverage-invalid"),
    ),
)
def test_source_lock_requires_exact_component_coverage(
    kind: SourceComponentKind, expected: str
) -> None:
    policy, request, objects = _inputs(_build_bundle())
    removed = next(binding for binding in request.source_objects if binding.component_kind is kind)
    remaining = tuple(binding for binding in request.source_objects if binding is not removed)
    request = _remint_request(request, source_objects=remaining)
    objects.pop(removed.object_ref.object_id)

    result = _verify(policy, request, objects)

    assert result.errors == (expected,)


@pytest.mark.parametrize(
    ("kind", "expected"),
    (
        (SourceComponentKind.TARGET, "m6-target-source-coverage-invalid"),
        (SourceComponentKind.ADAPTER, "m6-adapter-source-invalid"),
    ),
)
def test_source_bytes_must_match_parsed_locks(kind: SourceComponentKind, expected: str) -> None:
    policy, request, objects = _inputs(_build_bundle())
    index = next(
        index
        for index, binding in enumerate(request.source_objects)
        if binding.component_kind is kind
    )
    original = request.source_objects[index]
    replacement = canonical_json_bytes({"substituted": original.component_id})
    replacement_ref = _ref(
        role=original.object_ref.role,
        object_id=original.object_ref.object_id,
        content=replacement,
    )
    replacement_binding = SourceObjectBinding(
        component_kind=original.component_kind,
        component_id=original.component_id,
        component_version=original.component_version,
        source_sha256=_digest(replacement),
        object_ref=replacement_ref,
    )
    sources = list(request.source_objects)
    sources[index] = replacement_binding
    request_updates: dict[str, object] = {"source_objects": tuple(sources)}
    if kind is SourceComponentKind.TARGET and original.component_version == request.target_version:
        request_updates["source_sha256"] = _digest(replacement)
    request = _remint_request(request, **request_updates)
    objects[original.object_ref.object_id] = replacement

    result = _verify(policy, request, objects)

    assert result.errors == (expected,)


def test_invalid_reality_result_and_unexpected_value_error_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy, request, objects = _inputs(_build_bundle())
    monkeypatch.setattr(
        broker_module,
        "verify_reality_pre_receipt_bundle",
        lambda **_kwargs: SimpleNamespace(valid=False, snapshot_sha256=None),
    )
    invalid = _verify(policy, request, objects)
    monkeypatch.setattr(
        broker_module,
        "verify_reality_pre_receipt_bundle",
        lambda **_kwargs: (_ for _ in ()).throw(ValueError("unexpected")),
    )
    unexpected = _verify(policy, request, objects)

    assert invalid.errors == ("m6-reality-candidate-invalid",)
    assert unexpected.errors == ("m6-broker-input-invalid",)
