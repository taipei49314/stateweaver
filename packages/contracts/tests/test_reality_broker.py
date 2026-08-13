"""Fail-closed contracts for the producer-external M6 broker boundary."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError
from stateweaver.contracts import (
    AuthenticatedAcquisitionReceipt,
    BrokerIssuanceReceipt,
    BrokerReplayRequest,
    CleanConsumerReceipt,
    ExternalTrustPolicy,
    ImmutableObjectRef,
    ImmutableObjectRole,
    M6PromotionClosure,
    ManifestObjectBinding,
    SourceComponentKind,
    SourceObjectBinding,
    sha256_digest,
)

NOW = datetime(2026, 8, 13, 12, tzinfo=UTC)
DIGEST = "sha256:" + "1" * 64


def _object(role: ImmutableObjectRole, name: str, digit: str) -> ImmutableObjectRef:
    return ImmutableObjectRef(
        role=role,
        store_id="store.external.reality",
        object_id=f"object.m6.{name}",
        content_sha256="sha256:" + digit * 64,
        size_bytes=128,
        media_type="application/json",
    )


def _policy_values() -> dict[str, object]:
    return {
        "schema_version": "stateweaver-m6-trust-policy-v1",
        "policy_id": "policy.m6.external.01",
        "authority_id": "authority.external.01",
        "approval_authority_id": "authority.approval.01",
        "oidc_issuer": "https://token.actions.githubusercontent.com",
        "oidc_subject": (
            "github.com/example/authority/.github/workflows/issue.yml@refs/heads/main"
        ),
        "separated_consumer_identity": "machine.external.consumer.01",
        "immutable_store_id": "store.external.reality",
        "repository": "taipei49314/stateweaver",
        "source_ref": "refs/heads/main",
        "allowed_target_ids": ("target.synthetic.lab",),
        "allowed_scope_manifest_sha256": (DIGEST,),
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


def _policy() -> ExternalTrustPolicy:
    values = _policy_values()
    return ExternalTrustPolicy.model_validate({**values, "policy_digest": sha256_digest(values)})


def _request() -> BrokerReplayRequest:
    policy = _policy()
    manifest_objects = tuple(
        ManifestObjectBinding(
            manifest_entry_sha256="sha256:" + digit * 64,
            object_ref=_object(ImmutableObjectRole.PRE_RECEIPT_ARTIFACT, f"artifact{digit}", digit),
        )
        for digit in ("7", "8")
    )
    source_objects = (
        SourceObjectBinding(
            component_kind=SourceComponentKind.ADAPTER,
            component_id="adapter.replay.01",
            component_version="1.0.0",
            source_sha256="sha256:" + "2" * 64,
            object_ref=_object(ImmutableObjectRole.ADAPTER_SOURCE, "adapter", "2"),
        ),
        SourceObjectBinding(
            component_kind=SourceComponentKind.TARGET,
            component_id="target.synthetic.lab",
            component_version="lab-vulnerable",
            source_sha256="sha256:" + "5" * 64,
            object_ref=_object(ImmutableObjectRole.TARGET_SOURCE, "source", "5"),
        ),
    )
    values: dict[str, object] = {
        "schema_version": "stateweaver-m6-broker-request-v1",
        "request_id": "request.m6.replay.01",
        "payload_manifest_sha256": "sha256:" + "6" * 64,
        "policy_digest": policy.policy_digest,
        "immutable_store_id": policy.immutable_store_id,
        "scope_manifest_sha256": DIGEST,
        "target_id": "target.synthetic.lab",
        "target_version": "lab-vulnerable",
        "source_sha256": "sha256:" + "5" * 64,
        "adapter_lock_sha256": "sha256:" + "2" * 64,
        "pre_receipt_manifest_sha256": "sha256:" + "3" * 64,
        "reality_receipt_sha256": "sha256:" + "4" * 64,
        "payload_manifest_object": _object(ImmutableObjectRole.PAYLOAD_MANIFEST, "payload", "6"),
        "pre_receipt_manifest_object": _object(
            ImmutableObjectRole.PRE_RECEIPT_MANIFEST, "manifest", "3"
        ),
        "reality_receipt_object": _object(ImmutableObjectRole.REALITY_RECEIPT, "receipt", "4"),
        "manifest_objects": manifest_objects,
        "source_objects": source_objects,
        "approval_ids": ("approval.external.01",),
        "requested_at": NOW + timedelta(minutes=1),
    }
    return BrokerReplayRequest.model_validate({**values, "request_digest": sha256_digest(values)})


def _request_values() -> dict[str, object]:
    return _request().model_dump(mode="python", exclude={"request_digest"})


def _acquisition_values() -> dict[str, object]:
    request = _request()
    object_refs = (
        request.payload_manifest_object,
        request.pre_receipt_manifest_object,
        request.reality_receipt_object,
        *(binding.object_ref for binding in request.manifest_objects),
        *(binding.object_ref for binding in request.source_objects),
    )
    return {
        "schema_version": "stateweaver-m6-acquisition-v1",
        "request_digest": request.request_digest,
        "policy_digest": request.policy_digest,
        "immutable_store_id": request.immutable_store_id,
        "object_refs": tuple(
            sorted(object_refs, key=lambda item: (item.role.value, item.object_id))
        ),
        "snapshot_sha256": "sha256:" + "a" * 64,
        "acquired_at": NOW + timedelta(minutes=2),
        "authority_evidence_sha256": "sha256:" + "b" * 64,
    }


def _issuance_values() -> dict[str, object]:
    request = _request()
    return {
        "schema_version": "stateweaver-m6-issuance-v1",
        "status": "BROKER_ISSUED",
        "request_digest": request.request_digest,
        "policy_digest": request.policy_digest,
        "acquisition_receipt_sha256": "sha256:" + "a" * 64,
        "payload_manifest_sha256": request.payload_manifest_sha256,
        "reality_receipt_sha256": request.reality_receipt_sha256,
        "replay_snapshot_sha256": "sha256:" + "b" * 64,
        "semantic_result_sha256": "sha256:" + "c" * 64,
        "oidc_issuer": "https://token.actions.githubusercontent.com",
        "oidc_subject": "github.com/example/authority/workflows/issue@refs/heads/main",
        "issued_at": NOW + timedelta(minutes=3),
        "expires_at": NOW + timedelta(minutes=13),
        "revocation_epoch": 7,
        "cleanup_residuals": 0,
        "detached_attestation_sha256": "sha256:" + "d" * 64,
    }


def _consumer_values() -> dict[str, object]:
    request = _request()
    return {
        "schema_version": "stateweaver-m6-clean-consumer-v1",
        "status": "CLEAN_CONSUMER_REPLAYED",
        "payload_manifest_sha256": request.payload_manifest_sha256,
        "policy_digest": request.policy_digest,
        "issuance_receipt_sha256": "sha256:" + "e" * 64,
        "consumer_identity": "machine.external.consumer.01",
        "consumer_environment_sha256": "sha256:" + "f" * 64,
        "semantic_result_sha256": "sha256:" + "c" * 64,
        "replay_snapshot_sha256": "sha256:" + "b" * 64,
        "completed_at": NOW + timedelta(minutes=14),
        "cleanup_residuals": 0,
        "separation_attestation_sha256": "sha256:" + "9" * 64,
    }


def test_policy_and_request_are_canonical_content_bound_and_have_no_escape_hatches() -> None:
    policy = _policy()
    request = _request()

    assert policy.policy_digest == sha256_digest(
        policy.model_dump(mode="python", exclude={"policy_digest"})
    )
    assert request.request_digest == sha256_digest(
        request.model_dump(mode="python", exclude={"request_digest"})
    )
    assert "url" not in BrokerReplayRequest.model_fields
    assert "path" not in BrokerReplayRequest.model_fields
    assert "command" not in BrokerReplayRequest.model_fields
    assert "verdict" not in BrokerReplayRequest.model_fields
    assert "verified" not in BrokerReplayRequest.model_fields


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("oidc_subject", "*"),
        ("required_cleanup_residuals", 1),
        ("max_write_requests", 1),
        ("expires_at", NOW - timedelta(seconds=1)),
    ),
)
def test_policy_rejects_wildcard_write_cleanup_and_time_substitution(
    field: str, value: object
) -> None:
    values = {**_policy_values(), field: value}
    with pytest.raises(ValidationError):
        ExternalTrustPolicy.model_validate({**values, "policy_digest": sha256_digest(values)})


def test_policy_requires_a_producer_separated_consumer_identity() -> None:
    values = _policy_values()
    values["separated_consumer_identity"] = values["oidc_subject"]
    with pytest.raises(ValidationError, match="separated"):
        ExternalTrustPolicy.model_validate({**values, "policy_digest": sha256_digest(values)})


@pytest.mark.parametrize(
    ("mutation", "match"),
    (
        ({"valid_from": NOW.replace(tzinfo=None)}, "UTC offset"),
        ({"allowed_target_ids": ("target.z", "target.a")}, "canonically ordered"),
        ({"policy_digest": DIGEST}, "digest"),
    ),
)
def test_policy_rejects_naive_time_noncanonical_sets_and_stale_digest(
    mutation: dict[str, object], match: str
) -> None:
    values = {**_policy_values(), **mutation}
    digest = mutation.get("policy_digest", DIGEST)
    with pytest.raises(ValidationError, match=match):
        ExternalTrustPolicy.model_validate({**values, "policy_digest": digest})


def test_manifest_and_source_bindings_reject_role_or_digest_substitution() -> None:
    with pytest.raises(ValidationError, match="pre-receipt artifact role"):
        ManifestObjectBinding(
            manifest_entry_sha256=DIGEST,
            object_ref=_object(ImmutableObjectRole.TARGET_SOURCE, "wrong-manifest", "1"),
        )

    source = _request().source_objects[0]
    for object_ref, match in (
        (
            source.object_ref.model_copy(update={"role": ImmutableObjectRole.TARGET_SOURCE}),
            "component kind",
        ),
        (
            source.object_ref.model_copy(update={"content_sha256": DIGEST}),
            "source binding",
        ),
    ):
        with pytest.raises(ValidationError, match=match):
            SourceObjectBinding(
                component_kind=source.component_kind,
                component_id=source.component_id,
                component_version=source.component_version,
                source_sha256=source.source_sha256,
                object_ref=object_ref,
            )


def test_request_rejects_object_substitution_even_when_outer_digest_is_reminted() -> None:
    request = _request()
    values = request.model_dump(mode="python", exclude={"request_digest"})
    values["payload_manifest_object"] = request.payload_manifest_object.model_copy(
        update={"store_id": "store.producer.self"}
    )

    with pytest.raises(ValidationError, match="external immutable store"):
        BrokerReplayRequest.model_validate({**values, "request_digest": sha256_digest(values)})


@pytest.mark.parametrize("field", ("manifest_objects", "source_objects"))
def test_request_rejects_duplicate_object_bindings(field: str) -> None:
    request = _request()
    values = request.model_dump(mode="python", exclude={"request_digest"})
    items = values[field]
    assert isinstance(items, tuple)
    values[field] = (*items, items[0])
    with pytest.raises(ValidationError, match=r"canonically ordered|unique"):
        BrokerReplayRequest.model_validate({**values, "request_digest": sha256_digest(values)})


@pytest.mark.parametrize(
    ("mutation", "match"),
    (
        ({"requested_at": NOW.replace(tzinfo=None)}, "UTC offset"),
        ({"approval_ids": ("approval.z", "approval.a")}, "canonical"),
        ({"request_digest": DIGEST}, "request digest"),
    ),
)
def test_request_rejects_naive_time_noncanonical_approvals_and_stale_digest(
    mutation: dict[str, object], match: str
) -> None:
    values = {**_request_values(), **mutation}
    digest = mutation.get("request_digest", DIGEST)
    with pytest.raises(ValidationError, match=match):
        BrokerReplayRequest.model_validate({**values, "request_digest": digest})


@pytest.mark.parametrize(
    ("mutation", "match"),
    (
        (
            {
                "payload_manifest_object": _object(
                    ImmutableObjectRole.REALITY_RECEIPT, "bad-role", "6"
                )
            },
            "fixed object roles",
        ),
        ({"payload_manifest_sha256": "sha256:" + "0" * 64}, "fixed object digest"),
        ({"target_version": "other-version"}, "target source closure"),
    ),
)
def test_request_rejects_fixed_role_digest_and_target_closure_substitution(
    mutation: dict[str, object], match: str
) -> None:
    values = {**_request_values(), **mutation}
    with pytest.raises(ValidationError, match=match):
        BrokerReplayRequest.model_validate({**values, "request_digest": sha256_digest(values)})


def test_request_rejects_noncanonical_or_colliding_object_sets() -> None:
    request = _request()
    base = _request_values()
    mutations: tuple[tuple[dict[str, object], str], ...] = (
        ({"manifest_objects": tuple(reversed(request.manifest_objects))}, "manifest objects"),
        ({"source_objects": tuple(reversed(request.source_objects))}, "source objects"),
        (
            {
                "reality_receipt_object": request.reality_receipt_object.model_copy(
                    update={"object_id": request.payload_manifest_object.object_id}
                )
            },
            "object IDs",
        ),
    )
    for mutation, match in mutations:
        values = {**base, **mutation}
        with pytest.raises(ValidationError, match=match):
            BrokerReplayRequest.model_validate({**values, "request_digest": sha256_digest(values)})


def test_external_receipt_models_are_content_bound_and_time_closed() -> None:
    acquisition_values = _acquisition_values()
    acquisition = AuthenticatedAcquisitionReceipt.model_validate(
        {**acquisition_values, "receipt_digest": sha256_digest(acquisition_values)}
    )
    issuance_values = _issuance_values()
    issuance = BrokerIssuanceReceipt.model_validate(
        {**issuance_values, "receipt_digest": sha256_digest(issuance_values)}
    )
    consumer_values = _consumer_values()
    consumer = CleanConsumerReceipt.model_validate(
        {**consumer_values, "receipt_digest": sha256_digest(consumer_values)}
    )

    assert acquisition.receipt_digest == sha256_digest(acquisition_values)
    assert issuance.receipt_digest == sha256_digest(issuance_values)
    assert consumer.receipt_digest == sha256_digest(consumer_values)


@pytest.mark.parametrize(
    ("model", "values_factory", "mutation", "match"),
    (
        (
            AuthenticatedAcquisitionReceipt,
            _acquisition_values,
            {"acquired_at": NOW.replace(tzinfo=None)},
            "UTC offset",
        ),
        (
            AuthenticatedAcquisitionReceipt,
            _acquisition_values,
            {"receipt_digest": DIGEST},
            "digest",
        ),
        (
            BrokerIssuanceReceipt,
            _issuance_values,
            {"issued_at": NOW.replace(tzinfo=None)},
            "validity",
        ),
        (BrokerIssuanceReceipt, _issuance_values, {"expires_at": NOW}, "validity"),
        (BrokerIssuanceReceipt, _issuance_values, {"receipt_digest": DIGEST}, "digest"),
        (
            CleanConsumerReceipt,
            _consumer_values,
            {"completed_at": NOW.replace(tzinfo=None)},
            "UTC offset",
        ),
        (CleanConsumerReceipt, _consumer_values, {"receipt_digest": DIGEST}, "digest"),
    ),
)
def test_external_receipts_reject_invalid_time_or_digest(
    model: type[AuthenticatedAcquisitionReceipt]
    | type[BrokerIssuanceReceipt]
    | type[CleanConsumerReceipt],
    values_factory: Callable[[], dict[str, object]],
    mutation: dict[str, object],
    match: str,
) -> None:
    values = {**values_factory(), **mutation}
    digest = mutation.get("receipt_digest", DIGEST)
    with pytest.raises(ValidationError, match=match):
        model.model_validate({**values, "receipt_digest": digest})


def test_acquisition_rejects_noncanonical_object_refs() -> None:
    values = _acquisition_values()
    refs = values["object_refs"]
    assert isinstance(refs, tuple)
    values["object_refs"] = tuple(reversed(refs))
    with pytest.raises(ValidationError, match="canonically ordered"):
        AuthenticatedAcquisitionReceipt.model_validate(
            {**values, "receipt_digest": sha256_digest(values)}
        )


def test_promotion_contract_is_deliberately_non_promotable_without_external_receipts() -> None:
    values: dict[str, object] = {
        "schema_version": "stateweaver-m6-promotion-closure-v1",
        "payload_manifest_sha256": "sha256:" + "6" * 64,
        "policy_digest": _policy().policy_digest,
        "acquisition_receipt_sha256": "sha256:" + "7" * 64,
        "issuance_receipt_sha256": "sha256:" + "8" * 64,
        "clean_consumer_receipt_sha256": "sha256:" + "9" * 64,
        "promotion_authorized": False,
        "status": "EXTERNAL_QUALIFICATION_REQUIRED",
    }
    closure = M6PromotionClosure.model_validate({**values, "closure_digest": sha256_digest(values)})

    assert closure.promotion_authorized is False
    with pytest.raises(ValidationError, match="closure digest"):
        M6PromotionClosure.model_validate({**values, "closure_digest": DIGEST})
    with pytest.raises(ValidationError):
        M6PromotionClosure.model_validate(
            {
                **closure.model_dump(mode="python"),
                "promotion_authorized": True,
            }
        )
