"""Content-bound contracts for a producer-external M6 Reality broker.

These models do not authenticate their own producer.  They deliberately omit URLs,
filesystem paths, commands, caller verdicts, and caller-supplied verification booleans.
Authority belongs to an external verifier and immutable-store adapter that consume the
canonical bytes of these contracts.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, StringConstraints, field_validator, model_validator

from .base import ContractId, ContractModel, Name, Sha256Digest, sha256_digest

RepositoryId = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        to_lower=True,
        min_length=3,
        max_length=160,
        pattern=r"^[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$",
    ),
]
SourceRef = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=12,
        max_length=240,
        pattern=r"^refs/(?:heads|tags)/[A-Za-z0-9][A-Za-z0-9._/-]*$",
    ),
]
IssuerIdentity = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=12,
        max_length=320,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/@-]*$",
    ),
]
OidcIssuer = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=12,
        max_length=160,
        pattern=r"^https://[A-Za-z0-9][A-Za-z0-9._:/-]*$",
    ),
]
MediaType = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        to_lower=True,
        min_length=3,
        max_length=96,
        pattern=r"^[a-z0-9][a-z0-9.+-]*/[a-z0-9][a-z0-9.+-]*$",
    ),
]


class ImmutableObjectRole(StrEnum):
    ADAPTER_SOURCE = "adapter-source"
    PAYLOAD_MANIFEST = "payload-manifest"
    PRE_RECEIPT_ARTIFACT = "pre-receipt-artifact"
    PRE_RECEIPT_MANIFEST = "pre-receipt-manifest"
    REALITY_RECEIPT = "reality-receipt"
    TARGET_SOURCE = "target-source"


class SourceComponentKind(StrEnum):
    ADAPTER = "adapter"
    TARGET = "target"


class ExternalTrustPolicy(ContractModel):
    """Policy bytes that must be frozen and authenticated by a producer-external authority."""

    schema_version: Literal["stateweaver-m6-trust-policy-v1"]
    policy_id: ContractId
    policy_digest: Sha256Digest
    authority_id: ContractId
    approval_authority_id: ContractId
    oidc_issuer: OidcIssuer
    oidc_subject: IssuerIdentity
    separated_consumer_identity: IssuerIdentity
    immutable_store_id: ContractId
    repository: RepositoryId
    source_ref: SourceRef
    allowed_target_ids: Annotated[tuple[ContractId, ...], Field(min_length=1)]
    allowed_scope_manifest_sha256: Annotated[tuple[Sha256Digest, ...], Field(min_length=1)]
    required_approval_ids: Annotated[tuple[ContractId, ...], Field(min_length=1)]
    max_requests: Annotated[int, Field(ge=1, le=64)]
    max_requests_per_minute: Annotated[int, Field(ge=1, le=64)]
    max_write_requests: Literal[0]
    max_replay_seconds: Annotated[int, Field(ge=1, le=3600)]
    max_receipt_age_seconds: Annotated[int, Field(ge=60, le=86_400)]
    required_cleanup_residuals: Literal[0]
    revocation_epoch: Annotated[int, Field(ge=0, le=2**63 - 1)]
    rotation_epoch: Annotated[int, Field(ge=1, le=2**63 - 1)]
    valid_from: datetime
    expires_at: datetime

    @field_validator("valid_from", "expires_at")
    @classmethod
    def timestamps_are_absolute(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("M6 policy timestamps must include a UTC offset")
        return value

    @field_validator("allowed_scope_manifest_sha256", "allowed_target_ids", "required_approval_ids")
    @classmethod
    def tuples_are_canonical_and_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("M6 policy sets must be unique and canonically ordered")
        return value

    @model_validator(mode="after")
    def policy_is_closed_and_content_bound(self) -> Self:
        if self.expires_at <= self.valid_from:
            raise ValueError("M6 policy validity must move forward")
        if self.separated_consumer_identity == self.oidc_subject:
            raise ValueError("M6 consumer identity must be separated from the issuer")
        expected = sha256_digest(self.model_dump(mode="python", exclude={"policy_digest"}))
        if self.policy_digest != expected:
            raise ValueError("M6 policy digest does not match its content")
        return self


class ImmutableObjectRef(ContractModel):
    """One content-addressed object identifier; it is never a path or URL."""

    role: ImmutableObjectRole
    store_id: ContractId
    object_id: ContractId
    content_sha256: Sha256Digest
    size_bytes: Annotated[int, Field(ge=1, le=64 * 1_048_576)]
    media_type: MediaType


class ManifestObjectBinding(ContractModel):
    """Bind one manifest entry by its canonical entry digest, never by caller path."""

    manifest_entry_sha256: Sha256Digest
    object_ref: ImmutableObjectRef

    @model_validator(mode="after")
    def role_is_exact(self) -> Self:
        if self.object_ref.role is not ImmutableObjectRole.PRE_RECEIPT_ARTIFACT:
            raise ValueError("M6 manifest object requires the pre-receipt artifact role")
        return self


class SourceObjectBinding(ContractModel):
    """Bind source bytes that the parsed target/adapter lock must independently resolve."""

    component_kind: SourceComponentKind
    component_id: ContractId
    component_version: Name
    source_sha256: Sha256Digest
    object_ref: ImmutableObjectRef

    @model_validator(mode="after")
    def role_and_digest_are_exact(self) -> Self:
        expected_role = (
            ImmutableObjectRole.ADAPTER_SOURCE
            if self.component_kind is SourceComponentKind.ADAPTER
            else ImmutableObjectRole.TARGET_SOURCE
        )
        if self.object_ref.role is not expected_role:
            raise ValueError("M6 source object role does not match its component kind")
        if self.object_ref.content_sha256 != self.source_sha256:
            raise ValueError("M6 source object digest does not match its source binding")
        return self


class BrokerReplayRequest(ContractModel):
    """The only request shape accepted by the future trusted replay broker."""

    schema_version: Literal["stateweaver-m6-broker-request-v1"]
    request_id: ContractId
    request_digest: Sha256Digest
    payload_manifest_sha256: Sha256Digest
    policy_digest: Sha256Digest
    immutable_store_id: ContractId
    scope_manifest_sha256: Sha256Digest
    target_id: ContractId
    target_version: Name
    source_sha256: Sha256Digest
    adapter_lock_sha256: Sha256Digest
    pre_receipt_manifest_sha256: Sha256Digest
    reality_receipt_sha256: Sha256Digest
    payload_manifest_object: ImmutableObjectRef
    pre_receipt_manifest_object: ImmutableObjectRef
    reality_receipt_object: ImmutableObjectRef
    manifest_objects: Annotated[
        tuple[ManifestObjectBinding, ...], Field(min_length=1, max_length=1024)
    ]
    source_objects: Annotated[tuple[SourceObjectBinding, ...], Field(min_length=2, max_length=64)]
    approval_ids: Annotated[tuple[ContractId, ...], Field(min_length=1)]
    requested_at: datetime

    @field_validator("requested_at")
    @classmethod
    def requested_at_is_absolute(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("M6 request timestamp must include a UTC offset")
        return value

    @field_validator("approval_ids")
    @classmethod
    def approvals_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("M6 approvals must be unique and canonically ordered")
        return value

    @model_validator(mode="after")
    def object_closure_and_digest_are_exact(self) -> Self:
        fixed = (
            self.payload_manifest_object,
            self.pre_receipt_manifest_object,
            self.reality_receipt_object,
        )
        if tuple(item.role for item in fixed) != (
            ImmutableObjectRole.PAYLOAD_MANIFEST,
            ImmutableObjectRole.PRE_RECEIPT_MANIFEST,
            ImmutableObjectRole.REALITY_RECEIPT,
        ):
            raise ValueError("M6 fixed object roles are invalid")
        if tuple(
            (item.object_ref.object_id, item.manifest_entry_sha256)
            for item in self.manifest_objects
        ) != tuple(
            sorted(
                (
                    item.object_ref.object_id,
                    item.manifest_entry_sha256,
                )
                for item in self.manifest_objects
            )
        ):
            raise ValueError("M6 manifest objects must be canonically ordered")
        if len({item.manifest_entry_sha256 for item in self.manifest_objects}) != len(
            self.manifest_objects
        ):
            raise ValueError("M6 manifest objects must be unique")
        if tuple(
            (item.component_kind.value, item.component_id, item.component_version)
            for item in self.source_objects
        ) != tuple(
            sorted(
                (item.component_kind.value, item.component_id, item.component_version)
                for item in self.source_objects
            )
        ):
            raise ValueError("M6 source objects must be canonically ordered")
        if len(
            {
                (item.component_kind, item.component_id, item.component_version)
                for item in self.source_objects
            }
        ) != len(self.source_objects):
            raise ValueError("M6 source objects must be unique")
        all_refs = (
            *fixed,
            *(item.object_ref for item in self.manifest_objects),
            *(item.object_ref for item in self.source_objects),
        )
        if len({item.object_id for item in all_refs}) != len(all_refs):
            raise ValueError("M6 immutable object IDs must be unique")
        if any(item.store_id != self.immutable_store_id for item in all_refs):
            raise ValueError("M6 objects must use the external immutable store")
        if (
            self.payload_manifest_object.content_sha256 != self.payload_manifest_sha256
            or self.pre_receipt_manifest_object.content_sha256 != self.pre_receipt_manifest_sha256
            or self.reality_receipt_object.content_sha256 != self.reality_receipt_sha256
        ):
            raise ValueError("M6 fixed object digest does not match its request binding")
        target_sources = tuple(
            item
            for item in self.source_objects
            if item.component_kind is SourceComponentKind.TARGET
        )
        primary_sources = tuple(
            item
            for item in target_sources
            if item.component_id == self.target_id and item.component_version == self.target_version
        )
        if len(primary_sources) != 1 or primary_sources[0].source_sha256 != self.source_sha256:
            raise ValueError("M6 target source closure is invalid")
        expected = sha256_digest(self.model_dump(mode="python", exclude={"request_digest"}))
        if self.request_digest != expected:
            raise ValueError("M6 request digest does not match its content")
        return self


class AuthenticatedAcquisitionReceipt(ContractModel):
    """Typed output only after an external adapter authenticates one sealed store snapshot."""

    schema_version: Literal["stateweaver-m6-acquisition-v1"]
    request_digest: Sha256Digest
    policy_digest: Sha256Digest
    immutable_store_id: ContractId
    object_refs: Annotated[tuple[ImmutableObjectRef, ...], Field(min_length=6, max_length=1091)]
    snapshot_sha256: Sha256Digest
    acquired_at: datetime
    authority_evidence_sha256: Sha256Digest
    receipt_digest: Sha256Digest

    @model_validator(mode="after")
    def receipt_is_content_bound(self) -> Self:
        if self.acquired_at.tzinfo is None or self.acquired_at.utcoffset() is None:
            raise ValueError("M6 acquisition timestamp must include a UTC offset")
        identities = tuple((item.role.value, item.object_id) for item in self.object_refs)
        if identities != tuple(sorted(set(identities))):
            raise ValueError("M6 acquisition objects must be unique and canonically ordered")
        expected = sha256_digest(self.model_dump(mode="python", exclude={"receipt_digest"}))
        if self.receipt_digest != expected:
            raise ValueError("M6 acquisition receipt digest does not match")
        return self


class BrokerIssuanceReceipt(ContractModel):
    """Detached issuer record; authority still requires external signature/OIDC verification."""

    schema_version: Literal["stateweaver-m6-issuance-v1"]
    status: Literal["BROKER_ISSUED"]
    request_digest: Sha256Digest
    policy_digest: Sha256Digest
    acquisition_receipt_sha256: Sha256Digest
    payload_manifest_sha256: Sha256Digest
    reality_receipt_sha256: Sha256Digest
    replay_snapshot_sha256: Sha256Digest
    semantic_result_sha256: Sha256Digest
    oidc_issuer: OidcIssuer
    oidc_subject: IssuerIdentity
    issued_at: datetime
    expires_at: datetime
    revocation_epoch: Annotated[int, Field(ge=0, le=2**63 - 1)]
    cleanup_residuals: Literal[0]
    detached_attestation_sha256: Sha256Digest
    receipt_digest: Sha256Digest

    @model_validator(mode="after")
    def issuance_is_fresh_and_content_bound(self) -> Self:
        if (
            self.issued_at.tzinfo is None
            or self.expires_at.tzinfo is None
            or self.issued_at.utcoffset() is None
            or self.expires_at.utcoffset() is None
            or self.expires_at <= self.issued_at
        ):
            raise ValueError("M6 issuance validity is invalid")
        expected = sha256_digest(self.model_dump(mode="python", exclude={"receipt_digest"}))
        if self.receipt_digest != expected:
            raise ValueError("M6 issuance receipt digest does not match")
        return self


class CleanConsumerReceipt(ContractModel):
    """Separated-consumer result whose identity must be checked outside the producer."""

    schema_version: Literal["stateweaver-m6-clean-consumer-v1"]
    status: Literal["CLEAN_CONSUMER_REPLAYED"]
    payload_manifest_sha256: Sha256Digest
    policy_digest: Sha256Digest
    issuance_receipt_sha256: Sha256Digest
    consumer_identity: IssuerIdentity
    consumer_environment_sha256: Sha256Digest
    semantic_result_sha256: Sha256Digest
    replay_snapshot_sha256: Sha256Digest
    completed_at: datetime
    cleanup_residuals: Literal[0]
    separation_attestation_sha256: Sha256Digest
    receipt_digest: Sha256Digest

    @model_validator(mode="after")
    def consumer_receipt_is_content_bound(self) -> Self:
        if self.completed_at.tzinfo is None or self.completed_at.utcoffset() is None:
            raise ValueError("M6 consumer timestamp must include a UTC offset")
        expected = sha256_digest(self.model_dump(mode="python", exclude={"receipt_digest"}))
        if self.receipt_digest != expected:
            raise ValueError("M6 consumer receipt digest does not match")
        return self


class M6PromotionClosure(ContractModel):
    """Current repository posture: required inputs named, promotion still externally blocked."""

    schema_version: Literal["stateweaver-m6-promotion-closure-v1"]
    payload_manifest_sha256: Sha256Digest
    policy_digest: Sha256Digest
    acquisition_receipt_sha256: Sha256Digest
    issuance_receipt_sha256: Sha256Digest
    clean_consumer_receipt_sha256: Sha256Digest
    promotion_authorized: Literal[False]
    status: Literal["EXTERNAL_QUALIFICATION_REQUIRED"]
    closure_digest: Sha256Digest

    @model_validator(mode="after")
    def closure_is_content_bound(self) -> Self:
        expected = sha256_digest(self.model_dump(mode="python", exclude={"closure_digest"}))
        if self.closure_digest != expected:
            raise ValueError("M6 promotion closure digest does not match")
        return self


__all__ = [
    "AuthenticatedAcquisitionReceipt",
    "BrokerIssuanceReceipt",
    "BrokerReplayRequest",
    "CleanConsumerReceipt",
    "ExternalTrustPolicy",
    "ImmutableObjectRef",
    "ImmutableObjectRole",
    "M6PromotionClosure",
    "ManifestObjectBinding",
    "SourceComponentKind",
    "SourceObjectBinding",
]
