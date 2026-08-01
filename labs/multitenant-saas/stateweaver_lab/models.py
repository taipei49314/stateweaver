"""Typed API contracts local to the synthetic lab."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from .fixtures import FixtureBearer


class LabMode(StrEnum):
    VULNERABLE = "vulnerable"
    PATCHED = "patched"


class TenantId(StrEnum):
    A = "tenant-a"
    B = "tenant-b"
    PLATFORM = "platform"


class PrincipalId(StrEnum):
    A_EDITOR = "principal-a"
    B_VIEWER = "principal-b"
    ADMIN = "principal-admin"


class Role(StrEnum):
    EDITOR = "editor"
    VIEWER = "viewer"
    ADMIN = "admin"


class DocumentId(StrEnum):
    TENANT_A_OWNED = "doc-a-owned"
    TENANT_B_PROTECTED = "doc-b-protected"


class QueueJobId(StrEnum):
    ROLE_SYNC_A = "job-role-sync-a"


class ReferenceId(StrEnum):
    B_TO_A = "ref-b-to-a"


class Provenance(StrEnum):
    OBSERVED = "OBSERVED"
    MOCKED = "MOCKED"


class StrictApiModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


class RetainSessionRequest(StrictApiModel):
    purpose: Literal["clean-replay"] = "clean-replay"


class PrimeAuthorizationCacheRequest(StrictApiModel):
    document_id: Annotated[DocumentId, Field(strict=False)]


class RoleDowngradeRequest(StrictApiModel):
    principal_id: Annotated[PrincipalId, Field(strict=False)]
    new_role: Annotated[Role, Field(strict=False)]
    propagation: Literal["queued"] = "queued"


class DelayQueueRequest(StrictApiModel):
    job_id: Annotated[QueueJobId, Field(strict=False)]
    delay_seconds: Literal[240] = 240


class PublishReferenceRequest(StrictApiModel):
    document_id: Annotated[DocumentId, Field(strict=False)]
    recipient_id: Annotated[PrincipalId, Field(strict=False)]


class ClaimReferenceRequest(StrictApiModel):
    reference_id: Annotated[ReferenceId, Field(strict=False)]


class AdvanceClockRequest(StrictApiModel):
    seconds: int = Field(ge=1, le=300)


class ResetLabRequest(StrictApiModel):
    seed: Literal["m0-canonical-v1"] = "m0-canonical-v1"


class ReadDocumentRequest(StrictApiModel):
    document_id: Annotated[DocumentId, Field(strict=False)]


class HealthResponse(StrictApiModel):
    status: Literal["ok"] = "ok"
    mode: LabMode
    clock_mode: Literal["controlled"] = "controlled"
    network_scope: Literal["in-process-only"] = "in-process-only"


class ActionReceipt(StrictApiModel):
    action_id: str
    action_type: str
    outcome: str
    at: datetime


class RoleDowngradeResponse(ActionReceipt):
    principal_id: PrincipalId
    current_role: Role
    queue_job_id: QueueJobId


class ReferenceResponse(ActionReceipt):
    reference_id: ReferenceId
    document_id: DocumentId


class ClockResponse(ActionReceipt):
    now: datetime


class DocumentResponse(StrictApiModel):
    document_id: DocumentId
    owner_tenant: TenantId
    body: str
    provenance: Literal[Provenance.OBSERVED]
    evidence_id: str


class MaskedDocumentResponse(StrictApiModel):
    document_id: DocumentId
    status: Literal["masked"] = "masked"
    body: Literal["[MASKED]"] = "[MASKED]"
    masked: Literal[True] = True
    evidence_id: str


class MockPolicyResponse(StrictApiModel):
    document_id: DocumentId
    simulated_decision: Literal["allow"] = "allow"
    body: Literal["MOCK_ONLY_NOT_RUNTIME_DATA"] = "MOCK_ONLY_NOT_RUNTIME_DATA"
    provenance: Literal[Provenance.MOCKED] = Provenance.MOCKED
    evidence_id: str


class ChainStateResponse(StrictApiModel):
    old_session_retained: bool
    role_downgraded: bool
    queue_sync_delayed: bool
    queue_sync_pending: bool
    stale_authorization_cache: bool
    foreign_reference_obtained: bool
    replay_window_open: bool
    old_session_generation_stale: bool


class StateDigestResponse(StrictApiModel):
    seed: Literal["m0-canonical-v1"]
    mode: LabMode
    now: datetime
    policy_generation: int
    evidence_count: int
    fingerprint: str


class ApplicationLayerCapture(StrictApiModel):
    retained_session_handles: tuple[str, ...]
    role_downgraded_at: datetime | None
    replay_window_opens_at: datetime | None
    replay_window_closes_at: datetime | None
    reference_id: ReferenceId
    reference_published: bool
    reference_claimed_by_session_handle: str | None
    evidence_count: int


class PrincipalLayerEntry(StrictApiModel):
    principal_id: PrincipalId
    tenant_id: TenantId
    role: Role


class DocumentOwnershipLayerEntry(StrictApiModel):
    document_id: DocumentId
    tenant_id: TenantId


class DatabaseLayerCapture(StrictApiModel):
    policy_generation: int
    principals: tuple[PrincipalLayerEntry, ...]
    document_ownership: tuple[DocumentOwnershipLayerEntry, ...]


class CacheEntryLayerCapture(StrictApiModel):
    principal_id: PrincipalId
    permission: str
    allowed: bool
    primed_document_id: DocumentId
    tenant_scope: TenantId
    policy_generation: int


class CacheLayerCapture(StrictApiModel):
    entry: CacheEntryLayerCapture | None


class QueueEntryLayerCapture(StrictApiModel):
    job_id: QueueJobId
    principal_id: PrincipalId
    due_at: datetime
    status: str
    deliberately_delayed: bool


class QueueLayerCapture(StrictApiModel):
    entry: QueueEntryLayerCapture | None


class BrowserSessionLayerEntry(StrictApiModel):
    session_handle: str
    principal_id: PrincipalId
    issued_role: Role
    session_generation: int
    issued_at: datetime
    expires_at: datetime
    identity_hash: str


class BrowserLayerCapture(StrictApiModel):
    sessions: tuple[BrowserSessionLayerEntry, ...]


class ConfigurationLayerCapture(StrictApiModel):
    seed: Literal["m0-canonical-v1"]
    mode: LabMode
    network_scope: Literal["in-process-only"] = "in-process-only"
    external_egress_enabled: Literal[False] = False
    arbitrary_actions_enabled: Literal[False] = False


class ClockLayerCapture(StrictApiModel):
    mode: Literal["controlled"] = "controlled"
    epoch: datetime
    now: datetime


class LayeredStateCapture(StrictApiModel):
    schema_version: Literal["1.0"] = "1.0"
    fingerprint: str
    application: ApplicationLayerCapture
    database: DatabaseLayerCapture
    cache: CacheLayerCapture
    queue: QueueLayerCapture
    browser: BrowserLayerCapture
    configuration: ConfigurationLayerCapture
    clock: ClockLayerCapture


class EvidenceRecordResponse(StrictApiModel):
    evidence_id: str
    action_type: str
    actor_principal_id: PrincipalId
    outcome: str
    at: datetime
    resource_id: str = ""
    provenance: Provenance


class EvidenceListResponse(StrictApiModel):
    records: tuple[EvidenceRecordResponse, ...]


class OracleCheckResponse(StrictApiModel):
    check_id: str
    passed: bool


class OracleResultResponse(StrictApiModel):
    oracle_id: Literal["oracle.cross_tenant_document_disclosure.v1"]
    schema_version: Literal["1.0"] = "1.0"
    mode: LabMode
    violated: bool
    verdict: Literal["VIOLATED", "NOT_VIOLATED"]
    checks: tuple[OracleCheckResponse, ...]
    evidence_ids: tuple[str, ...]


class RetainSessionLabAction(StrictApiModel):
    action_type: Literal["session.retain"] = "session.retain"
    actor: Literal[FixtureBearer.TENANT_A_OLD_EDITOR] = FixtureBearer.TENANT_A_OLD_EDITOR
    payload: RetainSessionRequest = RetainSessionRequest()


class PrimeAuthorizationCacheLabAction(StrictApiModel):
    action_type: Literal["authorization_cache.prime"] = "authorization_cache.prime"
    actor: Literal[FixtureBearer.TENANT_A_OLD_EDITOR] = FixtureBearer.TENANT_A_OLD_EDITOR
    payload: PrimeAuthorizationCacheRequest


class DowngradeRoleLabAction(StrictApiModel):
    action_type: Literal["role.downgrade"] = "role.downgrade"
    actor: Literal[FixtureBearer.LAB_ADMIN] = FixtureBearer.LAB_ADMIN
    payload: RoleDowngradeRequest


class DeferQueueLabAction(StrictApiModel):
    action_type: Literal["queue.defer"] = "queue.defer"
    actor: Literal[FixtureBearer.LAB_ADMIN] = FixtureBearer.LAB_ADMIN
    payload: DelayQueueRequest


class PublishReferenceLabAction(StrictApiModel):
    action_type: Literal["reference.publish"] = "reference.publish"
    actor: Literal[FixtureBearer.TENANT_B_VIEWER] = FixtureBearer.TENANT_B_VIEWER
    payload: PublishReferenceRequest


class ClaimReferenceLabAction(StrictApiModel):
    action_type: Literal["reference.claim"] = "reference.claim"
    actor: Literal[FixtureBearer.TENANT_A_OLD_EDITOR] = FixtureBearer.TENANT_A_OLD_EDITOR
    payload: ClaimReferenceRequest


class AdvanceClockLabAction(StrictApiModel):
    action_type: Literal["clock.advance"] = "clock.advance"
    actor: Literal[FixtureBearer.LAB_ADMIN] = FixtureBearer.LAB_ADMIN
    payload: AdvanceClockRequest


class ReadDocumentLabAction(StrictApiModel):
    action_type: Literal["document.read"] = "document.read"
    actor: FixtureBearer
    payload: ReadDocumentRequest


class MaskedReadLabAction(StrictApiModel):
    action_type: Literal["decoy.masked_read"] = "decoy.masked_read"
    actor: FixtureBearer
    payload: ReadDocumentRequest


class MockPolicyLabAction(StrictApiModel):
    action_type: Literal["decoy.mock_policy"] = "decoy.mock_policy"
    actor: FixtureBearer
    payload: ReadDocumentRequest


TypedLabAction = Annotated[
    RetainSessionLabAction
    | PrimeAuthorizationCacheLabAction
    | DowngradeRoleLabAction
    | DeferQueueLabAction
    | PublishReferenceLabAction
    | ClaimReferenceLabAction
    | AdvanceClockLabAction
    | ReadDocumentLabAction
    | MaskedReadLabAction
    | MockPolicyLabAction,
    Field(discriminator="action_type"),
]
