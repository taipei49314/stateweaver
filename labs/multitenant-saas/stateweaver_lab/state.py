"""Deterministic state machine backing the synthetic FastAPI lab."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from threading import RLock

from .clock import CANONICAL_EPOCH, ControlledClock, canonical_timestamp
from .fixtures import (
    BEARER_TO_SESSION,
    CANONICAL_SEED,
    SYNTHETIC_TENANT_A_BODY,
    SYNTHETIC_TENANT_B_MARKER,
    FixtureSessionId,
)
from .models import (
    ActionReceipt,
    ApplicationLayerCapture,
    BrowserLayerCapture,
    BrowserSessionLayerEntry,
    CacheEntryLayerCapture,
    CacheLayerCapture,
    ChainStateResponse,
    ClockLayerCapture,
    ClockResponse,
    ConfigurationLayerCapture,
    DatabaseLayerCapture,
    DocumentId,
    DocumentOwnershipLayerEntry,
    DocumentResponse,
    EvidenceListResponse,
    EvidenceRecordResponse,
    LabMode,
    LayeredStateCapture,
    MaskedDocumentResponse,
    MockPolicyResponse,
    OracleResultResponse,
    PrincipalId,
    PrincipalLayerEntry,
    Provenance,
    QueueEntryLayerCapture,
    QueueJobId,
    QueueLayerCapture,
    ReferenceId,
    ReferenceResponse,
    Role,
    RoleDowngradeResponse,
    StateDigestResponse,
    TenantId,
)
from .oracle import DisclosureObservation, evaluate_disclosure


class LabActionError(Exception):
    """A stable, non-sensitive error emitted by a typed lab action."""

    def __init__(self, status_code: int, code: str) -> None:
        super().__init__(code)
        self.status_code = status_code
        self.code = code


@dataclass(frozen=True)
class PrincipalFixture:
    principal_id: PrincipalId
    tenant_id: TenantId
    role: Role


@dataclass(frozen=True)
class SessionFixture:
    session_id: FixtureSessionId
    principal_id: PrincipalId
    issued_role: Role
    policy_generation: int
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class AuthContext:
    session_id: FixtureSessionId
    principal_id: PrincipalId
    tenant_id: TenantId
    issued_role: Role
    policy_generation: int


@dataclass(frozen=True)
class DocumentFixture:
    document_id: DocumentId
    tenant_id: TenantId
    body: str


@dataclass(frozen=True)
class AuthorizationCacheEntry:
    principal_id: PrincipalId
    permission: str
    allowed: bool
    primed_document_id: DocumentId
    tenant_scope: TenantId
    policy_generation: int


@dataclass
class QueueJobFixture:
    job_id: QueueJobId
    principal_id: PrincipalId
    due_at: datetime
    status: str = "pending"
    deliberately_delayed: bool = False


@dataclass
class ReferenceFixture:
    reference_id: ReferenceId
    document_id: DocumentId
    publisher_id: PrincipalId
    recipient_id: PrincipalId
    published: bool = False
    claimed_by_session_id: FixtureSessionId | None = None


@dataclass(frozen=True)
class InternalEvidence:
    action_id: str
    evidence_id: str
    action_type: str
    actor_principal_id: PrincipalId
    outcome: str
    at: datetime
    resource_id: str
    provenance: Provenance


class LabState:
    """A resettable, deterministic simulation with no external side effects."""

    def __init__(self, mode: LabMode) -> None:
        self.mode = mode
        self.seed = CANONICAL_SEED
        self.clock = ControlledClock.canonical()
        self._lock = RLock()
        self._sequence = 0
        self.policy_generation = 1
        self.principals: dict[PrincipalId, PrincipalFixture] = {
            PrincipalId.A_EDITOR: PrincipalFixture(PrincipalId.A_EDITOR, TenantId.A, Role.EDITOR),
            PrincipalId.B_VIEWER: PrincipalFixture(PrincipalId.B_VIEWER, TenantId.B, Role.VIEWER),
            PrincipalId.ADMIN: PrincipalFixture(PrincipalId.ADMIN, TenantId.PLATFORM, Role.ADMIN),
        }
        epoch = self.clock.now
        self.sessions: dict[FixtureSessionId, SessionFixture] = {
            FixtureSessionId.TENANT_A_OLD: SessionFixture(
                session_id=FixtureSessionId.TENANT_A_OLD,
                principal_id=PrincipalId.A_EDITOR,
                issued_role=Role.EDITOR,
                policy_generation=1,
                issued_at=epoch - timedelta(minutes=5),
                expires_at=epoch + timedelta(hours=1),
            ),
            FixtureSessionId.TENANT_B_VIEWER: SessionFixture(
                session_id=FixtureSessionId.TENANT_B_VIEWER,
                principal_id=PrincipalId.B_VIEWER,
                issued_role=Role.VIEWER,
                policy_generation=1,
                issued_at=epoch - timedelta(minutes=2),
                expires_at=epoch + timedelta(hours=1),
            ),
            FixtureSessionId.LAB_ADMIN: SessionFixture(
                session_id=FixtureSessionId.LAB_ADMIN,
                principal_id=PrincipalId.ADMIN,
                issued_role=Role.ADMIN,
                policy_generation=1,
                issued_at=epoch - timedelta(minutes=10),
                expires_at=epoch + timedelta(days=1),
            ),
        }
        self.documents: dict[DocumentId, DocumentFixture] = {
            DocumentId.TENANT_A_OWNED: DocumentFixture(
                DocumentId.TENANT_A_OWNED,
                TenantId.A,
                SYNTHETIC_TENANT_A_BODY,
            ),
            DocumentId.TENANT_B_PROTECTED: DocumentFixture(
                DocumentId.TENANT_B_PROTECTED,
                TenantId.B,
                SYNTHETIC_TENANT_B_MARKER,
            ),
        }
        self.reference = ReferenceFixture(
            reference_id=ReferenceId.B_TO_A,
            document_id=DocumentId.TENANT_B_PROTECTED,
            publisher_id=PrincipalId.B_VIEWER,
            recipient_id=PrincipalId.A_EDITOR,
        )
        self.authorization_cache: AuthorizationCacheEntry | None = None
        self.queue_job: QueueJobFixture | None = None
        self.retained_sessions: set[FixtureSessionId] = set()
        self.role_downgraded_at: datetime | None = None
        self.replay_window_opens_at: datetime | None = None
        self.replay_window_closes_at: datetime | None = None
        self._evidence: list[InternalEvidence] = []
        self._last_disclosure: DisclosureObservation | None = None

    @classmethod
    def canonical(cls, mode: LabMode) -> LabState:
        return cls(mode=mode)

    def authenticate(self, bearer_value: str) -> AuthContext | None:
        """Resolve a fixture bearer without recording or returning its value."""

        session_id = BEARER_TO_SESSION.get(bearer_value)
        if session_id is None:
            return None
        with self._lock:
            session = self.sessions.get(session_id)
            if session is None or self.clock.now >= session.expires_at:
                return None
            principal = self.principals[session.principal_id]
            return AuthContext(
                session_id=session.session_id,
                principal_id=session.principal_id,
                tenant_id=principal.tenant_id,
                issued_role=session.issued_role,
                policy_generation=session.policy_generation,
            )

    def require_admin(self, context: AuthContext) -> None:
        if context.principal_id != PrincipalId.ADMIN:
            raise LabActionError(403, "admin_fixture_required")

    def retain_old_session(self, context: AuthContext) -> ActionReceipt:
        with self._lock:
            if context.session_id != FixtureSessionId.TENANT_A_OLD:
                raise LabActionError(403, "old_editor_session_required")
            if self.role_downgraded_at is not None:
                raise LabActionError(409, "session_must_be_retained_before_downgrade")
            if context.session_id in self.retained_sessions:
                raise LabActionError(409, "session_already_retained")
            self.retained_sessions.add(context.session_id)
            evidence = self._record(
                "session.retain",
                context,
                "retained",
                resource_id=context.session_id.value,
            )
            return self._receipt(evidence)

    def prime_authorization_cache(
        self, context: AuthContext, document_id: DocumentId
    ) -> ActionReceipt:
        with self._lock:
            document = self.documents[document_id]
            current = self.principals[context.principal_id]
            if context.session_id != FixtureSessionId.TENANT_A_OLD:
                raise LabActionError(403, "old_editor_session_required")
            if current.role != Role.EDITOR or document.tenant_id != current.tenant_id:
                raise LabActionError(403, "owned_editor_document_required")
            if self.role_downgraded_at is not None:
                raise LabActionError(409, "cache_must_be_primed_before_downgrade")
            self.authorization_cache = AuthorizationCacheEntry(
                principal_id=context.principal_id,
                permission="document:read",
                allowed=True,
                primed_document_id=document_id,
                tenant_scope=current.tenant_id,
                policy_generation=self.policy_generation,
            )
            evidence = self._record(
                "authorization_cache.prime",
                context,
                "allowed_cached",
                resource_id=document_id.value,
            )
            return self._receipt(evidence)

    def downgrade_role(
        self,
        context: AuthContext,
        principal_id: PrincipalId,
        new_role: Role,
    ) -> RoleDowngradeResponse:
        with self._lock:
            self.require_admin(context)
            if principal_id != PrincipalId.A_EDITOR or new_role != Role.VIEWER:
                raise LabActionError(422, "canonical_downgrade_only")
            principal = self.principals[principal_id]
            if principal.role != Role.EDITOR or self.role_downgraded_at is not None:
                raise LabActionError(409, "role_already_downgraded")
            self.policy_generation = 2
            self.principals[principal_id] = PrincipalFixture(
                principal_id=principal.principal_id,
                tenant_id=principal.tenant_id,
                role=Role.VIEWER,
            )
            now = self.clock.now
            self.role_downgraded_at = now
            self.replay_window_opens_at = now + timedelta(seconds=60)
            self.replay_window_closes_at = now + timedelta(seconds=180)
            self.queue_job = QueueJobFixture(
                job_id=QueueJobId.ROLE_SYNC_A,
                principal_id=principal_id,
                due_at=now + timedelta(seconds=30),
            )
            self.sessions[FixtureSessionId.TENANT_A_FRESH] = SessionFixture(
                session_id=FixtureSessionId.TENANT_A_FRESH,
                principal_id=principal_id,
                issued_role=Role.VIEWER,
                policy_generation=self.policy_generation,
                issued_at=now,
                expires_at=now + timedelta(hours=1),
            )
            # The patch invalidates stale authorization decisions immediately.
            if self.mode == LabMode.PATCHED:
                self.authorization_cache = None
            evidence = self._record(
                "role.downgrade",
                context,
                "queued",
                resource_id=principal_id.value,
            )
            return RoleDowngradeResponse(
                **self._receipt(evidence).model_dump(),
                principal_id=principal_id,
                current_role=Role.VIEWER,
                queue_job_id=QueueJobId.ROLE_SYNC_A,
            )

    def delay_queue_job(
        self,
        context: AuthContext,
        job_id: QueueJobId,
        delay_seconds: int,
    ) -> ActionReceipt:
        with self._lock:
            self.require_admin(context)
            if delay_seconds != 240:
                raise LabActionError(422, "canonical_delay_only")
            if self.queue_job is None or self.queue_job.job_id != job_id:
                raise LabActionError(409, "role_sync_job_not_created")
            self._process_due_jobs()
            if self.queue_job.status != "pending":
                raise LabActionError(409, "role_sync_job_not_pending")
            if self.queue_job.deliberately_delayed:
                raise LabActionError(409, "role_sync_job_already_delayed")
            downgraded_at = self.role_downgraded_at
            if downgraded_at is None:
                raise LabActionError(409, "role_downgrade_not_recorded")
            self.queue_job.due_at = downgraded_at + timedelta(seconds=delay_seconds)
            self.queue_job.deliberately_delayed = True
            evidence = self._record(
                "queue.defer",
                context,
                "delayed",
                resource_id=job_id.value,
            )
            return self._receipt(evidence)

    def publish_reference(
        self,
        context: AuthContext,
        document_id: DocumentId,
        recipient_id: PrincipalId,
    ) -> ReferenceResponse:
        with self._lock:
            if context.principal_id != PrincipalId.B_VIEWER:
                raise LabActionError(403, "tenant_b_viewer_required")
            document = self.documents[document_id]
            if (
                document_id != self.reference.document_id
                or document.tenant_id != context.tenant_id
                or recipient_id != self.reference.recipient_id
            ):
                raise LabActionError(422, "canonical_reference_only")
            if self.reference.published:
                raise LabActionError(409, "reference_already_published")
            self.reference.published = True
            evidence = self._record(
                "reference.publish",
                context,
                "opaque_reference_published",
                resource_id=self.reference.reference_id.value,
            )
            return ReferenceResponse(
                **self._receipt(evidence).model_dump(),
                reference_id=self.reference.reference_id,
                document_id=self.reference.document_id,
            )

    def claim_reference(self, context: AuthContext, reference_id: ReferenceId) -> ReferenceResponse:
        with self._lock:
            if context.principal_id != self.reference.recipient_id:
                raise LabActionError(403, "reference_recipient_required")
            if reference_id != self.reference.reference_id:
                raise LabActionError(422, "canonical_reference_only")
            if not self.reference.published:
                raise LabActionError(409, "reference_not_published")
            if self.reference.claimed_by_session_id is not None:
                raise LabActionError(409, "reference_already_claimed")
            self.reference.claimed_by_session_id = context.session_id
            evidence = self._record(
                "reference.claim",
                context,
                "foreign_reference_obtained",
                resource_id=reference_id.value,
            )
            return ReferenceResponse(
                **self._receipt(evidence).model_dump(),
                reference_id=self.reference.reference_id,
                document_id=self.reference.document_id,
            )

    def advance_clock(self, context: AuthContext, seconds: int) -> ClockResponse:
        with self._lock:
            self.require_admin(context)
            now = self.clock.advance(seconds)
            self._process_due_jobs()
            evidence = self._record(
                "clock.advance",
                context,
                "advanced",
                resource_id=f"seconds:{seconds}",
            )
            return ClockResponse(
                **self._receipt(evidence).model_dump(),
                now=now,
            )

    def read_document(self, context: AuthContext, document_id: DocumentId) -> DocumentResponse:
        with self._lock:
            self._process_due_jobs()
            document = self.documents[document_id]
            if document.tenant_id == context.tenant_id:
                evidence = self._record(
                    "document.read",
                    context,
                    "same_tenant_allowed",
                    resource_id=document_id.value,
                )
                return DocumentResponse(
                    document_id=document_id,
                    owner_tenant=document.tenant_id,
                    body=document.body,
                    provenance=Provenance.OBSERVED,
                    evidence_id=evidence.evidence_id,
                )

            conditions = self._chain_state_unlocked()
            complete_vulnerable_chain = (
                self.mode == LabMode.VULNERABLE
                and context.session_id == FixtureSessionId.TENANT_A_OLD
                and all(
                    (
                        conditions.old_session_retained,
                        conditions.role_downgraded,
                        conditions.queue_sync_delayed,
                        conditions.queue_sync_pending,
                        conditions.stale_authorization_cache,
                        conditions.foreign_reference_obtained,
                        conditions.replay_window_open,
                        conditions.old_session_generation_stale,
                    )
                )
            )
            if complete_vulnerable_chain:
                evidence = self._record(
                    "document.read",
                    context,
                    "cross_tenant_body_disclosed",
                    resource_id=document_id.value,
                )
                self._last_disclosure = DisclosureObservation(
                    evidence_id=evidence.evidence_id,
                    requester_tenant=context.tenant_id,
                    owner_tenant=document.tenant_id,
                    document_id=document_id,
                    response_status=200,
                    body_marker=document.body,
                    provenance=Provenance.OBSERVED,
                )
                return DocumentResponse(
                    document_id=document_id,
                    owner_tenant=document.tenant_id,
                    body=document.body,
                    provenance=Provenance.OBSERVED,
                    evidence_id=evidence.evidence_id,
                )

            self._record(
                "document.read",
                context,
                "tenant_boundary_blocked",
                resource_id=document_id.value,
            )
            raise LabActionError(403, "tenant_boundary_enforced")

    def masked_decoy(self, context: AuthContext, document_id: DocumentId) -> MaskedDocumentResponse:
        with self._lock:
            evidence = self._record(
                "decoy.masked_read",
                context,
                "masked_200",
                resource_id=document_id.value,
            )
            return MaskedDocumentResponse(
                document_id=document_id,
                evidence_id=evidence.evidence_id,
            )

    def mock_policy_decoy(
        self, context: AuthContext, document_id: DocumentId
    ) -> MockPolicyResponse:
        with self._lock:
            evidence = self._record(
                "decoy.mock_policy",
                context,
                "simulated_allow_only",
                resource_id=document_id.value,
                provenance=Provenance.MOCKED,
            )
            return MockPolicyResponse(
                document_id=document_id,
                evidence_id=evidence.evidence_id,
            )

    def chain_state(self) -> ChainStateResponse:
        with self._lock:
            self._process_due_jobs()
            return self._chain_state_unlocked()

    def oracle_result(self) -> OracleResultResponse:
        with self._lock:
            return evaluate_disclosure(self.mode, self._last_disclosure)

    def evidence(self) -> EvidenceListResponse:
        with self._lock:
            return EvidenceListResponse(
                records=tuple(
                    EvidenceRecordResponse(
                        evidence_id=item.evidence_id,
                        action_type=item.action_type,
                        actor_principal_id=item.actor_principal_id,
                        outcome=item.outcome,
                        at=item.at,
                        resource_id=item.resource_id,
                        provenance=item.provenance,
                    )
                    for item in self._evidence
                )
            )

    def state_digest(self) -> StateDigestResponse:
        with self._lock:
            return StateDigestResponse(
                seed=CANONICAL_SEED,
                mode=self.mode,
                now=self.clock.now,
                policy_generation=self.policy_generation,
                evidence_count=len(self._evidence),
                fingerprint=self._fingerprint_unlocked(),
            )

    def capture_layers(self) -> LayeredStateCapture:
        """Capture real in-memory layers without bearer values or document bodies."""

        with self._lock:
            self._process_due_jobs()
            cache = self.authorization_cache
            job = self.queue_job
            return LayeredStateCapture(
                fingerprint=self._fingerprint_unlocked(),
                application=ApplicationLayerCapture(
                    retained_session_handles=tuple(
                        sorted(item.value for item in self.retained_sessions)
                    ),
                    role_downgraded_at=self.role_downgraded_at,
                    replay_window_opens_at=self.replay_window_opens_at,
                    replay_window_closes_at=self.replay_window_closes_at,
                    reference_id=self.reference.reference_id,
                    reference_published=self.reference.published,
                    reference_claimed_by_session_handle=(
                        self.reference.claimed_by_session_id.value
                        if self.reference.claimed_by_session_id is not None
                        else None
                    ),
                    evidence_count=len(self._evidence),
                ),
                database=DatabaseLayerCapture(
                    policy_generation=self.policy_generation,
                    principals=tuple(
                        PrincipalLayerEntry(
                            principal_id=principal.principal_id,
                            tenant_id=principal.tenant_id,
                            role=principal.role,
                        )
                        for principal in sorted(
                            self.principals.values(),
                            key=lambda item: item.principal_id.value,
                        )
                    ),
                    document_ownership=tuple(
                        DocumentOwnershipLayerEntry(
                            document_id=document.document_id,
                            tenant_id=document.tenant_id,
                        )
                        for document in sorted(
                            self.documents.values(),
                            key=lambda item: item.document_id.value,
                        )
                    ),
                ),
                cache=CacheLayerCapture(
                    entry=(
                        CacheEntryLayerCapture(
                            principal_id=cache.principal_id,
                            permission=cache.permission,
                            allowed=cache.allowed,
                            primed_document_id=cache.primed_document_id,
                            tenant_scope=cache.tenant_scope,
                            policy_generation=cache.policy_generation,
                        )
                        if cache is not None
                        else None
                    )
                ),
                queue=QueueLayerCapture(
                    entry=(
                        QueueEntryLayerCapture(
                            job_id=job.job_id,
                            principal_id=job.principal_id,
                            due_at=job.due_at,
                            status=job.status,
                            deliberately_delayed=job.deliberately_delayed,
                        )
                        if job is not None
                        else None
                    )
                ),
                browser=BrowserLayerCapture(
                    sessions=tuple(
                        BrowserSessionLayerEntry(
                            session_handle=session.session_id.value,
                            principal_id=session.principal_id,
                            issued_role=session.issued_role,
                            session_generation=session.policy_generation,
                            issued_at=session.issued_at,
                            expires_at=session.expires_at,
                            identity_hash=self._identity_hash(session),
                        )
                        for session in sorted(
                            self.sessions.values(),
                            key=lambda item: item.session_id.value,
                        )
                    )
                ),
                configuration=ConfigurationLayerCapture(
                    seed=CANONICAL_SEED,
                    mode=self.mode,
                ),
                clock=ClockLayerCapture(
                    epoch=CANONICAL_EPOCH,
                    now=self.clock.now,
                ),
            )

    def _process_due_jobs(self) -> None:
        if (
            self.queue_job is not None
            and self.queue_job.status == "pending"
            and self.clock.now >= self.queue_job.due_at
        ):
            self.queue_job.status = "completed"
            self.authorization_cache = None

    def _chain_state_unlocked(self) -> ChainStateResponse:
        old_session = self.sessions[FixtureSessionId.TENANT_A_OLD]
        cache = self.authorization_cache
        job = self.queue_job
        reference_obtained = (
            self.reference.published
            and self.reference.claimed_by_session_id == FixtureSessionId.TENANT_A_OLD
        )
        window_open = (
            self.replay_window_opens_at is not None
            and self.replay_window_closes_at is not None
            and self.replay_window_opens_at <= self.clock.now
            and self.clock.now < self.replay_window_closes_at
        )
        return ChainStateResponse(
            old_session_retained=(FixtureSessionId.TENANT_A_OLD in self.retained_sessions),
            role_downgraded=(
                self.role_downgraded_at is not None
                and self.principals[PrincipalId.A_EDITOR].role == Role.VIEWER
            ),
            queue_sync_delayed=(job is not None and job.deliberately_delayed),
            queue_sync_pending=(job is not None and job.status == "pending"),
            stale_authorization_cache=(
                cache is not None
                and cache.allowed
                and cache.principal_id == PrincipalId.A_EDITOR
                and cache.policy_generation < self.policy_generation
            ),
            foreign_reference_obtained=reference_obtained,
            replay_window_open=window_open,
            old_session_generation_stale=(old_session.policy_generation < self.policy_generation),
        )

    def _record(
        self,
        action_type: str,
        context: AuthContext,
        outcome: str,
        resource_id: str = "",
        provenance: Provenance = Provenance.OBSERVED,
    ) -> InternalEvidence:
        self._sequence += 1
        item = InternalEvidence(
            action_id=f"act-{self._sequence:03d}",
            evidence_id=f"ev-{self._sequence:03d}",
            action_type=action_type,
            actor_principal_id=context.principal_id,
            outcome=outcome,
            at=self.clock.now,
            resource_id=resource_id,
            provenance=provenance,
        )
        self._evidence.append(item)
        return item

    @staticmethod
    def _receipt(evidence: InternalEvidence) -> ActionReceipt:
        return ActionReceipt(
            action_id=evidence.action_id,
            action_type=evidence.action_type,
            outcome=evidence.outcome,
            at=evidence.at,
        )

    def _fingerprint_unlocked(self) -> str:
        cache = self.authorization_cache
        job = self.queue_job
        payload = {
            "schema_version": "lab-state-v1",
            "seed": self.seed,
            "mode": self.mode.value,
            "now": canonical_timestamp(self.clock.now),
            "policy_generation": self.policy_generation,
            "principals": [
                {
                    "principal_id": principal.principal_id.value,
                    "tenant_id": principal.tenant_id.value,
                    "role": principal.role.value,
                }
                for principal in sorted(
                    self.principals.values(), key=lambda item: item.principal_id.value
                )
            ],
            "sessions": [
                {
                    "session_id": session.session_id.value,
                    "principal_id": session.principal_id.value,
                    "issued_role": session.issued_role.value,
                    "policy_generation": session.policy_generation,
                    "issued_at": canonical_timestamp(session.issued_at),
                    "expires_at": canonical_timestamp(session.expires_at),
                }
                for session in sorted(
                    self.sessions.values(), key=lambda item: item.session_id.value
                )
            ],
            "retained_session_ids": sorted(
                session_id.value for session_id in self.retained_sessions
            ),
            "cache": None
            if cache is None
            else {
                "principal_id": cache.principal_id.value,
                "permission": cache.permission,
                "allowed": cache.allowed,
                "primed_document_id": cache.primed_document_id.value,
                "tenant_scope": cache.tenant_scope.value,
                "policy_generation": cache.policy_generation,
            },
            "queue": None
            if job is None
            else {
                "job_id": job.job_id.value,
                "principal_id": job.principal_id.value,
                "due_at": canonical_timestamp(job.due_at),
                "status": job.status,
                "deliberately_delayed": job.deliberately_delayed,
            },
            "reference": {
                "reference_id": self.reference.reference_id.value,
                "document_id": self.reference.document_id.value,
                "publisher_id": self.reference.publisher_id.value,
                "recipient_id": self.reference.recipient_id.value,
                "published": self.reference.published,
                "claimed_by_session_id": (
                    self.reference.claimed_by_session_id.value
                    if self.reference.claimed_by_session_id is not None
                    else None
                ),
            },
            "role_downgraded_at": (
                canonical_timestamp(self.role_downgraded_at)
                if self.role_downgraded_at is not None
                else None
            ),
            "window": {
                "opens_at": (
                    canonical_timestamp(self.replay_window_opens_at)
                    if self.replay_window_opens_at is not None
                    else None
                ),
                "closes_at": (
                    canonical_timestamp(self.replay_window_closes_at)
                    if self.replay_window_closes_at is not None
                    else None
                ),
            },
            "evidence": [
                {
                    "evidence_id": item.evidence_id,
                    "action_type": item.action_type,
                    "actor_principal_id": item.actor_principal_id.value,
                    "outcome": item.outcome,
                    "at": canonical_timestamp(item.at),
                    "resource_id": item.resource_id,
                    "provenance": item.provenance.value,
                }
                for item in self._evidence
            ],
            "oracle_observation_evidence_id": (
                self._last_disclosure.evidence_id if self._last_disclosure is not None else None
            ),
        }
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(canonical).hexdigest()

    @staticmethod
    def _identity_hash(session: SessionFixture) -> str:
        canonical = "|".join(
            (
                session.session_id.value,
                session.principal_id.value,
                str(session.policy_generation),
            )
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(canonical).hexdigest()
