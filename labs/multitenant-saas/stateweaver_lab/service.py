"""Programmatic deterministic service used by replay adapters and tests."""

from __future__ import annotations

from .models import (
    ActionReceipt,
    AdvanceClockLabAction,
    ClaimReferenceLabAction,
    ClockResponse,
    DeferQueueLabAction,
    DocumentResponse,
    DowngradeRoleLabAction,
    EvidenceListResponse,
    LabMode,
    LayeredStateCapture,
    MaskedDocumentResponse,
    MaskedReadLabAction,
    MockPolicyLabAction,
    MockPolicyResponse,
    OracleResultResponse,
    PrimeAuthorizationCacheLabAction,
    PublishReferenceLabAction,
    ReadDocumentLabAction,
    ReferenceResponse,
    RetainSessionLabAction,
    RoleDowngradeResponse,
    StateDigestResponse,
    TypedLabAction,
)
from .state import AuthContext, LabActionError, LabState

LabActionResult = (
    ActionReceipt
    | RoleDowngradeResponse
    | ReferenceResponse
    | ClockResponse
    | DocumentResponse
    | MaskedDocumentResponse
    | MockPolicyResponse
)


class DeterministicLabService:
    """Own one isolated lab state and execute only allowlisted typed actions."""

    def __init__(self, mode: str | LabMode) -> None:
        selected_mode = mode if isinstance(mode, LabMode) else LabMode(mode)
        self._mode = selected_mode
        self._state = LabState.canonical(selected_mode)

    @classmethod
    def seed(cls, mode: str | LabMode) -> DeterministicLabService:
        return cls(mode)

    @property
    def mode(self) -> LabMode:
        return self._mode

    def reset(self) -> StateDigestResponse:
        self._state = LabState.canonical(self._mode)
        return self.capture()

    def capture(self) -> StateDigestResponse:
        return self._state.state_digest()

    def capture_layers(self) -> LayeredStateCapture:
        return self._state.capture_layers()

    def evidence(self) -> EvidenceListResponse:
        return self._state.evidence()

    def oracle(self) -> OracleResultResponse:
        return self._state.oracle_result()

    def execute(self, action: TypedLabAction) -> LabActionResult:
        context = self._context(action.actor.value)
        if isinstance(action, RetainSessionLabAction):
            return self._state.retain_old_session(context)
        if isinstance(action, PrimeAuthorizationCacheLabAction):
            return self._state.prime_authorization_cache(context, action.payload.document_id)
        if isinstance(action, DowngradeRoleLabAction):
            return self._state.downgrade_role(
                context,
                action.payload.principal_id,
                action.payload.new_role,
            )
        if isinstance(action, DeferQueueLabAction):
            return self._state.delay_queue_job(
                context,
                action.payload.job_id,
                action.payload.delay_seconds,
            )
        if isinstance(action, PublishReferenceLabAction):
            return self._state.publish_reference(
                context,
                action.payload.document_id,
                action.payload.recipient_id,
            )
        if isinstance(action, ClaimReferenceLabAction):
            return self._state.claim_reference(context, action.payload.reference_id)
        if isinstance(action, AdvanceClockLabAction):
            return self._state.advance_clock(context, action.payload.seconds)
        if isinstance(action, ReadDocumentLabAction):
            return self._state.read_document(context, action.payload.document_id)
        if isinstance(action, MaskedReadLabAction):
            return self._state.masked_decoy(context, action.payload.document_id)
        if isinstance(action, MockPolicyLabAction):
            return self._state.mock_policy_decoy(context, action.payload.document_id)
        raise TypeError("unsupported typed lab action")

    def _context(self, bearer_value: str) -> AuthContext:
        context = self._state.authenticate(bearer_value)
        if context is None:
            raise LabActionError(401, "unknown_or_expired_fixture")
        return context
