"""Deterministic, fail-closed authorization bindings for policy enforcement."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import Field, field_validator, model_validator
from stateweaver.contracts import (
    ActionEnvelope,
    ContractId,
    HttpMethod,
    HttpRequestAction,
    Sha256Digest,
    sha256_digest,
)

from .evaluator import evaluate_policy
from .models import PolicyDecision, PolicyModel, PolicyRequest


class PolicyAuthorizationDeniedError(ValueError):
    """Raised when a bound authorization cannot admit the attempted action."""


class PolicyAuthorization(PolicyModel):
    """One evaluator result bound to exact action, scope, budget slot, and validity window."""

    policy_decision_ref: ContractId
    action_id: ContractId
    idempotency_key: Sha256Digest
    envelope_hash: Sha256Digest
    policy_request_hash: Sha256Digest
    scope_manifest_hash: Sha256Digest
    budget_reservation_id: Sha256Digest
    evaluated_at: datetime
    not_before: datetime | None
    expires_at: datetime
    requests_before: Annotated[int, Field(ge=0)]
    write_requests_before: Annotated[int, Field(ge=0)]
    is_write: bool
    decision: PolicyDecision

    @classmethod
    def bind(
        cls,
        envelope: ActionEnvelope,
        request: PolicyRequest,
        decision: PolicyDecision,
    ) -> PolicyAuthorization:
        """Bind an already evaluated decision only when it is the sole evaluator result."""

        if (
            request.action_envelope != envelope
            or request.scope_manifest is None
            or request.budget is None
            or request.evaluated_at is None
        ):
            raise ValueError("policy request is incomplete or bound to another action")
        if evaluate_policy(request) != decision:
            raise ValueError("policy decision does not match deterministic evaluation")
        action = envelope.action
        is_write = isinstance(action, HttpRequestAction) and action.method not in {
            HttpMethod.GET,
            HttpMethod.HEAD,
            HttpMethod.OPTIONS,
        }
        envelope_hash = sha256_digest(envelope)
        scope_manifest_hash = sha256_digest(request.scope_manifest)
        return cls(
            policy_decision_ref=envelope.policy_decision_ref,
            action_id=envelope.action_id,
            idempotency_key=envelope.idempotency_key,
            envelope_hash=envelope_hash,
            policy_request_hash=request.fingerprint(),
            scope_manifest_hash=scope_manifest_hash,
            budget_reservation_id=sha256_digest(
                {
                    "envelope_hash": envelope_hash,
                    "scope_manifest_hash": scope_manifest_hash,
                    "requests_before": request.budget.requests_in_window,
                    "write_requests_before": request.budget.write_requests_used,
                }
            ),
            evaluated_at=request.evaluated_at,
            not_before=request.scope_manifest.spec.validity.not_before,
            expires_at=request.scope_manifest.spec.validity.expires_at,
            requests_before=request.budget.requests_in_window,
            write_requests_before=request.budget.write_requests_used,
            is_write=is_write,
            decision=decision,
        )

    @field_validator("evaluated_at", "not_before", "expires_at")
    @classmethod
    def timestamps_are_absolute(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("policy authorization timestamps must include a UTC offset")
        return value

    @model_validator(mode="after")
    def validity_is_coherent(self) -> PolicyAuthorization:
        if self.not_before is not None and self.evaluated_at < self.not_before:
            raise ValueError("policy evaluation predates scope validity")
        if self.evaluated_at > self.expires_at:
            raise ValueError("policy evaluation is outside scope validity")
        return self

    def require_allows(
        self,
        envelope: ActionEnvelope,
        *,
        at: datetime,
        requests_used: int,
        write_requests_used: int,
    ) -> None:
        """Fail closed unless every run-time binding equals its issued authorization."""

        action = envelope.action
        envelope_is_write = isinstance(action, HttpRequestAction) and action.method not in {
            HttpMethod.GET,
            HttpMethod.HEAD,
            HttpMethod.OPTIONS,
        }
        if (
            not self.decision.allowed
            or self.action_id != envelope.action_id
            or self.idempotency_key != envelope.idempotency_key
            or self.envelope_hash != sha256_digest(envelope)
            or at < self.evaluated_at
            or (self.not_before is not None and at < self.not_before)
            or at > self.expires_at
            or self.requests_before != requests_used
            or self.write_requests_before != write_requests_used
            or self.is_write is not envelope_is_write
        ):
            raise PolicyAuthorizationDeniedError("policy authorization denied")


def verify_policy_authorization(
    authorization: PolicyAuthorization,
    envelope: ActionEnvelope,
    *,
    at: datetime,
    requests_used: int,
    write_requests_used: int,
    request: PolicyRequest | None = None,
) -> PolicyAuthorization:
    """Verify one authorization using the shared enforcement semantics.

    Consumers with the retained issuance request can additionally prove that no
    request, scope, budget, or evaluator-result substitution occurred.
    """

    if request is not None and (
        request.action_envelope != envelope
        or request.scope_manifest is None
        or request.budget is None
        or request.evaluated_at is None
        or authorization.policy_request_hash != request.fingerprint()
        or authorization.scope_manifest_hash != sha256_digest(request.scope_manifest)
        or authorization.requests_before != request.budget.requests_in_window
        or authorization.write_requests_before != request.budget.write_requests_used
        or authorization.evaluated_at != request.evaluated_at
        or authorization.not_before != request.scope_manifest.spec.validity.not_before
        or authorization.expires_at != request.scope_manifest.spec.validity.expires_at
        or authorization.decision != evaluate_policy(request)
    ):
        raise PolicyAuthorizationDeniedError("policy authorization binding is invalid")

    authorization.require_allows(
        envelope,
        at=at,
        requests_used=requests_used,
        write_requests_used=write_requests_used,
    )
    return authorization


__all__ = [
    "PolicyAuthorization",
    "PolicyAuthorizationDeniedError",
    "verify_policy_authorization",
]
