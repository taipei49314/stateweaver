"""Immutable registries that are the adapter's only action translation path."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from types import MappingProxyType
from typing import Annotated, ClassVar

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from stateweaver.contracts import (
    ActionEnvelope,
    ArtifactHandle,
    ContractId,
    HttpMethod,
    HttpRequestAction,
    IdentityHandle,
    Sha256Digest,
)
from stateweaver.policy import PolicyDecision, PolicyRequest, evaluate_policy
from stateweaver.replay import canonical_sha256
from stateweaver_lab import TypedLabAction
from stateweaver_lab.fixtures import FixtureBearer
from stateweaver_lab.models import (
    AdvanceClockLabAction,
    ClaimReferenceLabAction,
    DeferQueueLabAction,
    DowngradeRoleLabAction,
    MaskedReadLabAction,
    MockPolicyLabAction,
    PrimeAuthorizationCacheLabAction,
    PublishReferenceLabAction,
    ReadDocumentLabAction,
    RetainSessionLabAction,
)

from .errors import (
    AdapterConfigurationError,
    LabIdentityRejectedError,
    LabPolicyDeniedError,
    LabTargetRejectedError,
    UnknownLabActionError,
)

type LabAction = (
    RetainSessionLabAction
    | PrimeAuthorizationCacheLabAction
    | DowngradeRoleLabAction
    | DeferQueueLabAction
    | PublishReferenceLabAction
    | ClaimReferenceLabAction
    | AdvanceClockLabAction
    | ReadDocumentLabAction
    | MaskedReadLabAction
    | MockPolicyLabAction
)

_LOCAL_ORIGINS: frozenset[tuple[str, str, int]] = frozenset(
    {
        ("http", "localhost", 80),
        ("https", "app.local", 443),
    }
)


def lab_action_artifact(action: LabAction) -> ArtifactHandle:
    """Return the content handle that binds a plan to exact typed lab parameters."""

    digest = canonical_sha256(action).removeprefix("sha256:")
    return f"artifact:lab-action/{digest}"


class _RegistryModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


class LabHttpActionSpec(_RegistryModel):
    """The one HTTP description accepted for a registered typed lab action."""

    method: HttpMethod
    path: Annotated[str, Field(pattern=r"^/v1/lab/[A-Za-z0-9_./{}-]+$")]
    identity_handle: IdentityHandle
    expected_statuses: tuple[Annotated[int, Field(ge=100, le=599)], ...]

    @field_validator("expected_statuses")
    @classmethod
    def statuses_are_nonempty_and_unique(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if not value or len(value) != len(set(value)):
            raise ValueError("expected_statuses must be nonempty and unique")
        return value


_ACTION_SPECS: tuple[tuple[type[object], HttpMethod, str, tuple[int, ...]], ...] = (
    (RetainSessionLabAction, HttpMethod.POST, "/v1/lab/session/retain", (200,)),
    (
        PrimeAuthorizationCacheLabAction,
        HttpMethod.POST,
        "/v1/lab/authorization-cache/prime",
        (200,),
    ),
    (
        DowngradeRoleLabAction,
        HttpMethod.POST,
        "/v1/lab/admin/role-downgrade",
        (200,),
    ),
    (DeferQueueLabAction, HttpMethod.POST, "/v1/lab/admin/queue/defer", (200,)),
    (PublishReferenceLabAction, HttpMethod.POST, "/v1/lab/references/publish", (200,)),
    (ClaimReferenceLabAction, HttpMethod.POST, "/v1/lab/references/claim", (200,)),
    (AdvanceClockLabAction, HttpMethod.POST, "/v1/lab/admin/clock/advance", (200,)),
)


def _identity_for_actor(actor: FixtureBearer) -> str:
    if actor in {
        FixtureBearer.TENANT_A_OLD_EDITOR,
        FixtureBearer.TENANT_A_FRESH_VIEWER,
    }:
        return "identity:test_user_a"
    if actor is FixtureBearer.TENANT_B_VIEWER:
        return "identity:test_user_b"
    if actor is FixtureBearer.LAB_ADMIN:
        return "identity:test_admin"
    raise AdapterConfigurationError("registered lab actor is unsupported")


def lab_http_action_spec(action: LabAction) -> LabHttpActionSpec:
    """Derive a fixed route from a concrete closed-union lab action."""

    identity_handle = _identity_for_actor(action.actor)
    for action_type, method, path, statuses in _ACTION_SPECS:
        if isinstance(action, action_type):
            return LabHttpActionSpec(
                method=method,
                path=path,
                identity_handle=identity_handle,
                expected_statuses=statuses,
            )

    if isinstance(action, ReadDocumentLabAction):
        document_id = action.payload.document_id.value
        path = f"/v1/lab/documents/{document_id}"
        statuses = (200, 403)
    elif isinstance(action, MaskedReadLabAction):
        document_id = action.payload.document_id.value
        path = f"/v1/lab/decoys/masked/{document_id}"
        statuses = (200,)
    elif isinstance(action, MockPolicyLabAction):
        document_id = action.payload.document_id.value
        path = f"/v1/lab/decoys/mock-policy/{document_id}"
        statuses = (200,)
    else:
        raise AdapterConfigurationError("registered lab action is unsupported")
    return LabHttpActionSpec(
        method=HttpMethod.GET,
        path=path,
        identity_handle=identity_handle,
        expected_statuses=statuses,
    )


class PolicyAuthorization(_RegistryModel):
    """A deterministic policy evaluation bound to an action, scope, validity, and budget slot."""

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
        if (
            request.action_envelope != envelope
            or request.scope_manifest is None
            or request.budget is None
            or request.evaluated_at is None
        ):
            raise AdapterConfigurationError(
                "policy request is incomplete or bound to another action"
            )
        if evaluate_policy(request) != decision:
            raise AdapterConfigurationError(
                "policy decision does not match deterministic evaluation"
            )
        action = envelope.action
        is_write = isinstance(action, HttpRequestAction) and action.method not in {
            HttpMethod.GET,
            HttpMethod.HEAD,
            HttpMethod.OPTIONS,
        }
        reservation_id = canonical_sha256(
            {
                "envelope_hash": canonical_sha256(envelope),
                "scope_manifest_hash": canonical_sha256(request.scope_manifest),
                "requests_before": request.budget.requests_in_window,
                "write_requests_before": request.budget.write_requests_used,
            }
        )
        return cls(
            policy_decision_ref=envelope.policy_decision_ref,
            action_id=envelope.action_id,
            idempotency_key=envelope.idempotency_key,
            envelope_hash=canonical_sha256(envelope),
            policy_request_hash=request.fingerprint(),
            scope_manifest_hash=canonical_sha256(request.scope_manifest),
            budget_reservation_id=reservation_id,
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
            or self.envelope_hash != canonical_sha256(envelope)
            or at < self.evaluated_at
            or (self.not_before is not None and at < self.not_before)
            or at > self.expires_at
            or self.requests_before != requests_used
            or self.write_requests_before != write_requests_used
            or self.is_write is not envelope_is_write
        ):
            raise LabPolicyDeniedError("policy authorization denied")


class FixedLabActionRegistry(_RegistryModel):
    """Closed mappings copied and frozen at adapter construction time."""

    by_action_id: Mapping[ContractId, TypedLabAction]
    by_body_artifact: Mapping[ArtifactHandle, TypedLabAction]
    policy_authorizations: Mapping[ContractId, PolicyAuthorization]

    @field_validator("by_action_id", "by_body_artifact", "policy_authorizations")
    @classmethod
    def mapping_is_copied_and_frozen(cls, value: Mapping[str, object]) -> Mapping[str, object]:
        if not isinstance(value, Mapping):
            raise ValueError("registry fields must be mappings")
        return MappingProxyType(dict(value))

    @model_validator(mode="after")
    def registry_is_coherent(self) -> FixedLabActionRegistry:
        if not self.by_action_id or not self.by_body_artifact:
            raise ValueError("action IDs and parameter artifacts must both be registered")
        for artifact_handle, action in self.by_body_artifact.items():
            if artifact_handle != lab_action_artifact(action):
                raise ValueError("parameter artifact is not the canonical lab action digest")
        for action in self.by_action_id.values():
            registered = self.by_body_artifact.get(lab_action_artifact(action))
            if registered != action:
                raise ValueError("action ID is not bound to its canonical parameter artifact")
        for decision_ref, authorization in self.policy_authorizations.items():
            if decision_ref != authorization.policy_decision_ref:
                raise ValueError("policy authorization key does not match its decision reference")
        return self

    def resolve(self, envelope: ActionEnvelope) -> LabAction:
        from stateweaver.contracts import HttpRequestAction

        if not isinstance(envelope.action, HttpRequestAction):
            raise UnknownLabActionError("only registered HTTP lab actions are supported")

        direct = self.by_action_id.get(envelope.action_id)
        artifact_handle = envelope.action.body_artifact
        if direct is None or artifact_handle is None:
            raise UnknownLabActionError("action ID or parameter artifact is not registered")
        artifact = self.by_body_artifact.get(artifact_handle)
        if artifact is None or artifact != direct or artifact_handle != lab_action_artifact(direct):
            raise UnknownLabActionError("action and parameter artifact binding does not match")
        return direct

    def require_policy_allows(
        self,
        envelope: ActionEnvelope,
        *,
        at: datetime,
        requests_used: int,
        write_requests_used: int,
    ) -> PolicyAuthorization:
        authorization = self.policy_authorizations.get(envelope.policy_decision_ref)
        if authorization is None:
            raise LabPolicyDeniedError("policy authorization is missing")
        authorization.require_allows(
            envelope,
            at=at,
            requests_used=requests_used,
            write_requests_used=write_requests_used,
        )
        return authorization


def validate_fixed_http_envelope(envelope: ActionEnvelope, lab_action: LabAction) -> None:
    """Reject every transport field not supplied by the fixed server-side registry."""

    from stateweaver.contracts import HttpRequestAction, ScopeAction

    action = envelope.action
    if (
        not isinstance(action, HttpRequestAction)
        or envelope.scope_action is not ScopeAction.HTTP_REQUEST
    ):
        raise LabTargetRejectedError("only HTTP request envelopes are supported")
    if action.target is None or action.method is None:
        raise LabTargetRejectedError("a concrete target and method are required")

    expected = lab_http_action_spec(lab_action)
    origin = (action.target.scheme, action.target.host, action.target.port)
    if origin not in _LOCAL_ORIGINS:
        raise LabTargetRejectedError("target origin is outside the in-process allowlist")
    if action.method is not expected.method or action.target.path != expected.path:
        raise LabTargetRejectedError("target route does not match the registered action")
    if action.body_artifact != lab_action_artifact(lab_action):
        raise LabTargetRejectedError("typed parameters do not match their content handle")
    if action.template_ref is not None or action.query or action.headers:
        raise LabTargetRejectedError("dynamic request fields are not supported")
    if action.expected_statuses != expected.expected_statuses:
        raise LabTargetRejectedError("expected statuses do not match the registered action")
    if action.identity_handle != expected.identity_handle:
        raise LabIdentityRejectedError("identity does not match the registered actor")


__all__ = [
    "FixedLabActionRegistry",
    "LabAction",
    "LabHttpActionSpec",
    "PolicyAuthorization",
    "lab_action_artifact",
    "lab_http_action_spec",
    "validate_fixed_http_envelope",
]
