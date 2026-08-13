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
    IdentityHandle,
)
from stateweaver.policy import (
    PolicyAuthorization,
    PolicyAuthorizationDeniedError,
    verify_policy_authorization,
)
from stateweaver_lab import (
    TypedLabAction,
    resolve_lab_http_action,
)
from stateweaver_lab import (
    lab_action_artifact as _lab_action_artifact,
)
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

    return _lab_action_artifact(action)


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


def lab_http_action_spec(action: LabAction) -> LabHttpActionSpec:
    """Derive a fixed route from a concrete closed-union lab action."""

    spec = resolve_lab_http_action(action)
    return LabHttpActionSpec(
        method=HttpMethod(spec.method.value),
        path=spec.path,
        identity_handle=spec.identity_handle,
        expected_statuses=spec.expected_statuses,
    )


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
        try:
            verify_policy_authorization(
                authorization,
                envelope,
                at=at,
                requests_used=requests_used,
                write_requests_used=write_requests_used,
            )
        except PolicyAuthorizationDeniedError:
            raise LabPolicyDeniedError("policy authorization denied") from None
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
