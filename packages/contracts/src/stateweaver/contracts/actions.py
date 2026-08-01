"""Closed, typed action vocabulary used by the policy gateway.

There is intentionally no generic command or shell action in this module.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, field_validator, model_validator

from .base import (
    ArtifactHandle,
    AwareTimestampMixin,
    ContractId,
    ContractModel,
    IdentityHandle,
    JsonScalar,
    Name,
    NonNegativeInt,
    PositiveInt,
    Sha256Digest,
    VersionedContract,
    validate_effect_operation_value,
)
from .enums import (
    EffectOperation,
    HttpMethod,
    QueueOrder,
    RequesterType,
    RiskClass,
    ScopeAction,
)
from .scope import Host, PathPattern, Port

StatePath = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=3,
        max_length=256,
        pattern=r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$",
    ),
]
SelectorRef = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=3,
        max_length=160,
        pattern=r"^selector:[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
]
QueueRef = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=3,
        max_length=160,
        pattern=r"^queue:[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
]
JobRef = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=3,
        max_length=160,
        pattern=r"^job:[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
]


class ActionTarget(ContractModel):
    scheme: Literal["http", "https"]
    host: Host
    port: Port
    path: PathPattern


class HttpParameter(ContractModel):
    name: Name
    value: JsonScalar

    @field_validator("value")
    @classmethod
    def floats_must_be_finite(cls, value: JsonScalar) -> JsonScalar:
        if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
            raise ValueError("parameter floats must be finite")
        return value


class HttpHeader(ContractModel):
    name: Annotated[
        str,
        StringConstraints(
            strip_whitespace=True,
            min_length=1,
            max_length=128,
            pattern=r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$",
        ),
    ]
    value: Annotated[str, StringConstraints(max_length=1024)]

    @model_validator(mode="after")
    def raw_credentials_are_not_contract_data(self) -> HttpHeader:
        if self.name.lower() in {"authorization", "cookie", "proxy-authorization", "x-api-key"}:
            raise ValueError(
                "credential-bearing headers must be supplied through an identity handle"
            )
        if "\r" in self.value or "\n" in self.value:
            raise ValueError("header values must not contain line breaks")
        return self


class HttpRequestAction(ContractModel):
    type: Literal["http.request"] = "http.request"
    method: HttpMethod | None = None
    target: ActionTarget | None = None
    query: tuple[HttpParameter, ...] = ()
    headers: tuple[HttpHeader, ...] = ()
    body_artifact: ArtifactHandle | None = None
    identity_handle: IdentityHandle | None = None
    template_ref: Name | None = None
    expected_statuses: tuple[Annotated[int, Field(ge=100, le=599)], ...] = ()

    @model_validator(mode="after")
    def http_fields_are_unambiguous(self) -> HttpRequestAction:
        if self.target is None and self.template_ref is None:
            raise ValueError("HTTP action requires a concrete target or a typed template reference")
        if self.target is not None and self.method is None:
            raise ValueError("a concrete HTTP target requires a method")
        query_names = [item.name for item in self.query]
        header_names = [item.name.lower() for item in self.headers]
        if len(query_names) != len(set(query_names)):
            raise ValueError("query parameter names must be unique")
        if len(header_names) != len(set(header_names)):
            raise ValueError("HTTP header names must be unique")
        if len(self.expected_statuses) != len(set(self.expected_statuses)):
            raise ValueError("expected statuses must be unique")
        return self


class BrowserNavigateAction(ContractModel):
    type: Literal["browser.navigate"] = "browser.navigate"
    target: ActionTarget
    identity_handle: IdentityHandle | None = None


class BrowserClickAction(ContractModel):
    type: Literal["browser.click"] = "browser.click"
    selector_ref: SelectorRef


class BrowserFillAction(ContractModel):
    type: Literal["browser.fill"] = "browser.fill"
    selector_ref: SelectorRef
    value_artifact: ArtifactHandle
    is_secret: bool = False


class QueueReorderAction(ContractModel):
    type: Literal["queue.reorder"] = "queue.reorder"
    queue_ref: QueueRef
    job_ref: JobRef
    order: QueueOrder
    relative_to_job_ref: JobRef | None = None

    @model_validator(mode="after")
    def relative_order_requires_anchor(self) -> QueueReorderAction:
        relative = self.order in {QueueOrder.BEFORE, QueueOrder.AFTER}
        if relative != (self.relative_to_job_ref is not None):
            raise ValueError("before/after queue order requires exactly one relative job reference")
        if self.relative_to_job_ref == self.job_ref:
            raise ValueError("a queue job cannot be ordered relative to itself")
        return self


class QueueReleaseAction(ContractModel):
    type: Literal["queue.release"] = "queue.release"
    queue_ref: QueueRef
    job_ref: JobRef


class TimeAdvanceAction(ContractModel):
    type: Literal["time.advance"] = "time.advance"
    milliseconds: Annotated[int, Field(gt=0, le=86_400_000)]


class TimeSetAction(AwareTimestampMixin):
    type: Literal["time.set"] = "time.set"
    epoch: datetime


class SessionRotateAction(ContractModel):
    type: Literal["session.rotate"] = "session.rotate"
    identity_handle: IdentityHandle


type Action = Annotated[
    HttpRequestAction
    | BrowserNavigateAction
    | BrowserClickAction
    | BrowserFillAction
    | QueueReorderAction
    | QueueReleaseAction
    | TimeAdvanceAction
    | TimeSetAction
    | SessionRotateAction,
    Field(discriminator="type"),
]


class ActionGuard(ContractModel):
    path: StatePath
    expected: JsonScalar


class ExpectedEffect(ContractModel):
    path: StatePath
    operation: EffectOperation
    value: JsonScalar = None

    @model_validator(mode="after")
    def operation_value_is_coherent(self) -> ExpectedEffect:
        validate_effect_operation_value(self.operation, self.value)
        return self


class RequestedBy(ContractModel):
    type: RequesterType
    role: Name
    actor_id: Name | None = None


_ACTION_SCOPE = {
    "http.request": ScopeAction.HTTP_REQUEST,
    "browser.navigate": ScopeAction.BROWSER_INTERACTION,
    "browser.click": ScopeAction.BROWSER_INTERACTION,
    "browser.fill": ScopeAction.BROWSER_INTERACTION,
    "queue.reorder": ScopeAction.QUEUE_REORDER,
    "queue.release": ScopeAction.QUEUE_REORDER,
    "time.advance": ScopeAction.CONTROLLED_TIME,
    "time.set": ScopeAction.CONTROLLED_TIME,
    "session.rotate": ScopeAction.SESSION_ROTATION,
}


class ActionEnvelope(VersionedContract):
    action_id: ContractId
    experiment_id: ContractId
    world_id: ContractId
    scope_action: ScopeAction
    action: Action
    preconditions: tuple[ActionGuard, ...] = ()
    expected_effects: tuple[ExpectedEffect, ...] = ()
    risk_class: RiskClass
    idempotency_key: Sha256Digest
    requested_by: RequestedBy
    policy_decision_ref: ContractId
    approval_ref: ContractId | None = None
    sequence: NonNegativeInt = 0
    timeout_ms: PositiveInt = 30_000

    @model_validator(mode="after")
    def authorization_metadata_is_coherent(self) -> ActionEnvelope:
        expected_scope = _ACTION_SCOPE[self.action.type]
        if self.scope_action is not expected_scope:
            raise ValueError(f"{self.action.type} requires scope action {expected_scope.value}")
        if isinstance(self.action, HttpRequestAction) and self.action.target is None:
            raise ValueError(
                "authorized HTTP envelopes must resolve templates to a concrete target"
            )
        if self.risk_class is RiskClass.ELEVATED_REVERSIBLE and self.approval_ref is None:
            raise ValueError("elevated reversible actions require an approval reference")
        if self.risk_class is RiskClass.PASSIVE and self.action.type not in {
            "http.request",
            "browser.navigate",
        }:
            raise ValueError("state-changing action cannot use the passive risk class")
        return self

    @property
    def action_type(self) -> str:
        return self.action.type


def validate_scope_authorization(
    manifest: object, envelope: ActionEnvelope, *, at: datetime
) -> None:
    """Validate only manifest metadata; execution remains a policy-engine concern."""

    # The local import keeps the action vocabulary independent of policy storage.
    from .enums import AuthorizationRequirement
    from .scope import ScopeManifest

    if not isinstance(manifest, ScopeManifest):
        raise TypeError("manifest must be a ScopeManifest")
    if not manifest.is_valid_at(at):
        raise ValueError("scope manifest is not valid at the requested time")
    requirement = manifest.authorization_requirement(envelope.scope_action)
    if requirement in {AuthorizationRequirement.DENIED, AuthorizationRequirement.UNSPECIFIED}:
        raise ValueError(f"scope action is {requirement.value}")
    if requirement is AuthorizationRequirement.APPROVAL_REQUIRED and envelope.approval_ref is None:
        raise ValueError("scope action requires an approval reference")
