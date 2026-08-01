"""Authorization scope manifest contracts.

These models describe permission; they never execute or resolve a target.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, field_validator, model_validator

from .base import AwareTimestampMixin, ContractModel, Name, PositiveInt
from .enums import AuthorizationRequirement, EnvironmentMode, ScopeAction

Host = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        to_lower=True,
        min_length=1,
        max_length=253,
        pattern=(
            r"^(?:localhost|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
            r"(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*)$"
        ),
    ),
]
PathPattern = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=512,
        pattern=r"^/[^?#]*$",
    ),
]
Port = Annotated[int, Field(ge=1, le=65535)]


class ScopeMetadata(ContractModel):
    name: Name


class TargetSelector(ContractModel):
    host: Host | None = None
    ports: tuple[Port, ...] = ()
    paths: tuple[PathPattern, ...] = ()

    @field_validator("paths")
    @classmethod
    def paths_are_absolute_and_safe(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for path in value:
            if path.startswith("//") or any(segment == ".." for segment in path.split("/")):
                raise ValueError("target paths must be absolute and contain no traversal segments")
        return tuple(sorted(value))

    @field_validator("ports")
    @classmethod
    def ports_are_canonical(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        return tuple(sorted(value))

    @model_validator(mode="after")
    def selector_is_not_empty(self) -> TargetSelector:
        if self.host is None and not self.ports and not self.paths:
            raise ValueError("target selector must constrain host, port, or path")
        if self.ports and self.host is None:
            raise ValueError("ports require a host constraint")
        if len(set(self.ports)) != len(self.ports):
            raise ValueError("target selector ports must be unique")
        if len(set(self.paths)) != len(self.paths):
            raise ValueError("target selector paths must be unique")
        return self


class ScopeTargets(ContractModel):
    include: tuple[TargetSelector, ...]
    exclude: tuple[TargetSelector, ...] = ()

    @field_validator("include")
    @classmethod
    def include_must_be_explicit(
        cls, value: tuple[TargetSelector, ...]
    ) -> tuple[TargetSelector, ...]:
        if not value:
            raise ValueError("at least one included target is required")
        if any(selector.host is None for selector in value):
            raise ValueError("every included target must name an explicit host")
        if len(value) != len(set(value)):
            raise ValueError("included target selectors must be unique")
        return tuple(sorted(value, key=lambda selector: selector.canonical_bytes()))

    @field_validator("exclude")
    @classmethod
    def exclude_is_canonical(cls, value: tuple[TargetSelector, ...]) -> tuple[TargetSelector, ...]:
        if len(value) != len(set(value)):
            raise ValueError("excluded target selectors must be unique")
        return tuple(sorted(value, key=lambda selector: selector.canonical_bytes()))


class ScopeIdentities(ContractModel):
    allowed: tuple[Name, ...]

    @field_validator("allowed")
    @classmethod
    def identities_must_be_explicit(cls, value: tuple[Name, ...]) -> tuple[Name, ...]:
        if not value:
            raise ValueError("at least one test identity is required")
        if len(set(value)) != len(value):
            raise ValueError("allowed identities must be unique")
        return tuple(sorted(value))


class ScopeActions(ContractModel):
    allow: tuple[ScopeAction, ...] = ()
    require_approval: tuple[ScopeAction, ...] = Field(default=(), alias="requireApproval")
    deny: tuple[ScopeAction, ...] = ()

    @field_validator("allow", "require_approval", "deny")
    @classmethod
    def action_sets_are_canonical(cls, value: tuple[ScopeAction, ...]) -> tuple[ScopeAction, ...]:
        return tuple(sorted(value, key=str))

    @model_validator(mode="after")
    def action_sets_must_be_disjoint(self) -> ScopeActions:
        allow = set(self.allow)
        approval = set(self.require_approval)
        deny = set(self.deny)
        if allow & approval or allow & deny or approval & deny:
            raise ValueError("allow, requireApproval, and deny action sets must be disjoint")
        if any(
            len(group) != len(set(group))
            for group in (self.allow, self.require_approval, self.deny)
        ):
            raise ValueError("action policy sets must not contain duplicates")
        if not allow and not approval:
            raise ValueError("scope must allow or require approval for at least one action")
        return self

    def requirement_for(self, action: ScopeAction) -> AuthorizationRequirement:
        if action in self.deny:
            return AuthorizationRequirement.DENIED
        if action in self.require_approval:
            return AuthorizationRequirement.APPROVAL_REQUIRED
        if action in self.allow:
            return AuthorizationRequirement.ALLOWED
        return AuthorizationRequirement.UNSPECIFIED


class ScopeLimits(ContractModel):
    requests_per_second: Annotated[float, Field(gt=0, le=1000)] = Field(alias="requestsPerSecond")
    concurrent_materialized_worlds: PositiveInt = Field(alias="concurrentMaterializedWorlds")
    max_write_requests: Annotated[int, Field(ge=0)] = Field(alias="maxWriteRequests")


class ScopeValidity(AwareTimestampMixin):
    not_before: datetime | None = Field(default=None, alias="notBefore")
    expires_at: datetime = Field(alias="expiresAt")

    @field_validator("not_before")
    @classmethod
    def not_before_must_have_timezone(cls, value: datetime | None) -> datetime | None:
        return cls.timestamp_must_have_timezone(value)

    @model_validator(mode="after")
    def interval_must_be_forward(self) -> ScopeValidity:
        if self.not_before is not None and self.expires_at <= self.not_before:
            raise ValueError("expiresAt must be later than notBefore")
        return self

    def contains(self, instant: datetime) -> bool:
        if instant.tzinfo is None or instant.utcoffset() is None:
            raise ValueError("instant must include a UTC offset")
        return (
            self.not_before is None or instant >= self.not_before
        ) and instant <= self.expires_at


class ScopeSpec(ContractModel):
    environment_mode: EnvironmentMode = Field(alias="environmentMode")
    targets: ScopeTargets
    identities: ScopeIdentities
    actions: ScopeActions
    limits: ScopeLimits
    validity: ScopeValidity


class ScopeManifest(ContractModel):
    api_version: Literal["stateweaver.io/v1"] = Field(
        default="stateweaver.io/v1", alias="apiVersion"
    )
    kind: Literal["ScopeManifest"] = "ScopeManifest"
    metadata: ScopeMetadata
    spec: ScopeSpec

    def authorization_requirement(self, action: ScopeAction) -> AuthorizationRequirement:
        return self.spec.actions.requirement_for(action)

    def is_valid_at(self, instant: datetime) -> bool:
        return self.spec.validity.contains(instant)
