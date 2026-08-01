"""Immutable inputs and machine-readable outputs for policy evaluation.

The models deliberately contain no executable callback, command, or adapter.  They
only describe the data needed to make a deterministic authorization decision.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, ClassVar, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)
from stateweaver.contracts import (
    ActionEnvelope,
    RiskClass,
    ScopeManifest,
    canonical_json_bytes,
    sha256_digest,
)

NonNegativeInt = Annotated[int, Field(ge=0)]
PositiveMilliseconds = Annotated[int, Field(gt=0, le=120_000)]
WindowSeconds = Annotated[float, Field(gt=0.0, le=60.0)]


class PolicyModel(BaseModel):
    """Closed and immutable base for every public policy model."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        strict=True,
        str_strip_whitespace=True,
        validate_default=True,
    )

    def canonical_bytes(self) -> bytes:
        """Return deterministic JSON bytes without exposing them in a decision."""

        return canonical_json_bytes(self)

    def fingerprint(self) -> str:
        """Return a content digest suitable for correlation without echoing inputs."""

        return sha256_digest(self)


class PolicyOutcome(StrEnum):
    """The only three outcomes understood by an action gateway."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class PolicyReasonCode(StrEnum):
    """Stable reason vocabulary; values intentionally never contain user data."""

    POLICY_ALLOWED = "policy.allowed"
    MALFORMED_REQUEST = "request.malformed"
    CONTEXT_MISSING = "request.context_missing"
    SCOPE_NOT_YET_VALID = "scope.not_yet_valid"
    SCOPE_EXPIRED = "scope.expired"
    ACTION_EXPLICITLY_DENIED = "action.explicitly_denied"
    ACTION_NOT_LISTED = "action.not_listed"
    APPROVAL_MISSING = "approval.missing"
    IDENTITY_MISSING = "identity.missing"
    IDENTITY_NOT_ALLOWED = "identity.not_allowed"
    TARGET_MISSING = "target.missing"
    TARGET_NOT_INCLUDED = "target.not_included"
    TARGET_EXCLUDED = "target.excluded"
    REQUEST_BUDGET_EXHAUSTED = "budget.request_exhausted"
    WRITE_BUDGET_EXHAUSTED = "budget.write_exhausted"
    TIMEOUT_LIMIT_EXCEEDED = "timeout.limit_exceeded"
    RISK_CLASS_DISALLOWED = "risk.disallowed"
    RISK_UNDERCLASSIFIED = "risk.underclassified"


class PolicyConstraint(StrEnum):
    """Checks evaluated in this exact, wire-stable order."""

    CONTEXT_COMPLETE = "context.complete"
    SCOPE_VALIDITY = "scope.validity"
    ACTION_AUTHORIZATION = "action.authorization"
    APPROVAL = "approval"
    IDENTITY = "identity"
    TARGET = "target"
    REQUEST_BUDGET = "budget.request"
    WRITE_BUDGET = "budget.write"
    TIMEOUT = "timeout"
    RISK_CLASS = "risk.class"


class ConstraintStatus(StrEnum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ConstraintResult(PolicyModel):
    """One redacted constraint result.

    No target, identity, header, or supplied value is copied into this model.
    """

    constraint: PolicyConstraint
    status: ConstraintStatus
    reason_code: PolicyReasonCode | None = None

    @model_validator(mode="after")
    def failure_shape_is_coherent(self) -> ConstraintResult:
        if self.status is ConstraintStatus.FAILED and self.reason_code is None:
            raise ValueError("failed constraint requires a reason code")
        if self.status is not ConstraintStatus.FAILED and self.reason_code is not None:
            raise ValueError("only failed constraints may carry a reason code")
        return self


class BudgetSnapshot(PolicyModel):
    """Trusted counters captured before reserving the proposed action.

    ``requests_in_window`` represents completed plus already-reserved actions in
    the current fixed window.  Evaluation reserves one additional action.
    """

    requests_in_window: NonNegativeInt
    request_window_seconds: WindowSeconds
    write_requests_used: NonNegativeInt


class EvaluationConstraints(PolicyModel):
    """Server-owned policy ceilings, independent of a caller's scope manifest."""

    max_timeout_ms: PositiveMilliseconds = 30_000
    allowed_risk_classes: tuple[RiskClass, ...] = (
        RiskClass.PASSIVE,
        RiskClass.READ_ONLY,
        RiskClass.REVERSIBLE_STATE_CHANGE,
        RiskClass.ELEVATED_REVERSIBLE,
    )
    approval_required_risk_classes: tuple[RiskClass, ...] = (RiskClass.ELEVATED_REVERSIBLE,)

    @model_validator(mode="after")
    def risk_sets_are_canonical(self) -> EvaluationConstraints:
        if not self.allowed_risk_classes:
            raise ValueError("allowed_risk_classes must not be empty")
        if len(self.allowed_risk_classes) != len(set(self.allowed_risk_classes)):
            raise ValueError("allowed_risk_classes must not contain duplicates")
        if len(self.approval_required_risk_classes) != len(
            set(self.approval_required_risk_classes)
        ):
            raise ValueError("approval_required_risk_classes must not contain duplicates")
        if not set(self.approval_required_risk_classes) <= set(self.allowed_risk_classes):
            raise ValueError("approval-required risks must also be allowed risks")
        return self


class PolicyRequest(PolicyModel):
    """Complete input to a policy decision.

    Context fields are nullable on purpose: ingestion code can hand incomplete
    context to the evaluator and receive DENY instead of accidentally bypassing
    the policy gate.  Sensitive nested values are omitted from ``repr``.
    """

    schema_version: Literal["1.0"] = "1.0"
    scope_manifest: ScopeManifest | None = Field(default=None, repr=False)
    action_envelope: ActionEnvelope | None = Field(default=None, repr=False)
    budget: BudgetSnapshot | None = Field(default=None, repr=False)
    evaluated_at: datetime | None = None
    constraints: EvaluationConstraints = Field(default_factory=EvaluationConstraints, repr=False)

    @field_validator("evaluated_at")
    @classmethod
    def evaluated_at_is_absolute(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("evaluated_at must include a UTC offset")
        return value


class PolicyDecision(PolicyModel):
    """Redacted, deterministic result returned to an enforcement gateway."""

    schema_version: Literal["1.0"] = "1.0"
    outcome: PolicyOutcome
    reason_codes: tuple[PolicyReasonCode, ...]
    constraints: tuple[ConstraintResult, ...]

    @model_validator(mode="after")
    def decision_shape_is_coherent(self) -> PolicyDecision:
        if not self.reason_codes:
            raise ValueError("a policy decision requires at least one reason code")
        if len(self.reason_codes) != len(set(self.reason_codes)):
            raise ValueError("policy reason codes must not contain duplicates")

        failed_codes = tuple(
            item.reason_code for item in self.constraints if item.status is ConstraintStatus.FAILED
        )
        if self.outcome is PolicyOutcome.ALLOW:
            if self.reason_codes != (PolicyReasonCode.POLICY_ALLOWED,) or failed_codes:
                raise ValueError("ALLOW requires all constraints to pass")
        elif self.reason_codes != failed_codes:
            raise ValueError("non-ALLOW reasons must match failed constraints")

        if self.outcome is PolicyOutcome.REQUIRE_APPROVAL and self.reason_codes != (
            PolicyReasonCode.APPROVAL_MISSING,
        ):
            raise ValueError("REQUIRE_APPROVAL may only report a missing approval")
        return self

    @property
    def allowed(self) -> bool:
        return self.outcome is PolicyOutcome.ALLOW
