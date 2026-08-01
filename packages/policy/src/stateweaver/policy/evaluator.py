"""Stateless, fail-closed policy evaluation for typed StateWeaver actions."""

from __future__ import annotations

import re
from decimal import Decimal
from typing import Final

from stateweaver.contracts import (
    AuthorizationRequirement,
    HttpMethod,
    RiskClass,
    TargetSelector,
)

from .models import (
    ConstraintResult,
    ConstraintStatus,
    PolicyConstraint,
    PolicyDecision,
    PolicyOutcome,
    PolicyReasonCode,
    PolicyRequest,
)

_SAFE_HTTP_METHODS: Final = frozenset({HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS})
_RISK_RANK: Final = {
    RiskClass.PASSIVE: 0,
    RiskClass.READ_ONLY: 1,
    RiskClass.REVERSIBLE_STATE_CHANGE: 2,
    RiskClass.ELEVATED_REVERSIBLE: 3,
}
_WRITE_ACTION_TYPES: Final = frozenset(
    {
        "browser.click",
        "browser.fill",
        "queue.reorder",
        "queue.release",
        "time.advance",
        "time.set",
        "session.rotate",
    }
)
_NO_FIELD: Final = object()


def _passed(constraint: PolicyConstraint) -> ConstraintResult:
    return ConstraintResult(constraint=constraint, status=ConstraintStatus.PASSED)


def _failed(
    constraint: PolicyConstraint,
    reason_code: PolicyReasonCode,
) -> ConstraintResult:
    return ConstraintResult(
        constraint=constraint,
        status=ConstraintStatus.FAILED,
        reason_code=reason_code,
    )


def _not_applicable(constraint: PolicyConstraint) -> ConstraintResult:
    return ConstraintResult(constraint=constraint, status=ConstraintStatus.NOT_APPLICABLE)


def _path_matches(pattern: str, path: str) -> bool:
    """Match a scoped path where ``*`` stays in one segment and ``**`` may cross segments."""

    escaped = re.escape(pattern)
    expression = escaped.replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
    return re.fullmatch(expression, path) is not None


def _identity_is_allowed(identity: str, allowed: tuple[str, ...]) -> bool:
    """Accept the manifest's short name or its explicit opaque-handle form, never substrings."""

    short_name = identity.removeprefix("identity:")
    return identity in allowed or short_name in allowed


def _selector_matches(selector: TargetSelector, target: object) -> bool:
    host = getattr(target, "host", None)
    port = getattr(target, "port", None)
    path = getattr(target, "path", None)
    if selector.host is not None and selector.host != host:
        return False
    if selector.ports and port not in selector.ports:
        return False
    return not selector.paths or (
        isinstance(path, str) and any(_path_matches(pattern, path) for pattern in selector.paths)
    )


def _is_write_action(action: object) -> bool:
    action_type = getattr(action, "type", None)
    if action_type == "http.request":
        return getattr(action, "method", None) not in _SAFE_HTTP_METHODS
    return action_type in _WRITE_ACTION_TYPES


def _minimum_risk_rank(action: object) -> int | None:
    action_type = getattr(action, "type", None)
    if action_type == "http.request":
        method = getattr(action, "method", None)
        return 0 if method in _SAFE_HTTP_METHODS else 2
    if action_type == "browser.navigate":
        return 0
    if action_type in _WRITE_ACTION_TYPES:
        return 2
    return None


def _malformed_decision() -> PolicyDecision:
    result = _failed(PolicyConstraint.CONTEXT_COMPLETE, PolicyReasonCode.MALFORMED_REQUEST)
    return PolicyDecision(
        outcome=PolicyOutcome.DENY,
        reason_codes=(PolicyReasonCode.MALFORMED_REQUEST,),
        constraints=(result,),
    )


def _evaluate_typed(request: PolicyRequest) -> PolicyDecision:
    results: list[ConstraintResult] = []
    manifest = request.scope_manifest
    envelope = request.action_envelope
    budget = request.budget
    evaluated_at = request.evaluated_at

    context_complete = all(item is not None for item in (manifest, envelope, budget, evaluated_at))
    results.append(
        _passed(PolicyConstraint.CONTEXT_COMPLETE)
        if context_complete
        else _failed(PolicyConstraint.CONTEXT_COMPLETE, PolicyReasonCode.CONTEXT_MISSING)
    )

    if manifest is None or evaluated_at is None:
        results.append(_not_applicable(PolicyConstraint.SCOPE_VALIDITY))
    elif manifest.spec.validity.not_before is not None and (
        evaluated_at < manifest.spec.validity.not_before
    ):
        results.append(
            _failed(PolicyConstraint.SCOPE_VALIDITY, PolicyReasonCode.SCOPE_NOT_YET_VALID)
        )
    elif evaluated_at > manifest.spec.validity.expires_at:
        results.append(_failed(PolicyConstraint.SCOPE_VALIDITY, PolicyReasonCode.SCOPE_EXPIRED))
    else:
        results.append(_passed(PolicyConstraint.SCOPE_VALIDITY))

    requirement: AuthorizationRequirement | None = None
    if manifest is None or envelope is None:
        results.append(_not_applicable(PolicyConstraint.ACTION_AUTHORIZATION))
    else:
        requirement = manifest.authorization_requirement(envelope.scope_action)
        if requirement is AuthorizationRequirement.DENIED:
            results.append(
                _failed(
                    PolicyConstraint.ACTION_AUTHORIZATION,
                    PolicyReasonCode.ACTION_EXPLICITLY_DENIED,
                )
            )
        elif requirement is AuthorizationRequirement.UNSPECIFIED:
            results.append(
                _failed(
                    PolicyConstraint.ACTION_AUTHORIZATION,
                    PolicyReasonCode.ACTION_NOT_LISTED,
                )
            )
        else:
            results.append(_passed(PolicyConstraint.ACTION_AUTHORIZATION))

    if envelope is None or requirement is None:
        results.append(_not_applicable(PolicyConstraint.APPROVAL))
    else:
        approval_required = (
            requirement is AuthorizationRequirement.APPROVAL_REQUIRED
            or envelope.risk_class in request.constraints.approval_required_risk_classes
        )
        if approval_required and envelope.approval_ref is None:
            results.append(_failed(PolicyConstraint.APPROVAL, PolicyReasonCode.APPROVAL_MISSING))
        else:
            results.append(_passed(PolicyConstraint.APPROVAL))

    if manifest is None or envelope is None:
        results.append(_not_applicable(PolicyConstraint.IDENTITY))
    else:
        identity = getattr(envelope.action, "identity_handle", _NO_FIELD)
        if identity is _NO_FIELD:
            results.append(_not_applicable(PolicyConstraint.IDENTITY))
        elif identity is None:
            results.append(_failed(PolicyConstraint.IDENTITY, PolicyReasonCode.IDENTITY_MISSING))
        elif not isinstance(identity, str) or not _identity_is_allowed(
            identity, manifest.spec.identities.allowed
        ):
            results.append(
                _failed(PolicyConstraint.IDENTITY, PolicyReasonCode.IDENTITY_NOT_ALLOWED)
            )
        else:
            results.append(_passed(PolicyConstraint.IDENTITY))

    if manifest is None or envelope is None:
        results.append(_not_applicable(PolicyConstraint.TARGET))
    else:
        target = getattr(envelope.action, "target", _NO_FIELD)
        if target is _NO_FIELD:
            results.append(_not_applicable(PolicyConstraint.TARGET))
        elif target is None:
            results.append(_failed(PolicyConstraint.TARGET, PolicyReasonCode.TARGET_MISSING))
        else:
            included = any(
                _selector_matches(selector, target) for selector in manifest.spec.targets.include
            )
            excluded = any(
                _selector_matches(selector, target) for selector in manifest.spec.targets.exclude
            )
            if excluded:
                results.append(_failed(PolicyConstraint.TARGET, PolicyReasonCode.TARGET_EXCLUDED))
            elif not included:
                results.append(
                    _failed(PolicyConstraint.TARGET, PolicyReasonCode.TARGET_NOT_INCLUDED)
                )
            else:
                results.append(_passed(PolicyConstraint.TARGET))

    if manifest is None or budget is None:
        results.append(_not_applicable(PolicyConstraint.REQUEST_BUDGET))
    else:
        capacity = Decimal(str(manifest.spec.limits.requests_per_second)) * Decimal(
            str(budget.request_window_seconds)
        )
        projected = Decimal(budget.requests_in_window + 1)
        if projected > capacity:
            results.append(
                _failed(
                    PolicyConstraint.REQUEST_BUDGET,
                    PolicyReasonCode.REQUEST_BUDGET_EXHAUSTED,
                )
            )
        else:
            results.append(_passed(PolicyConstraint.REQUEST_BUDGET))

    if (
        manifest is None
        or envelope is None
        or budget is None
        or not _is_write_action(envelope.action)
    ):
        results.append(_not_applicable(PolicyConstraint.WRITE_BUDGET))
    elif budget.write_requests_used + 1 > manifest.spec.limits.max_write_requests:
        results.append(
            _failed(
                PolicyConstraint.WRITE_BUDGET,
                PolicyReasonCode.WRITE_BUDGET_EXHAUSTED,
            )
        )
    else:
        results.append(_passed(PolicyConstraint.WRITE_BUDGET))

    if envelope is None:
        results.append(_not_applicable(PolicyConstraint.TIMEOUT))
    elif envelope.timeout_ms > request.constraints.max_timeout_ms:
        results.append(_failed(PolicyConstraint.TIMEOUT, PolicyReasonCode.TIMEOUT_LIMIT_EXCEEDED))
    else:
        results.append(_passed(PolicyConstraint.TIMEOUT))

    if envelope is None:
        results.append(_not_applicable(PolicyConstraint.RISK_CLASS))
    elif envelope.risk_class not in request.constraints.allowed_risk_classes:
        results.append(_failed(PolicyConstraint.RISK_CLASS, PolicyReasonCode.RISK_CLASS_DISALLOWED))
    else:
        minimum_rank = _minimum_risk_rank(envelope.action)
        if minimum_rank is None:
            results.append(
                _failed(PolicyConstraint.RISK_CLASS, PolicyReasonCode.RISK_CLASS_DISALLOWED)
            )
        elif _RISK_RANK[envelope.risk_class] < minimum_rank:
            results.append(
                _failed(PolicyConstraint.RISK_CLASS, PolicyReasonCode.RISK_UNDERCLASSIFIED)
            )
        else:
            results.append(_passed(PolicyConstraint.RISK_CLASS))

    failed_codes = tuple(
        item.reason_code for item in results if item.status is ConstraintStatus.FAILED
    )
    reason_codes = tuple(code for code in failed_codes if code is not None)
    deny_codes = tuple(
        code for code in reason_codes if code is not PolicyReasonCode.APPROVAL_MISSING
    )
    if deny_codes:
        outcome = PolicyOutcome.DENY
    elif reason_codes == (PolicyReasonCode.APPROVAL_MISSING,):
        outcome = PolicyOutcome.REQUIRE_APPROVAL
    elif reason_codes:
        outcome = PolicyOutcome.DENY
    else:
        outcome = PolicyOutcome.ALLOW
        reason_codes = (PolicyReasonCode.POLICY_ALLOWED,)

    return PolicyDecision(
        outcome=outcome,
        reason_codes=reason_codes,
        constraints=tuple(results),
    )


class DeterministicPolicyEvaluator:
    """A stateless reference evaluator that never executes an action."""

    __slots__ = ()

    def evaluate(self, request: object) -> PolicyDecision:
        """Evaluate a request, converting every malformed input or error to DENY."""

        if not isinstance(request, PolicyRequest):
            return _malformed_decision()
        try:
            return _evaluate_typed(request)
        except Exception:
            # Fail closed without copying exception text, which may contain supplied data.
            return _malformed_decision()


def evaluate_policy(request: object) -> PolicyDecision:
    """Functional entry point for adapters and tests."""

    return DeterministicPolicyEvaluator().evaluate(request)
