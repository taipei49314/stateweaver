"""Public API for StateWeaver's fail-closed reference policy layer."""

from .authorization import (
    PolicyAuthorization,
    PolicyAuthorizationDeniedError,
    verify_policy_authorization,
)
from .evaluator import DeterministicPolicyEvaluator, evaluate_policy
from .models import (
    BudgetSnapshot,
    ConstraintResult,
    ConstraintStatus,
    EvaluationConstraints,
    PolicyConstraint,
    PolicyDecision,
    PolicyOutcome,
    PolicyReasonCode,
    PolicyRequest,
)

__all__ = [
    "BudgetSnapshot",
    "ConstraintResult",
    "ConstraintStatus",
    "DeterministicPolicyEvaluator",
    "EvaluationConstraints",
    "PolicyAuthorization",
    "PolicyAuthorizationDeniedError",
    "PolicyConstraint",
    "PolicyDecision",
    "PolicyOutcome",
    "PolicyReasonCode",
    "PolicyRequest",
    "evaluate_policy",
    "verify_policy_authorization",
]
