"""Policy decisions are deterministic, fail closed, and contain no supplied data."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError
from stateweaver.contracts import (
    ActionEnvelope,
    ActionTarget,
    AuthorizationRequirement,
    EnvironmentMode,
    HttpMethod,
    HttpRequestAction,
    RequestedBy,
    RequesterType,
    RiskClass,
    ScopeAction,
    ScopeActions,
    ScopeIdentities,
    ScopeLimits,
    ScopeManifest,
    ScopeMetadata,
    ScopeSpec,
    ScopeTargets,
    ScopeValidity,
    TargetSelector,
)
from stateweaver.policy import (
    BudgetSnapshot,
    DeterministicPolicyEvaluator,
    EvaluationConstraints,
    PolicyOutcome,
    PolicyReasonCode,
    PolicyRequest,
    evaluate_policy,
)

NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
DIGEST = "sha256:" + "a" * 64


def make_manifest(
    *,
    requirement: AuthorizationRequirement = AuthorizationRequirement.ALLOWED,
    expires_at: datetime | None = None,
    requests_per_second: float = 10.0,
    max_write_requests: int = 3,
) -> ScopeManifest:
    action_groups: dict[AuthorizationRequirement, ScopeActions] = {
        AuthorizationRequirement.ALLOWED: ScopeActions(allow=(ScopeAction.HTTP_REQUEST,)),
        AuthorizationRequirement.APPROVAL_REQUIRED: ScopeActions(
            requireApproval=(ScopeAction.HTTP_REQUEST,)
        ),
        AuthorizationRequirement.DENIED: ScopeActions(
            allow=(ScopeAction.PASSIVE_OBSERVATION,),
            deny=(ScopeAction.HTTP_REQUEST,),
        ),
        AuthorizationRequirement.UNSPECIFIED: ScopeActions(
            allow=(ScopeAction.PASSIVE_OBSERVATION,)
        ),
    }
    return ScopeManifest(
        metadata=ScopeMetadata(name="local-lab"),
        spec=ScopeSpec(
            environmentMode=EnvironmentMode.BLACK_BOX,
            targets=ScopeTargets(
                include=(
                    TargetSelector(
                        host="localhost",
                        ports=(8080,),
                        paths=("/api/*",),
                    ),
                ),
                exclude=(
                    TargetSelector(
                        host="localhost",
                        ports=(8080,),
                        paths=("/api/admin/*",),
                    ),
                ),
            ),
            identities=ScopeIdentities(allowed=("identity:test-user",)),
            actions=action_groups[requirement],
            limits=ScopeLimits(
                requestsPerSecond=requests_per_second,
                concurrentMaterializedWorlds=1,
                maxWriteRequests=max_write_requests,
            ),
            validity=ScopeValidity(
                notBefore=NOW - timedelta(minutes=5),
                expiresAt=expires_at or NOW + timedelta(minutes=5),
            ),
        ),
    )


def make_envelope(
    *,
    host: str = "localhost",
    port: int = 8080,
    path: str = "/api/documents",
    method: HttpMethod = HttpMethod.GET,
    identity_handle: str | None = "identity:test-user",
    risk_class: RiskClass = RiskClass.READ_ONLY,
    approval_ref: str | None = None,
    timeout_ms: int = 30_000,
) -> ActionEnvelope:
    return ActionEnvelope(
        action_id="action:test",
        experiment_id="experiment:test",
        world_id="world:test",
        scope_action=ScopeAction.HTTP_REQUEST,
        action=HttpRequestAction(
            method=method,
            target=ActionTarget(scheme="http", host=host, port=port, path=path),
            identity_handle=identity_handle,
        ),
        risk_class=risk_class,
        idempotency_key=DIGEST,
        requested_by=RequestedBy(type=RequesterType.WORKFLOW, role="policy-test"),
        policy_decision_ref="decision:pending",
        approval_ref=approval_ref,
        timeout_ms=timeout_ms,
    )


def make_request(
    *,
    manifest: ScopeManifest | None = None,
    envelope: ActionEnvelope | None = None,
    budget: BudgetSnapshot | None = None,
    constraints: EvaluationConstraints | None = None,
) -> PolicyRequest:
    return PolicyRequest(
        scope_manifest=manifest or make_manifest(),
        action_envelope=envelope or make_envelope(),
        budget=budget
        or BudgetSnapshot(
            requests_in_window=0,
            request_window_seconds=1.0,
            write_requests_used=0,
        ),
        evaluated_at=NOW,
        constraints=constraints or EvaluationConstraints(),
    )


def test_localhost_target_is_allowed() -> None:
    decision = evaluate_policy(make_request())

    assert decision.outcome is PolicyOutcome.ALLOW
    assert decision.reason_codes == (PolicyReasonCode.POLICY_ALLOWED,)
    assert decision.allowed is True


def test_external_host_is_denied() -> None:
    decision = evaluate_policy(make_request(envelope=make_envelope(host="example.com")))

    assert decision.outcome is PolicyOutcome.DENY
    assert PolicyReasonCode.TARGET_NOT_INCLUDED in decision.reason_codes


@pytest.mark.parametrize(
    "envelope",
    [
        make_envelope(port=9090),
        make_envelope(path="/private/documents"),
    ],
)
def test_target_must_match_included_port_and_path(envelope: ActionEnvelope) -> None:
    decision = evaluate_policy(make_request(envelope=envelope))

    assert decision.outcome is PolicyOutcome.DENY
    assert PolicyReasonCode.TARGET_NOT_INCLUDED in decision.reason_codes


def test_excluded_path_overrides_inclusion() -> None:
    decision = evaluate_policy(make_request(envelope=make_envelope(path="/api/admin/export")))

    assert decision.outcome is PolicyOutcome.DENY
    assert PolicyReasonCode.TARGET_EXCLUDED in decision.reason_codes


def test_unlisted_action_is_denied() -> None:
    decision = evaluate_policy(
        make_request(manifest=make_manifest(requirement=AuthorizationRequirement.UNSPECIFIED))
    )

    assert decision.outcome is PolicyOutcome.DENY
    assert PolicyReasonCode.ACTION_NOT_LISTED in decision.reason_codes


def test_expired_scope_is_denied() -> None:
    decision = evaluate_policy(
        make_request(manifest=make_manifest(expires_at=NOW - timedelta(microseconds=1)))
    )

    assert decision.outcome is PolicyOutcome.DENY
    assert PolicyReasonCode.SCOPE_EXPIRED in decision.reason_codes


def test_missing_approval_requires_approval_when_other_constraints_pass() -> None:
    decision = evaluate_policy(
        make_request(manifest=make_manifest(requirement=AuthorizationRequirement.APPROVAL_REQUIRED))
    )

    assert decision.outcome is PolicyOutcome.REQUIRE_APPROVAL
    assert decision.reason_codes == (PolicyReasonCode.APPROVAL_MISSING,)


def test_approved_action_is_allowed() -> None:
    decision = evaluate_policy(
        make_request(
            manifest=make_manifest(requirement=AuthorizationRequirement.APPROVAL_REQUIRED),
            envelope=make_envelope(approval_ref="approval:reviewed"),
        )
    )

    assert decision.outcome is PolicyOutcome.ALLOW


def test_explicit_deny_wins_over_missing_approval() -> None:
    constraints = EvaluationConstraints(
        approval_required_risk_classes=(RiskClass.READ_ONLY, RiskClass.ELEVATED_REVERSIBLE)
    )
    decision = evaluate_policy(
        make_request(
            manifest=make_manifest(requirement=AuthorizationRequirement.DENIED),
            constraints=constraints,
        )
    )

    assert decision.outcome is PolicyOutcome.DENY
    assert PolicyReasonCode.ACTION_EXPLICITLY_DENIED in decision.reason_codes
    assert PolicyReasonCode.APPROVAL_MISSING in decision.reason_codes


@pytest.mark.parametrize(
    ("budget", "envelope", "reason"),
    [
        (
            BudgetSnapshot(
                requests_in_window=10,
                request_window_seconds=1.0,
                write_requests_used=0,
            ),
            make_envelope(),
            PolicyReasonCode.REQUEST_BUDGET_EXHAUSTED,
        ),
        (
            BudgetSnapshot(
                requests_in_window=0,
                request_window_seconds=1.0,
                write_requests_used=3,
            ),
            make_envelope(
                method=HttpMethod.POST,
                risk_class=RiskClass.REVERSIBLE_STATE_CHANGE,
            ),
            PolicyReasonCode.WRITE_BUDGET_EXHAUSTED,
        ),
    ],
)
def test_exhausted_budget_is_denied(
    budget: BudgetSnapshot,
    envelope: ActionEnvelope,
    reason: PolicyReasonCode,
) -> None:
    decision = evaluate_policy(make_request(budget=budget, envelope=envelope))

    assert decision.outcome is PolicyOutcome.DENY
    assert reason in decision.reason_codes


def test_identity_must_be_present_and_allowlisted() -> None:
    missing = evaluate_policy(make_request(envelope=make_envelope(identity_handle=None)))
    unknown = evaluate_policy(
        make_request(envelope=make_envelope(identity_handle="identity:other-user"))
    )

    assert PolicyReasonCode.IDENTITY_MISSING in missing.reason_codes
    assert PolicyReasonCode.IDENTITY_NOT_ALLOWED in unknown.reason_codes
    assert missing.outcome is unknown.outcome is PolicyOutcome.DENY


def test_architecture_style_identity_name_matches_opaque_handle() -> None:
    manifest = make_manifest().model_copy(
        update={
            "spec": make_manifest().spec.model_copy(
                update={"identities": ScopeIdentities(allowed=("test-user",))}
            )
        }
    )

    assert evaluate_policy(make_request(manifest=manifest)).outcome is PolicyOutcome.ALLOW


def test_single_star_does_not_expand_across_path_segments() -> None:
    decision = evaluate_policy(
        make_request(envelope=make_envelope(path="/api/public/nested-document"))
    )

    assert decision.outcome is PolicyOutcome.DENY
    assert PolicyReasonCode.TARGET_NOT_INCLUDED in decision.reason_codes


def test_timeout_and_risk_underclassification_are_denied() -> None:
    timeout = evaluate_policy(make_request(envelope=make_envelope(timeout_ms=30_001)))
    risk = evaluate_policy(
        make_request(envelope=make_envelope(method=HttpMethod.POST, risk_class=RiskClass.READ_ONLY))
    )

    assert PolicyReasonCode.TIMEOUT_LIMIT_EXCEEDED in timeout.reason_codes
    assert PolicyReasonCode.RISK_UNDERCLASSIFIED in risk.reason_codes


def test_missing_context_and_malformed_objects_fail_closed() -> None:
    incomplete = evaluate_policy(PolicyRequest(evaluated_at=NOW))
    malformed = DeterministicPolicyEvaluator().evaluate({"action": "http.request"})

    assert incomplete.outcome is PolicyOutcome.DENY
    assert incomplete.reason_codes == (PolicyReasonCode.CONTEXT_MISSING,)
    assert malformed.outcome is PolicyOutcome.DENY
    assert malformed.reason_codes == (PolicyReasonCode.MALFORMED_REQUEST,)


def test_decision_roundtrip_is_deterministic_and_redacted() -> None:
    secret_marker = "never-echo-this-marker"
    request = make_request(envelope=make_envelope(host="example.com", path=f"/api/{secret_marker}"))
    restored = PolicyRequest.model_validate_json(request.model_dump_json(by_alias=True))

    first = evaluate_policy(request)
    second = evaluate_policy(restored)
    restored_decision = type(first).model_validate_json(first.model_dump_json())

    assert first == second == restored_decision
    assert first.canonical_bytes() == second.canonical_bytes()
    assert first.fingerprint() == second.fingerprint()
    assert secret_marker not in first.model_dump_json()


def test_models_are_strict_frozen_and_closed() -> None:
    budget = BudgetSnapshot(
        requests_in_window=0,
        request_window_seconds=1.0,
        write_requests_used=0,
    )
    with pytest.raises(ValidationError):
        BudgetSnapshot.model_validate(
            {
                "requests_in_window": "0",
                "request_window_seconds": 1.0,
                "write_requests_used": 0,
            }
        )
    with pytest.raises(ValidationError):
        BudgetSnapshot.model_validate(
            {
                "requests_in_window": 0,
                "request_window_seconds": 1.0,
                "write_requests_used": 0,
                "unexpected": True,
            }
        )
    with pytest.raises(ValidationError):
        budget.requests_in_window = 1
