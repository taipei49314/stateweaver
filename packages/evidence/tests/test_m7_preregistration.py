from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError
from stateweaver.contracts import sha256_digest
from stateweaver.evidence.m7_preregistration import (
    EXTERNAL_M7_REQUIREMENT_IDS,
    M7ExternalEvidenceStatus,
    M7Metric,
    M7ProducerPreregistration,
    external_m7_boundary_assessment,
)


def _preregistration() -> M7ProducerPreregistration:
    return M7ProducerPreregistration(
        producer_identity="identity:stateweaver.synthetic-producer",
        created_at=datetime(2026, 8, 13, 12, 0, tzinfo=UTC),
        challenge_commitment=sha256_digest({"challenge": "internal-synthetic"}),
        hidden_oracle_commitment=sha256_digest({"oracle": "internal-synthetic"}),
        baseline_config_digest=sha256_digest({"baseline": "linear"}),
        full_config_digest=sha256_digest({"full": "stateweaver"}),
        experiment_plan_digest=sha256_digest({"plan": "closed-equal-budget"}),
        measured_budget_digest=sha256_digest({"budget": "cpu-ram-wall-token-request-cost"}),
        primary_metric=M7Metric.PAIRED_SUCCESS_RATE_DIFFERENCE,
        minimum_effect_basis_points=500,
        reproduction_tolerance_basis_points=200,
        uncertainty_method="paired-bootstrap-v1",
    )


def test_producer_preregistration_is_strict_frozen_and_never_external_custodian_evidence() -> None:
    preregistration = _preregistration()

    assert preregistration.authority_scope == "producer-internal"
    assert preregistration.external_custodian is False
    assert preregistration.protected_holdout is False
    assert preregistration.satisfies_external_preregistration is False
    assert preregistration.results_digest is None
    assert preregistration.preregistration_digest.startswith("sha256:")

    with pytest.raises(ValidationError, match="Extra inputs"):
        M7ProducerPreregistration.model_validate(
            {
                **preregistration.model_dump(mode="python"),
                "custodian_signature": "forged",
            }
        )
    with pytest.raises(ValidationError, match="frozen"):
        setattr(preregistration, "external_custodian", True)  # noqa: B010


def test_internal_preregistration_cannot_satisfy_any_external_m7_row() -> None:
    assessment = external_m7_boundary_assessment(
        preregistration=_preregistration(),
        measured_receipt_digest=sha256_digest({"receipt": "producer-run"}),
    )

    assert assessment.authoritative is False
    assert assessment.promotable is False
    assert assessment.release_eligible is False
    assert tuple(item.requirement_id for item in assessment.rows) == EXTERNAL_M7_REQUIREMENT_IDS
    assert {item.status for item in assessment.rows} == {
        M7ExternalEvidenceStatus.BLOCKED_EXTERNAL_CUSTODIAN
    }
    assert all(not item.satisfied for item in assessment.rows)

    forged = assessment.model_dump(mode="python")
    forged["rows"][0]["satisfied"] = True
    with pytest.raises(ValidationError, match="Input should be False"):
        type(assessment).model_validate(forged)


def test_results_or_naive_timestamps_cannot_be_added_after_the_fact() -> None:
    payload = _preregistration().model_dump(mode="python")
    payload["results_digest"] = sha256_digest({"selected": "result"})
    with pytest.raises(ValidationError, match="producer preregistration cannot include results"):
        M7ProducerPreregistration.model_validate(payload)

    payload = _preregistration().model_dump(mode="python")
    payload["created_at"] = datetime(2026, 8, 13, 12, 0)  # noqa: DTZ001
    with pytest.raises(ValidationError, match="UTC offset"):
        M7ProducerPreregistration.model_validate(payload)
