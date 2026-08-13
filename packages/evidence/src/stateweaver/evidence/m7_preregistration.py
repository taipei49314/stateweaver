"""Truthful producer-owned M7 preregistration and external-boundary contracts.

These contracts let the repository freeze an internal experiment before it is
run.  They cannot represent an external custodian, protected holdout, or
independent reproduction and therefore cannot satisfy any external M7 row.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, model_validator
from stateweaver.contracts import IdentityHandle, Sha256Digest, sha256_digest
from stateweaver.contracts.base import AwareTimestampMixin, ContractModel

type ExternalM7RequirementId = Literal[
    "M7-X01",
    "SW-M7-FAIR",
    "SW-M7-PREREG",
    "SW-M7-HOLDOUT",
    "SW-M7-REPRO",
]

EXTERNAL_M7_REQUIREMENT_IDS: tuple[ExternalM7RequirementId, ...] = (
    "M7-X01",
    "SW-M7-FAIR",
    "SW-M7-PREREG",
    "SW-M7-HOLDOUT",
    "SW-M7-REPRO",
)


class M7Metric(StrEnum):
    PAIRED_SUCCESS_RATE_DIFFERENCE = "paired_success_rate_difference"


class M7ExternalEvidenceStatus(StrEnum):
    BLOCKED_EXTERNAL_CUSTODIAN = "BLOCKED_EXTERNAL_CUSTODIAN"


class M7ProducerPreregistration(AwareTimestampMixin):
    schema_version: Literal["m7-producer-preregistration-v1"] = "m7-producer-preregistration-v1"
    authority_scope: Literal["producer-internal"] = "producer-internal"
    external_custodian: Literal[False] = False
    protected_holdout: Literal[False] = False
    independent_reproduction: Literal[False] = False
    satisfies_external_preregistration: Literal[False] = False
    producer_identity: IdentityHandle
    created_at: datetime
    challenge_commitment: Sha256Digest
    hidden_oracle_commitment: Sha256Digest
    baseline_config_digest: Sha256Digest
    full_config_digest: Sha256Digest
    experiment_plan_digest: Sha256Digest
    measured_budget_digest: Sha256Digest
    primary_metric: M7Metric
    minimum_effect_basis_points: Annotated[int, Field(ge=1, le=10_000)]
    reproduction_tolerance_basis_points: Annotated[int, Field(ge=0, le=10_000)]
    uncertainty_method: Literal["paired-bootstrap-v1"]
    results_digest: Sha256Digest | None = None

    @model_validator(mode="after")
    def results_are_not_part_of_preregistration(self) -> M7ProducerPreregistration:
        if self.results_digest is not None:
            raise ValueError("producer preregistration cannot include results")
        return self

    @property
    def preregistration_digest(self) -> str:
        return sha256_digest(self)


class M7ExternalBoundaryRow(ContractModel):
    requirement_id: ExternalM7RequirementId
    status: Literal[M7ExternalEvidenceStatus.BLOCKED_EXTERNAL_CUSTODIAN] = (
        M7ExternalEvidenceStatus.BLOCKED_EXTERNAL_CUSTODIAN
    )
    satisfied: Literal[False] = False
    reason: Literal["producer evidence is not external-custodian qualification"] = (
        "producer evidence is not external-custodian qualification"
    )


class M7ExternalBoundaryAssessment(ContractModel):
    schema_version: Literal["m7-external-boundary-v1"] = "m7-external-boundary-v1"
    preregistration_digest: Sha256Digest
    measured_receipt_digest: Sha256Digest
    rows: tuple[M7ExternalBoundaryRow, ...]
    authoritative: Literal[False] = False
    promotable: Literal[False] = False
    release_eligible: Literal[False] = False

    @model_validator(mode="after")
    def no_external_row_can_be_satisfied(self) -> M7ExternalBoundaryAssessment:
        if tuple(item.requirement_id for item in self.rows) != EXTERNAL_M7_REQUIREMENT_IDS:
            raise ValueError("assessment must retain every external M7 row in canonical order")
        if any(item.satisfied for item in self.rows):
            raise ValueError("producer evidence cannot satisfy external M7 rows")
        return self

    @property
    def assessment_digest(self) -> str:
        return sha256_digest(self)


def external_m7_boundary_assessment(
    *,
    preregistration: M7ProducerPreregistration,
    measured_receipt_digest: Sha256Digest,
) -> M7ExternalBoundaryAssessment:
    preregistration = M7ProducerPreregistration.model_validate(
        preregistration.model_dump(mode="python")
    )
    return M7ExternalBoundaryAssessment(
        preregistration_digest=preregistration.preregistration_digest,
        measured_receipt_digest=measured_receipt_digest,
        rows=tuple(
            M7ExternalBoundaryRow(requirement_id=requirement_id)
            for requirement_id in EXTERNAL_M7_REQUIREMENT_IDS
        ),
    )
