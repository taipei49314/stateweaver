"""Deterministic oracle for the only security invariant in the M0 lab."""

from __future__ import annotations

from dataclasses import dataclass

from .fixtures import SYNTHETIC_TENANT_B_MARKER
from .models import (
    DocumentId,
    LabMode,
    OracleCheckResponse,
    OracleResultResponse,
    Provenance,
    TenantId,
)


@dataclass(frozen=True)
class DisclosureObservation:
    evidence_id: str
    requester_tenant: TenantId
    owner_tenant: TenantId
    document_id: DocumentId
    response_status: int
    body_marker: str
    provenance: Provenance


def evaluate_disclosure(
    mode: LabMode, observation: DisclosureObservation | None
) -> OracleResultResponse:
    """Evaluate exact runtime facts; no heuristic or model judgment is used."""

    checks = (
        OracleCheckResponse(
            check_id="runtime_response_status_is_200",
            passed=observation is not None and observation.response_status == 200,
        ),
        OracleCheckResponse(
            check_id="requester_and_owner_tenants_differ",
            passed=(
                observation is not None and observation.requester_tenant != observation.owner_tenant
            ),
        ),
        OracleCheckResponse(
            check_id="protected_document_id_matches",
            passed=(
                observation is not None and observation.document_id == DocumentId.TENANT_B_PROTECTED
            ),
        ),
        OracleCheckResponse(
            check_id="synthetic_protected_marker_matches_exactly",
            passed=(
                observation is not None and observation.body_marker == SYNTHETIC_TENANT_B_MARKER
            ),
        ),
        OracleCheckResponse(
            check_id="evidence_provenance_is_observed",
            passed=(observation is not None and observation.provenance == Provenance.OBSERVED),
        ),
    )
    violated = all(check.passed for check in checks)
    return OracleResultResponse(
        oracle_id="oracle.cross_tenant_document_disclosure.v1",
        mode=mode,
        violated=violated,
        verdict="VIOLATED" if violated else "NOT_VIOLATED",
        checks=checks,
        evidence_ids=(observation.evidence_id,) if violated and observation else (),
    )
