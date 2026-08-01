"""Machine-oracle mapping for the deterministic in-process lab."""

from __future__ import annotations

from typing import Final

from pydantic import JsonValue
from stateweaver.contracts import (
    ActionEnvelope,
    OracleOutcome,
    OracleResult,
    OracleType,
)
from stateweaver.replay import ReplayObservation, StateCapture, canonical_sha256
from stateweaver_lab import DeterministicLabService

from .errors import LabEvidenceRejectedError

ORACLE_ID: Final = "oracle.cross_tenant_document_disclosure.v1"
ORACLE_VERSION: Final = "1.0"
_INVARIANT: Final = "actor.tenant == resource.tenant OR response.protected_field_present == false"
_EXPECTED_CHECK_IDS: Final = frozenset(
    {
        "runtime_response_status_is_200",
        "requester_and_owner_tenants_differ",
        "protected_document_id_matches",
        "synthetic_protected_marker_matches_exactly",
        "evidence_provenance_is_observed",
    }
)


class InProcessLabReplayOracle:
    """Map the lab's pure machine verdict to the public OracleResult contract."""

    id = ORACLE_ID
    version = ORACLE_VERSION

    def __init__(self, service: DeterministicLabService) -> None:
        self._service = service
        self._last_result: OracleResult | None = None

    @property
    def last_result(self) -> OracleResult | None:
        """Expose the last mapped verdict for patched failure diagnostics."""

        return self._last_result

    def reset_diagnostics(self) -> None:
        self._last_result = None

    async def evaluate(
        self,
        before: StateCapture,
        action: ActionEnvelope,
        after: StateCapture,
        observations: tuple[ReplayObservation, ...],
    ) -> OracleResult:
        del before
        if not observations:
            raise LabEvidenceRejectedError("oracle evaluation requires an action observation")

        machine = self._service.oracle()
        if machine.oracle_id != self.id or machine.mode is not self._service.mode:
            raise LabEvidenceRejectedError("machine oracle identity or mode changed")
        if machine.violated != (machine.verdict == "VIOLATED"):
            raise LabEvidenceRejectedError("machine oracle verdict is incoherent")
        check_ids = [check.check_id for check in machine.checks]
        if len(check_ids) != len(set(check_ids)) or set(check_ids) != _EXPECTED_CHECK_IDS:
            raise LabEvidenceRejectedError("machine oracle check set changed")
        if machine.violated and not all(check.passed for check in machine.checks):
            raise LabEvidenceRejectedError("machine oracle violation checks are incomplete")

        observation_evidence = tuple(
            evidence_id for observation in observations for evidence_id in observation.evidence_ids
        )
        if not observation_evidence or len(observation_evidence) != len(set(observation_evidence)):
            raise LabEvidenceRejectedError("oracle evidence is missing or duplicated")
        if machine.violated and not set(machine.evidence_ids) <= set(observation_evidence):
            raise LabEvidenceRejectedError("violation evidence is not correlated to this action")

        evidence_ids = machine.evidence_ids if machine.violated else observation_evidence
        provenance = {item.payload.get("provenance") for item in observations}
        action_types = {item.payload.get("action_type") for item in observations}
        relevant_runtime_observation = bool(action_types & {"document.read", "decoy.masked_read"})
        if machine.violated:
            if provenance != {"OBSERVED"}:
                raise LabEvidenceRejectedError("violation evidence is not observed runtime data")
            outcome = OracleOutcome.VIOLATED
        elif provenance == {"OBSERVED"} and relevant_runtime_observation:
            outcome = OracleOutcome.SATISFIED
        else:
            outcome = OracleOutcome.INCONCLUSIVE
        checks: list[JsonValue] = [
            {"check_id": check.check_id, "passed": check.passed} for check in machine.checks
        ]
        observed: dict[str, JsonValue] = {
            "mode": machine.mode.value,
            "verdict": machine.verdict,
            "checks": checks,
            "observation_ids": [item.observation_id for item in observations],
            "after_fingerprint": after.fingerprint,
        }
        result_hash = canonical_sha256(
            {
                "oracle_id": self.id,
                "version": self.version,
                "world_id": action.world_id,
                "action_id": action.action_id,
                "observed": observed,
                "evidence_ids": evidence_ids,
            }
        ).removeprefix("sha256:")
        result = OracleResult(
            oracle_result_id=f"oracle.result:{result_hash[:24]}",
            oracle_type=OracleType.TENANT_ISOLATION,
            world_id=action.world_id,
            invariant=_INVARIANT,
            result=outcome,
            observed=observed,
            evidence_ids=evidence_ids,
            deterministic=True,
            evaluator_version="in-process-lab-v1",
        )
        self._last_result = result
        return result


__all__ = [
    "ORACLE_ID",
    "ORACLE_VERSION",
    "InProcessLabReplayOracle",
]
