"""Machine-checkable oracle and verified-finding contracts."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, cast

from pydantic import (
    JsonValue,
    StringConstraints,
    field_serializer,
    field_validator,
    model_validator,
)

from .base import (
    ContractId,
    ContractModel,
    Name,
    VersionedContract,
    freeze_json,
    thaw_json,
)
from .enums import (
    FindingStatus,
    OracleOutcome,
    OracleType,
    ProvenanceKind,
    ReplayOutcome,
)
from .state_ir import FidelityProfile

InvariantExpression = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=3, max_length=4096),
]


class OracleResult(VersionedContract):
    oracle_result_id: ContractId
    oracle_type: OracleType
    world_id: ContractId
    invariant: InvariantExpression
    result: OracleOutcome
    observed: Mapping[str, JsonValue]
    evidence_ids: tuple[ContractId, ...]
    deterministic: bool
    provenance: ProvenanceKind = ProvenanceKind.OBSERVED
    evaluator_version: Name = "builtin-v1"

    @field_validator("observed")
    @classmethod
    def observations_are_deeply_immutable(
        cls, value: Mapping[str, JsonValue]
    ) -> Mapping[str, JsonValue]:
        return cast(Mapping[str, JsonValue], freeze_json(value))

    @field_serializer("observed")
    def serialize_observed(self, value: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
        return cast(dict[str, JsonValue], thaw_json(value))

    @field_validator("evidence_ids")
    @classmethod
    def evidence_is_unique(cls, value: tuple[ContractId, ...]) -> tuple[ContractId, ...]:
        if len(value) != len(set(value)):
            raise ValueError("oracle evidence ids must be unique")
        return value

    @model_validator(mode="after")
    def results_have_honest_evidence(self) -> OracleResult:
        if (
            self.result in {OracleOutcome.SATISFIED, OracleOutcome.VIOLATED}
            and not self.evidence_ids
        ):
            raise ValueError("conclusive oracle results require evidence")
        if self.provenance is ProvenanceKind.UNKNOWN and self.evidence_ids:
            raise ValueError("unknown-provenance oracle results cannot claim evidence")
        if self.deterministic and self.result is not OracleOutcome.ERROR:
            if not self.observed or not self.evidence_ids:
                raise ValueError(
                    "deterministic non-error results require machine observations and evidence"
                )
            if self.provenance is ProvenanceKind.MOCKED:
                raise ValueError("mocked oracle results cannot be deterministic reality evidence")
        if self.result is OracleOutcome.ERROR and self.deterministic:
            raise ValueError("an evaluator error cannot be a deterministic result")
        return self


class NegativeControl(ContractModel):
    name: Name
    result: ReplayOutcome
    evidence_ids: tuple[ContractId, ...] = ()


class PatchedVersionReplay(ContractModel):
    target_version: Name
    replay_run_id: ContractId
    replay_result: ReplayOutcome
    evidence_ids: tuple[ContractId, ...] = ()


class Finding(VersionedContract):
    finding_id: ContractId
    title: Annotated[str, StringConstraints(strip_whitespace=True, min_length=8, max_length=240)]
    status: FindingStatus
    chain_id: ContractId
    oracle_result_ids: tuple[ContractId, ...]
    fidelity: FidelityProfile
    negative_controls: tuple[NegativeControl, ...] = ()
    patched_version: PatchedVersionReplay | None = None
    replay_run_id: ContractId | None = None
    replay_outcome: ReplayOutcome | None = None

    @field_validator("oracle_result_ids")
    @classmethod
    def oracle_results_are_unique(cls, value: tuple[ContractId, ...]) -> tuple[ContractId, ...]:
        if len(value) != len(set(value)):
            raise ValueError("oracle result ids must be unique")
        return value

    @model_validator(mode="after")
    def confirmed_findings_pin_successful_replay(self) -> Finding:
        confirmed = self.status in {FindingStatus.REALITY_REPLAYED, FindingStatus.VERIFIED}
        if confirmed:
            if self.replay_run_id is None or self.replay_outcome is not ReplayOutcome.REPRODUCED:
                raise ValueError("confirmed findings require a successful pinned replay run")
            if not self.oracle_result_ids:
                raise ValueError("confirmed findings require at least one oracle result")
        if (self.replay_run_id is None) != (self.replay_outcome is None):
            raise ValueError("replay_run_id and replay_outcome must be supplied together")
        control_names = [control.name for control in self.negative_controls]
        if len(control_names) != len(set(control_names)):
            raise ValueError("negative control names must be unique")
        return self
