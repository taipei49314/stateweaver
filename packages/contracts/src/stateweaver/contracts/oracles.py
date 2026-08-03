"""Machine-checkable oracle and verified-finding contracts."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Literal, Self, cast

from pydantic import (
    ConfigDict,
    Field,
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
    Sha256Digest,
    VersionedContract,
    freeze_json,
    sha256_digest,
    thaw_json,
)
from .enums import (
    FindingStatus,
    NegativeControlKind,
    OracleOutcome,
    OracleType,
    ProvenanceKind,
    RealityAnchorMode,
    ReplayOutcome,
)
from .state_ir import FidelityProfile

InvariantExpression = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=3, max_length=4096),
]


class _VersionedContractV2(ContractModel):
    model_config = ConfigDict(revalidate_instances="always")
    schema_version: Literal["2.0"] = "2.0"


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


def _unique_nonempty_ids(
    value: tuple[ContractId, ...], *, field_name: str
) -> tuple[ContractId, ...]:
    if not value:
        raise ValueError(f"{field_name} must not be empty")
    if len(value) != len(set(value)):
        raise ValueError(f"{field_name} must be unique")
    return value


def _oracle_definition(result: OracleResult) -> tuple[OracleType, str, str]:
    return result.oracle_type, result.invariant, result.evaluator_version


def _oracle_definitions(
    results: tuple[OracleResult, ...],
) -> tuple[tuple[OracleType, str, str], ...]:
    return tuple(
        sorted(
            (_oracle_definition(result) for result in results),
            key=lambda item: (str(item[0]), item[1], item[2]),
        )
    )


def _oracle_definitions_hash(results: tuple[OracleResult, ...]) -> Sha256Digest:
    definitions = tuple(
        {
            "oracle_type": oracle_type,
            "invariant": invariant,
            "evaluator_version": evaluator_version,
        }
        for oracle_type, invariant, evaluator_version in _oracle_definitions(results)
    )
    return sha256_digest(definitions)


def _oracle_evidence(results: tuple[OracleResult, ...]) -> set[ContractId]:
    return {evidence_id for result in results for evidence_id in result.evidence_ids}


def _revalidate_contract[ContractModelT: ContractModel](
    model_type: type[ContractModelT], value: object
) -> ContractModelT:
    payload = value.model_dump(mode="python") if isinstance(value, ContractModel) else value
    return model_type.model_validate(payload)


def _revalidate_oracles(results: tuple[OracleResult, ...]) -> tuple[OracleResult, ...]:
    return tuple(_revalidate_contract(OracleResult, result) for result in results)


def _require_canonical_unique_oracles(results: tuple[OracleResult, ...], *, boundary: str) -> None:
    oracle_ids = tuple(result.oracle_result_id for result in results)
    if oracle_ids != tuple(sorted(oracle_ids)):
        raise ValueError(f"{boundary} Oracle results must use canonical ID order")
    if len(oracle_ids) != len(set(oracle_ids)):
        raise ValueError(f"{boundary} Oracle result IDs must be unique")
    definitions = _oracle_definitions(results)
    if len(definitions) != len(set(definitions)):
        raise ValueError(f"{boundary} Oracle definitions must be unique")


def _require_oracle_evidence(
    evidence_ids: tuple[ContractId, ...],
    oracle_results: tuple[OracleResult, ...],
) -> None:
    if not _oracle_evidence(oracle_results).issubset(evidence_ids):
        raise ValueError("receipt evidence must cover Oracle evidence")


class RealityReplayAttempt(ContractModel):
    """One content-bound execution contributing to a deterministic reality replay."""

    replay_run_id: ContractId
    replay_outcome: ReplayOutcome
    scope_manifest_sha256: Sha256Digest
    target_id: ContractId
    target_version: Name
    target_lock_sha256: Sha256Digest
    adapter_lock_sha256: Sha256Digest
    plan_id: ContractId
    plan_hash: Sha256Digest
    root_seed_id: ContractId
    root_fingerprint: Sha256Digest
    replay_result_sha256: Sha256Digest
    action_log_sha256: Sha256Digest
    trace_hash: Sha256Digest
    semantic_signature: Sha256Digest
    oracle_results_hash: Sha256Digest
    evidence_ids: tuple[ContractId, ...]

    @field_validator("evidence_ids")
    @classmethod
    def evidence_is_nonempty_and_unique(
        cls, value: tuple[ContractId, ...]
    ) -> tuple[ContractId, ...]:
        return _unique_nonempty_ids(value, field_name="reality replay attempt evidence IDs")


class NegativeControl(_VersionedContractV2):
    """A non-vacuous control replay proving that the violation is condition-specific."""

    name: Name
    kind: NegativeControlKind
    target_id: ContractId
    target_version: Name
    target_lock_sha256: Sha256Digest
    adapter_lock_sha256: Sha256Digest
    plan_id: ContractId
    plan_hash: Sha256Digest
    root_seed_id: ContractId
    root_fingerprint: Sha256Digest
    replay_run_id: ContractId
    replay_result_sha256: Sha256Digest
    action_log_sha256: Sha256Digest
    control_delta_sha256: Sha256Digest
    trace_hash: Sha256Digest
    semantic_signature: Sha256Digest
    result: ReplayOutcome
    oracle_results: Annotated[tuple[OracleResult, ...], Field(min_length=1)]
    oracle_results_hash: Sha256Digest
    evidence_ids: tuple[ContractId, ...]

    @field_validator("evidence_ids")
    @classmethod
    def evidence_is_nonempty_and_unique(
        cls, value: tuple[ContractId, ...]
    ) -> tuple[ContractId, ...]:
        return _unique_nonempty_ids(value, field_name="negative-control evidence IDs")

    @model_validator(mode="after")
    def control_is_observed_and_nonviolating(self) -> NegativeControl:
        oracle_results = _revalidate_oracles(self.oracle_results)
        _require_canonical_unique_oracles(oracle_results, boundary="negative-control")
        if self.result is not ReplayOutcome.NOT_REPRODUCED:
            raise ValueError("negative controls must not reproduce the violation")
        if any(
            not result.deterministic
            or result.provenance is not ProvenanceKind.OBSERVED
            or result.result is not OracleOutcome.SATISFIED
            for result in oracle_results
        ):
            raise ValueError(
                "negative controls require deterministic OBSERVED SATISFIED Oracle results"
            )
        if self.oracle_results_hash != sha256_digest(oracle_results):
            raise ValueError("negative-control Oracle result hash does not match its results")
        _require_oracle_evidence(self.evidence_ids, oracle_results)
        return self


class PatchedVersionReplay(_VersionedContractV2):
    target_id: ContractId
    target_version: Name
    target_lock_sha256: Sha256Digest
    adapter_lock_sha256: Sha256Digest
    plan_id: ContractId
    plan_hash: Sha256Digest
    root_seed_id: ContractId
    root_fingerprint: Sha256Digest
    replay_run_id: ContractId
    replay_result_sha256: Sha256Digest
    action_log_sha256: Sha256Digest
    trace_hash: Sha256Digest
    semantic_signature: Sha256Digest
    replay_result: ReplayOutcome
    oracle_results: Annotated[tuple[OracleResult, ...], Field(min_length=1)]
    oracle_results_hash: Sha256Digest
    evidence_ids: tuple[ContractId, ...]
    failed_step_id: ContractId
    failure_code: Name

    @field_validator("evidence_ids")
    @classmethod
    def evidence_is_nonempty_and_unique(
        cls, value: tuple[ContractId, ...]
    ) -> tuple[ContractId, ...]:
        return _unique_nonempty_ids(value, field_name="patched replay evidence IDs")

    @model_validator(mode="after")
    def patch_replay_is_an_observed_block(self) -> PatchedVersionReplay:
        oracle_results = _revalidate_oracles(self.oracle_results)
        _require_canonical_unique_oracles(oracle_results, boundary="patched")
        if self.replay_result is not ReplayOutcome.BLOCKED_BY_FIX:
            raise ValueError("patched replay must have the exact BLOCKED_BY_FIX outcome")
        if any(
            not result.deterministic
            or result.provenance is not ProvenanceKind.OBSERVED
            or result.result is not OracleOutcome.SATISFIED
            for result in oracle_results
        ):
            raise ValueError("patched replay requires deterministic OBSERVED SATISFIED Oracles")
        if self.oracle_results_hash != sha256_digest(oracle_results):
            raise ValueError("patched replay Oracle result hash does not match its results")
        _require_oracle_evidence(self.evidence_ids, oracle_results)
        return self


class RealityReplayReceipt(VersionedContract):
    """Content-addressed candidate record for an evidence-backed reality replay.

    This contract proves internal causal coherence, not producer identity. A broker or proof-bundle
    verifier must resolve every retained digest and attest it before Finding promotion. Consumers
    must revalidate serialized data; Pydantic's unsafe construction and copy APIs do not create a
    trusted receipt.
    """

    model_config = ConfigDict(revalidate_instances="always")

    receipt_id: ContractId
    receipt_hash: Sha256Digest
    anchor_mode: RealityAnchorMode
    scope_id: ContractId
    scope_manifest_sha256: Sha256Digest
    target_id: ContractId
    target_version: Name
    target_lock_sha256: Sha256Digest
    adapter_lock_sha256: Sha256Digest
    chain_id: ContractId
    plan_id: ContractId
    plan_hash: Sha256Digest
    root_seed_id: ContractId
    root_fingerprint: Sha256Digest
    attempts: Annotated[tuple[RealityReplayAttempt, ...], Field(min_length=2)]
    oracle_results: Annotated[tuple[OracleResult, ...], Field(min_length=1)]
    oracle_definition_sha256: Sha256Digest
    negative_controls: Annotated[tuple[NegativeControl, ...], Field(min_length=1)]
    patched_version: PatchedVersionReplay | None = None
    pre_receipt_evidence_manifest_sha256: Sha256Digest = Field(
        description=(
            "Digest of the canonical evidence-only manifest created before the receipt; it "
            "excludes the receipt, Finding, final report, publication manifest, and attestation"
        )
    )

    @classmethod
    def create(
        cls,
        *,
        anchor_mode: RealityAnchorMode,
        scope_id: ContractId,
        scope_manifest_sha256: Sha256Digest,
        target_id: ContractId,
        target_version: Name,
        target_lock_sha256: Sha256Digest,
        adapter_lock_sha256: Sha256Digest,
        chain_id: ContractId,
        plan_id: ContractId,
        plan_hash: Sha256Digest,
        root_seed_id: ContractId,
        root_fingerprint: Sha256Digest,
        attempts: tuple[RealityReplayAttempt, ...],
        oracle_results: tuple[OracleResult, ...],
        negative_controls: tuple[NegativeControl, ...],
        patched_version: PatchedVersionReplay | None,
        pre_receipt_evidence_manifest_sha256: Sha256Digest,
    ) -> Self:
        canonical_attempts = tuple(sorted(attempts, key=lambda item: item.replay_run_id))
        canonical_oracles = tuple(sorted(oracle_results, key=lambda item: item.oracle_result_id))
        canonical_controls = tuple(sorted(negative_controls, key=lambda item: item.name))
        payload = {
            "schema_version": "1.0",
            "anchor_mode": anchor_mode,
            "scope_id": scope_id,
            "scope_manifest_sha256": scope_manifest_sha256,
            "target_id": target_id,
            "target_version": target_version,
            "target_lock_sha256": target_lock_sha256,
            "adapter_lock_sha256": adapter_lock_sha256,
            "chain_id": chain_id,
            "plan_id": plan_id,
            "plan_hash": plan_hash,
            "root_seed_id": root_seed_id,
            "root_fingerprint": root_fingerprint,
            "attempts": canonical_attempts,
            "oracle_results": canonical_oracles,
            "oracle_definition_sha256": _oracle_definitions_hash(canonical_oracles),
            "negative_controls": canonical_controls,
            "patched_version": patched_version,
            "pre_receipt_evidence_manifest_sha256": pre_receipt_evidence_manifest_sha256,
        }
        receipt_hash = sha256_digest(payload)
        return cls(
            receipt_id=f"receipt.reality:{receipt_hash.removeprefix('sha256:')[:24]}",
            receipt_hash=receipt_hash,
            anchor_mode=anchor_mode,
            scope_id=scope_id,
            scope_manifest_sha256=scope_manifest_sha256,
            target_id=target_id,
            target_version=target_version,
            target_lock_sha256=target_lock_sha256,
            adapter_lock_sha256=adapter_lock_sha256,
            chain_id=chain_id,
            plan_id=plan_id,
            plan_hash=plan_hash,
            root_seed_id=root_seed_id,
            root_fingerprint=root_fingerprint,
            attempts=canonical_attempts,
            oracle_results=canonical_oracles,
            oracle_definition_sha256=_oracle_definitions_hash(canonical_oracles),
            negative_controls=canonical_controls,
            patched_version=patched_version,
            pre_receipt_evidence_manifest_sha256=pre_receipt_evidence_manifest_sha256,
        )

    @model_validator(mode="after")
    def receipt_is_a_coherent_reality_replay(self) -> RealityReplayReceipt:
        attempts = tuple(
            _revalidate_contract(RealityReplayAttempt, attempt) for attempt in self.attempts
        )
        oracle_results = _revalidate_oracles(self.oracle_results)
        controls = tuple(
            _revalidate_contract(NegativeControl, control) for control in self.negative_controls
        )
        patched = (
            None
            if self.patched_version is None
            else _revalidate_contract(PatchedVersionReplay, self.patched_version)
        )

        if len(attempts) < 2:
            raise ValueError("reality replay attempts must contain at least 2 items")
        if not oracle_results:
            raise ValueError("reality replay must contain at least one Oracle result")
        if not controls:
            raise ValueError("reality replay must contain at least one negative control")
        run_ids = tuple(attempt.replay_run_id for attempt in attempts)
        if run_ids != tuple(sorted(run_ids)):
            raise ValueError("reality replay attempts must use canonical run ID order")
        if len(run_ids) != len(set(run_ids)):
            raise ValueError("reality replay run IDs must be unique")
        all_run_ids = run_ids + tuple(control.replay_run_id for control in controls)
        if patched is not None:
            all_run_ids += (patched.replay_run_id,)
        if len(all_run_ids) != len(set(all_run_ids)):
            raise ValueError("reality replay receipt run IDs must be globally unique")
        all_result_digests = tuple(attempt.replay_result_sha256 for attempt in attempts) + tuple(
            control.replay_result_sha256 for control in controls
        )
        if patched is not None:
            all_result_digests += (patched.replay_result_sha256,)
        if len(all_result_digests) != len(set(all_result_digests)):
            raise ValueError("reality replay receipt replay-result digests must be globally unique")
        if any(attempt.replay_outcome is not ReplayOutcome.REPRODUCED for attempt in attempts):
            raise ValueError("every reality replay attempt must reproduce the violation")
        for attempt in attempts:
            if attempt.scope_manifest_sha256 != self.scope_manifest_sha256:
                raise ValueError("reality replay attempt scope does not match the receipt")
            if (
                attempt.target_id != self.target_id
                or attempt.target_version != self.target_version
                or attempt.target_lock_sha256 != self.target_lock_sha256
            ):
                raise ValueError("reality replay attempt target does not match the receipt")
            if attempt.adapter_lock_sha256 != self.adapter_lock_sha256:
                raise ValueError("reality replay attempt adapter lock does not match the receipt")
            if attempt.plan_id != self.plan_id or attempt.plan_hash != self.plan_hash:
                raise ValueError("reality replay attempt plan does not match the receipt")
            if (
                attempt.root_seed_id != self.root_seed_id
                or attempt.root_fingerprint != self.root_fingerprint
            ):
                raise ValueError("reality replay attempt root does not match the receipt")
        if len({attempt.semantic_signature for attempt in attempts}) != 1:
            raise ValueError("reality replay attempts must share one deterministic signature")
        if len({attempt.trace_hash for attempt in attempts}) != 1:
            raise ValueError("reality replay attempts must share one deterministic trace hash")
        if len({attempt.replay_result_sha256 for attempt in attempts}) != len(attempts):
            raise ValueError("reality replay attempts must bind unique replay-result digests")
        if len({attempt.action_log_sha256 for attempt in attempts}) != 1:
            raise ValueError("reality replay attempts must share one action-log digest")

        _require_canonical_unique_oracles(oracle_results, boundary="reality")
        if any(
            not result.deterministic
            or result.provenance is not ProvenanceKind.OBSERVED
            or result.result is not OracleOutcome.VIOLATED
            for result in oracle_results
        ):
            raise ValueError("reality replay requires deterministic OBSERVED VIOLATED Oracles")
        if len({result.world_id for result in oracle_results}) != 1:
            raise ValueError("reality Oracle results must describe one replay world")
        expected_oracle_hash = sha256_digest(oracle_results)
        for attempt in attempts:
            if attempt.oracle_results_hash != expected_oracle_hash:
                raise ValueError("reality replay attempt Oracle result hash does not match")
            _require_oracle_evidence(attempt.evidence_ids, oracle_results)
        if self.oracle_definition_sha256 != _oracle_definitions_hash(oracle_results):
            raise ValueError("Oracle definition hash does not match the reality Oracles")

        control_names = tuple(control.name for control in controls)
        if control_names != tuple(sorted(control_names)):
            raise ValueError("negative controls must use canonical name order")
        if len(control_names) != len(set(control_names)):
            raise ValueError("negative control names must be unique")
        primary_definitions = _oracle_definitions(oracle_results)
        primary_signatures = {attempt.semantic_signature for attempt in attempts}
        for control in controls:
            if control.target_id != self.target_id or control.target_version != self.target_version:
                raise ValueError("negative control target does not match the primary replay")
            if (
                control.target_lock_sha256 != self.target_lock_sha256
                or control.adapter_lock_sha256 != self.adapter_lock_sha256
            ):
                raise ValueError("negative control locks do not match the primary replay")
            if (
                control.root_seed_id != self.root_seed_id
                or control.root_fingerprint != self.root_fingerprint
            ):
                raise ValueError("negative control root does not match the primary replay")
            if control.plan_id == self.plan_id or control.plan_hash == self.plan_hash:
                raise ValueError("negative control must use a distinct control plan")
            if control.semantic_signature in primary_signatures:
                raise ValueError("negative control must not reuse the primary replay signature")
            control_definitions = _oracle_definitions(control.oracle_results)
            if control_definitions != primary_definitions:
                raise ValueError(
                    "negative control Oracle definition does not match the primary replay"
                )

        if patched is not None:
            if patched.target_id != self.target_id:
                raise ValueError("patched replay target does not match the primary replay")
            if patched.target_version == self.target_version:
                raise ValueError("patched replay requires a different target version")
            if patched.target_lock_sha256 == self.target_lock_sha256:
                raise ValueError("patched replay requires a different target lock")
            if patched.adapter_lock_sha256 != self.adapter_lock_sha256:
                raise ValueError("patched replay adapter lock does not match the primary replay")
            if patched.plan_id != self.plan_id or patched.plan_hash != self.plan_hash:
                raise ValueError("patched replay must use the same plan as the primary replay")
            if (
                patched.root_seed_id != self.root_seed_id
                or patched.root_fingerprint != self.root_fingerprint
            ):
                raise ValueError("patched replay root does not match the primary replay")
            if patched.semantic_signature in primary_signatures:
                raise ValueError("patched replay must not reuse the vulnerable replay signature")
            patched_definitions = _oracle_definitions(patched.oracle_results)
            if patched_definitions != primary_definitions:
                raise ValueError(
                    "patched replay Oracle definition does not match the primary replay"
                )

        payload = self.model_dump(mode="python", exclude={"receipt_id", "receipt_hash"})
        expected_hash = sha256_digest(payload)
        if self.receipt_hash != expected_hash:
            raise ValueError("reality replay receipt hash does not match its causal content")
        expected_id = f"receipt.reality:{expected_hash.removeprefix('sha256:')[:24]}"
        if self.receipt_id != expected_id:
            raise ValueError("reality replay receipt ID does not match its content hash")
        return self


class Finding(_VersionedContractV2):
    finding_id: ContractId
    title: Annotated[str, StringConstraints(strip_whitespace=True, min_length=8, max_length=240)]
    status: FindingStatus
    chain_id: ContractId
    oracle_result_ids: tuple[ContractId, ...]
    fidelity: FidelityProfile
    reality_replay: RealityReplayReceipt | None = None

    @field_validator("oracle_result_ids")
    @classmethod
    def oracle_results_are_unique(cls, value: tuple[ContractId, ...]) -> tuple[ContractId, ...]:
        if len(value) != len(set(value)):
            raise ValueError("oracle result ids must be unique")
        return value

    @model_validator(mode="after")
    def confirmed_findings_require_revalidated_reality_receipts(self) -> Finding:
        confirmed = self.status in {
            FindingStatus.REALITY_REPLAYED,
            FindingStatus.PATCH_VERIFIED,
        }
        if confirmed:
            if self.reality_replay is None:
                raise ValueError("confirmed findings require a typed reality replay receipt")
            receipt = RealityReplayReceipt.model_validate(
                self.reality_replay.model_dump(mode="python")
            )
            if receipt.chain_id != self.chain_id:
                raise ValueError("finding chain does not match its reality replay receipt")
            receipt_oracle_ids = {result.oracle_result_id for result in receipt.oracle_results}
            if set(self.oracle_result_ids) != receipt_oracle_ids:
                raise ValueError("finding Oracle result IDs do not match the reality receipt")
            if (
                self.status is FindingStatus.REALITY_REPLAYED
                and receipt.patched_version is not None
            ):
                raise ValueError("REALITY_REPLAYED cannot under-report an available patch proof")
            if self.status is FindingStatus.PATCH_VERIFIED and receipt.patched_version is None:
                raise ValueError("PATCH_VERIFIED requires a patched-version receipt")
            raise ValueError(
                "confirmed findings require broker-verified artifact attestation; "
                "a self-issued receipt cannot promote"
            )
        elif self.reality_replay is not None:
            raise ValueError("only confirmed findings may carry a reality replay receipt")
        return self
