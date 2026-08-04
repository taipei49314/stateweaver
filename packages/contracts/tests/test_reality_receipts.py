from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel, ValidationError
from stateweaver.contracts import (
    FidelityLevel,
    FidelityProfile,
    Finding,
    FindingStatus,
    NegativeControl,
    NegativeControlKind,
    OracleOutcome,
    OracleResult,
    OracleType,
    PatchedVersionReplay,
    ProvenanceKind,
    RealityAnchorMode,
    RealityReplayAttempt,
    RealityReplayReceipt,
    ReplayOutcome,
    sha256_digest,
)


def digest(character: str) -> str:
    return f"sha256:{character * 64}"


def raw_model_values(model: BaseModel) -> dict[str, Any]:
    return {name: getattr(model, name) for name in type(model).model_fields}


def fidelity() -> FidelityProfile:
    return FidelityProfile(
        code=FidelityLevel.EXACT,
        identity=FidelityLevel.EXACT,
        database=FidelityLevel.EXACT,
        cache=FidelityLevel.OBSERVED,
        queue=FidelityLevel.PARTIAL,
        timing=FidelityLevel.OBSERVED,
    )


def oracle(
    *,
    outcome: OracleOutcome = OracleOutcome.VIOLATED,
    provenance: ProvenanceKind = ProvenanceKind.OBSERVED,
    deterministic: bool = True,
    result_id: str = "oracle.reality.primary",
    invariant: str = "actor.tenant == resource.tenant",
    evidence_id: str = "evidence.reality.primary",
) -> OracleResult:
    return OracleResult(
        oracle_result_id=result_id,
        oracle_type=OracleType.TENANT_ISOLATION,
        world_id="world.reality.primary",
        invariant=invariant,
        result=outcome,
        observed={"actor_tenant": "tenant-a", "resource_tenant": "tenant-b"},
        evidence_ids=(evidence_id,),
        deterministic=deterministic,
        provenance=provenance,
        evaluator_version="tenant-oracle-v1",
    )


def attempt(
    index: int,
    oracle_results: tuple[OracleResult, ...],
    **changes: object,
) -> RealityReplayAttempt:
    values: dict[str, object] = {
        "replay_run_id": f"run.reality.{index}",
        "replay_outcome": ReplayOutcome.REPRODUCED,
        "scope_manifest_sha256": digest("9"),
        "target_id": "target.local-lab",
        "target_version": "lab-vulnerable",
        "target_lock_sha256": digest("a"),
        "adapter_lock_sha256": digest("b"),
        "plan_id": "plan.reality.primary",
        "plan_hash": digest("6"),
        "root_seed_id": "root.reality.primary",
        "root_fingerprint": digest("1"),
        "replay_result_sha256": digest(str(index)),
        "action_log_sha256": digest("e"),
        "trace_hash": digest("2"),
        "semantic_signature": digest("3"),
        "oracle_results_hash": sha256_digest(oracle_results),
        "evidence_ids": ("evidence.reality.primary",),
    }
    values.update(changes)
    return RealityReplayAttempt.model_validate(values)


def negative_control(
    *,
    name: str = "fresh-session",
    invariant: str = "actor.tenant == resource.tenant",
    **changes: object,
) -> NegativeControl:
    control_oracles = (
        oracle(
            outcome=OracleOutcome.SATISFIED,
            result_id=f"oracle.control.{name}",
            invariant=invariant,
            evidence_id=f"evidence.control.{name}",
        ),
    )
    values: dict[str, object] = {
        "name": name,
        "kind": NegativeControlKind.FRESH_SESSION,
        "target_id": "target.local-lab",
        "target_version": "lab-vulnerable",
        "target_lock_sha256": digest("a"),
        "adapter_lock_sha256": digest("b"),
        "plan_id": f"plan.control.{name}",
        "plan_hash": digest("4"),
        "root_seed_id": "root.reality.primary",
        "root_fingerprint": digest("1"),
        "replay_run_id": f"run.control.{name}",
        "replay_result_sha256": digest("0"),
        "action_log_sha256": digest("f"),
        "control_delta_sha256": digest("d"),
        "trace_hash": digest("5"),
        "semantic_signature": digest("4"),
        "result": ReplayOutcome.NOT_REPRODUCED,
        "oracle_results": control_oracles,
        "oracle_results_hash": sha256_digest(control_oracles),
        "evidence_ids": (f"evidence.control.{name}",),
    }
    values.update(changes)
    return NegativeControl.model_validate(values)


def patched_replay(**changes: object) -> PatchedVersionReplay:
    patched_oracles = (
        oracle(
            outcome=OracleOutcome.SATISFIED,
            result_id="oracle.patch.primary",
            evidence_id="evidence.patch.primary",
        ),
    )
    values: dict[str, object] = {
        "target_id": "target.local-lab",
        "target_version": "lab-patched",
        "target_lock_sha256": digest("e"),
        "adapter_lock_sha256": digest("b"),
        "plan_id": "plan.reality.primary",
        "plan_hash": digest("6"),
        "root_seed_id": "root.reality.primary",
        "root_fingerprint": digest("1"),
        "replay_run_id": "run.patch.primary",
        "replay_result_sha256": digest("9"),
        "action_log_sha256": digest("f"),
        "trace_hash": digest("8"),
        "semantic_signature": digest("7"),
        "replay_result": ReplayOutcome.BLOCKED_BY_FIX,
        "oracle_results": patched_oracles,
        "oracle_results_hash": sha256_digest(patched_oracles),
        "evidence_ids": ("evidence.patch.primary",),
        "failed_step_id": "step.07",
        "failure_code": "ORACLE_EXPECTATION_MISMATCH",
    }
    values.update(changes)
    return PatchedVersionReplay.model_validate(values)


def receipt(
    *, patched: PatchedVersionReplay | None = None, **changes: object
) -> RealityReplayReceipt:
    primary_oracles = (oracle(),)
    values: dict[str, Any] = {
        "anchor_mode": RealityAnchorMode.SOURCE_BACKED,
        "scope_id": "scope.local-lab",
        "scope_manifest_sha256": digest("9"),
        "target_id": "target.local-lab",
        "target_version": "lab-vulnerable",
        "target_lock_sha256": digest("a"),
        "adapter_lock_sha256": digest("b"),
        "chain_id": "chain.reality.primary",
        "plan_id": "plan.reality.primary",
        "plan_hash": digest("6"),
        "root_seed_id": "root.reality.primary",
        "root_fingerprint": digest("1"),
        "attempts": (attempt(1, primary_oracles), attempt(2, primary_oracles)),
        "oracle_results": primary_oracles,
        "negative_controls": (negative_control(),),
        "patched_version": patched,
        "pre_receipt_evidence_manifest_sha256": digest("c"),
    }
    values.update(changes)
    return RealityReplayReceipt.create(**values)


def finding(
    *,
    status: FindingStatus = FindingStatus.REALITY_REPLAYED,
    reality_replay: RealityReplayReceipt | None = None,
    **changes: object,
) -> Finding:
    values: dict[str, object] = {
        "finding_id": "finding.reality.primary",
        "title": "stale authorization cache enables cross-tenant document read",
        "status": status,
        "chain_id": "chain.reality.primary",
        "oracle_result_ids": ("oracle.reality.primary",),
        "fidelity": fidelity(),
        "reality_replay": reality_replay,
    }
    values.update(changes)
    return Finding.model_validate(values)


def test_confirmed_finding_requires_typed_reality_receipt() -> None:
    with pytest.raises(ValidationError, match="typed reality replay receipt"):
        finding()

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        Finding.model_validate(
            {
                "finding_id": "finding.legacy",
                "title": "legacy replay identifiers cannot confirm this finding",
                "status": "REALITY_REPLAYED",
                "chain_id": "chain.reality.primary",
                "oracle_result_ids": ("oracle.reality.primary",),
                "fidelity": fidelity(),
                "replay_run_id": "run.forged",
                "replay_outcome": "REPRODUCED",
            }
        )


def test_reality_receipt_is_content_addressed_and_binds_finding() -> None:
    proof = receipt()

    assert proof.receipt_hash == sha256_digest(
        proof.model_dump(mode="python", exclude={"receipt_id", "receipt_hash"})
    )
    assert proof.receipt_id == f"receipt.reality:{proof.receipt_hash[7:31]}"
    assert proof.negative_controls[0].schema_version == "2.0"
    assert RealityReplayReceipt.model_validate_json(proof.model_dump_json()) == proof

    with pytest.raises(ValidationError, match="broker-verified artifact attestation"):
        finding(reality_replay=proof)

    primary_oracles = (oracle(),)
    reversed_attempts = (attempt(2, primary_oracles), attempt(1, primary_oracles))
    assert receipt(attempts=reversed_attempts) == proof
    assert len({item.replay_result_sha256 for item in proof.attempts}) == 2


@pytest.mark.parametrize(
    ("kind", "control_delta_sha256"),
    (
        (NegativeControlKind.ALTERNATE_ORDER, digest("d")),
        (NegativeControlKind.FRESH_SESSION, digest("8")),
    ),
)
def test_reality_receipt_identity_binds_control_label_and_delta_digest(
    kind: NegativeControlKind,
    control_delta_sha256: str,
) -> None:
    baseline = receipt()
    changed = receipt(
        negative_controls=(negative_control(kind=kind, control_delta_sha256=control_delta_sha256),)
    )

    assert changed.receipt_hash != baseline.receipt_hash
    assert changed.receipt_id != baseline.receipt_id


@pytest.mark.parametrize(
    ("attempt_changes", "message"),
    [
        ({"replay_outcome": ReplayOutcome.NOT_REPRODUCED}, "must reproduce"),
        ({"scope_manifest_sha256": digest("d")}, "attempt scope"),
        ({"target_id": "target.other"}, "attempt target"),
        ({"target_version": "lab-other"}, "attempt target"),
        ({"target_lock_sha256": digest("d")}, "attempt target"),
        ({"adapter_lock_sha256": digest("d")}, "attempt adapter"),
        ({"plan_id": "plan.other"}, "attempt plan"),
        ({"plan_hash": digest("d")}, "attempt plan"),
        ({"root_seed_id": "root.other"}, "attempt root"),
        ({"root_fingerprint": digest("d")}, "attempt root"),
        ({"action_log_sha256": digest("0")}, "action-log digest"),
        ({"semantic_signature": digest("e")}, "deterministic signature"),
        ({"trace_hash": digest("f")}, "trace hash"),
        ({"oracle_results_hash": digest("0")}, "Oracle result hash"),
        ({"evidence_ids": ("evidence.unrelated",)}, "cover Oracle evidence"),
    ],
)
def test_reality_receipt_rejects_mismatched_attempts(
    attempt_changes: dict[str, object], message: str
) -> None:
    primary_oracles = (oracle(),)
    attempts = (attempt(1, primary_oracles), attempt(2, primary_oracles, **attempt_changes))
    with pytest.raises(ValidationError, match=message):
        receipt(attempts=attempts)


def test_reality_receipt_requires_multiple_unique_attempts() -> None:
    primary_oracles = (oracle(),)
    one = attempt(1, primary_oracles)
    with pytest.raises(ValidationError, match="at least 2 items"):
        receipt(attempts=(one,))
    with pytest.raises(ValidationError, match="run IDs must be unique"):
        receipt(attempts=(one, one))


def test_reality_receipt_requires_run_specific_result_artifacts() -> None:
    primary_oracles = (oracle(),)
    first = attempt(1, primary_oracles)
    second = attempt(2, primary_oracles, replay_result_sha256=first.replay_result_sha256)

    with pytest.raises(ValidationError, match="replay-result digests must be globally unique"):
        receipt(attempts=(first, second))


@pytest.mark.parametrize(
    "collision", ["primary-control", "control-control", "primary-patch", "control-patch"]
)
def test_reality_receipt_requires_globally_unique_run_ids(collision: str) -> None:
    primary_oracles = (oracle(),)
    attempts = (attempt(1, primary_oracles), attempt(2, primary_oracles))
    controls: tuple[NegativeControl, ...] = (negative_control(),)
    patched: PatchedVersionReplay | None = None
    if collision == "primary-control":
        controls = (negative_control(replay_run_id="run.reality.1"),)
    elif collision == "control-control":
        controls = (
            negative_control(),
            negative_control(
                name="same-tenant",
                kind=NegativeControlKind.SAME_TENANT,
                replay_run_id="run.control.fresh-session",
                replay_result_sha256=digest("4"),
            ),
        )
    elif collision == "primary-patch":
        patched = patched_replay(replay_run_id="run.reality.2")
    else:
        patched = patched_replay(replay_run_id="run.control.fresh-session")

    with pytest.raises(ValidationError, match="run IDs must be globally unique"):
        receipt(attempts=attempts, negative_controls=controls, patched_version=patched)


@pytest.mark.parametrize(
    "collision",
    ["primary-control", "control-control", "primary-patch", "control-patch"],
)
def test_reality_receipt_requires_globally_unique_result_artifacts(collision: str) -> None:
    primary_oracles = (oracle(),)
    attempts = (attempt(1, primary_oracles), attempt(2, primary_oracles))
    controls: tuple[NegativeControl, ...] = (negative_control(),)
    patched: PatchedVersionReplay | None = None
    if collision == "primary-control":
        controls = (negative_control(replay_result_sha256=digest("1")),)
    elif collision == "control-control":
        controls = (
            negative_control(),
            negative_control(
                name="same-tenant",
                kind=NegativeControlKind.SAME_TENANT,
                replay_result_sha256=digest("0"),
            ),
        )
    elif collision == "primary-patch":
        patched = patched_replay(replay_result_sha256=digest("2"))
    else:
        patched = patched_replay(replay_result_sha256=digest("0"))

    with pytest.raises(ValidationError, match="replay-result digests must be globally unique"):
        receipt(attempts=attempts, negative_controls=controls, patched_version=patched)


@pytest.mark.parametrize(
    ("oracle_changes", "message"),
    [
        ({"outcome": OracleOutcome.SATISFIED}, "VIOLATED"),
        ({"deterministic": False}, "deterministic"),
        ({"provenance": ProvenanceKind.INFERRED}, "OBSERVED"),
    ],
)
def test_reality_receipt_rejects_non_reality_oracles(
    oracle_changes: dict[str, Any], message: str
) -> None:
    primary_oracles = (oracle(**oracle_changes),)
    attempts = (attempt(1, primary_oracles), attempt(2, primary_oracles))
    with pytest.raises(ValidationError, match=message):
        receipt(oracle_results=primary_oracles, attempts=attempts)


@pytest.mark.parametrize(
    ("control_changes", "message"),
    [
        ({"result": ReplayOutcome.REPRODUCED}, "must not reproduce"),
        ({"target_id": "target.other"}, "target"),
        ({"target_version": "lab-other"}, "target"),
        ({"target_lock_sha256": digest("d")}, "locks"),
        ({"adapter_lock_sha256": digest("d")}, "locks"),
        ({"root_seed_id": "root.other"}, "root"),
        ({"root_fingerprint": digest("d")}, "root"),
        ({"plan_id": "plan.reality.primary"}, "distinct control plan"),
        ({"plan_hash": digest("6")}, "distinct control plan"),
        ({"semantic_signature": digest("3")}, "primary replay signature"),
        ({"invariant": "actor.role == resource.required_role"}, "Oracle definition"),
    ],
)
def test_negative_controls_are_bound_to_primary_replay(
    control_changes: dict[str, Any], message: str
) -> None:
    invariant = str(control_changes.pop("invariant", "actor.tenant == resource.tenant"))
    with pytest.raises(ValidationError, match=message):
        control = negative_control(invariant=invariant, **control_changes)
        receipt(negative_controls=(control,))


def test_negative_control_requires_observed_satisfied_oracle_and_evidence() -> None:
    violated = (oracle(result_id="oracle.control.bad"),)
    with pytest.raises(ValidationError, match="SATISFIED"):
        negative_control(
            oracle_results=violated,
            oracle_results_hash=sha256_digest(violated),
            evidence_ids=("evidence.reality.primary",),
        )

    with pytest.raises(ValidationError, match="cover Oracle evidence"):
        negative_control(evidence_ids=("evidence.unrelated",))


def test_patch_verified_requires_same_plan_blocked_patch_receipt() -> None:
    with pytest.raises(ValidationError, match="patched-version receipt"):
        finding(status=FindingStatus.PATCH_VERIFIED, reality_replay=receipt())

    patched = patched_replay()
    proof = receipt(patched=patched)
    assert proof.patched_version == patched
    assert patched.schema_version == "2.0"

    with pytest.raises(ValidationError, match="broker-verified artifact attestation"):
        finding(status=FindingStatus.PATCH_VERIFIED, reality_replay=proof)

    with pytest.raises(ValidationError, match="under-report"):
        finding(status=FindingStatus.REALITY_REPLAYED, reality_replay=proof)


@pytest.mark.parametrize(
    ("patch_changes", "message"),
    [
        ({"target_id": "target.other"}, "target"),
        ({"target_version": "lab-vulnerable"}, "different target version"),
        ({"target_lock_sha256": digest("a")}, "different target lock"),
        ({"adapter_lock_sha256": digest("d")}, "adapter lock"),
        ({"plan_id": "plan.other"}, "same plan"),
        ({"plan_hash": digest("d")}, "same plan"),
        ({"root_seed_id": "root.other"}, "root"),
        ({"root_fingerprint": digest("d")}, "root"),
        ({"semantic_signature": digest("3")}, "vulnerable replay signature"),
    ],
)
def test_patch_receipt_cannot_be_substituted(
    patch_changes: dict[str, object], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        receipt(patched=patched_replay(**patch_changes))


def test_patched_replay_requires_observed_satisfied_block() -> None:
    with pytest.raises(ValidationError, match="BLOCKED_BY_FIX"):
        patched_replay(replay_result=ReplayOutcome.NOT_REPRODUCED)

    violated = (oracle(result_id="oracle.patch.bad"),)
    with pytest.raises(ValidationError, match="SATISFIED"):
        patched_replay(
            oracle_results=violated,
            oracle_results_hash=sha256_digest(violated),
            evidence_ids=("evidence.reality.primary",),
        )


@pytest.mark.parametrize(
    ("finding_changes", "message"),
    [
        ({"chain_id": "chain.other"}, "chain"),
        ({"oracle_result_ids": ("oracle.other",)}, "Oracle result IDs"),
    ],
)
def test_finding_rejects_receipt_substitution(
    finding_changes: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        finding(reality_replay=receipt(), **finding_changes)


@pytest.mark.parametrize(
    "oracle_result_ids",
    [(), ("oracle.reality.primary", "oracle.other")],
)
def test_finding_requires_the_exact_receipt_oracle_set(
    oracle_result_ids: tuple[str, ...],
) -> None:
    with pytest.raises(ValidationError, match="Oracle result IDs"):
        finding(reality_replay=receipt(), oracle_result_ids=oracle_result_ids)


def test_receipt_canonicalizes_oracles_and_controls_and_finding_uses_exact_set() -> None:
    primary_oracles = (
        oracle(result_id="oracle.reality.a", evidence_id="evidence.reality.a"),
        oracle(
            result_id="oracle.reality.b",
            invariant="actor.role == resource.required_role",
            evidence_id="evidence.reality.b",
        ),
    )
    primary_evidence = ("evidence.reality.a", "evidence.reality.b")
    attempts = (
        attempt(1, primary_oracles, evidence_ids=primary_evidence),
        attempt(2, primary_oracles, evidence_ids=primary_evidence),
    )

    def control(name: str, kind: NegativeControlKind) -> NegativeControl:
        results = (
            oracle(
                outcome=OracleOutcome.SATISFIED,
                result_id=f"oracle.control.{name}.a",
                evidence_id=f"evidence.control.{name}.a",
            ),
            oracle(
                outcome=OracleOutcome.SATISFIED,
                result_id=f"oracle.control.{name}.b",
                invariant="actor.role == resource.required_role",
                evidence_id=f"evidence.control.{name}.b",
            ),
        )
        return negative_control(
            name=name,
            kind=kind,
            replay_run_id=f"run.control.{name}",
            replay_result_sha256=(
                digest("4") if kind is NegativeControlKind.FRESH_SESSION else digest("5")
            ),
            plan_id=f"plan.control.{name}",
            oracle_results=results,
            oracle_results_hash=sha256_digest(results),
            evidence_ids=(
                f"evidence.control.{name}.a",
                f"evidence.control.{name}.b",
            ),
        )

    controls = (
        control("fresh-session", NegativeControlKind.FRESH_SESSION),
        control("same-tenant", NegativeControlKind.SAME_TENANT),
    )
    canonical = receipt(
        attempts=attempts,
        oracle_results=primary_oracles,
        negative_controls=controls,
    )
    permuted = receipt(
        attempts=attempts,
        oracle_results=tuple(reversed(primary_oracles)),
        negative_controls=tuple(reversed(controls)),
    )
    assert permuted == canonical

    with pytest.raises(ValidationError, match="Oracle result IDs"):
        finding(reality_replay=canonical, oracle_result_ids=("oracle.reality.a",))
    with pytest.raises(ValidationError, match="broker-verified artifact attestation"):
        finding(
            reality_replay=canonical,
            oracle_result_ids=("oracle.reality.b", "oracle.reality.a"),
        )


def test_receipt_rejects_duplicate_oracle_definitions() -> None:
    primary = oracle()
    duplicate_definition = oracle(
        result_id="oracle.reality.duplicate",
        evidence_id="evidence.reality.duplicate",
    )
    oracle_results = (primary, duplicate_definition)
    evidence_ids = ("evidence.reality.primary", "evidence.reality.duplicate")
    attempts = (
        attempt(1, oracle_results, evidence_ids=evidence_ids),
        attempt(2, oracle_results, evidence_ids=evidence_ids),
    )
    with pytest.raises(ValidationError, match="Oracle definitions must be unique"):
        receipt(oracle_results=oracle_results, attempts=attempts)


def test_receipt_rejects_rehashed_or_renamed_content() -> None:
    proof = receipt()
    payload = proof.model_dump(mode="python")
    payload["pre_receipt_evidence_manifest_sha256"] = digest("d")
    with pytest.raises(ValidationError, match="receipt hash"):
        RealityReplayReceipt.model_validate(payload)

    payload = proof.model_dump(mode="python")
    payload["receipt_hash"] = digest("0")
    with pytest.raises(ValidationError, match="receipt hash"):
        RealityReplayReceipt.model_validate(payload)


def test_finding_revalidates_a_constructed_receipt_at_the_promotion_boundary() -> None:
    proof = receipt()
    payload = raw_model_values(proof)
    payload["attempts"] = payload["attempts"][:1]
    forged = RealityReplayReceipt.model_construct(**payload)

    with pytest.raises(ValidationError, match="at least 2 items"):
        finding(reality_replay=forged)


@pytest.mark.parametrize(
    ("field", "message"),
    [
        ("oracle_results", "at least 1 item"),
        ("negative_controls", "at least 1 item"),
    ],
)
def test_finding_rejects_constructed_receipt_with_vacuous_vectors(field: str, message: str) -> None:
    proof = receipt()
    payload = raw_model_values(proof)
    payload[field] = ()
    forged = RealityReplayReceipt.model_construct(**payload)
    with pytest.raises(ValidationError, match=message):
        finding(reality_replay=forged)


def test_finding_rejects_constructed_nested_proof_models() -> None:
    proof = receipt()

    oracle_payload = raw_model_values(proof.oracle_results[0])
    oracle_payload["provenance"] = ProvenanceKind.MOCKED
    forged_oracle = OracleResult.model_construct(**oracle_payload)
    receipt_payload = raw_model_values(proof)
    receipt_payload["oracle_results"] = (forged_oracle,)
    forged_receipt = RealityReplayReceipt.model_construct(**receipt_payload)
    with pytest.raises(ValidationError, match="mocked oracle results"):
        finding(reality_replay=forged_receipt)

    control_payload = raw_model_values(proof.negative_controls[0])
    control_payload["result"] = ReplayOutcome.REPRODUCED
    forged_control = NegativeControl.model_construct(**control_payload)
    receipt_payload = raw_model_values(proof)
    receipt_payload["negative_controls"] = (forged_control,)
    forged_receipt = RealityReplayReceipt.model_construct(**receipt_payload)
    with pytest.raises(ValidationError, match="must not reproduce"):
        finding(reality_replay=forged_receipt)

    patched_proof = receipt(patched=patched_replay())
    assert patched_proof.patched_version is not None
    patch_payload = raw_model_values(patched_proof.patched_version)
    patch_payload["replay_result"] = ReplayOutcome.REPRODUCED
    forged_patch = PatchedVersionReplay.model_construct(**patch_payload)
    receipt_payload = raw_model_values(patched_proof)
    receipt_payload["patched_version"] = forged_patch
    forged_receipt = RealityReplayReceipt.model_construct(**receipt_payload)
    with pytest.raises(ValidationError, match="BLOCKED_BY_FIX"):
        finding(status=FindingStatus.PATCH_VERIFIED, reality_replay=forged_receipt)

    payload = proof.model_dump(mode="python")
    payload["receipt_id"] = "receipt.reality:000000000000000000000000"
    with pytest.raises(ValidationError, match="receipt ID"):
        RealityReplayReceipt.model_validate(payload)


def test_synthetic_status_cannot_cross_the_reality_boundary() -> None:
    synthetic = finding(status=FindingStatus.SYNTHETIC_REPRODUCED)
    assert synthetic.schema_version == "2.0"
    assert synthetic.reality_replay is None

    with pytest.raises(ValidationError, match="only confirmed findings"):
        finding(status=FindingStatus.SYNTHETIC_REPRODUCED, reality_replay=receipt())

    with pytest.raises(ValidationError, match="FindingStatus"):
        Finding.model_validate(
            {
                "finding_id": "finding.legacy-status",
                "title": "legacy verified is no longer a confirmation state",
                "status": "VERIFIED",
                "chain_id": "chain.reality.primary",
                "oracle_result_ids": ("oracle.reality.primary",),
                "fidelity": fidelity(),
            }
        )


@pytest.mark.parametrize(
    "status",
    [FindingStatus.CANDIDATE, FindingStatus.CHAIN_COMPILED, FindingStatus.REJECTED],
)
def test_nonconfirmed_statuses_reject_reality_receipts(status: FindingStatus) -> None:
    with pytest.raises(ValidationError, match="only confirmed findings"):
        finding(status=status, reality_replay=receipt())


def test_raw_receipt_handle_and_unvalidated_model_copy_cannot_promote() -> None:
    payload = {
        "finding_id": "finding.raw-receipt",
        "title": "raw receipt handles cannot promote a finding",
        "status": "REALITY_REPLAYED",
        "chain_id": "chain.reality.primary",
        "oracle_result_ids": ("oracle.reality.primary",),
        "fidelity": fidelity(),
        "reality_replay": "run.forged",
    }
    with pytest.raises(ValidationError, match=r"valid dictionary|RealityReplayReceipt"):
        Finding.model_validate(payload)

    synthetic = finding(status=FindingStatus.SYNTHETIC_REPRODUCED)
    forged = synthetic.model_copy(update={"status": FindingStatus.REALITY_REPLAYED})
    with pytest.raises(ValidationError, match="typed reality replay receipt"):
        Finding.model_validate(forged)
    with pytest.raises(ValidationError, match="typed reality replay receipt"):
        Finding.model_validate(forged.model_dump(mode="python"))
