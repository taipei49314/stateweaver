"""Adversarial tests for machine-derived acceptance row results."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from stateweaver.evidence import (
    AcceptanceRegistryClosure,
    AcceptanceRequirementResult,
    AcceptanceResults,
    AcceptanceResultsError,
    AcceptanceResultStatus,
    GateClass,
    build_acceptance_registry_closure,
    derive_acceptance_results,
    load_acceptance_registry,
)


def _by_id(results: AcceptanceResults, requirement_id: str) -> AcceptanceRequirementResult:
    return next(row for row in results.requirements if row.requirement_id == requirement_id)


def test_local_result_requires_the_exact_selector_module_and_evidence_path() -> None:
    registry = load_acceptance_registry()
    selector_name = "test_scope_is_canonical_and_valid_at_inclusive_boundaries"

    observed = derive_acceptance_results(
        registry,
        passing_test_identities=(f"tests.test_contracts::{selector_name}",),
        observed_evidence_paths=("junit/contracts.xml",),
    )
    substituted = derive_acceptance_results(
        registry,
        passing_test_identities=(f"tests.test_unrelated::{selector_name}",),
        observed_evidence_paths=("junit/contracts.xml",),
    )

    assert _by_id(observed, "M0-C01").status == "PASS"
    assert _by_id(substituted, "M0-C01").status == "NOT_RUN"


def test_nonlocal_gate_stays_blocked_even_when_declared_inputs_are_present() -> None:
    results = derive_acceptance_results(
        load_acceptance_registry(),
        passing_test_identities=(
            "tests.integration.worlds.test_live_docker_compose::"
            "test_four_live_siblings_overlap_isolate_and_restore",
        ),
        observed_evidence_paths=("qualification/m2/four-way-receipt.json",),
    )
    row = _by_id(results, "SW-M2-4WAY")

    assert row.tests_missing == ()
    assert row.evidence_missing == ()
    assert row.status == "BLOCKED"
    assert row.qualification_admission_digest is None


def test_nonlocal_gate_pass_requires_complete_inputs_and_verified_admission() -> None:
    digest = "sha256:" + "d" * 64
    selector = (
        "tests.integration.observation.test_runtime_observation::"
        "test_controller_issues_trace_and_derives_state_delta_from_authorized_lab_action"
    )
    results = derive_acceptance_results(
        load_acceptance_registry(),
        passing_test_identities=(selector,),
        observed_evidence_paths=("qualification/m3/runtime-observation-receipt.json",),
        verified_admission_digests={"M3-T03": digest},
    )
    row = _by_id(results, "M3-T03")

    assert row.status == "PASS"
    assert row.qualification_admission_digest == digest

    with pytest.raises(AcceptanceResultsError, match="complete proof inputs"):
        derive_acceptance_results(
            load_acceptance_registry(),
            passing_test_identities=(),
            observed_evidence_paths=(),
            verified_admission_digests={"M3-T03": digest},
        )
    with pytest.raises(AcceptanceResultsError, match="admissions are invalid"):
        derive_acceptance_results(
            load_acceptance_registry(),
            passing_test_identities=(),
            observed_evidence_paths=(),
            verified_admission_digests={"M0-C01": digest},
        )


def test_closure_rejects_selector_count_tampering() -> None:
    closure = build_acceptance_registry_closure(load_acceptance_registry())
    payload = closure.model_dump(mode="python")
    payload["selector_count"] += 1

    with pytest.raises(ValidationError):
        AcceptanceRegistryClosure.model_validate(payload, strict=True)


def test_result_set_rejects_gate_class_substitution() -> None:
    results = derive_acceptance_results(
        load_acceptance_registry(),
        passing_test_identities=(),
        observed_evidence_paths=(),
    )
    payload = results.model_dump(mode="python")
    target = next(row for row in payload["requirements"] if row["requirement_id"] == "SW-M6-TRUST")
    target["gate_class"] = GateClass.LOCAL_OFFLINE
    target["status"] = AcceptanceResultStatus.NOT_RUN
    payload["summary"]["blocked"] -= 1
    payload["summary"]["not_run"] += 1

    with pytest.raises(ValidationError):
        AcceptanceResults.model_validate(payload, strict=True)


def test_duplicate_observed_inputs_fail_closed() -> None:
    registry = load_acceptance_registry()
    with pytest.raises(AcceptanceResultsError, match="unique"):
        derive_acceptance_results(
            registry,
            passing_test_identities=("tests.test_contracts::test_one",) * 2,
            observed_evidence_paths=(),
        )
    with pytest.raises(AcceptanceResultsError, match="unique"):
        derive_acceptance_results(
            registry,
            passing_test_identities=(),
            observed_evidence_paths=("junit/contracts.xml",) * 2,
        )


@pytest.mark.parametrize(
    "unsafe_path",
    ("../outside.json", "/absolute.json", "C:/absolute.json", "mixed\\path.json"),
)
def test_observed_evidence_paths_reject_noncanonical_spellings(
    unsafe_path: str,
) -> None:
    with pytest.raises(AcceptanceResultsError, match="invalid"):
        derive_acceptance_results(
            load_acceptance_registry(),
            passing_test_identities=(),
            observed_evidence_paths=(unsafe_path,),
        )
