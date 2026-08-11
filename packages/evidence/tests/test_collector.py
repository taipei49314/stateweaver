"""Acceptance tests for the offline, causally-bound evidence bundle."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any, cast
from xml.etree import ElementTree

import pytest
from evidence_test_fixtures import EPOCH
from evidence_test_fixtures import foundation as fixture_foundation
from stateweaver.cli.runtime_qualification import qualify_runtime_observation
from stateweaver.contracts import ScopeManifest
from stateweaver.evidence import (
    ACCEPTANCE_TEST_COMMAND,
    EXPECTED_ACCEPTANCE_REGISTRY_SHA256,
    EXPECTED_REQUIREMENT_IDS,
    AcceptanceEvidenceError,
    CollectionInput,
    ExpectedProvenance,
    collect_acceptance_evidence,
    collect_from_json_file,
    verify_acceptance_evidence,
)
from stateweaver.evidence._io import (
    EvidenceInputError,
    canonical_json_bytes,
    semantic_sha256,
    sha256_bytes,
)
from stateweaver.policy import BudgetSnapshot, PolicyRequest, evaluate_policy
from stateweaver.replay import ReplayPlan, ReplayRunResult, canonical_sha256

JUNIT_NAMES = ("contracts", "policy", "lab", "replay")
M6_NEGATIVE_CONTROL_IDENTITIES = tuple(
    "tests.test_reality_receipts::"
    f"test_negative_controls_are_bound_to_primary_replay[control_changes{index}-{label}]"
    for index, label in enumerate(
        (
            "must not reproduce",
            "target",
            "target",
            "locks",
            "locks",
            "root",
            "root",
            "distinct control plan",
            "distinct control plan",
            "primary replay signature",
            "Oracle definition",
        )
    )
)
LOCAL_REPLAY_IDENTITIES = (
    "tests.integration.twin.test_local_synthetic_flow::"
    "test_testclient_source_and_trace_evidence_build_one_observed_transition",
    "adapters.source.fastapi_sqlalchemy.tests.test_extractor::"
    "test_extracts_actual_sqlalchemy_table_metadata_without_engine_or_connection",
    "adapters.source.fastapi_sqlalchemy.tests.test_extractor::"
    "test_extracts_real_fastapi_route_and_narrow_openapi_without_requesting_it",
    "tests.integration.observation.test_runtime_observation::"
    "test_controller_issues_trace_and_derives_state_delta_from_authorized_lab_action",
    "packages.twin.tests.test_twin::"
    "test_builds_canonical_evidence_bound_twin_and_observed_transition",
    "apps.cli.tests.test_runtime_qualification::"
    "test_runtime_qualification_reexecutes_with_stable_semantics",
    "apps.cli.tests.test_runtime_qualification::test_adapter_receipt_substitution_fails_closed",
    "packages.search.tests.test_search::"
    "test_strict_models_reject_unknown_fields_bool_integers_and_duplicate_candidates",
    "packages.search.tests.test_search::test_materialized_source_tier_is_not_promotable",
    "packages.search.tests.test_search::test_twenty_four_ghosts_promote_only_the_bounded_beam",
    "packages.search.tests.test_search::test_budget_ledger_is_immutable_and_append_only",
    "packages.search.tests.test_search::"
    "test_model_score_cannot_override_materialization_evidence_gates",
    "apps.cli.tests.test_materialized_search_qualification::"
    "test_ghost_batch_is_derived_from_the_exact_m3_observation",
    "apps.cli.tests.test_materialized_search_qualification::"
    "test_ghost_scores_change_with_the_admitted_m3_semantic_receipt",
    "apps.cli.tests.test_materialized_search_qualification::"
    "test_non_sha_repository_marker_is_rejected_before_docker_execution",
    "apps.cli.tests.test_materialized_search_qualification::"
    "test_complete_receipt_conserves_budget_and_never_materializes_the_ghost_set",
    "apps.cli.tests.test_materialized_search_qualification::"
    "test_rehashed_stage_substitution_is_rejected",
    "packages.compiler.tests.test_compiler::"
    "test_compiles_three_fragment_minimal_chain_and_replay_plan",
    "tests.integration.compiler.test_clean_room_chain::"
    "test_fresh_authorizations_retain_exact_policy_request_decision_and_fragment_bindings",
    "tests.integration.compiler.test_clean_room_chain::"
    "test_compiler_minimizer_cannot_remove_any_required_fragment",
    "packages.evidence.tests.test_reality_bundle::"
    "test_valid_synthetic_bundle_is_a_non_promotable_candidate",
    "benchmarks.statechainbench.tests.test_generator::"
    "test_generation_is_seeded_canonical_and_changes_across_seeds",
    "benchmarks.statechainbench.tests.test_oracle_budget::"
    "test_hidden_oracle_surface_and_solver_boundary_do_not_expose_answers",
    "benchmarks.statechainbench.tests.test_runner::"
    "test_holdout_comparison_uses_raw_matched_results_and_shows_tiered_gain",
    "benchmarks.statechainbench.tests.test_runner::"
    "test_equal_budget_result_is_reproducible_byte_for_byte",
    "benchmarks.statechainbench.tests.test_runner::"
    "test_ablation_labels_cannot_reuse_one_report_and_reports_close_provenance",
)
JUNIT_REQUIRED_IDENTITIES = {
    "contracts": (
        "tests.test_canonical::test_canonical_fingerprint_is_input_order_independent",
        "tests.test_canonical::test_security_fingerprint_uses_explicit_semantic_projection",
        "tests.test_canonical::test_fingerprint_property_is_permutation_invariant",
        "tests.test_canonical::test_fingerprint_property_detects_security_semantic_change",
        "tests.test_contracts::test_closed_schema_rejects_unknown_fields",
        "tests.test_contracts::test_six_m0_contract_families_are_exported_from_the_public_surface",
        *M6_NEGATIVE_CONTROL_IDENTITIES,
        "tests.test_reality_receipts::test_patch_verified_requires_same_plan_blocked_patch_receipt",
        "tests.test_reality_receipts::test_confirmed_finding_requires_typed_reality_receipt",
    ),
    "policy": (
        "tests.test_evaluator::test_localhost_target_is_allowed",
        "tests.test_evaluator::test_missing_context_and_malformed_objects_fail_closed",
    ),
    "lab": (
        "tests.test_lab::test_complete_chain_violates_oracle_only_in_vulnerable_mode",
        "tests.test_lab::test_same_chain_is_blocked_by_patched_mode",
        "tests.test_lab::test_clean_seed_and_reset_are_deterministic",
        "tests.test_lab::test_vulnerable_and_patched_apps_have_no_process_global_mode_state",
        "tests.test_lab::test_evidence_and_layered_capture_never_record_bearer_values",
        "tests.test_lab::test_invalid_mode_is_rejected",
    ),
    "replay": (
        "packages.replay.tests.test_kernel::test_replay_is_deterministic_across_five_clean_roots",
        "packages.replay.tests.test_kernel::test_observation_drift_is_classified_as_nondeterministic",
        "packages.replay.tests.test_kernel::test_cleanup_failure_is_visible_and_redacted",
        "packages.replay.tests.test_kernel::test_boundary_failures_are_localized_cleanup_is_reentrant_and_reset_recovers[reset-RESET_FAILURE]",
        "packages.replay.tests.test_kernel::test_boundary_failures_are_localized_cleanup_is_reentrant_and_reset_recovers[capture_before-CAPTURE_BEFORE_FAILURE]",
        "packages.replay.tests.test_kernel::test_boundary_failures_are_localized_cleanup_is_reentrant_and_reset_recovers[execute-EXECUTE_FAILURE]",
        "packages.replay.tests.test_kernel::test_boundary_failures_are_localized_cleanup_is_reentrant_and_reset_recovers[capture_after-CAPTURE_AFTER_FAILURE]",
        "packages.replay.tests.test_kernel::test_reset_is_bounded_and_cleanup_still_runs",
        "adapters.environments.in_process_lab.tests.test_in_process_lab_environment::test_full_vulnerable_plan_is_deterministic_over_five_runs",
        "adapters.environments.in_process_lab.tests.test_in_process_lab_environment::test_root_creation_reset_and_capture_contain_all_seven_redacted_layers",
        "apps.cli.tests.test_foundation::test_foundation_verification_meets_all_acceptance_conditions",
        "packages.evidence.tests.test_collector::test_collects_exact_complete_and_verifiable_tree",
        "packages.evidence.tests.test_acceptance_registry::test_packaged_registry_is_canonical_and_has_exact_required_ids",
        *LOCAL_REPLAY_IDENTITIES,
    ),
}


def foundation() -> dict[str, object]:
    """Use the seven-layer root required by local qualification receipt tests."""

    return fixture_foundation(layered_root=True)


def _junit_sources(
    tmp_path: Path,
    *,
    tests: int | None = None,
    failures: int = 0,
    errors: int = 0,
    skipped: int = 0,
) -> dict[str, Path]:
    sources: dict[str, Path] = {}
    for name in JUNIT_NAMES:
        identities = JUNIT_REQUIRED_IDENTITIES[name] if tests is None or tests else ()
        if tests == 1:
            identities = identities[:1]
        outcome = ""
        if failures:
            outcome = "<failure />"
        elif errors:
            outcome = "<error />"
        elif skipped:
            outcome = "<skipped />"
        testcases = "".join(
            f'<testcase classname="{identity.split("::", 1)[0]}" '
            f'name="{identity.split("::", 1)[1]}">{outcome}</testcase>'
            for identity in identities
        )
        count = len(identities) if tests is None else tests
        path = tmp_path / f"{name}.xml"
        path.write_text(
            (
                f'<testsuite name="{name}" tests="{count}" failures="{failures}" '
                f'errors="{errors}" skipped="{skipped}">{testcases}</testsuite>'
            ),
            encoding="utf-8",
        )
        sources[name] = path
    return sources


def _append_junit_identity(path: Path, identity: str) -> None:
    tree = ElementTree.parse(path)
    root = tree.getroot()
    root.set("tests", str(int(root.attrib["tests"]) + 1))
    classname, testcase_name = identity.split("::", 1)
    ElementTree.SubElement(root, "testcase", classname=classname, name=testcase_name)
    tree.write(path, encoding="utf-8", xml_declaration=False)


def _metadata(proof: dict[str, object]) -> dict[str, object]:
    policy = proof["policy_decisions"]
    assert isinstance(policy, dict)
    first_policy = next(iter(policy.values()))
    assert isinstance(first_policy, dict)
    root = proof["root_state"]
    assert isinstance(root, dict)
    return {
        "repository_marker": "synthetic-test-tree",
        "python_version": "3.12",
        "docker_compose_version": "not-used-in-process",
        "target_mode": "differential",
        "root_seed": root["root_seed_id"],
        "controlled_clock_epoch": EPOCH.isoformat().replace("+00:00", "Z"),
        "test_command": ACCEPTANCE_TEST_COMMAND,
        "test_exit_code": 0,
        "app_source_digest": "sha256:" + "a" * 64,
        "scope_manifest_hash": first_policy["scope_manifest_hash"],
        "replay_plan_hash": proof["plan_hash"],
        "oracle_definition_hash": "sha256:" + "b" * 64,
        "runtime_dependency_fingerprint": "sha256:" + "c" * 64,
        "network_mode": "offline-in-process",
        "network_guard": "python-socket-deny-v2",
        "model_calls": 0,
        "started_at": "2026-01-01T00:00:00Z",
        "completed_at": "2026-01-01T00:01:00Z",
    }


def _input(
    tmp_path: Path,
    *,
    proof: dict[str, object] | None = None,
    sources: dict[str, Path] | None = None,
    metadata: dict[str, object] | None = None,
    package_install_receipt: dict[str, object] | None = None,
    runtime_observation_receipt: dict[str, object] | None = None,
) -> CollectionInput:
    accepted_proof = foundation() if proof is None else proof
    return CollectionInput(
        foundation=accepted_proof,
        junit_sources=_junit_sources(tmp_path) if sources is None else sources,
        run_metadata=_metadata(accepted_proof) if metadata is None else metadata,
        package_install_receipt=package_install_receipt,
        runtime_observation_receipt=runtime_observation_receipt,
    )


def _collect(tmp_path: Path, run_id: str = "m0-m1.1") -> Path:
    return collect_acceptance_evidence(
        input=_input(tmp_path), output_root=tmp_path / "artifacts", run_id=run_id
    ).run_directory


def _package_install_receipt() -> dict[str, object]:
    return {
        "schema_version": "stateweaver-package-install-qualification-v1",
        "requirement_id": "M0-C07",
        "repository_marker": "synthetic-test-tree",
        "producer_command": "stateweaver foundation qualify-package-install",
        "python": {
            "implementation": "CPython",
            "version": "3.13.1",
            "virtual_environment": True,
        },
        "source_root_excluded": True,
        "installation": {
            "distribution": "stateweaver-contracts",
            "version": "0.1.0",
            "editable": False,
            "installed_from_wheel": True,
            "site_packages_relative_path": "lib/python3.13/site-packages",
            "module_relative_path": (
                "lib/python3.13/site-packages/stateweaver/contracts/__init__.py"
            ),
            "metadata_sha256": "sha256:" + "1" * 64,
            "wheel_sha256": "sha256:" + "2" * 64,
            "record_sha256": "sha256:" + "3" * 64,
        },
        "families": [
            {"family": "scope", "symbols": ["ScopeManifest"]},
            {"family": "action", "symbols": ["ActionEnvelope"]},
            {
                "family": "security-state-ir",
                "symbols": ["Entity", "Fact", "Relation"],
            },
            {"family": "transition", "symbols": ["TransitionFragment"]},
            {"family": "world", "symbols": ["WorldManifest"]},
            {"family": "oracle", "symbols": ["OracleResult"]},
        ],
        "public_all_sha256": "sha256:" + "4" * 64,
        "all_symbols_exported": True,
    }


def _expect_rejected(
    tmp_path: Path,
    mutate: Callable[[dict[str, object]], None],
    *,
    match: str | None = None,
) -> None:
    proof = foundation()
    mutate(proof)
    with pytest.raises(AcceptanceEvidenceError, match=match):
        collect_acceptance_evidence(
            input=_input(tmp_path, proof=proof), output_root=tmp_path / "artifacts", run_id="bad"
        )


def _rebuild_result(result: dict[str, Any]) -> ReplayRunResult:
    result["trace_hash"] = canonical_sha256(
        {
            "plan_id": result["plan_id"],
            "status": result["status"],
            "root_fingerprint": result["root_fingerprint"],
            "final_fingerprint": result["final_fingerprint"],
            "steps": result["steps"],
            "action_log": result["action_log"],
            "failed_step_id": result["failed_step_id"],
        }
    )
    return ReplayRunResult.model_validate_json(canonical_json_bytes(result))


def _replace_scenario_result(scenario: dict[str, Any], result: ReplayRunResult) -> None:
    final = result.steps[-1]
    scenario["replay_result"] = result.model_dump(mode="json")
    scenario["signature"] = result.deterministic_signature()
    scenario["action_log_hash"] = canonical_sha256(result.action_log)
    scenario["status"] = result.status.value
    scenario["failed_step_id"] = result.failed_step_id
    scenario["failure_code"] = final.failure_code
    scenario["terminal_observations"] = [
        item.model_dump(mode="json") for item in final.observations
    ]
    scenario["oracle_results"] = [item.model_dump(mode="json") for item in final.oracle_results]
    scenario["response_status"] = final.observations[-1].payload.get("response_status")
    scenario["oracle_outcome"] = final.oracle_results[-1].result.value


def _rewrite_manifest_digest(run: Path, relative: str) -> None:
    manifest = run / "artifact-manifest.sha256"
    digest = sha256_bytes((run / relative).read_bytes())
    entries = []
    for line in manifest.read_text(encoding="ascii").splitlines():
        _, entry = line.split("  ", 1)
        entries.append(f"{digest if entry == relative else line[:64]}  {entry}")
    manifest.write_text("\n".join(entries) + "\n", encoding="ascii")


def test_collects_exact_complete_and_verifiable_tree(tmp_path: Path) -> None:
    result = collect_acceptance_evidence(
        input=_input(tmp_path), output_root=tmp_path / "artifacts", run_id="m0-m1.1"
    )
    run = result.run_directory

    assert result.redacted_values == 0
    verification = verify_acceptance_evidence(run)
    assert verification.valid
    assert verification.snapshot_sha256 is not None
    assert {path.relative_to(run).as_posix() for path in run.rglob("*") if path.is_file()} == {
        "artifact-manifest.sha256",
        "foundation/source.json",
        "junit/contracts.xml",
        "junit/policy.xml",
        "junit/lab.xml",
        "junit/replay.xml",
        "oracle/vulnerable.json",
        "oracle/patched.json",
        "oracle/negative-controls.json",
        "policy/decisions.json",
        "replay/root-state.json",
        "replay/plan.json",
        "replay/attempts.json",
        "replay/failure-localization.json",
        "replay/action-log.json",
        "qualification/m0/property-seed.json",
        "qualification/m0/mode-isolation.json",
        "qualification/m0/configuration-snapshot.json",
        "qualification/m1/session-manifest.json",
        "qualification/m1/provider-digests.json",
        "qualification/m1/reset-diff.json",
        "qualification/m1/nondeterminism.json",
        "qualification/m1/cleanup-events.json",
        "qualification/m3/openapi-ingest.json",
        "qualification/m3/source-extractor.json",
        "qualification/m4/search-receipt.json",
        "qualification/m5/compiler-receipt.json",
        "qualification/m5/clean-room-replay.json",
        "qualification/m6/candidate-bundle.json",
        "qualification/m7/benchmark-receipt.json",
        "qualification/registry/closure.json",
        "qualification/registry/results.json",
        "run-manifest.json",
    }
    for name in JUNIT_NAMES:
        assert (run / "junit" / f"{name}.xml").read_text(encoding="utf-8").startswith("<testsuite")


def test_proof_derives_exact_fail_closed_registry_results(tmp_path: Path) -> None:
    run = _collect(tmp_path, "registry-results")
    closure = json.loads(
        (run / "qualification" / "registry" / "closure.json").read_text(encoding="utf-8")
    )
    results = json.loads(
        (run / "qualification" / "registry" / "results.json").read_text(encoding="utf-8")
    )
    manifest = json.loads((run / "run-manifest.json").read_text(encoding="utf-8"))
    by_id = {row["requirement_id"]: row for row in results["requirements"]}

    assert closure["registry_sha256"] == EXPECTED_ACCEPTANCE_REGISTRY_SHA256
    assert tuple(closure["requirement_ids"]) == EXPECTED_REQUIREMENT_IDS
    assert closure["requirement_count"] == 92
    assert tuple(row["requirement_id"] for row in results["requirements"]) == (
        EXPECTED_REQUIREMENT_IDS
    )
    assert results["summary"]["required"] == 92
    assert results["summary"] == {
        "blocked": 39,
        "failed": 0,
        "not_run": 15,
        "passed": 38,
        "required": 92,
    }
    assert (
        sum(results["summary"][name] for name in ("blocked", "failed", "not_run", "passed")) == 92
    )
    assert results["release_eligible"] is False
    assert by_id["SW-REGISTRY"]["status"] == "PASS"
    assert by_id["M0-L03"]["status"] == "PASS"
    for requirement_id in (
        "M0-C08",
        "M0-L02",
        "M0-L10",
        "M1-R02",
        "M1-R04",
        "M1-R05",
        "M1-R10",
        "M1-R11",
    ):
        assert by_id[requirement_id]["status"] == "PASS"
    assert by_id["M0-C07"]["status"] == "NOT_RUN"
    assert by_id["SW-M6-TRUST"]["status"] == "BLOCKED"
    assert by_id["SW-M6-TRUST"]["tests_observed"] == []
    assert by_id["SW-M6-TRUST"]["evidence_missing"] == [
        "qualification/m6/trust-policy-receipt.json"
    ]
    assert manifest["acceptance_registry"]["registry_sha256"] == (
        EXPECTED_ACCEPTANCE_REGISTRY_SHA256
    )
    assert manifest["acceptance_registry"]["summary"] == results["summary"]

    property_receipt = json.loads(
        (run / "qualification" / "m0" / "property-seed.json").read_text(encoding="utf-8")
    )
    assert property_receipt["seed"] == 982341
    assert property_receipt["examples_per_property"] == 150
    assert property_receipt["security_semantic_change_detected"] is True

    mode_receipt = json.loads(
        (run / "qualification" / "m0" / "mode-isolation.json").read_text(encoding="utf-8")
    )
    assert mode_receipt["vulnerable"]["mode"] == "vulnerable"
    assert mode_receipt["patched"]["mode"] == "patched"
    assert mode_receipt["shared_process_state"] is False

    session_receipt = json.loads(
        (run / "qualification" / "m1" / "session-manifest.json").read_text(encoding="utf-8")
    )
    assert session_receipt["session_count"] == 3
    assert session_receipt["raw_bearer_values_retained"] is False

    provider_receipt = json.loads(
        (run / "qualification" / "m1" / "provider-digests.json").read_text(encoding="utf-8")
    )
    assert set(provider_receipt["providers"]) == {"cache", "database", "queue"}
    assert provider_receipt["equivalent_across_clean_roots"] is True

    nondeterminism_receipt = json.loads(
        (run / "qualification" / "m1" / "nondeterminism.json").read_text(encoding="utf-8")
    )
    assert nondeterminism_receipt["classification"] == "NONDETERMINISTIC"
    assert nondeterminism_receipt["finding_promotion_allowed"] is False

    cleanup_receipt = json.loads(
        (run / "qualification" / "m1" / "cleanup-events.json").read_text(encoding="utf-8")
    )
    assert len(cleanup_receipt["injected_boundaries"]) == 4
    assert cleanup_receipt["next_reset_permitted"] is True

    expected_local_receipts = {
        "qualification/m3/openapi-ingest.json": ["M3-T01"],
        "qualification/m3/source-extractor.json": ["M3-T02"],
        "qualification/m4/search-receipt.json": [
            "M4-S01",
            "M4-S02",
            "M4-S03",
            "M4-S04",
            "M4-S05",
        ],
        "qualification/m5/compiler-receipt.json": [
            "M5-C01",
            "M5-C02",
            "M5-C03",
            "M5-C05",
        ],
        "qualification/m5/clean-room-replay.json": ["M5-C04"],
        "qualification/m6/candidate-bundle.json": [
            "M6-R02",
            "M6-R03",
            "M6-R04",
            "M6-R05",
        ],
        "qualification/m7/benchmark-receipt.json": [
            "M7-B01",
            "M7-B02",
            "M7-B03",
            "M7-B04",
            "M7-B05",
            "M7-B06",
        ],
    }
    for relative, requirement_ids in expected_local_receipts.items():
        receipt = json.loads((run / relative).read_text(encoding="utf-8"))
        assert receipt["requirement_ids"] == requirement_ids
        assert receipt["status"] == "LOCAL_IMPLEMENTATION_QUALIFIED"
        assert receipt["authoritative"] is False
        assert receipt["promotable"] is False
        assert receipt["release_eligible"] is False
        assert receipt["exit_criterion_satisfied"] is False
        assert receipt["receipt_digest"] == canonical_sha256(
            {key: value for key, value in receipt.items() if key != "receipt_digest"}
        )
        assert all(by_id[requirement_id]["status"] == "PASS" for requirement_id in requirement_ids)


def test_verifier_rejects_rehashed_registry_result_promotion(tmp_path: Path) -> None:
    run = _collect(tmp_path, "registry-promotion")
    results_path = run / "qualification" / "registry" / "results.json"
    results = json.loads(results_path.read_text(encoding="utf-8"))
    target = next(row for row in results["requirements"] if row["requirement_id"] == "SW-M6-TRUST")
    target["status"] = "PASS"
    results["summary"]["blocked"] -= 1
    results["summary"]["passed"] += 1
    results_path.write_bytes(canonical_json_bytes(results))
    _rewrite_manifest_digest(run, "qualification/registry/results.json")

    run_manifest_path = run / "run-manifest.json"
    run_manifest = json.loads(run_manifest_path.read_text(encoding="utf-8"))
    run_manifest["acceptance_registry"]["results_sha256"] = sha256_bytes(results_path.read_bytes())
    run_manifest["acceptance_registry"]["summary"] = results["summary"]
    run_manifest_path.write_bytes(canonical_json_bytes(run_manifest))
    _rewrite_manifest_digest(run, "run-manifest.json")

    verification = verify_acceptance_evidence(run)
    assert not verification.valid
    assert verification.snapshot_sha256 is None
    assert any("coherent" in error for error in verification.errors)


def test_verifier_rejects_rehashed_qualification_receipt_tampering(tmp_path: Path) -> None:
    run = _collect(tmp_path, "qualification-tampering")
    receipt_path = run / "qualification" / "m1" / "nondeterminism.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["classification"] = "DETERMINISTIC"
    receipt["finding_promotion_allowed"] = True
    receipt_path.write_bytes(canonical_json_bytes(receipt))
    _rewrite_manifest_digest(run, "qualification/m1/nondeterminism.json")

    verification = verify_acceptance_evidence(run)

    assert not verification.valid
    assert verification.snapshot_sha256 is None
    assert "artifact bundle is not causally coherent" in verification.errors


def test_verifier_rejects_rehashed_local_deliverable_receipt_tampering(tmp_path: Path) -> None:
    run = _collect(tmp_path, "local-qualification-tampering")
    receipt_path = run / "qualification" / "m7" / "benchmark-receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["authoritative"] = True
    receipt["promotable"] = True
    receipt["exit_criterion_satisfied"] = True
    receipt["receipt_digest"] = canonical_sha256(
        {key: value for key, value in receipt.items() if key != "receipt_digest"}
    )
    receipt_path.write_bytes(canonical_json_bytes(receipt))
    _rewrite_manifest_digest(run, "qualification/m7/benchmark-receipt.json")

    verification = verify_acceptance_evidence(run)

    assert not verification.valid
    assert verification.snapshot_sha256 is None
    assert "artifact bundle is not causally coherent" in verification.errors


def test_clean_wheel_receipt_promotes_only_m0_c07(tmp_path: Path) -> None:
    result = collect_acceptance_evidence(
        input=_input(tmp_path, package_install_receipt=_package_install_receipt()),
        output_root=tmp_path / "artifacts",
        run_id="package-install",
    )
    run = result.run_directory
    results = json.loads(
        (run / "qualification" / "registry" / "results.json").read_text(encoding="utf-8")
    )
    by_id = {row["requirement_id"]: row for row in results["requirements"]}

    assert verify_acceptance_evidence(run).valid
    assert (run / "qualification" / "m0" / "package-install.json").is_file()
    assert by_id["M0-C07"]["status"] == "PASS"
    assert results["summary"] == {
        "blocked": 39,
        "failed": 0,
        "not_run": 14,
        "passed": 39,
        "required": 92,
    }


def test_runtime_receipt_admits_only_the_five_exact_m3_rows(tmp_path: Path) -> None:
    marker = "d" * 40
    proof = foundation()
    metadata = _metadata(proof)
    metadata["repository_marker"] = marker
    runtime_receipt = qualify_runtime_observation(marker)
    result = collect_acceptance_evidence(
        input=_input(
            tmp_path,
            proof=proof,
            metadata=metadata,
            runtime_observation_receipt=runtime_receipt.model_dump(mode="json"),
        ),
        output_root=tmp_path / "artifacts",
        run_id="runtime-observation",
    )
    run = result.run_directory
    results = json.loads(
        (run / "qualification" / "registry" / "results.json").read_text(encoding="utf-8")
    )
    by_id = {row["requirement_id"]: row for row in results["requirements"]}
    admitted = {"M3-T03", "M3-T04", "M3-T05", "M3-X01", "SW-M3-OBSERVED"}

    assert verify_acceptance_evidence(run).valid
    assert (run / "qualification" / "m3" / "runtime-observation-receipt.json").is_file()
    assert (run / "qualification" / "m3" / "observed-fragment-receipt.json").is_file()
    assert results["summary"] == {
        "blocked": 34,
        "failed": 0,
        "not_run": 15,
        "passed": 43,
        "required": 92,
    }
    assert {
        requirement_id
        for requirement_id, row in by_id.items()
        if row["qualification_admission_digest"] is not None
    } == admitted
    assert all(by_id[requirement_id]["status"] == "PASS" for requirement_id in admitted)
    assert all(
        by_id[requirement_id]["qualification_admission_digest"] == runtime_receipt.receipt_digest
        for requirement_id in admitted
    )


def test_clean_wheel_and_runtime_receipts_combine_without_cross_promotion(tmp_path: Path) -> None:
    marker = "d" * 40
    proof = foundation()
    metadata = _metadata(proof)
    metadata["repository_marker"] = marker
    package_receipt = _package_install_receipt()
    package_receipt["repository_marker"] = marker

    result = collect_acceptance_evidence(
        input=_input(
            tmp_path,
            proof=proof,
            metadata=metadata,
            package_install_receipt=package_receipt,
            runtime_observation_receipt=qualify_runtime_observation(marker).model_dump(mode="json"),
        ),
        output_root=tmp_path / "artifacts",
        run_id="complete-current-projection",
    )
    results = json.loads(
        (result.run_directory / "qualification" / "registry" / "results.json").read_text(
            encoding="utf-8"
        )
    )

    assert verify_acceptance_evidence(result.run_directory).valid
    assert results["summary"] == {
        "blocked": 34,
        "failed": 0,
        "not_run": 14,
        "passed": 44,
        "required": 92,
    }


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(
            lambda receipt: receipt.__setitem__("repository_marker", "other-tree"),
            id="wrong-repository",
        ),
        pytest.param(
            lambda receipt: cast(dict[str, object], receipt["installation"]).__setitem__(
                "editable", True
            ),
            id="editable-install",
        ),
        pytest.param(
            lambda receipt: cast(list[dict[str, object]], receipt["families"])[0].__setitem__(
                "symbols", ["ScopeManifest", "UnexpectedExport"]
            ),
            id="wrong-public-surface",
        ),
    ],
)
def test_rejects_unqualified_package_install_receipt(
    tmp_path: Path, mutation: Callable[[dict[str, object]], None]
) -> None:
    receipt = _package_install_receipt()
    mutation(receipt)

    with pytest.raises(AcceptanceEvidenceError, match="package install"):
        collect_acceptance_evidence(
            input=_input(tmp_path, package_install_receipt=receipt),
            output_root=tmp_path / "artifacts",
            run_id="bad-package-install",
        )


def test_verifier_rejects_rehashed_package_install_receipt_tampering(tmp_path: Path) -> None:
    run = collect_acceptance_evidence(
        input=_input(tmp_path, package_install_receipt=_package_install_receipt()),
        output_root=tmp_path / "artifacts",
        run_id="package-tampering",
    ).run_directory
    receipt_path = run / "qualification" / "m0" / "package-install.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["installation"]["editable"] = True
    receipt_path.write_bytes(canonical_json_bytes(receipt))
    _rewrite_manifest_digest(run, "qualification/m0/package-install.json")

    verification = verify_acceptance_evidence(run)

    assert not verification.valid
    assert verification.snapshot_sha256 is None
    assert "artifact bundle is not causally coherent" in verification.errors


@pytest.mark.parametrize("run_id", ["../escape", "two/slashes", "..", "", "has space"])
def test_rejects_unsafe_run_ids(tmp_path: Path, run_id: str) -> None:
    with pytest.raises(AcceptanceEvidenceError, match="invalid run id"):
        collect_acceptance_evidence(input=_input(tmp_path), output_root=tmp_path, run_id=run_id)


def test_does_not_overwrite_existing_run(tmp_path: Path) -> None:
    inputs = _input(tmp_path)
    collect_acceptance_evidence(input=inputs, output_root=tmp_path, run_id="once")
    with pytest.raises(AcceptanceEvidenceError, match="already exists"):
        collect_acceptance_evidence(input=inputs, output_root=tmp_path, run_id="once")


def test_rejects_secret_without_echoing_it(tmp_path: Path) -> None:
    metadata = _metadata(foundation())
    metadata["authorization"] = "Bearer synthetic-secret-never-printed"
    with pytest.raises(AcceptanceEvidenceError) as raised:
        collect_acceptance_evidence(
            input=_input(tmp_path, metadata=metadata),
            output_root=tmp_path,
            run_id="secret",
        )
    assert "synthetic-secret-never-printed" not in str(raised.value)


@pytest.mark.parametrize("remove_or_add", ["missing", "extra"])
def test_requires_exactly_four_named_junit_sources(tmp_path: Path, remove_or_add: str) -> None:
    sources = _junit_sources(tmp_path)
    if remove_or_add == "missing":
        del sources["policy"]
    else:
        sources["unexpected"] = tmp_path / "contracts.xml"
    with pytest.raises(AcceptanceEvidenceError, match="JUnit"):
        collect_acceptance_evidence(
            input=_input(tmp_path, sources=sources), output_root=tmp_path, run_id="missing-junit"
        )


@pytest.mark.parametrize(
    ("attribute", "value"),
    [("skipped", 1), ("failures", 1), ("errors", 1), ("tests", 0)],
)
def test_rejects_non_passing_or_empty_junit(tmp_path: Path, attribute: str, value: int) -> None:
    settings = {"tests": 1, "failures": 0, "errors": 0, "skipped": 0}
    settings[attribute] = value
    with pytest.raises(AcceptanceEvidenceError, match=r"JUnit|passing"):
        collect_acceptance_evidence(
            input=_input(tmp_path, sources=_junit_sources(tmp_path, **settings)),
            output_root=tmp_path,
            run_id="bad-junit",
        )


def test_rejects_malformed_junit_as_a_safe_evidence_error(tmp_path: Path) -> None:
    sources = _junit_sources(tmp_path)
    sources["policy"].write_text('<testsuite tests="not-an-int" />', encoding="utf-8")
    with pytest.raises(AcceptanceEvidenceError, match="JUnit"):
        collect_acceptance_evidence(
            input=_input(tmp_path, sources=sources), output_root=tmp_path, run_id="malformed-junit"
        )


@pytest.mark.parametrize(
    ("group", "identity"),
    [
        (
            "contracts",
            "tests.test_event_history::test_event_history_round_trip_binds_exact_chain_and_head",
        ),
        (
            "replay",
            "packages.evidence.tests.test_acceptance_registry::test_registry_resource_is_canonical_and_exact",
        ),
        (
            "replay",
            "packages.evidence.tests.test_acceptance_results::test_local_result_requires_the_exact_selector_module_and_evidence_path",
        ),
        (
            "replay",
            "packages.evidence.tests.test_semantic_trace::test_success_trace_projects_exact_action_semantics",
        ),
    ],
)
def test_accepts_known_package_junit_extensions(tmp_path: Path, group: str, identity: str) -> None:
    sources = _junit_sources(tmp_path)
    _append_junit_identity(sources[group], identity)

    result = collect_acceptance_evidence(
        input=_input(tmp_path, sources=sources),
        output_root=tmp_path / "artifacts",
        run_id="known-junit-extension",
    )

    assert verify_acceptance_evidence(result.run_directory).valid


@pytest.mark.parametrize(
    "identity",
    [
        "packages.reporting.tests.test_reality_publication::test_build_is_byte_deterministic_and_immutable",
        "tests.e2e.proof_bundle.test_publication_journey::test_independent_consumer_reproduces_the_publication_candidate",
    ],
)
def test_rejects_later_milestone_junit_in_replay_group(tmp_path: Path, identity: str) -> None:
    sources = _junit_sources(tmp_path)
    _append_junit_identity(sources["replay"], identity)

    with pytest.raises(AcceptanceEvidenceError, match="required group"):
        collect_acceptance_evidence(
            input=_input(tmp_path, sources=sources),
            output_root=tmp_path / "artifacts",
            run_id="cross-milestone-junit",
        )


def test_rejects_junit_aggregate_counts_that_do_not_match_testcases(tmp_path: Path) -> None:
    sources = _junit_sources(tmp_path)
    sources["policy"].write_text(
        '<testsuite tests="2" failures="0" errors="0" skipped="0">'
        '<testcase name="only-one" /></testsuite>',
        encoding="utf-8",
    )
    with pytest.raises(AcceptanceEvidenceError, match="aggregate"):
        collect_acceptance_evidence(
            input=_input(tmp_path, sources=sources), output_root=tmp_path, run_id="bad-counts"
        )


def test_rejects_junit_substitution_even_after_manifest_rehash(tmp_path: Path) -> None:
    run = _collect(tmp_path, "junit-substitution")
    replacement = (
        '<testsuite name="contracts" tests="2" failures="0" errors="0" skipped="0">'
        '<testcase classname="tests.test_unrelated" name="test_passes" />'
        '<testcase classname="tests.test_unrelated" name="test_also_passes" />'
        "</testsuite>"
    )
    target = run / "junit" / "contracts.xml"
    target.write_text(replacement, encoding="utf-8")
    _rewrite_manifest_digest(run, "junit/contracts.xml")
    manifest = run / "run-manifest.json"
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["junit"]["contracts"] = {
        "errors": 0,
        "failures": 0,
        "skipped": 0,
        "testcase_identities": [
            "tests.test_unrelated::test_also_passes",
            "tests.test_unrelated::test_passes",
        ],
        "testcase_identity_count": 2,
        "testcase_identity_sha256": "sha256:" + "0" * 64,
        "tests": 2,
    }
    manifest.write_bytes(canonical_json_bytes(payload))
    _rewrite_manifest_digest(run, "run-manifest.json")

    result = verify_acceptance_evidence(run)
    assert not result.valid
    assert any("coher" in error.lower() for error in result.errors)


def test_verifier_hashes_and_parses_each_artifact_from_one_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _collect(tmp_path, "single-read-snapshot")
    target = run / "replay" / "plan.json"
    original_read_bytes = Path.read_bytes
    target_reads = 0

    def mutate_after_first_read(path: Path) -> bytes:
        nonlocal target_reads
        content = original_read_bytes(path)
        if path == target:
            target_reads += 1
            if target_reads == 1:
                path.write_bytes(canonical_json_bytes({"substituted": "after-snapshot"}))
        return content

    monkeypatch.setattr(Path, "read_bytes", mutate_after_first_read)
    result = verify_acceptance_evidence(run)

    assert result.valid
    assert result.snapshot_sha256 is not None
    assert target_reads == 1

    monkeypatch.undo()
    current = verify_acceptance_evidence(run)
    assert not current.valid
    assert current.snapshot_sha256 is None


def test_verifier_detects_tampering_extra_and_missing_artifacts(tmp_path: Path) -> None:
    run = _collect(tmp_path, "tampered")
    (run / "oracle" / "patched.json").write_bytes(canonical_json_bytes({}))
    assert not verify_acceptance_evidence(run).valid

    run = _collect(tmp_path, "extra")
    (run / "untracked.txt").write_text("not admitted", encoding="utf-8")
    assert not verify_acceptance_evidence(run).valid

    run = _collect(tmp_path, "missing")
    (run / "oracle" / "patched.json").unlink()
    assert not verify_acceptance_evidence(run).valid


def test_verifier_rejects_rehashed_cross_artifact_tampering(tmp_path: Path) -> None:
    run = _collect(tmp_path, "rehash")
    plan_path = run / "replay" / "plan.json"
    plan_path.write_bytes(canonical_json_bytes({"substituted": "plan"}))
    _rewrite_manifest_digest(run, "replay/plan.json")

    result = verify_acceptance_evidence(run)
    assert not result.valid
    assert any("coher" in error.lower() or "plan" in error.lower() for error in result.errors)


def test_verifier_rejects_nonfinite_json_without_raising(tmp_path: Path) -> None:
    run = _collect(tmp_path, "nonfinite")
    target = run / "replay" / "plan.json"
    target.write_text('{"value":NaN}\n', encoding="utf-8")
    _rewrite_manifest_digest(run, "replay/plan.json")

    result = verify_acceptance_evidence(run)
    assert not result.valid
    assert any("invalid" in error.lower() for error in result.errors)


def test_verifier_rejects_drive_qualified_manifest_path(tmp_path: Path) -> None:
    run = _collect(tmp_path, "unsafe-manifest")
    manifest = run / "artifact-manifest.sha256"
    lines = manifest.read_text(encoding="ascii").splitlines()
    digest, _ = lines[0].split("  ", 1)
    lines[0] = f"{digest}  C:/Windows/system.ini"
    manifest.write_text("\n".join(lines) + "\n", encoding="ascii")

    result = verify_acceptance_evidence(run)
    assert not result.valid
    assert "artifact manifest has an unsafe path" in result.errors


def test_verifier_rejects_rehashed_boolean_zero_metadata(tmp_path: Path) -> None:
    run = _collect(tmp_path, "bool-metadata")
    target = run / "run-manifest.json"
    payload = json.loads(target.read_text(encoding="utf-8"))
    payload["metadata"]["model_calls"] = False
    target.write_bytes(canonical_json_bytes(payload))
    _rewrite_manifest_digest(run, "run-manifest.json")

    result = verify_acceptance_evidence(run)
    assert not result.valid
    assert any("coher" in error.lower() for error in result.errors)


def test_verifier_returns_invalid_for_oversized_json_integer(tmp_path: Path) -> None:
    run = _collect(tmp_path, "oversized-json-integer")
    target = run / "run-manifest.json"
    target.write_text('{"number":' + "9" * 5000 + "}\n", encoding="utf-8")
    _rewrite_manifest_digest(run, "run-manifest.json")

    result = verify_acceptance_evidence(run)

    assert not result.valid
    assert "JSON artifact is unreadable or contains invalid values" in result.errors


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("repository_marker", "different-tree"),
        ("app_source_digest", "sha256:" + "c" * 64),
        ("oracle_definition_hash", "sha256:" + "d" * 64),
        ("runtime_dependency_fingerprint", "sha256:" + "e" * 64),
        ("foundation_semantic_sha256", "sha256:" + "f" * 64),
    ],
)
def test_verifier_binds_independently_supplied_provenance(
    tmp_path: Path, field: str, value: str
) -> None:
    run = _collect(tmp_path, f"provenance-{field}")
    expected = {
        "repository_marker": "synthetic-test-tree",
        "app_source_digest": "sha256:" + "a" * 64,
        "oracle_definition_hash": "sha256:" + "b" * 64,
        "runtime_dependency_fingerprint": "sha256:" + "c" * 64,
        "foundation_semantic_sha256": semantic_sha256(foundation()),
    }
    expected[field] = value
    result = verify_acceptance_evidence(run, expected_provenance=ExpectedProvenance(**expected))
    assert not result.valid
    assert result.errors == ("artifact provenance does not match independent expectations",)


def test_file_collection_is_closed_while_semantic_hash_ignores_audit_clocks(
    tmp_path: Path,
) -> None:
    accepted = foundation()
    source = tmp_path / "foundation.json"
    source.write_text(json.dumps(accepted), encoding="utf-8")
    result = collect_from_json_file(
        foundation_json=source,
        output_root=tmp_path / "artifacts",
        run_id="first",
        junit_sources=_junit_sources(tmp_path),
        run_metadata=_metadata(accepted),
    )
    assert verify_acceptance_evidence(result.run_directory).valid

    first = copy.deepcopy(accepted)
    second = copy.deepcopy(accepted)
    first["collected_at"] = "2026-01-01T00:00:00Z"
    second["collected_at"] = "2026-02-01T00:00:00Z"
    assert semantic_sha256(first) == semantic_sha256(second)
    source.write_text(json.dumps(first), encoding="utf-8")
    with pytest.raises(AcceptanceEvidenceError, match="incomplete"):
        collect_from_json_file(
            foundation_json=source,
            output_root=tmp_path / "artifacts",
            run_id="second",
            junit_sources=_junit_sources(tmp_path),
            run_metadata=_metadata(first),
        )


def test_canonical_json_rejects_invalid_numbers_and_mapping_keys() -> None:
    with pytest.raises(EvidenceInputError, match="finite"):
        canonical_json_bytes({"value": float("nan")})
    with pytest.raises(EvidenceInputError, match="strings"):
        semantic_sha256({1: "numeric", "1": "string"})


def test_semantic_hash_retains_nested_controlled_timestamps() -> None:
    first = {"observation": {"controlled_at": "2026-01-01T00:00:00Z"}}
    second = {"observation": {"controlled_at": "2026-01-01T00:00:01Z"}}
    assert semantic_sha256(first) != semantic_sha256(second)


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(
            lambda proof: proof["root_state"].__setitem__("root_seed_id", "mixed.root"),
            id="mixed-canonical-root",
        ),
        pytest.param(
            lambda proof: proof["canonical_plan"].__setitem__("plan_id", "mixed.plan"),
            id="mixed-canonical-plan",
        ),
        pytest.param(
            lambda proof: proof["policy_decisions"]["policy.evidence"].__setitem__(
                "envelope_hash", "sha256:" + "0" * 64
            ),
            id="tampered-policy-envelope",
        ),
        pytest.param(
            lambda proof: proof["vulnerable"]["attempts"][0].__setitem__(
                "signature", "not-the-replay-signature"
            ),
            id="tampered-vulnerable-signature",
        ),
    ],
)
def test_rejects_mixed_or_tampered_causal_bindings(
    tmp_path: Path, mutation: Callable[[dict[str, Any]], None]
) -> None:
    _expect_rejected(tmp_path, mutation)


def test_rejects_fabricated_or_rewritten_evidence_record_content(tmp_path: Path) -> None:
    def fabricate_record(proof: dict[str, object]) -> None:
        attempts = cast(Any, proof["vulnerable"])["attempts"]
        record = attempts[0]["evidence_records"][0]
        evidence_id = record["evidence_id"]
        record.clear()
        record.update({"evidence_id": evidence_id, "fabricated": True})

    _expect_rejected(tmp_path, fabricate_record, match="evidence record schema")

    def rewrite_valid_field(proof: dict[str, object]) -> None:
        attempts = cast(Any, proof["vulnerable"])["attempts"]
        attempts[0]["evidence_records"][0]["outcome"] = "fabricated_but_well_formed"

    _expect_rejected(tmp_path, rewrite_valid_field, match="replay observation")


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(
            lambda proof: proof.__setitem__("reviewer_claim", "unsupported"),
            id="foundation-extra-field",
        ),
        pytest.param(
            lambda proof: cast(Any, proof["vulnerable"])["attempts"][0].__setitem__(
                "reviewer_claim", "unsupported"
            ),
            id="scenario-extra-field",
        ),
        pytest.param(
            lambda proof: cast(Any, proof["vulnerable"]).__setitem__(
                "reviewer_claim", "unsupported"
            ),
            id="vulnerable-summary-extra-field",
        ),
        pytest.param(
            lambda proof: cast(Any, proof["patched"]).__setitem__("reviewer_claim", "unsupported"),
            id="patched-summary-extra-field",
        ),
    ],
)
def test_rejects_unrecognized_proof_claims(
    tmp_path: Path, mutation: Callable[[dict[str, Any]], None]
) -> None:
    _expect_rejected(tmp_path, mutation, match=r"schema|incomplete")


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(
            lambda proof: proof["policy_decisions"]["policy.evidence"].__setitem__(
                "policy_request_hash", "sha256:" + "1" * 64
            ),
            id="forged-policy-request-hash",
        ),
        pytest.param(
            lambda proof: proof["policy_decisions"]["policy.evidence"].__setitem__(
                "budget_reservation_id", "sha256:" + "2" * 64
            ),
            id="forged-budget-reservation",
        ),
        pytest.param(
            lambda proof: proof["policy_decisions"]["policy.evidence"].__setitem__(
                "evaluated_at", "2026-01-03T00:00:00Z"
            ),
            id="expired-policy-evaluation",
        ),
        pytest.param(
            lambda proof: proof["policy_decisions"]["policy.evidence"].__setitem__(
                "decision",
                {
                    "schema_version": "1.0",
                    "outcome": "ALLOW",
                    "reason_codes": ["policy.allowed"],
                    "constraints": [],
                },
            ),
            id="forged-policy-decision",
        ),
    ],
)
def test_rejects_mutated_typed_policy_authorizations(
    tmp_path: Path, mutation: Callable[[dict[str, Any]], None]
) -> None:
    _expect_rejected(tmp_path, mutation, match="policy")


def test_rejects_fully_recomputed_policy_evaluated_after_clean_root_clock(
    tmp_path: Path,
) -> None:
    def move_policy_into_future(proof: dict[str, object]) -> None:
        replay_plan = ReplayPlan.model_validate_json(canonical_json_bytes(proof["canonical_plan"]))
        scope_manifest = ScopeManifest.model_validate_json(
            canonical_json_bytes(proof["scope_manifest"])
        )
        envelope = replay_plan.steps[0].action
        evaluated_at = EPOCH + timedelta(hours=1)
        request = PolicyRequest(
            scope_manifest=scope_manifest,
            action_envelope=envelope,
            budget=BudgetSnapshot(
                requests_in_window=0,
                request_window_seconds=1.0,
                write_requests_used=0,
            ),
            evaluated_at=evaluated_at,
        )
        decisions = cast(dict[str, dict[str, object]], proof["policy_decisions"])
        record = decisions[envelope.policy_decision_ref]
        record["evaluated_at"] = evaluated_at.isoformat().replace("+00:00", "Z")
        record["policy_request_hash"] = request.fingerprint()
        record["decision"] = evaluate_policy(request).model_dump(mode="json")

    _expect_rejected(tmp_path, move_policy_into_future, match="policy")


def test_rejects_fully_rehashed_violated_oracle_with_a_failed_check(tmp_path: Path) -> None:
    def falsify_oracle_check(proof: dict[str, object]) -> None:
        vulnerable = cast(dict[str, Any], proof["vulnerable"])
        attempts = cast(list[dict[str, Any]], vulnerable["attempts"])
        for attempt in attempts:
            result = cast(dict[str, Any], attempt["replay_result"])
            final_step = cast(dict[str, Any], result["steps"][-1])
            oracle = cast(dict[str, Any], final_step["oracle_results"][0])
            observed = cast(dict[str, Any], oracle["observed"])
            cast(list[dict[str, Any]], observed["checks"])[0]["passed"] = False
            plan_payload = cast(dict[str, Any], attempt["plan"])
            final_action = cast(dict[str, Any], plan_payload["steps"][-1])["action"]
            oracle_hash = canonical_sha256(
                {
                    "oracle_id": "oracle.cross_tenant_document_disclosure.v1",
                    "version": "1.0",
                    "world_id": oracle["world_id"],
                    "action_id": final_action["action_id"],
                    "observed": observed,
                    "evidence_ids": oracle["evidence_ids"],
                }
            ).removeprefix("sha256:")
            oracle["oracle_result_id"] = f"oracle.result:{oracle_hash[:24]}"
            action_log = cast(list[dict[str, Any]], result["action_log"])
            action_log[-1]["oracle_results_hash"] = canonical_sha256(final_step["oracle_results"])
            result["trace_hash"] = canonical_sha256(
                {
                    "plan_id": result["plan_id"],
                    "status": result["status"],
                    "root_fingerprint": result["root_fingerprint"],
                    "final_fingerprint": result["final_fingerprint"],
                    "steps": result["steps"],
                    "action_log": action_log,
                    "failed_step_id": result["failed_step_id"],
                }
            )
            typed = ReplayRunResult.model_validate_json(canonical_json_bytes(result))
            attempt["oracle_results"] = final_step["oracle_results"]
            attempt["signature"] = typed.deterministic_signature()
            attempt["action_log_hash"] = canonical_sha256(typed.action_log)
        first = attempts[0]
        vulnerable["signature"] = first["signature"]
        vulnerable["action_log_hash"] = first["action_log_hash"]
        proof["canonical_action_log"] = first["replay_result"]["action_log"]

    _expect_rejected(tmp_path, falsify_oracle_check, match="Oracle predicate")


def test_rejects_missing_or_incorrect_mandatory_controls(tmp_path: Path) -> None:
    def remove_required(proof: dict[str, object]) -> None:
        controls = proof["negative_controls"]
        assert isinstance(controls, list)
        removed = controls.pop()
        assert isinstance(removed, dict)
        plan = removed["plan"]
        assert isinstance(plan, dict)
        steps = plan["steps"]
        assert isinstance(steps, list)
        action = steps[0]["action"]
        assert isinstance(action, dict)
        decisions = proof["policy_decisions"]
        assert isinstance(decisions, dict)
        del decisions[action["policy_decision_ref"]]

    _expect_rejected(tmp_path, remove_required, match="negative-control")

    def rename_required(proof: dict[str, object]) -> None:
        controls = proof["negative_controls"]
        assert isinstance(controls, list)
        assert isinstance(controls[0], dict)
        controls[0]["name"] = "not-the-required-control"

    _expect_rejected(tmp_path, rename_required, match="negative-control")


def test_rejects_fully_coherent_reduction_to_only_four_controls(tmp_path: Path) -> None:
    retained_names = {
        "masked_response",
        "mock_only_response",
        "fresh_session",
        "same_tenant_document",
    }

    def retain_only_four(proof: dict[str, object]) -> None:
        controls = cast(list[dict[str, Any]], proof["negative_controls"])
        removed = [control for control in controls if control["name"] not in retained_names]
        proof["negative_controls"] = [
            control for control in controls if control["name"] in retained_names
        ]
        decisions = cast(dict[str, Any], proof["policy_decisions"])
        for control in removed:
            control_plan = cast(dict[str, Any], control["plan"])
            for step in cast(list[dict[str, Any]], control_plan["steps"]):
                envelope = cast(dict[str, Any], step["action"])
                decisions.pop(str(envelope["policy_decision_ref"]))

    _expect_rejected(tmp_path, retain_only_four, match="negative-control")


def test_rejects_fully_rehashed_control_status_outside_named_profile(tmp_path: Path) -> None:
    def rewrite_status(proof: dict[str, object]) -> None:
        controls = cast(list[dict[str, Any]], proof["negative_controls"])
        control = next(item for item in controls if item["name"] == "missing_prerequisite_0")
        result = cast(dict[str, Any], control["replay_result"])
        steps = cast(list[dict[str, Any]], result["steps"])
        final = steps[-1]
        observations = cast(list[dict[str, Any]], final["observations"])
        payload = cast(dict[str, Any], observations[0]["payload"])
        payload["response_status"] = 999
        action_log = cast(list[dict[str, Any]], result["action_log"])
        action_log[-1]["observation_hash"] = canonical_sha256(observations)
        _replace_scenario_result(control, _rebuild_result(result))

    _expect_rejected(tmp_path, rewrite_status, match="status contract|negative control")


def test_rejects_cloned_control_with_a_different_top_level_name(tmp_path: Path) -> None:
    def clone_named_control(proof: dict[str, object]) -> None:
        controls = cast(list[dict[str, Any]], proof["negative_controls"])
        original_replaced = controls[1]
        clone = copy.deepcopy(controls[0])
        clone["name"] = "missing_prerequisite_1"
        controls[1] = clone
        replaced_plan = cast(dict[str, Any], original_replaced["plan"])
        decisions = cast(dict[str, Any], proof["policy_decisions"])
        for step in cast(list[dict[str, Any]], replaced_plan["steps"]):
            envelope = cast(dict[str, Any], step["action"])
            decisions.pop(str(envelope["policy_decision_ref"]))

    _expect_rejected(tmp_path, clone_named_control, match="negative-control")


def test_rejects_fully_rehashed_action_log_that_diverges_from_plan(tmp_path: Path) -> None:
    def replace_executed_target(proof: dict[str, object]) -> None:
        summary = cast(dict[str, Any], proof["vulnerable"])
        attempts = cast(list[dict[str, Any]], summary["attempts"])
        for attempt in attempts:
            result = cast(dict[str, Any], attempt["replay_result"])
            action_log = cast(list[dict[str, Any]], result["action_log"])
            entry = action_log[-1]
            envelope = cast(dict[str, Any], entry["action"])
            action = cast(dict[str, Any], envelope["action"])
            target = cast(dict[str, Any], action["target"])
            target["path"] = "/v1/lab/documents/doc-a-public"
            entry["request_template_hash"] = canonical_sha256(action)
            entry["envelope_hash"] = canonical_sha256(envelope)
            entry["trace_id"] = canonical_sha256(
                {
                    "plan_id": result["plan_id"],
                    "step_id": entry["step_id"],
                    "envelope_hash": entry["envelope_hash"],
                }
            ).removeprefix("sha256:")[:32]
            _replace_scenario_result(attempt, _rebuild_result(result))
        summary["signature"] = attempts[0]["signature"]
        summary["action_log_hash"] = attempts[0]["action_log_hash"]
        proof["canonical_action_log"] = attempts[0]["replay_result"]["action_log"]

    _expect_rejected(tmp_path, replace_executed_target, match="execute the supplied plan")


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("model_calls", False),
        ("model_calls", True),
        ("test_exit_code", False),
        ("test_exit_code", True),
        ("controlled_clock_epoch", "2026-01-01T00:00:01Z"),
    ],
)
def test_metadata_requires_strict_types_and_clock_binding(
    tmp_path: Path, field: str, invalid_value: object
) -> None:
    proof = foundation()
    metadata = _metadata(proof)
    metadata[field] = invalid_value
    with pytest.raises(AcceptanceEvidenceError, match="metadata"):
        collect_acceptance_evidence(
            input=_input(tmp_path, proof=proof, metadata=metadata),
            output_root=tmp_path,
            run_id="metadata",
        )
