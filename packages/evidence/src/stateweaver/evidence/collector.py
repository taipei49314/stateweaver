"""Collector for one causally coherent, local M0/M1 acceptance proof."""

from __future__ import annotations

import re
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypedDict
from xml.etree import ElementTree

from pydantic import ValidationError
from stateweaver.contracts import (
    ActionEnvelope,
    HttpMethod,
    HttpRequestAction,
    OracleOutcome,
    ScopeManifest,
)
from stateweaver.policy import (
    BudgetSnapshot,
    PolicyDecision,
    PolicyRequest,
    evaluate_policy,
)
from stateweaver.replay import (
    ReplayObservation,
    ReplayPlan,
    ReplayRunResult,
    ReplayRunStatus,
    ReplayStepResult,
    RootSeed,
    canonical_sha256,
)

from ._io import (
    EvidenceInputError,
    assert_secret_free,
    atomic_json,
    atomic_write,
    canonical_json_bytes,
    json_mapping,
    semantic_sha256,
    sha256_bytes,
    validate_run_id,
)
from .acceptance_registry import EXPECTED_ACCEPTANCE_REGISTRY_SHA256, load_acceptance_registry
from .acceptance_results import (
    AcceptanceRegistryClosure,
    AcceptanceResults,
    AcceptanceResultsError,
    build_acceptance_registry_closure,
    derive_acceptance_results,
)
from .package_install import (
    PACKAGE_INSTALL_QUALIFICATION_PATH,
    PackageInstallQualificationError,
    validate_package_install_receipt,
)
from .runtime_observation import (
    OBSERVED_FRAGMENT_QUALIFICATION_PATH,
    RUNTIME_OBSERVATION_QUALIFICATION_PATH,
    RuntimeObservationQualificationError,
    observed_fragment_qualification_payload,
    runtime_observation_admissions,
    validate_runtime_observation_qualification,
)

_JUNIT_NAMES = ("contracts", "policy", "lab", "replay")
_M0_PROPERTY_SEED = 982341
_M0_PROPERTY_EXAMPLES = 150
_M0_PROPERTY_IDENTITIES = (
    "tests.test_canonical::test_security_fingerprint_uses_explicit_semantic_projection",
    "tests.test_canonical::test_fingerprint_property_is_permutation_invariant",
    "tests.test_canonical::test_fingerprint_property_detects_security_semantic_change",
)
_M0_MODE_ISOLATION_IDENTITY = (
    "tests.test_lab::test_vulnerable_and_patched_apps_have_no_process_global_mode_state"
)
_M0_CONFIGURATION_IDENTITY = "tests.test_lab::test_invalid_mode_is_rejected"
_M1_SESSION_IDENTITY = (
    "tests.test_lab::test_evidence_and_layered_capture_never_record_bearer_values"
)
_M1_PROVIDER_IDENTITY = (
    "adapters.environments.in_process_lab.tests.test_in_process_lab_environment::"
    "test_root_creation_reset_and_capture_contain_all_seven_redacted_layers"
)
_M1_RESET_IDENTITY = "tests.test_lab::test_clean_seed_and_reset_are_deterministic"
_M1_NONDETERMINISM_IDENTITY = (
    "packages.replay.tests.test_kernel::test_observation_drift_is_classified_as_nondeterministic"
)
_M1_CLEANUP_CASES = (
    ("reset", "RESET_FAILURE"),
    ("capture_before", "CAPTURE_BEFORE_FAILURE"),
    ("execute", "EXECUTE_FAILURE"),
    ("capture_after", "CAPTURE_AFTER_FAILURE"),
)
_M1_CLEANUP_BASE_IDENTITY = (
    "packages.replay.tests.test_kernel::"
    "test_boundary_failures_are_localized_cleanup_is_reentrant_and_reset_recovers"
)
_M1_CLEANUP_FAILURE_IDENTITY = (
    "packages.replay.tests.test_kernel::test_cleanup_failure_is_visible_and_redacted"
)
_M1_RESET_TIMEOUT_IDENTITY = (
    "packages.replay.tests.test_kernel::test_reset_is_bounded_and_cleanup_still_runs"
)
_M3_OPENAPI_IDENTITY = (
    "tests.integration.twin.test_local_synthetic_flow::"
    "test_testclient_source_and_trace_evidence_build_one_observed_transition"
)
_M3_SOURCE_IDENTITIES = (
    "adapters.source.fastapi_sqlalchemy.tests.test_extractor::"
    "test_extracts_actual_sqlalchemy_table_metadata_without_engine_or_connection",
    "adapters.source.fastapi_sqlalchemy.tests.test_extractor::"
    "test_extracts_real_fastapi_route_and_narrow_openapi_without_requesting_it",
)
_M3_RUNTIME_IDENTITY = (
    "tests.integration.observation.test_runtime_observation::"
    "test_controller_issues_trace_and_derives_state_delta_from_authorized_lab_action"
)
_M3_TWIN_IDENTITY = (
    "packages.twin.tests.test_twin::"
    "test_builds_canonical_evidence_bound_twin_and_observed_transition"
)
_M3_QUALIFICATION_IDENTITIES = (
    "apps.cli.tests.test_runtime_qualification::"
    "test_runtime_qualification_reexecutes_with_stable_semantics",
    "apps.cli.tests.test_runtime_qualification::test_adapter_receipt_substitution_fails_closed",
)
_M4_IDENTITIES = (
    "packages.search.tests.test_search::"
    "test_strict_models_reject_unknown_fields_bool_integers_and_duplicate_candidates",
    "packages.search.tests.test_search::test_materialized_source_tier_is_not_promotable",
    "packages.search.tests.test_search::test_twenty_four_ghosts_promote_only_the_bounded_beam",
    "packages.search.tests.test_search::test_budget_ledger_is_immutable_and_append_only",
    "packages.search.tests.test_search::"
    "test_model_score_cannot_override_materialization_evidence_gates",
)
_M5_COMPILER_IDENTITY = (
    "packages.compiler.tests.test_compiler::"
    "test_compiles_three_fragment_minimal_chain_and_replay_plan"
)
_M5_CLEAN_ROOM_IDENTITY = (
    "tests.integration.compiler.test_clean_room_chain::"
    "test_fresh_authorizations_retain_exact_policy_request_decision_and_fragment_bindings"
)
_M5_MINIMIZER_IDENTITY = (
    "tests.integration.compiler.test_clean_room_chain::"
    "test_compiler_minimizer_cannot_remove_any_required_fragment"
)
_M6_NEGATIVE_CONTROL_IDENTITIES = (
    "tests.test_reality_receipts::"
    "test_negative_controls_are_bound_to_primary_replay[control_changes0-must not reproduce]",
    "tests.test_reality_receipts::"
    "test_negative_controls_are_bound_to_primary_replay[control_changes1-target]",
    "tests.test_reality_receipts::"
    "test_negative_controls_are_bound_to_primary_replay[control_changes2-target]",
    "tests.test_reality_receipts::"
    "test_negative_controls_are_bound_to_primary_replay[control_changes3-locks]",
    "tests.test_reality_receipts::"
    "test_negative_controls_are_bound_to_primary_replay[control_changes4-locks]",
    "tests.test_reality_receipts::"
    "test_negative_controls_are_bound_to_primary_replay[control_changes5-root]",
    "tests.test_reality_receipts::"
    "test_negative_controls_are_bound_to_primary_replay[control_changes6-root]",
    "tests.test_reality_receipts::"
    "test_negative_controls_are_bound_to_primary_replay[control_changes7-distinct control plan]",
    "tests.test_reality_receipts::"
    "test_negative_controls_are_bound_to_primary_replay[control_changes8-distinct control plan]",
    "tests.test_reality_receipts::"
    "test_negative_controls_are_bound_to_primary_replay[control_changes9-primary replay signature]",
    "tests.test_reality_receipts::"
    "test_negative_controls_are_bound_to_primary_replay[control_changes10-Oracle definition]",
)
_M6_PATCH_IDENTITY = (
    "tests.test_reality_receipts::test_patch_verified_requires_same_plan_blocked_patch_receipt"
)
_M6_FINDING_IDENTITY = (
    "tests.test_reality_receipts::test_confirmed_finding_requires_typed_reality_receipt"
)
_M6_BUNDLE_IDENTITY = (
    "packages.evidence.tests.test_reality_bundle::"
    "test_valid_synthetic_bundle_is_a_non_promotable_candidate"
)
_M7_IDENTITIES = (
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
_JUNIT_REQUIRED_IDENTITIES: dict[str, frozenset[str]] = {
    "contracts": frozenset(
        {
            "tests.test_canonical::test_canonical_fingerprint_is_input_order_independent",
            *_M0_PROPERTY_IDENTITIES,
            "tests.test_contracts::test_closed_schema_rejects_unknown_fields",
            "tests.test_contracts::test_six_m0_contract_families_are_exported_from_the_public_surface",
            *_M6_NEGATIVE_CONTROL_IDENTITIES,
            _M6_PATCH_IDENTITY,
            _M6_FINDING_IDENTITY,
        }
    ),
    "policy": frozenset(
        {
            "tests.test_evaluator::test_localhost_target_is_allowed",
            "tests.test_evaluator::test_missing_context_and_malformed_objects_fail_closed",
        }
    ),
    "lab": frozenset(
        {
            "tests.test_lab::test_complete_chain_violates_oracle_only_in_vulnerable_mode",
            "tests.test_lab::test_same_chain_is_blocked_by_patched_mode",
            _M1_RESET_IDENTITY,
            _M0_MODE_ISOLATION_IDENTITY,
            _M1_SESSION_IDENTITY,
            _M0_CONFIGURATION_IDENTITY,
        }
    ),
    "replay": frozenset(
        {
            "packages.replay.tests.test_kernel::test_replay_is_deterministic_across_five_clean_roots",
            _M1_NONDETERMINISM_IDENTITY,
            _M1_CLEANUP_FAILURE_IDENTITY,
            *(
                f"{_M1_CLEANUP_BASE_IDENTITY}[{phase}-{failure_code}]"
                for phase, failure_code in _M1_CLEANUP_CASES
            ),
            _M1_RESET_TIMEOUT_IDENTITY,
            "adapters.environments.in_process_lab.tests.test_in_process_lab_environment::test_full_vulnerable_plan_is_deterministic_over_five_runs",
            _M1_PROVIDER_IDENTITY,
            "apps.cli.tests.test_foundation::test_foundation_verification_meets_all_acceptance_conditions",
            "packages.evidence.tests.test_collector::test_collects_exact_complete_and_verifiable_tree",
            "packages.evidence.tests.test_acceptance_registry::test_packaged_registry_is_canonical_and_has_exact_required_ids",
            _M3_OPENAPI_IDENTITY,
            *_M3_SOURCE_IDENTITIES,
            _M3_RUNTIME_IDENTITY,
            _M3_TWIN_IDENTITY,
            *_M3_QUALIFICATION_IDENTITIES,
            *_M4_IDENTITIES,
            _M5_COMPILER_IDENTITY,
            _M5_CLEAN_ROOM_IDENTITY,
            _M5_MINIMIZER_IDENTITY,
            _M6_BUNDLE_IDENTITY,
            *_M7_IDENTITIES,
        }
    ),
}
_JUNIT_ALLOWED_PREFIXES: dict[str, tuple[str, ...]] = {
    "contracts": (
        "tests.test_canonical::",
        "tests.test_contracts::",
        "tests.test_event_history::",
        "tests.test_reality_receipts::",
    ),
    "policy": ("tests.test_evaluator::",),
    "lab": ("tests.test_lab::",),
    "replay": (
        "packages.replay.tests.test_kernel::",
        "packages.replay.tests.test_models::",
        "adapters.environments.in_process_lab.tests.test_in_process_lab_environment::",
        "apps.cli.tests.test_foundation::",
        "apps.cli.tests.test_runtime_qualification::",
        "packages.evidence.tests.test_acceptance_registry::",
        "packages.evidence.tests.test_acceptance_results::",
        "packages.evidence.tests.test_collector::",
        "packages.evidence.tests.test_reality_bundle::",
        "packages.evidence.tests.test_semantic_trace::",
        "adapters.source.fastapi_sqlalchemy.tests.test_extractor::",
        "packages.compiler.tests.test_compiler::",
        "packages.search.tests.test_search::",
        "packages.twin.tests.test_twin::",
        "benchmarks.statechainbench.tests.",
        "tests.integration.compiler.test_clean_room_chain::",
        "tests.integration.observation.test_runtime_observation::",
        "tests.integration.twin.test_local_synthetic_flow::",
    ),
}
ACCEPTANCE_TEST_COMMAND = (
    "pytest packages/contracts/tests; "
    "pytest packages/policy/tests; "
    "pytest labs/multitenant-saas/tests; "
    "pytest packages/replay/tests adapters/environments/in_process_lab/tests apps/cli/tests "
    "packages/evidence/tests adapters/source/fastapi_sqlalchemy/tests "
    "packages/twin/tests packages/search/tests packages/compiler/tests "
    "benchmarks/statechainbench/tests tests/integration/observation tests/integration/twin "
    "tests/integration/compiler"
)
NETWORK_GUARD_ID = "python-socket-deny-v2"
_LAB_ORACLE_ID = "oracle.cross_tenant_document_disclosure.v1"
_LAB_ORACLE_VERSION = "1.0"
_LAB_EVALUATOR_VERSION = "in-process-lab-v1"
_LAB_INVARIANT = "actor.tenant == resource.tenant OR response.protected_field_present == false"
_LAB_CHECK_IDS = frozenset(
    {
        "runtime_response_status_is_200",
        "requester_and_owner_tenants_differ",
        "protected_document_id_matches",
        "synthetic_protected_marker_matches_exactly",
        "evidence_provenance_is_observed",
    }
)


@dataclass(frozen=True)
class _ControlProfile:
    outcome: OracleOutcome
    response_status: int
    action_type: str
    observation_kind: str
    path: str
    resource_id: str
    protected_field_present: bool
    provenance: str
    payload_outcome: str
    expected_statuses: tuple[int, ...]
    owner_tenant: str | None = None


@dataclass(frozen=True)
class _LocalQualificationSpec:
    qualification_kind: str
    requirement_ids: tuple[str, ...]
    junit: tuple[tuple[str, tuple[str, ...]], ...]
    limitations: tuple[str, ...]


_LOCAL_QUALIFICATION_SPECS: dict[str, _LocalQualificationSpec] = {
    "qualification/m3/openapi-ingest.json": _LocalQualificationSpec(
        qualification_kind="openapi-source-ingest",
        requirement_ids=("M3-T01",),
        junit=(("replay", (_M3_OPENAPI_IDENTITY,)),),
        limitations=(
            "This qualifies the socket-free local source-ingest implementation only.",
            "It is not an authenticated runtime-observation or M3 exit receipt.",
        ),
    ),
    "qualification/m3/source-extractor.json": _LocalQualificationSpec(
        qualification_kind="fastapi-sqlalchemy-source-extraction",
        requirement_ids=("M3-T02",),
        junit=(("replay", _M3_SOURCE_IDENTITIES),),
        limitations=(
            "This qualifies repository-owned FastAPI and SQLAlchemy metadata extraction only.",
            "It opens no network connection and does not certify an external source system.",
        ),
    ),
    "qualification/m4/search-receipt.json": _LocalQualificationSpec(
        qualification_kind="bounded-offline-tiered-search",
        requirement_ids=("M4-S01", "M4-S02", "M4-S03", "M4-S04", "M4-S05"),
        junit=(("replay", _M4_IDENTITIES),),
        limitations=(
            "This qualifies the deterministic offline search controller and immutable "
            "budget ledger.",
            "It is not the M4 live materialized-runtime exit receipt.",
        ),
    ),
    "qualification/m5/compiler-receipt.json": _LocalQualificationSpec(
        qualification_kind="deterministic-local-chain-compilation",
        requirement_ids=("M5-C01", "M5-C02", "M5-C03", "M5-C05"),
        junit=(("replay", (_M5_COMPILER_IDENTITY, _M5_MINIMIZER_IDENTITY)),),
        limitations=(
            "This qualifies deterministic compilation and minimization over synthetic fragments.",
            "It does not claim execution in a live materialized world.",
        ),
    ),
    "qualification/m5/clean-room-replay.json": _LocalQualificationSpec(
        qualification_kind="authorized-synthetic-clean-root-replay",
        requirement_ids=("M5-C04",),
        junit=(("replay", (_M5_CLEAN_ROOM_IDENTITY,)),),
        limitations=(
            "This qualifies fresh authorization and exact bindings in local synthetic clean roots.",
            "It is not the M5 materialized-chain exit receipt.",
        ),
    ),
    "qualification/m6/candidate-bundle.json": _LocalQualificationSpec(
        qualification_kind="non-promotable-reality-bundle-candidate",
        requirement_ids=("M6-R02", "M6-R03", "M6-R04", "M6-R05"),
        junit=(
            (
                "contracts",
                (*_M6_NEGATIVE_CONTROL_IDENTITIES, _M6_PATCH_IDENTITY, _M6_FINDING_IDENTITY),
            ),
            ("replay", (_M6_BUNDLE_IDENTITY,)),
        ),
        limitations=(
            "This is a self-contained synthetic candidate and remains non-authoritative.",
            "It has no external Reality Broker trust root or clean-machine reproduction receipt.",
        ),
    ),
    "qualification/m7/benchmark-receipt.json": _LocalQualificationSpec(
        qualification_kind="built-in-synthetic-equal-tariff-benchmark",
        requirement_ids=("M7-B01", "M7-B02", "M7-B03", "M7-B04", "M7-B05", "M7-B06"),
        junit=(("replay", _M7_IDENTITIES),),
        limitations=(
            "This qualifies the trusted built-in synthetic runner and retained raw-result checks.",
            "It is not an independently preregistered measured-cost holdout benchmark.",
        ),
    ),
}
_LOCAL_QUALIFICATION_PATHS = tuple(_LOCAL_QUALIFICATION_SPECS)


_BLOCKED_CONTROL_NAMES = (
    "missing_prerequisite_0",
    "missing_prerequisite_1",
    "missing_prerequisite_3",
    "missing_prerequisite_5",
    "missing_prerequisite_6",
    "expired_replay_window",
    "fresh_session",
)
_BLOCKED_CONTROL_PROFILE = _ControlProfile(
    outcome=OracleOutcome.SATISFIED,
    response_status=403,
    action_type="document.read",
    observation_kind="lab.document.read",
    path="/v1/lab/documents/doc-b-protected",
    resource_id="doc-b-protected",
    protected_field_present=False,
    provenance="OBSERVED",
    payload_outcome="tenant_boundary_blocked",
    expected_statuses=(200, 403),
)
_CONTROL_PROFILES: dict[str, _ControlProfile] = {
    **dict.fromkeys(_BLOCKED_CONTROL_NAMES, _BLOCKED_CONTROL_PROFILE),
    "masked_response": _ControlProfile(
        outcome=OracleOutcome.SATISFIED,
        response_status=200,
        action_type="decoy.masked_read",
        observation_kind="lab.decoy.masked_read",
        path="/v1/lab/decoys/masked/doc-b-protected",
        resource_id="doc-b-protected",
        protected_field_present=False,
        provenance="OBSERVED",
        payload_outcome="masked_200",
        expected_statuses=(200,),
    ),
    "mock_only_response": _ControlProfile(
        outcome=OracleOutcome.INCONCLUSIVE,
        response_status=200,
        action_type="decoy.mock_policy",
        observation_kind="lab.decoy.mock_policy",
        path="/v1/lab/decoys/mock-policy/doc-b-protected",
        resource_id="doc-b-protected",
        protected_field_present=False,
        provenance="MOCKED",
        payload_outcome="simulated_allow_only",
        expected_statuses=(200,),
    ),
    "same_tenant_document": _ControlProfile(
        outcome=OracleOutcome.SATISFIED,
        response_status=200,
        action_type="document.read",
        observation_kind="lab.document.read",
        path="/v1/lab/documents/doc-a-owned",
        resource_id="doc-a-owned",
        protected_field_present=True,
        provenance="OBSERVED",
        payload_outcome="same_tenant_allowed",
        expected_statuses=(200, 403),
        owner_tenant="tenant-a",
    ),
}
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_RECORD_VALUE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_EVIDENCE_RECORD_FIELDS = frozenset(
    {
        "evidence_id",
        "action_type",
        "actor_principal_id",
        "outcome",
        "at",
        "resource_id",
        "provenance",
    }
)
_POLICY_AUTHORIZATION_FIELDS = frozenset(
    {
        "policy_decision_ref",
        "action_id",
        "idempotency_key",
        "envelope_hash",
        "policy_request_hash",
        "scope_manifest_hash",
        "budget_reservation_id",
        "evaluated_at",
        "not_before",
        "expires_at",
        "requests_before",
        "write_requests_before",
        "is_write",
        "decision",
    }
)
_FOUNDATION_FIELDS = frozenset(
    {
        "accepted",
        "plan_hash",
        "canonical_plan",
        "canonical_action_log",
        "root_state",
        "scope_manifest",
        "policy_decisions",
        "vulnerable",
        "patched",
        "negative_controls",
        "patched_uses_identical_plan",
        "model_calls",
        "network_mode",
        "network_guard",
    }
)
_SCENARIO_FIELDS = frozenset(
    {
        "action_log_hash",
        "evidence_count",
        "evidence_records",
        "failed_step_id",
        "failure_code",
        "name",
        "oracle_outcome",
        "oracle_results",
        "plan",
        "replay_result",
        "response_status",
        "root_seed",
        "signature",
        "status",
        "terminal_observations",
    }
)
_VULNERABLE_SUMMARY_FIELDS = frozenset(
    {
        "all_runs_succeeded",
        "action_log_hash",
        "action_log_count",
        "deterministic",
        "oracle_outcome",
        "response_status",
        "run_count",
        "signature",
        "attempts",
    }
)
_PATCHED_SUMMARY_FIELDS = frozenset(
    {
        "evidence_count",
        "action_log_hash",
        "action_log_count",
        "failed_step_id",
        "failure_code",
        "oracle_outcome",
        "response_status",
        "status",
        "proof",
    }
)
_RUN_METADATA_FIELDS = frozenset(
    {
        "repository_marker",
        "python_version",
        "docker_compose_version",
        "target_mode",
        "root_seed",
        "controlled_clock_epoch",
        "test_command",
        "test_exit_code",
        "app_source_digest",
        "scope_manifest_hash",
        "replay_plan_hash",
        "oracle_definition_hash",
        "runtime_dependency_fingerprint",
        "network_mode",
        "network_guard",
        "model_calls",
        "started_at",
        "completed_at",
    }
)
_REQUIRED_RELATIVE = (
    "foundation/source.json",
    "run-manifest.json",
    "junit/contracts.xml",
    "junit/policy.xml",
    "junit/lab.xml",
    "junit/replay.xml",
    "oracle/vulnerable.json",
    "oracle/patched.json",
    "oracle/negative-controls.json",
    "replay/root-state.json",
    "replay/plan.json",
    "replay/attempts.json",
    "replay/failure-localization.json",
    "replay/action-log.json",
    "policy/decisions.json",
    "qualification/m0/property-seed.json",
    "qualification/m0/mode-isolation.json",
    "qualification/m0/configuration-snapshot.json",
    "qualification/m1/session-manifest.json",
    "qualification/m1/provider-digests.json",
    "qualification/m1/reset-diff.json",
    "qualification/m1/nondeterminism.json",
    "qualification/m1/cleanup-events.json",
    *_LOCAL_QUALIFICATION_PATHS,
    "qualification/registry/closure.json",
    "qualification/registry/results.json",
)


class AcceptanceEvidenceError(EvidenceInputError):
    """Raised when evidence cannot be safely or truthfully collected."""


@dataclass(frozen=True)
class CollectionInput:
    """Caller-owned proof and test outputs; no command is executed by this package."""

    foundation: Mapping[str, Any]
    junit_sources: Mapping[str, Path]
    run_metadata: Mapping[str, Any]
    package_install_receipt: Mapping[str, object] | None = None
    runtime_observation_receipt: Mapping[str, object] | None = None


@dataclass(frozen=True)
class CollectionResult:
    run_directory: Path
    semantic_sha256: str
    redacted_values: int


@dataclass(frozen=True)
class _Scenario:
    raw: Mapping[str, Any]
    plan: ReplayPlan
    root: RootSeed
    result: ReplayRunResult


@dataclass(frozen=True)
class _Foundation:
    raw: Mapping[str, Any]
    plan: ReplayPlan
    root: RootSeed
    scope: ScopeManifest
    vulnerable: tuple[_Scenario, ...]
    patched: _Scenario
    controls: tuple[_Scenario, ...]


class _JunitSummary(TypedDict):
    tests: int
    failures: int
    errors: int
    skipped: int
    testcase_identity_count: int
    testcase_identities: list[str]
    testcase_identity_sha256: str


def collect_from_json_file(
    *,
    foundation_json: Path,
    output_root: Path,
    run_id: str,
    junit_sources: Mapping[str, Path],
    run_metadata: Mapping[str, Any],
) -> CollectionResult:
    """Read only caller-selected artifacts and delegate to the pure collector."""

    return collect_acceptance_evidence(
        input=CollectionInput(
            foundation=json_mapping(foundation_json),
            junit_sources=junit_sources,
            run_metadata=run_metadata,
        ),
        output_root=output_root,
        run_id=run_id,
    )


def collect_acceptance_evidence(
    *, input: CollectionInput, output_root: Path, run_id: str
) -> CollectionResult:
    """Create one non-overwriteable evidence tree after cross-artifact validation."""

    try:
        validate_run_id(run_id)
    except EvidenceInputError as error:
        raise AcceptanceEvidenceError("invalid run id") from error
    validated = _validate_foundation(input.foundation)
    junit_bytes, junit_results = _read_junit_sources(input.junit_sources)
    _validate_supporting_inputs(input, validated, junit_results)
    qualification_payloads = _m01_qualification_payloads(validated, junit_results)
    qualification_payloads.update(
        _local_deliverable_qualification_payloads(junit_results, input.run_metadata)
    )
    observed_evidence_paths: tuple[str, ...] = _REQUIRED_RELATIVE
    verified_admission_digests: dict[str, str] = {}
    if input.package_install_receipt is not None:
        repository_marker = input.run_metadata.get("repository_marker")
        if not isinstance(repository_marker, str):
            raise AcceptanceEvidenceError("package install qualification marker is invalid")
        try:
            package_install_receipt = validate_package_install_receipt(
                input.package_install_receipt,
                expected_repository_marker=repository_marker,
            )
        except PackageInstallQualificationError:
            raise AcceptanceEvidenceError(
                "package install qualification receipt is invalid"
            ) from None
        qualification_payloads[PACKAGE_INSTALL_QUALIFICATION_PATH] = package_install_receipt
        observed_evidence_paths = (*_REQUIRED_RELATIVE, PACKAGE_INSTALL_QUALIFICATION_PATH)
    if input.runtime_observation_receipt is not None:
        repository_marker = input.run_metadata.get("repository_marker")
        if not isinstance(repository_marker, str):
            raise AcceptanceEvidenceError("runtime observation qualification marker is invalid")
        try:
            runtime_receipt = validate_runtime_observation_qualification(
                input.runtime_observation_receipt,
                expected_repository_marker=repository_marker,
            )
        except RuntimeObservationQualificationError:
            raise AcceptanceEvidenceError(
                "runtime observation qualification receipt is invalid"
            ) from None
        qualification_payloads[RUNTIME_OBSERVATION_QUALIFICATION_PATH] = runtime_receipt.model_dump(
            mode="json"
        )
        qualification_payloads[OBSERVED_FRAGMENT_QUALIFICATION_PATH] = (
            observed_fragment_qualification_payload(runtime_receipt)
        )
        observed_evidence_paths = (
            *observed_evidence_paths,
            RUNTIME_OBSERVATION_QUALIFICATION_PATH,
            OBSERVED_FRAGMENT_QUALIFICATION_PATH,
        )
        verified_admission_digests = runtime_observation_admissions(runtime_receipt)
    try:
        registry = load_acceptance_registry()
        registry_closure = build_acceptance_registry_closure(registry)
        passing_test_identities = tuple(
            identity
            for name in _JUNIT_NAMES
            for identity in junit_results[name]["testcase_identities"]
        )
        acceptance_results = derive_acceptance_results(
            registry,
            passing_test_identities=passing_test_identities,
            observed_evidence_paths=observed_evidence_paths,
            verified_admission_digests=verified_admission_digests,
        )
    except AcceptanceResultsError:
        raise AcceptanceEvidenceError("acceptance registry results could not be derived") from None

    root = output_root / run_id
    try:
        root.mkdir(parents=True, exist_ok=False)
    except FileExistsError as error:
        raise AcceptanceEvidenceError("acceptance run already exists") from error

    try:
        artifacts = _proof_artifact_payloads(validated.raw)
        artifacts.update(qualification_payloads)
        artifacts["qualification/registry/closure.json"] = registry_closure.model_dump(mode="json")
        artifacts["qualification/registry/results.json"] = acceptance_results.model_dump(
            mode="json"
        )
        manifest = _run_manifest(
            validated,
            input.run_metadata,
            junit_results,
            run_id,
            registry_closure,
            acceptance_results,
        )
        artifacts["run-manifest.json"] = manifest
        for relative, payload in artifacts.items():
            atomic_json(root / relative, payload)
        for name, source in junit_bytes.items():
            atomic_write(root / "junit" / f"{name}.xml", source)
        _write_manifest(root, observed_evidence_paths)
    except BaseException:
        # A partial directory must never be mistaken for an immutable proof.
        shutil.rmtree(root, ignore_errors=True)
        raise
    return CollectionResult(root, semantic_sha256(validated.raw), 0)


def _mapping(value: object, message: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise AcceptanceEvidenceError(message)
    return value


def _parse_plan(value: object) -> ReplayPlan:
    try:
        return ReplayPlan.model_validate_json(canonical_json_bytes(value))
    except (ValidationError, EvidenceInputError) as error:
        raise AcceptanceEvidenceError("foundation replay plan is invalid") from error


def _parse_root(value: object) -> RootSeed:
    try:
        return RootSeed.model_validate_json(canonical_json_bytes(value))
    except (ValidationError, EvidenceInputError) as error:
        raise AcceptanceEvidenceError("foundation root seed is invalid") from error


def _parse_scope(value: object) -> ScopeManifest:
    try:
        return ScopeManifest.model_validate_json(canonical_json_bytes(value))
    except (ValidationError, EvidenceInputError) as error:
        raise AcceptanceEvidenceError("foundation scope manifest is invalid") from error


def _parse_result(value: object) -> ReplayRunResult:
    try:
        return ReplayRunResult.model_validate_json(canonical_json_bytes(value))
    except (ValidationError, EvidenceInputError) as error:
        raise AcceptanceEvidenceError("foundation replay result is invalid") from error


def _same_json(left: object, right: object) -> bool:
    return canonical_json_bytes(left) == canonical_json_bytes(right)


def _scenario(value: object) -> _Scenario:
    raw = _mapping(value, "scenario proof is invalid")
    if set(raw) != _SCENARIO_FIELDS:
        raise AcceptanceEvidenceError("scenario proof schema is invalid")
    plan = _parse_plan(raw.get("plan"))
    root = _parse_root(raw.get("root_seed"))
    result = _parse_result(raw.get("replay_result"))
    if plan.root_seed_id != root.root_seed_id or result.plan_id != plan.plan_id:
        raise AcceptanceEvidenceError("scenario plan, root, and result identifiers do not match")
    if result.root_fingerprint != root.capture.fingerprint:
        raise AcceptanceEvidenceError("scenario result is not bound to its supplied root capture")
    if raw.get("signature") != result.deterministic_signature():
        raise AcceptanceEvidenceError("scenario signature does not match its replay result")
    if raw.get("action_log_hash") != canonical_sha256(result.action_log):
        raise AcceptanceEvidenceError("scenario action-log hash does not match its replay result")
    if (
        raw.get("status") != result.status.value
        or raw.get("failed_step_id") != result.failed_step_id
    ):
        raise AcceptanceEvidenceError("scenario status projection does not match its replay result")

    planned_step_ids = tuple(step.step_id for step in plan.steps)
    if (
        tuple(step.step_id for step in result.steps) != planned_step_ids
        or tuple(entry.step_id for entry in result.action_log) != planned_step_ids
        or any(
            entry.action != planned.action
            for planned, entry in zip(plan.steps, result.action_log, strict=True)
        )
    ):
        raise AcceptanceEvidenceError(
            "scenario replay trace does not execute the supplied plan envelopes exactly"
        )
    for planned, executed in zip(plan.steps, result.steps, strict=True):
        typed_action = planned.action.action
        if isinstance(typed_action, HttpRequestAction) and (
            len(executed.observations) != 1
            or executed.observations[0].payload.get("response_status")
            not in typed_action.expected_statuses
        ):
            raise AcceptanceEvidenceError(
                "scenario HTTP observation is outside the typed action status contract"
            )

    result_steps = {step.step_id: step for step in result.steps}
    final = result_steps.get(plan.steps[-1].step_id)
    if final is None:
        raise AcceptanceEvidenceError("scenario result omits the final planned step")
    observations = [item.model_dump(mode="json") for item in final.observations]
    oracle_results = [item.model_dump(mode="json") for item in final.oracle_results]
    if not _same_json(raw.get("terminal_observations"), observations) or not _same_json(
        raw.get("oracle_results"), oracle_results
    ):
        raise AcceptanceEvidenceError("scenario terminal evidence projection is inconsistent")
    outcome = final.oracle_results[-1].result.value if final.oracle_results else None
    response_status = (
        final.observations[-1].payload.get("response_status") if final.observations else None
    )
    if raw.get("oracle_outcome") != outcome or raw.get("response_status") != response_status:
        raise AcceptanceEvidenceError("scenario verdict projection is inconsistent")
    _validate_oracle_semantics(plan, root, final)
    final_evidence_count = sum(len(item.evidence_ids) for item in final.observations)
    if raw.get("evidence_count") != final_evidence_count:
        raise AcceptanceEvidenceError("scenario evidence count is inconsistent")

    record_ids = _validate_evidence_records(raw.get("evidence_records"), result)
    referenced = {
        evidence_id
        for step in result.steps
        for evidence_group in (
            *(item.evidence_ids for item in step.observations),
            *(item.evidence_ids for item in step.oracle_results),
        )
        for evidence_id in evidence_group
    }
    if referenced != set(record_ids):
        raise AcceptanceEvidenceError("scenario evidence records do not cover replay references")
    return _Scenario(raw=raw, plan=plan, root=root, result=result)


def _validate_oracle_semantics(plan: ReplayPlan, root: RootSeed, final: ReplayStepResult) -> None:
    if len(final.oracle_results) != 1 or len(final.observations) != 1:
        raise AcceptanceEvidenceError("foundation final step requires one observation and Oracle")
    oracle = final.oracle_results[0]
    observation = final.observations[0]
    observed = oracle.observed
    if set(observed) != {
        "after_fingerprint",
        "checks",
        "mode",
        "observation_ids",
        "verdict",
    }:
        raise AcceptanceEvidenceError("foundation Oracle observation schema is invalid")
    raw_checks = observed.get("checks")
    if not isinstance(raw_checks, tuple | list) or len(raw_checks) != len(_LAB_CHECK_IDS):
        raise AcceptanceEvidenceError("foundation Oracle check set is invalid")
    checks: dict[str, bool] = {}
    for raw_check in raw_checks:
        check = _mapping(raw_check, "foundation Oracle check is invalid")
        check_id = check.get("check_id")
        passed = check.get("passed")
        if (
            set(check) != {"check_id", "passed"}
            or not isinstance(check_id, str)
            or type(passed) is not bool
            or check_id in checks
        ):
            raise AcceptanceEvidenceError("foundation Oracle check is invalid")
        checks[check_id] = passed
    if set(checks) != _LAB_CHECK_IDS:
        raise AcceptanceEvidenceError("foundation Oracle check set is invalid")

    expected_mode = {
        "lab-vulnerable": "vulnerable",
        "lab-patched": "patched",
    }.get(root.target_version)
    observation_ids = observed.get("observation_ids")
    if not isinstance(observation_ids, tuple | list):
        raise AcceptanceEvidenceError("foundation Oracle observation ids are invalid")
    if (
        expected_mode is None
        or oracle.oracle_type.value != "tenant_isolation"
        or oracle.invariant != _LAB_INVARIANT
        or oracle.evaluator_version != _LAB_EVALUATOR_VERSION
        or oracle.provenance.value != "observed"
        or oracle.deterministic is not True
        or oracle.world_id != plan.steps[-1].action.world_id
        or observed.get("mode") != expected_mode
        or observed.get("after_fingerprint") != final.after_fingerprint
        or tuple(observation_ids) != (observation.observation_id,)
    ):
        raise AcceptanceEvidenceError("foundation Oracle identity or trace binding is invalid")
    if tuple(oracle.evidence_ids) != tuple(observation.evidence_ids):
        raise AcceptanceEvidenceError("foundation Oracle evidence binding is invalid")

    payload = observation.payload
    outcome = oracle.result
    if outcome is OracleOutcome.VIOLATED:
        semantics_valid = (
            observed.get("verdict") == "VIOLATED"
            and all(checks.values())
            and expected_mode == "vulnerable"
            and payload.get("response_status") == 200
            and payload.get("action_type") == "document.read"
            and payload.get("actor_principal_id") == "principal-a"
            and payload.get("owner_tenant") == "tenant-b"
            and payload.get("resource_id") == "doc-b-protected"
            and payload.get("protected_field_present") is True
            and payload.get("provenance") == "OBSERVED"
        )
    elif outcome is OracleOutcome.SATISFIED:
        protected = payload.get("protected_field_present")
        same_tenant = (payload.get("actor_principal_id"), payload.get("owner_tenant")) in {
            ("principal-a", "tenant-a"),
            ("principal-b", "tenant-b"),
        }
        base_satisfied = (
            observed.get("verdict") == "NOT_VIOLATED"
            and not any(checks.values())
            and payload.get("provenance") == "OBSERVED"
            and (protected is False or (protected is True and same_tenant))
        )
        semantics_valid = base_satisfied and (
            expected_mode != "patched"
            or (
                observation.kind == "lab.document.read"
                and payload.get("action_type") == "document.read"
                and payload.get("actor_principal_id") == "principal-a"
                and payload.get("outcome") == "tenant_boundary_blocked"
                and payload.get("resource_id") == "doc-b-protected"
                and protected is False
                and payload.get("response_status") == 403
            )
        )
    elif outcome is OracleOutcome.INCONCLUSIVE:
        semantics_valid = (
            observed.get("verdict") == "NOT_VIOLATED"
            and not any(checks.values())
            and payload.get("provenance") == "MOCKED"
            and payload.get("action_type") == "decoy.mock_policy"
        )
    else:
        semantics_valid = False
    if not semantics_valid:
        raise AcceptanceEvidenceError("foundation Oracle predicate is internally inconsistent")

    expected_result_hash = canonical_sha256(
        {
            "oracle_id": _LAB_ORACLE_ID,
            "version": _LAB_ORACLE_VERSION,
            "world_id": oracle.world_id,
            "action_id": plan.steps[-1].action.action_id,
            "observed": observed,
            "evidence_ids": oracle.evidence_ids,
        }
    ).removeprefix("sha256:")
    if oracle.oracle_result_id != f"oracle.result:{expected_result_hash[:24]}":
        raise AcceptanceEvidenceError("foundation Oracle result id is not content-derived")


def _validate_evidence_records(value: object, result: ReplayRunResult) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise AcceptanceEvidenceError("scenario evidence records are missing")
    records: list[Mapping[str, Any]] = []
    for value_record in value:
        record = _mapping(value_record, "scenario evidence record is invalid")
        if set(record) != _EVIDENCE_RECORD_FIELDS:
            raise AcceptanceEvidenceError("scenario evidence record schema is invalid")
        evidence_id = record.get("evidence_id")
        text_fields = ("action_type", "actor_principal_id", "outcome")
        if (
            not isinstance(evidence_id, str)
            or any(
                not isinstance(record.get(field), str)
                or not _SAFE_RECORD_VALUE_RE.fullmatch(record[field])
                for field in text_fields
            )
            or not isinstance(record.get("resource_id"), str)
            or record.get("provenance") not in {"OBSERVED", "MOCKED"}
        ):
            raise AcceptanceEvidenceError("scenario evidence record values are invalid")
        _metadata_datetime(record.get("at"))
        records.append(record)

    record_ids = tuple(str(record["evidence_id"]) for record in records)
    if len(record_ids) != len(set(record_ids)):
        raise AcceptanceEvidenceError("scenario evidence record identifiers are invalid")

    observations_by_evidence: dict[str, ReplayObservation] = {}
    ordered_observation_evidence: list[str] = []
    for step in result.steps:
        for observation in step.observations:
            if len(observation.evidence_ids) != 1:
                raise AcceptanceEvidenceError(
                    "foundation observations must bind one complete evidence record"
                )
            evidence_id = observation.evidence_ids[0]
            if evidence_id in observations_by_evidence:
                raise AcceptanceEvidenceError("evidence record is bound to multiple observations")
            observations_by_evidence[evidence_id] = observation
            ordered_observation_evidence.append(evidence_id)
    if record_ids != tuple(ordered_observation_evidence):
        raise AcceptanceEvidenceError("scenario evidence record order is inconsistent")

    for record in records:
        evidence_id = str(record["evidence_id"])
        bound_observation = observations_by_evidence.get(evidence_id)
        if bound_observation is None:
            raise AcceptanceEvidenceError("scenario evidence record has no observation")
        payload = bound_observation.payload
        if (
            payload.get("action_type") != record["action_type"]
            or payload.get("actor_principal_id") != record["actor_principal_id"]
            or payload.get("outcome") != record["outcome"]
            or payload.get("resource_id") != record["resource_id"]
            or payload.get("provenance") != record["provenance"]
            or _metadata_datetime(payload.get("controlled_at")) != _metadata_datetime(record["at"])
            or payload.get("evidence_record_hash") != canonical_sha256(record)
        ):
            raise AcceptanceEvidenceError(
                "scenario evidence record does not match its replay observation"
            )
    return record_ids


def _validate_control_profile(scenario: _Scenario, profile: _ControlProfile) -> None:
    """Bind each named negative control to its closed final request and observation semantics."""

    planned = scenario.plan.steps[-1].action.action
    final = scenario.result.steps[-1]
    if not isinstance(planned, HttpRequestAction) or planned.target is None:
        raise AcceptanceEvidenceError(
            "negative control final action is not a concrete HTTP request"
        )
    observation = final.observations[0]
    payload = observation.payload
    target = planned.target
    if (
        planned.method is not HttpMethod.GET
        or target.scheme != "http"
        or target.host != "localhost"
        or target.port != 80
        or target.path != profile.path
        or planned.identity_handle != "identity:test_user_a"
        or planned.query
        or planned.headers
        or planned.template_ref is not None
        or planned.expected_statuses != profile.expected_statuses
        or observation.kind != profile.observation_kind
        or payload.get("action_type") != profile.action_type
        or payload.get("actor_principal_id") != "principal-a"
        or payload.get("outcome") != profile.payload_outcome
        or payload.get("resource_id") != profile.resource_id
        or payload.get("protected_field_present") is not profile.protected_field_present
        or payload.get("provenance") != profile.provenance
        or payload.get("response_status") != profile.response_status
        or (
            profile.owner_tenant is not None and payload.get("owner_tenant") != profile.owner_tenant
        )
    ):
        raise AcceptanceEvidenceError("negative control does not match its named semantic profile")


def _validate_foundation(value: Mapping[str, Any]) -> _Foundation:
    model_calls = value.get("model_calls")
    if (
        set(value) != _FOUNDATION_FIELDS
        or value.get("accepted") is not True
        or type(model_calls) is not int
        or model_calls != 0
        or value.get("network_mode") != "offline-in-process"
        or value.get("network_guard") != NETWORK_GUARD_ID
    ):
        raise AcceptanceEvidenceError("foundation verification is incomplete or not accepted")
    try:
        assert_secret_free(value)
    except EvidenceInputError as error:
        raise AcceptanceEvidenceError("secret-like foundation evidence was rejected") from error

    plan = _parse_plan(value["canonical_plan"])
    root = _parse_root(value["root_state"])
    scope = _parse_scope(value["scope_manifest"])
    if value["plan_hash"] != canonical_sha256(plan) or plan.root_seed_id != root.root_seed_id:
        raise AcceptanceEvidenceError("canonical plan hash or root binding is invalid")

    vulnerable_summary = _mapping(value["vulnerable"], "vulnerable proof is invalid")
    if set(vulnerable_summary) != _VULNERABLE_SUMMARY_FIELDS:
        raise AcceptanceEvidenceError("vulnerable summary schema is invalid")
    raw_attempts = vulnerable_summary.get("attempts")
    if not isinstance(raw_attempts, list) or len(raw_attempts) != 5:
        raise AcceptanceEvidenceError("exactly five vulnerable attempts must be retained")
    vulnerable = tuple(_scenario(item) for item in raw_attempts)
    if any(item.plan != plan or item.root != root for item in vulnerable):
        raise AcceptanceEvidenceError(
            "vulnerable attempts do not share the canonical plan and root"
        )
    if len({item.result.run_id for item in vulnerable}) != len(vulnerable):
        raise AcceptanceEvidenceError("vulnerable attempt identifiers must be unique")
    signatures = {item.result.deterministic_signature() for item in vulnerable}
    vulnerable_reference = vulnerable[0]
    if (
        len(signatures) != 1
        or any(item.result.status is not ReplayRunStatus.SUCCEEDED for item in vulnerable)
        or any(
            item.raw.get("oracle_outcome") != OracleOutcome.VIOLATED.value for item in vulnerable
        )
        or any(item.raw.get("response_status") != 200 for item in vulnerable)
        or vulnerable_summary.get("deterministic") is not True
        or vulnerable_summary.get("all_runs_succeeded") is not True
        or vulnerable_summary.get("run_count") != len(vulnerable)
        or vulnerable_summary.get("action_log_hash")
        != vulnerable_reference.raw.get("action_log_hash")
        or vulnerable_summary.get("action_log_count") != len(vulnerable_reference.result.action_log)
        or vulnerable_summary.get("oracle_outcome")
        != vulnerable_reference.raw.get("oracle_outcome")
        or vulnerable_summary.get("response_status")
        != vulnerable_reference.raw.get("response_status")
        or vulnerable_summary.get("signature") != vulnerable_reference.raw.get("signature")
    ):
        raise AcceptanceEvidenceError("retained vulnerable attempts do not prove determinism")
    first_action_log = [
        entry.model_dump(mode="json") for entry in vulnerable_reference.result.action_log
    ]
    if not _same_json(value["canonical_action_log"], first_action_log):
        raise AcceptanceEvidenceError("canonical action log is not the retained replay action log")

    patched_summary = _mapping(value["patched"], "patched proof is invalid")
    if set(patched_summary) != _PATCHED_SUMMARY_FIELDS:
        raise AcceptanceEvidenceError("patched summary schema is invalid")
    patched = _scenario(patched_summary.get("proof"))
    if (
        patched.plan != plan
        or patched.root.root_seed_id != root.root_seed_id
        or patched.root.random_seed != root.random_seed
        or patched.root.clock_epoch != root.clock_epoch
        or patched.root.adapter_versions != root.adapter_versions
        or value["patched_uses_identical_plan"] is not True
        or patched.raw.get("oracle_outcome") != OracleOutcome.SATISFIED.value
        or patched.raw.get("response_status") != 403
        or patched.raw.get("failure_code") != "ORACLE_EXPECTATION_MISMATCH"
        or patched.result.status is not ReplayRunStatus.FAILED
        or patched_summary.get("failed_step_id") != patched.result.failed_step_id
        or patched_summary.get("evidence_count") != patched.raw.get("evidence_count")
        or patched_summary.get("action_log_hash") != patched.raw.get("action_log_hash")
        or patched_summary.get("action_log_count") != len(patched.result.action_log)
        or patched_summary.get("failure_code") != patched.raw.get("failure_code")
        or patched_summary.get("oracle_outcome") != patched.raw.get("oracle_outcome")
        or patched_summary.get("response_status") != patched.raw.get("response_status")
        or patched_summary.get("status") != patched.raw.get("status")
    ):
        raise AcceptanceEvidenceError("patched proof is not the same-plan blocked replay")

    raw_controls = value["negative_controls"]
    if not isinstance(raw_controls, list) or not raw_controls:
        raise AcceptanceEvidenceError("negative controls are missing")
    controls = tuple(_scenario(item) for item in raw_controls)
    if any(item.root != root for item in controls):
        raise AcceptanceEvidenceError("negative controls do not share the canonical clean root")
    names = [item.raw.get("name") for item in controls]
    required_controls = {
        name: (profile.outcome.value, profile.response_status)
        for name, profile in _CONTROL_PROFILES.items()
    }
    control_results = {
        item.raw.get("name"): (item.raw.get("oracle_outcome"), item.raw.get("response_status"))
        for item in controls
    }
    if any(not isinstance(name, str) for name in names):
        raise AcceptanceEvidenceError("negative-control proofs are invalid")
    if (
        len(names) != len(set(names))
        or len({item.plan.plan_id for item in controls}) != len(controls)
        or len({item.result.run_id for item in controls}) != len(controls)
        or any(item.raw.get("oracle_outcome") == OracleOutcome.VIOLATED.value for item in controls)
        or any(item.result.status is not ReplayRunStatus.SUCCEEDED for item in controls)
        or control_results != required_controls
    ):
        raise AcceptanceEvidenceError("negative-control proofs are invalid")
    for item in controls:
        name = str(item.raw["name"])
        _validate_control_profile(item, _CONTROL_PROFILES[name])

    all_scenarios = (*vulnerable, patched, *controls)
    _validate_policy_bindings(value["policy_decisions"], scope, all_scenarios)
    return _Foundation(value, plan, root, scope, vulnerable, patched, controls)


def _validate_policy_bindings(
    supplied: object,
    scope: ScopeManifest,
    scenarios: tuple[_Scenario, ...],
) -> None:
    decisions = _mapping(supplied, "policy decisions are invalid")
    expected: dict[str, ActionEnvelope] = {}
    authorization_deadlines: dict[str, datetime] = {}
    plans: dict[str, ReplayPlan] = {}
    for scenario in scenarios:
        prior_plan = plans.setdefault(scenario.plan.plan_id, scenario.plan)
        if prior_plan != scenario.plan:
            raise AcceptanceEvidenceError("a replay plan id is bound to different plans")
        for step in scenario.plan.steps:
            reference = step.action.policy_decision_ref
            previous = expected.setdefault(reference, step.action)
            if previous != step.action:
                raise AcceptanceEvidenceError("a policy reference is bound to different actions")
            prior_deadline = authorization_deadlines.setdefault(
                reference, scenario.root.clock_epoch
            )
            if scenario.root.clock_epoch < prior_deadline:
                authorization_deadlines[reference] = scenario.root.clock_epoch
    if set(decisions) != set(expected):
        raise AcceptanceEvidenceError("policy decisions do not exactly cover replay actions")

    scope_hash = canonical_sha256(scope)
    for reference, action in expected.items():
        record = _mapping(decisions[reference], "policy decision record is invalid")
        if set(record) != _POLICY_AUTHORIZATION_FIELDS:
            raise AcceptanceEvidenceError("policy authorization record schema is invalid")
        try:
            decision = PolicyDecision.model_validate_json(canonical_json_bytes(record["decision"]))
        except (ValidationError, EvidenceInputError, KeyError) as error:
            raise AcceptanceEvidenceError("policy decision is invalid") from error
        requests_before = record.get("requests_before")
        writes_before = record.get("write_requests_before")
        if type(requests_before) is not int or type(writes_before) is not int:
            raise AcceptanceEvidenceError("policy budget counters are invalid")
        evaluated_at = _metadata_datetime(record.get("evaluated_at"))
        not_before = _optional_metadata_datetime(record.get("not_before"))
        expires_at = _metadata_datetime(record.get("expires_at"))
        request = PolicyRequest(
            scope_manifest=scope,
            action_envelope=action,
            budget=BudgetSnapshot(
                requests_in_window=requests_before,
                request_window_seconds=1.0,
                write_requests_used=writes_before,
            ),
            evaluated_at=evaluated_at,
        )
        expected_reservation = canonical_sha256(
            {
                "envelope_hash": canonical_sha256(action),
                "scope_manifest_hash": scope_hash,
                "requests_before": requests_before,
                "write_requests_before": writes_before,
            }
        )
        expected_decision = evaluate_policy(request)
        typed_action = action.action
        is_write = isinstance(typed_action, HttpRequestAction) and typed_action.method not in {
            HttpMethod.GET,
            HttpMethod.HEAD,
            HttpMethod.OPTIONS,
        }
        if (
            record.get("policy_decision_ref") != reference
            or record.get("action_id") != action.action_id
            or record.get("idempotency_key") != action.idempotency_key
            or record.get("envelope_hash") != canonical_sha256(action)
            or record.get("policy_request_hash") != request.fingerprint()
            or record.get("scope_manifest_hash") != scope_hash
            or record.get("budget_reservation_id") != expected_reservation
            or evaluated_at > authorization_deadlines[reference]
            or not_before != scope.spec.validity.not_before
            or expires_at != scope.spec.validity.expires_at
            or decision != expected_decision
            or not decision.allowed
            or record.get("is_write") is not is_write
        ):
            raise AcceptanceEvidenceError("policy authorization is not bound to its replay action")

    for plan in plans.values():
        write_requests = 0
        for requests, step in enumerate(plan.steps):
            record = _mapping(
                decisions[step.action.policy_decision_ref], "policy decision record is invalid"
            )
            requests_before = record.get("requests_before")
            writes_before = record.get("write_requests_before")
            typed_action = step.action.action
            is_write = isinstance(typed_action, HttpRequestAction) and typed_action.method not in {
                HttpMethod.GET,
                HttpMethod.HEAD,
                HttpMethod.OPTIONS,
            }
            if (
                type(requests_before) is not int
                or requests_before != requests
                or type(writes_before) is not int
                or writes_before != write_requests
                or record.get("is_write") is not is_write
            ):
                raise AcceptanceEvidenceError("policy budget reservation order is inconsistent")
            if is_write:
                write_requests += 1


def _validate_supporting_inputs(
    input: CollectionInput,
    foundation: _Foundation,
    junit_results: Mapping[str, _JunitSummary],
) -> None:
    metadata = input.run_metadata
    if not metadata or set(metadata) != _RUN_METADATA_FIELDS:
        raise AcceptanceEvidenceError("run metadata is incomplete")
    model_calls = metadata.get("model_calls")
    test_exit_code = metadata.get("test_exit_code")
    controlled_clock = _metadata_datetime(metadata.get("controlled_clock_epoch"))
    started_at = _metadata_datetime(metadata.get("started_at"))
    completed_at = _metadata_datetime(metadata.get("completed_at"))
    text_fields = (
        "repository_marker",
        "python_version",
        "docker_compose_version",
        "target_mode",
        "root_seed",
        "test_command",
        "app_source_digest",
        "scope_manifest_hash",
        "replay_plan_hash",
        "oracle_definition_hash",
        "runtime_dependency_fingerprint",
        "network_mode",
        "network_guard",
    )
    if (
        any(
            not isinstance(metadata.get(field), str) or not metadata[field] for field in text_fields
        )
        or metadata.get("target_mode") != "differential"
        or metadata.get("network_mode") != "offline-in-process"
        or metadata.get("network_guard") != NETWORK_GUARD_ID
        or metadata.get("test_command") != ACCEPTANCE_TEST_COMMAND
        or type(model_calls) is not int
        or model_calls != 0
        or type(test_exit_code) is not int
        or test_exit_code != 0
        or metadata.get("root_seed") != foundation.root.root_seed_id
        or metadata.get("replay_plan_hash") != canonical_sha256(foundation.plan)
        or metadata.get("scope_manifest_hash") != canonical_sha256(foundation.scope)
        or not _SHA256_RE.fullmatch(str(metadata.get("app_source_digest")))
        or not _SHA256_RE.fullmatch(str(metadata.get("oracle_definition_hash")))
        or not _SHA256_RE.fullmatch(str(metadata.get("runtime_dependency_fingerprint")))
        or controlled_clock != foundation.root.clock_epoch
        or completed_at < started_at
    ):
        raise AcceptanceEvidenceError("run metadata is not bound to the foundation proof")
    if any(
        summary["tests"] < 1 or summary["failures"] or summary["errors"] or summary["skipped"]
        for summary in junit_results.values()
    ):
        raise AcceptanceEvidenceError("accepted evidence requires passing, nonempty JUnit inputs")
    try:
        assert_secret_free(metadata)
    except EvidenceInputError as error:
        raise AcceptanceEvidenceError("secret-like run metadata was rejected") from error


def _metadata_datetime(value: object) -> datetime:
    if not isinstance(value, str) or not value:
        raise AcceptanceEvidenceError("run metadata timestamps are invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise AcceptanceEvidenceError("run metadata timestamps are invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise AcceptanceEvidenceError("run metadata timestamps must use UTC")
    return parsed


def _optional_metadata_datetime(value: object) -> datetime | None:
    return None if value is None else _metadata_datetime(value)


def _read_junit_sources(
    sources: Mapping[str, Path],
) -> tuple[dict[str, bytes], dict[str, _JunitSummary]]:
    if set(sources) != set(_JUNIT_NAMES):
        raise AcceptanceEvidenceError("all required JUnit inputs must be supplied")
    content_by_name: dict[str, bytes] = {}
    for name in _JUNIT_NAMES:
        try:
            content = sources[name].read_bytes()
        except OSError as error:
            raise AcceptanceEvidenceError("JUnit input is missing or invalid") from error
        content_by_name[name] = content
    return content_by_name, _read_junit_payloads(content_by_name)


def _read_junit_payloads(sources: Mapping[str, bytes]) -> dict[str, _JunitSummary]:
    """Validate JUnit from caller-captured bytes without reopening a source path."""

    if set(sources) != set(_JUNIT_NAMES):
        raise AcceptanceEvidenceError("all required JUnit inputs must be supplied")
    summaries: dict[str, _JunitSummary] = {}
    for name in _JUNIT_NAMES:
        content = sources[name]
        if type(content) is not bytes:
            raise AcceptanceEvidenceError("JUnit input is missing or invalid")
        try:
            root = ElementTree.fromstring(content)
        except ElementTree.ParseError as error:
            raise AcceptanceEvidenceError("JUnit input is missing or invalid") from error
        if root.tag not in {"testsuite", "testsuites"}:
            raise AcceptanceEvidenceError("JUnit input is missing or invalid")
        try:
            assert_secret_free(content.decode("utf-8"))
        except UnicodeDecodeError as error:
            raise AcceptanceEvidenceError("JUnit input is not UTF-8") from error
        except EvidenceInputError as error:
            raise AcceptanceEvidenceError("secret-like JUnit input was rejected") from error
        suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
        summaries[name] = _junit_summary(name, suites)
    return summaries


def _junit_summary(name: str, suites: list[ElementTree.Element]) -> _JunitSummary:
    fields = ("tests", "failures", "errors", "skipped")
    summary: dict[str, int] = dict.fromkeys(fields, 0)
    identities: list[str] = []
    try:
        for suite in suites:
            counts = {field: int(suite.attrib.get(field, "0")) for field in fields}
            if any(count < 0 for count in counts.values()):
                raise ValueError
            testcases = list(suite.findall("testcase"))
            actual = {
                "tests": len(testcases),
                "failures": sum(case.find("failure") is not None for case in testcases),
                "errors": sum(case.find("error") is not None for case in testcases),
                "skipped": sum(case.find("skipped") is not None for case in testcases),
            }
            if counts != actual:
                raise AcceptanceEvidenceError("JUnit aggregate counts are inconsistent")
            for case in testcases:
                classname = case.attrib.get("classname")
                testcase_name = case.attrib.get("name")
                if not classname or not testcase_name:
                    raise AcceptanceEvidenceError("JUnit testcase identity is invalid")
                identities.append(f"{classname}::{testcase_name}")
            for field in fields:
                summary[field] += counts[field]
    except ValueError as error:
        raise AcceptanceEvidenceError("JUnit aggregate counts are invalid") from error
    sorted_identities = sorted(identities)
    if len(sorted_identities) != len(set(sorted_identities)):
        raise AcceptanceEvidenceError("JUnit testcase identities must be unique")
    allowed_prefixes = _JUNIT_ALLOWED_PREFIXES[name]
    if any(not identity.startswith(allowed_prefixes) for identity in sorted_identities):
        raise AcceptanceEvidenceError("JUnit testcase does not belong to its required group")
    if not _JUNIT_REQUIRED_IDENTITIES[name].issubset(sorted_identities):
        raise AcceptanceEvidenceError("JUnit required testcase set is incomplete")
    return _JunitSummary(
        tests=summary["tests"],
        failures=summary["failures"],
        errors=summary["errors"],
        skipped=summary["skipped"],
        testcase_identity_count=len(sorted_identities),
        testcase_identities=sorted_identities,
        testcase_identity_sha256=canonical_sha256(sorted_identities),
    )


def _oracle_projection(scenario: Mapping[str, Any]) -> dict[str, object]:
    replay_result = _mapping(scenario.get("replay_result"), "scenario replay result is invalid")
    return {
        "name": scenario["name"],
        "oracle_outcome": scenario["oracle_outcome"],
        "terminal_observations": scenario["terminal_observations"],
        "oracle_results": scenario["oracle_results"],
        "evidence_records": scenario["evidence_records"],
        "replay_trace_hash": replay_result["trace_hash"],
    }


def _junit_qualification_binding(
    junit_results: Mapping[str, _JunitSummary],
    group: str,
    identities: tuple[str, ...],
) -> dict[str, object]:
    observed = frozenset(junit_results[group]["testcase_identities"])
    if not set(identities).issubset(observed):
        raise AcceptanceEvidenceError("qualification JUnit testcase set is incomplete")
    return {
        "report": f"junit/{group}.xml",
        "testcase_identities": list(identities),
        "report_identity_sha256": junit_results[group]["testcase_identity_sha256"],
    }


def _local_deliverable_qualification_payloads(
    junit_results: Mapping[str, _JunitSummary],
    run_metadata: Mapping[str, Any],
) -> dict[str, object]:
    source_fields = (
        "repository_marker",
        "app_source_digest",
        "oracle_definition_hash",
        "runtime_dependency_fingerprint",
        "test_command",
        "network_mode",
        "network_guard",
    )
    source_binding: dict[str, str] = {}
    for field in source_fields:
        value = run_metadata.get(field)
        if not isinstance(value, str) or not value:
            raise AcceptanceEvidenceError("local qualification source binding is invalid")
        source_binding[field] = value

    registry = load_acceptance_registry()
    by_id = {requirement.id: requirement for requirement in registry.requirements}
    receipts: dict[str, object] = {}
    for path, spec in _LOCAL_QUALIFICATION_SPECS.items():
        requirements: list[dict[str, object]] = []
        for requirement_id in spec.requirement_ids:
            requirement = by_id.get(requirement_id)
            if requirement is None or {item.path for item in requirement.evidence} != {path}:
                raise AcceptanceEvidenceError("local qualification registry binding is invalid")
            requirements.append(
                {
                    "requirement_id": requirement.id,
                    "kind": requirement.kind.value,
                    "gate_class": requirement.gate_class.value,
                    "statement_sha256": canonical_sha256(
                        {"id": requirement.id, "statement": requirement.statement}
                    ),
                    "evidence_roles": sorted(item.role for item in requirement.evidence),
                    "test_selectors": sorted(item.selector for item in requirement.tests),
                }
            )
        receipt: dict[str, object] = {
            "schema_version": "stateweaver-local-deliverable-qualification-v1",
            "producer": "stateweaver.evidence.collector",
            "qualification_kind": spec.qualification_kind,
            "evidence_path": path,
            "requirement_ids": list(spec.requirement_ids),
            "requirements": requirements,
            "registry_sha256": EXPECTED_ACCEPTANCE_REGISTRY_SHA256,
            "source_binding": source_binding,
            "junit": [
                _junit_qualification_binding(junit_results, group, identities)
                for group, identities in spec.junit
            ],
            "qualification_basis": "exact-passing-junit-bound-to-source-and-registry",
            "status": "LOCAL_IMPLEMENTATION_QUALIFIED",
            "authoritative": False,
            "promotable": False,
            "release_eligible": False,
            "exit_criterion_satisfied": False,
            "limitations": list(spec.limitations),
        }
        receipt["receipt_digest"] = canonical_sha256(receipt)
        receipts[path] = receipt
    try:
        assert_secret_free(receipts)
    except EvidenceInputError:
        raise AcceptanceEvidenceError(
            "derived local qualification receipt is not redacted"
        ) from None
    return receipts


def _root_layer_payloads(root: RootSeed) -> dict[str, dict[str, object]]:
    layers: dict[str, dict[str, object]] = {}
    for artifact in root.capture.artifacts:
        raw = artifact.model_dump(mode="json")
        layer = raw.get("layer")
        payload = raw.get("payload")
        if not isinstance(layer, str) or layer in layers or not isinstance(payload, dict):
            raise AcceptanceEvidenceError("qualification root capture layer is invalid")
        layers[layer] = {
            "schema_version": raw["schema_version"],
            "content_hash": raw["content_hash"],
            "payload": payload,
        }
    required = {
        "application",
        "database",
        "cache",
        "queue",
        "browser",
        "configuration",
        "clock",
    }
    if set(layers) != required:
        raise AcceptanceEvidenceError("qualification requires all seven root capture layers")
    return layers


def _configuration_payload(
    layers: Mapping[str, Mapping[str, object]], expected_mode: str
) -> dict[str, object]:
    payload = _mapping(
        layers["configuration"].get("payload"),
        "qualification configuration layer is invalid",
    )
    required = {
        "arbitrary_actions_enabled",
        "external_egress_enabled",
        "mode",
        "network_scope",
        "seed",
    }
    if (
        set(payload) != required
        or payload.get("mode") != expected_mode
        or payload.get("arbitrary_actions_enabled") is not False
        or payload.get("external_egress_enabled") is not False
        or payload.get("network_scope") != "in-process-only"
        or payload.get("seed") != "m0-canonical-v1"
    ):
        raise AcceptanceEvidenceError("qualification configuration is not explicit and fail closed")
    return dict(payload)


def _session_manifest(layers: Mapping[str, Mapping[str, object]]) -> tuple[list[object], str]:
    browser = layers["browser"]
    payload = _mapping(browser.get("payload"), "qualification browser layer is invalid")
    sessions = payload.get("sessions")
    if not isinstance(sessions, list) or not sessions:
        raise AcceptanceEvidenceError("qualification browser session capture is missing")
    required = {
        "session_handle",
        "principal_id",
        "issued_role",
        "session_generation",
        "issued_at",
        "expires_at",
        "identity_hash",
    }
    handles: set[str] = set()
    hashes: set[str] = set()
    for raw_session in sessions:
        session = _mapping(raw_session, "qualification browser session is invalid")
        handle = session.get("session_handle")
        identity_hash = session.get("identity_hash")
        generation = session.get("session_generation")
        string_fields = (
            handle,
            session.get("principal_id"),
            session.get("issued_role"),
            session.get("issued_at"),
            session.get("expires_at"),
            identity_hash,
        )
        if (
            set(session) != required
            or any(not isinstance(value, str) or not value for value in string_fields)
            or type(generation) is not int
            or generation < 0
            or not isinstance(identity_hash, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", identity_hash) is None
            or not isinstance(handle, str)
            or handle in handles
            or identity_hash in hashes
        ):
            raise AcceptanceEvidenceError("qualification browser session schema is invalid")
        handles.add(handle)
        hashes.add(identity_hash)
    try:
        assert_secret_free(sessions)
    except EvidenceInputError:
        raise AcceptanceEvidenceError(
            "qualification browser session capture is not redacted"
        ) from None
    content_hash = browser.get("content_hash")
    if not isinstance(content_hash, str):
        raise AcceptanceEvidenceError("qualification browser layer digest is invalid")
    return sessions, content_hash


def _clean_root_contamination(
    layers: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    application = _mapping(
        layers["application"].get("payload"),
        "qualification application layer is invalid",
    )
    cache = _mapping(layers["cache"].get("payload"), "qualification cache layer is invalid")
    queue = _mapping(layers["queue"].get("payload"), "qualification queue layer is invalid")
    retained = application.get("retained_session_handles")
    markers = {
        "cache_entry": cache.get("entry"),
        "evidence_count": application.get("evidence_count"),
        "queue_entry": queue.get("entry"),
        "reference_claimed_by_session_handle": application.get(
            "reference_claimed_by_session_handle"
        ),
        "reference_published": application.get("reference_published"),
        "replay_window_closes_at": application.get("replay_window_closes_at"),
        "replay_window_opens_at": application.get("replay_window_opens_at"),
        "retained_session_handles": retained,
        "role_downgraded_at": application.get("role_downgraded_at"),
    }
    if (
        markers["cache_entry"] is not None
        or markers["evidence_count"] != 0
        or markers["queue_entry"] is not None
        or markers["reference_claimed_by_session_handle"] is not None
        or markers["reference_published"] is not False
        or markers["replay_window_closes_at"] is not None
        or markers["replay_window_opens_at"] is not None
        or retained not in ([], ())
        or markers["role_downgraded_at"] is not None
    ):
        raise AcceptanceEvidenceError("qualification root retains replay contamination")
    return markers


def _m01_qualification_payloads(
    foundation: _Foundation,
    junit_results: Mapping[str, _JunitSummary],
) -> dict[str, object]:
    vulnerable_layers = _root_layer_payloads(foundation.root)
    patched_layers = _root_layer_payloads(foundation.patched.root)
    vulnerable_configuration = _configuration_payload(vulnerable_layers, "vulnerable")
    patched_configuration = _configuration_payload(patched_layers, "patched")
    sessions, browser_content_hash = _session_manifest(vulnerable_layers)
    contamination = _clean_root_contamination(vulnerable_layers)

    if (
        foundation.root.target_version != "lab-vulnerable"
        or foundation.patched.root.target_version != "lab-patched"
        or foundation.root.root_seed_id != foundation.patched.root.root_seed_id
        or foundation.root.random_seed != foundation.patched.root.random_seed
        or foundation.root.clock_epoch != foundation.patched.root.clock_epoch
        or foundation.root.adapter_versions != foundation.patched.root.adapter_versions
    ):
        raise AcceptanceEvidenceError("qualification vulnerable and patched roots are not isolated")

    root_fingerprints = [scenario.result.root_fingerprint for scenario in foundation.vulnerable]
    if len(root_fingerprints) != 5 or set(root_fingerprints) != {
        foundation.root.capture.fingerprint
    }:
        raise AcceptanceEvidenceError("qualification clean root fingerprints are not equivalent")

    provider_payloads: dict[str, object] = {}
    for provider in ("database", "cache", "queue"):
        layer = vulnerable_layers[provider]
        payload = layer["payload"]
        content_hash = layer["content_hash"]
        if content_hash != canonical_sha256(payload):
            raise AcceptanceEvidenceError("qualification provider digest is inconsistent")
        provider_payloads[provider] = {
            "schema_version": layer["schema_version"],
            "content_hash": content_hash,
        }

    foundation_hash = semantic_sha256(foundation.raw)
    schema = "stateweaver-local-qualification-receipt-v1"
    cleanup_identities = tuple(
        f"{_M1_CLEANUP_BASE_IDENTITY}[{phase}-{failure_code}]"
        for phase, failure_code in _M1_CLEANUP_CASES
    )
    receipts: dict[str, object] = {
        "qualification/m0/property-seed.json": {
            "schema_version": schema,
            "requirement_id": "M0-C08",
            "foundation_semantic_sha256": foundation_hash,
            "seed": _M0_PROPERTY_SEED,
            "examples_per_property": _M0_PROPERTY_EXAMPLES,
            "permutation_invariant": True,
            "nonsemantic_metadata_ignored": True,
            "security_semantic_change_detected": True,
            "junit": _junit_qualification_binding(
                junit_results, "contracts", _M0_PROPERTY_IDENTITIES
            ),
        },
        "qualification/m0/mode-isolation.json": {
            "schema_version": schema,
            "requirement_id": "M0-L02",
            "foundation_semantic_sha256": foundation_hash,
            "vulnerable": {
                "mode": vulnerable_configuration["mode"],
                "target_version": foundation.root.target_version,
                "root_fingerprint": foundation.root.capture.fingerprint,
            },
            "patched": {
                "mode": patched_configuration["mode"],
                "target_version": foundation.patched.root.target_version,
                "root_fingerprint": foundation.patched.root.capture.fingerprint,
            },
            "shared_root_seed_id": foundation.root.root_seed_id,
            "shared_random_seed": foundation.root.random_seed,
            "shared_clock_epoch": foundation.root.model_dump(mode="json")["clock_epoch"],
            "shared_adapter_versions": dict(foundation.root.adapter_versions),
            "shared_process_state": False,
            "junit": _junit_qualification_binding(
                junit_results, "lab", (_M0_MODE_ISOLATION_IDENTITY,)
            ),
        },
        "qualification/m0/configuration-snapshot.json": {
            "schema_version": schema,
            "requirement_id": "M0-L10",
            "foundation_semantic_sha256": foundation_hash,
            "construction_requires_explicit_mode": True,
            "missing_or_invalid_mode_rejected": True,
            "vulnerable": vulnerable_configuration,
            "patched": patched_configuration,
            "junit": _junit_qualification_binding(
                junit_results, "lab", (_M0_CONFIGURATION_IDENTITY,)
            ),
        },
        "qualification/m1/session-manifest.json": {
            "schema_version": schema,
            "requirement_id": "M1-R02",
            "foundation_semantic_sha256": foundation_hash,
            "layer_schema_version": vulnerable_layers["browser"]["schema_version"],
            "layer_content_hash": browser_content_hash,
            "storage_schema": sorted(sessions[0]) if isinstance(sessions[0], dict) else [],
            "session_count": len(sessions),
            "sessions": sessions,
            "raw_bearer_values_retained": False,
            "junit": _junit_qualification_binding(junit_results, "lab", (_M1_SESSION_IDENTITY,)),
        },
        "qualification/m1/provider-digests.json": {
            "schema_version": schema,
            "requirement_id": "M1-R04",
            "foundation_semantic_sha256": foundation_hash,
            "providers": provider_payloads,
            "clean_root_fingerprints": root_fingerprints,
            "equivalent_across_clean_roots": True,
            "junit": _junit_qualification_binding(
                junit_results, "replay", (_M1_PROVIDER_IDENTITY,)
            ),
        },
        "qualification/m1/reset-diff.json": {
            "schema_version": schema,
            "requirement_id": "M1-R05",
            "foundation_semantic_sha256": foundation_hash,
            "baseline_root_fingerprint": foundation.root.capture.fingerprint,
            "observed_root_fingerprints": root_fingerprints,
            "baseline_contamination_markers": contamination,
            "seeded_browser_session_count": len(sessions),
            "retained_contamination": False,
            "junit": _junit_qualification_binding(junit_results, "lab", (_M1_RESET_IDENTITY,)),
        },
        "qualification/m1/nondeterminism.json": {
            "schema_version": schema,
            "requirement_id": "M1-R10",
            "foundation_semantic_sha256": foundation_hash,
            "fixture": "controlled-observation-drift",
            "run_ids": ["run.001", "run.002", "run.003"],
            "classification": "NONDETERMINISTIC",
            "divergent_run_id": "run.002",
            "finding_promotion_allowed": False,
            "junit": _junit_qualification_binding(
                junit_results, "replay", (_M1_NONDETERMINISM_IDENTITY,)
            ),
        },
        "qualification/m1/cleanup-events.json": {
            "schema_version": schema,
            "requirement_id": "M1-R11",
            "foundation_semantic_sha256": foundation_hash,
            "injected_boundaries": [
                {
                    "phase": phase,
                    "failure_code": failure_code,
                    "testcase_identity": testcase_identity,
                }
                for (phase, failure_code), testcase_identity in zip(
                    _M1_CLEANUP_CASES, cleanup_identities, strict=True
                )
            ],
            "cleanup_failure_visible": True,
            "cleanup_failure_detail_redacted": True,
            "reset_timeout_cleanup_observed": True,
            "cleanup_reentrant_calls": 2,
            "next_reset_permitted": True,
            "junit": _junit_qualification_binding(
                junit_results,
                "replay",
                (*cleanup_identities, _M1_CLEANUP_FAILURE_IDENTITY, _M1_RESET_TIMEOUT_IDENTITY),
            ),
        },
    }
    try:
        assert_secret_free(receipts)
    except EvidenceInputError:
        raise AcceptanceEvidenceError("derived qualification receipt is not redacted") from None
    return receipts


def _proof_artifact_payloads(foundation: Mapping[str, Any]) -> dict[str, object]:
    vulnerable = _mapping(foundation["vulnerable"], "vulnerable proof is invalid")
    patched = _mapping(foundation["patched"], "patched proof is invalid")
    attempts = vulnerable["attempts"]
    controls = foundation["negative_controls"]
    if not isinstance(attempts, list) or not isinstance(controls, list):
        raise AcceptanceEvidenceError("foundation scenario collections are invalid")
    patched_proof = _mapping(patched["proof"], "patched proof is invalid")
    return {
        "foundation/source.json": foundation,
        "oracle/vulnerable.json": {
            "attempts": [_oracle_projection(_mapping(item, "invalid attempt")) for item in attempts]
        },
        "oracle/patched.json": _oracle_projection(patched_proof),
        "oracle/negative-controls.json": [
            _oracle_projection(_mapping(item, "invalid control")) for item in controls
        ],
        "replay/root-state.json": foundation["root_state"],
        "replay/plan.json": foundation["canonical_plan"],
        "replay/attempts.json": {
            "vulnerable": attempts,
            "patched": patched_proof,
            "negative_controls": controls,
        },
        "replay/failure-localization.json": {
            "failed_step_id": patched_proof["failed_step_id"],
            "failure_code": patched_proof["failure_code"],
            "oracle_results": patched_proof["oracle_results"],
            "status": patched_proof["status"],
            "terminal_observations": patched_proof["terminal_observations"],
        },
        "replay/action-log.json": foundation["canonical_action_log"],
        "policy/decisions.json": foundation["policy_decisions"],
    }


def _run_manifest(
    foundation: _Foundation,
    metadata: Mapping[str, Any],
    junit_results: Mapping[str, _JunitSummary],
    run_id: str,
    registry_closure: AcceptanceRegistryClosure,
    acceptance_results: AcceptanceResults,
) -> dict[str, object]:
    closure_payload = registry_closure.model_dump(mode="json")
    results_payload = acceptance_results.model_dump(mode="json")
    return {
        "schema_version": "acceptance-evidence-v1",
        "run_id": run_id,
        "accepted": True,
        "foundation_semantic_sha256": semantic_sha256(foundation.raw),
        "root_state_fingerprint": foundation.root.capture.fingerprint,
        "plan_hash": canonical_sha256(foundation.plan),
        "policy_semantic_sha256": semantic_sha256(foundation.raw["policy_decisions"]),
        "metadata": metadata,
        "collected_at": datetime.now(UTC).isoformat(),
        "redacted_values": 0,
        "junit": junit_results,
        "acceptance_registry": {
            "closure_sha256": sha256_bytes(canonical_json_bytes(closure_payload)),
            "registry_sha256": registry_closure.registry_sha256,
            "results_sha256": sha256_bytes(canonical_json_bytes(results_payload)),
            "summary": acceptance_results.summary.model_dump(mode="json"),
        },
    }


def _write_manifest(root: Path, required_relative: tuple[str, ...]) -> None:
    lines: list[str] = []
    for relative in required_relative:
        target = root / relative
        if not target.is_file():
            raise AcceptanceEvidenceError("required artifact was not produced")
        lines.append(f"{sha256_bytes(target.read_bytes())}  {relative}")
    atomic_write(root / "artifact-manifest.sha256", ("\n".join(lines) + "\n").encode("ascii"))
