"""Adversarial tests for the closed M0-M8 acceptance registry."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from importlib import resources
from pathlib import Path
from typing import Any, cast

import pytest
from stateweaver.evidence import (
    EXPECTED_ACCEPTANCE_REGISTRY_SHA256,
    EXPECTED_REQUIREMENT_IDS,
    EXPECTED_TESTLESS_REQUIREMENT_IDS,
    QUALIFICATION_REQUIREMENT_IDS,
    AcceptanceRegistryError,
    GateClass,
    RequirementKind,
    load_acceptance_registry,
    parse_acceptance_registry,
    validate_acceptance_registry_selectors,
)
from stateweaver.evidence._io import canonical_json_bytes
from stateweaver.evidence.acceptance_registry import (
    _parse_acceptance_registry_structure,
    _validate_acceptance_registry_selectors_structure,
)


def _packaged_bytes() -> bytes:
    return resources.files("stateweaver.evidence").joinpath("acceptance-registry.json").read_bytes()


def _payload() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_packaged_bytes()))


def _requirement(payload: dict[str, Any], requirement_id: str) -> dict[str, Any]:
    requirements = cast(list[dict[str, Any]], payload["requirements"])
    return next(item for item in requirements if item["id"] == requirement_id)


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_packaged_registry_is_canonical_and_has_exact_required_ids() -> None:
    packaged = _packaged_bytes()
    registry = load_acceptance_registry()

    assert parse_acceptance_registry(packaged) == registry
    assert canonical_json_bytes(json.loads(packaged)) == packaged
    assert canonical_json_bytes(registry.model_dump(mode="json")) == packaged
    assert hashlib.sha256(packaged).hexdigest() == EXPECTED_ACCEPTANCE_REGISTRY_SHA256
    assert (
        tuple(requirement.id for requirement in registry.requirements) == EXPECTED_REQUIREMENT_IDS
    )
    assert tuple(requirement.id for requirement in registry.requirements[-20:]) == (
        QUALIFICATION_REQUIREMENT_IDS
    )
    assert len(registry.requirements) == 92
    assert all(requirement.required is True for requirement in registry.requirements)
    assert {
        requirement.id for requirement in registry.requirements if not requirement.tests
    } == EXPECTED_TESTLESS_REQUIREMENT_IDS
    assert all(
        requirement.tests
        for requirement in registry.requirements
        if requirement.gate_class in {GateClass.LOCAL_OFFLINE, GateClass.LOCAL_IN_PROCESS}
    )
    assert sum(requirement.milestone == "M0" for requirement in registry.requirements) == 18
    assert sum(requirement.milestone == "M1" for requirement in registry.requirements) == 12
    assert {
        milestone: sum(requirement.milestone == milestone for requirement in registry.requirements)
        for milestone in ("M2", "M3", "M4", "M5", "M6", "M7", "M8")
    } == {"M2": 10, "M3": 7, "M4": 7, "M5": 7, "M6": 11, "M7": 11, "M8": 8}
    assert sum(requirement.milestone == "GLOBAL" for requirement in registry.requirements) == 1


def test_local_implementation_rows_bind_their_semantic_pytest_nodes() -> None:
    by_id = {requirement.id: requirement for requirement in load_acceptance_registry().requirements}

    expected = {
        "M0-C07": (
            "packages/contracts/tests/test_contracts.py::"
            "test_six_m0_contract_families_are_exported_from_the_public_surface",
        ),
        "M0-L02": (
            "labs/multitenant-saas/tests/test_lab.py::"
            "test_vulnerable_and_patched_apps_have_no_process_global_mode_state",
        ),
        "M0-L09": (
            "labs/multitenant-saas/tests/test_lab.py::test_host_header_is_fail_closed",
            "labs/multitenant-saas/tests/test_lab.py::"
            "test_local_lab_flow_uses_no_socket_connect_dns_or_wildcard_bind",
        ),
        "M0-L10": ("labs/multitenant-saas/tests/test_lab.py::test_invalid_mode_is_rejected",),
        "M1-R02": (
            "labs/multitenant-saas/tests/test_lab.py::"
            "test_evidence_and_layered_capture_never_record_bearer_values",
        ),
        "M1-R07": (
            "adapters/environments/in_process_lab/tests/"
            "test_in_process_lab_environment.py::"
            "test_exact_plan_binds_typed_action_parameters_by_content_hash",
            "labs/multitenant-saas/tests/test_lab.py::"
            "test_typed_action_union_rejects_unknown_actions_and_extras",
        ),
        "M7-B03": (
            "benchmarks/statechainbench/tests/test_runner.py::"
            "test_holdout_comparison_uses_raw_matched_results_and_shows_tiered_gain",
        ),
        "SW-M4-MATERIALIZED": (
            "tests/integration/worlds/test_live_materialized_search.py::"
            "test_observed_search_materializes_only_four_two_one_and_reclaims_every_world",
        ),
    }
    assert {
        requirement_id: tuple(mapping.selector for mapping in by_id[requirement_id].tests)
        for requirement_id in expected
    } == expected


def test_kind_and_source_closure_cover_acceptance_deliverable_and_exit_rows() -> None:
    registry = load_acceptance_registry()
    by_id = {requirement.id: requirement for requirement in registry.requirements}

    assert by_id["M0-C01"].kind is RequirementKind.ACCEPTANCE
    assert by_id["M1-R12"].kind is RequirementKind.ACCEPTANCE
    assert by_id["M2-W01"].kind is RequirementKind.DELIVERABLE
    assert by_id["M8-X01"].kind is RequirementKind.EXIT
    assert by_id["SW-M6-TRUST"].kind is RequirementKind.QUALIFICATION
    assert by_id["M0-C01"].source.path == "docs/architecture/M0_M1_ACCEPTANCE.md"
    assert by_id["M7-B06"].source.path == "ARCHITECTURE.md"
    assert by_id["M8-U01"].source.path == "docs/architecture/TRACEABILITY.md"
    assert by_id["SW-M8-PROVIDER"].source.path == "BLOCKERS.md"
    assert all(requirement.evidence for requirement in registry.requirements)


def test_gate_classes_do_not_let_local_evidence_certify_external_claims() -> None:
    registry = load_acceptance_registry()
    by_id = {requirement.id: requirement for requirement in registry.requirements}

    assert by_id["M2-X01"].gate_class is GateClass.LIVE_PROVIDER
    assert by_id["M3-X01"].gate_class is GateClass.RUNTIME_OBSERVATION
    assert by_id["M4-X01"].gate_class is GateClass.MATERIALIZED_RUNTIME
    assert by_id["M5-X01"].gate_class is GateClass.MATERIALIZED_RUNTIME
    assert by_id["M6-R01"].gate_class is GateClass.EXTERNAL_TRUST
    assert by_id["M6-X01"].gate_class is GateClass.CLEAN_MACHINE
    assert by_id["M7-X01"].gate_class is GateClass.INDEPENDENT_BENCHMARK
    assert by_id["SW-M2-PROVIDERS"].gate_class is GateClass.MATERIALIZED_RUNTIME
    assert by_id["SW-M8-NEWUSER"].gate_class is GateClass.EXTERNAL_NEW_USER
    assert by_id["SW-M8-PACKAGE"].gate_class is GateClass.CLEAN_MACHINE
    assert by_id["SW-M8-PROVIDER"].gate_class is GateClass.LIVE_MODEL_PROVIDER
    assert "external-reviewer" in by_id["M7-X01"].platforms
    assert "clean-machine" in by_id["M8-X01"].platforms


def test_synthetic_four_way_selector_cannot_stand_for_real_provider_qualification() -> None:
    registry = load_acceptance_registry()
    by_id = {requirement.id: requirement for requirement in registry.requirements}

    assert tuple(mapping.selector for mapping in by_id["SW-M2-4WAY"].tests) == (
        "tests/integration/worlds/test_live_docker_compose.py::"
        "test_four_live_siblings_overlap_isolate_and_restore",
    )
    assert not by_id["SW-M2-LIVE"].tests
    assert not by_id["SW-M2-PROVIDERS"].tests
    assert not by_id["SW-M2-CLEANUP"].tests
    assert (
        "Real PostgreSQL, Redis, queue, browser-session, filesystem"
        in by_id["SW-M2-PROVIDERS"].statement
    )


def test_every_declared_selector_is_repo_relative_and_resolves() -> None:
    registry = load_acceptance_registry()

    validate_acceptance_registry_selectors(registry, _repository_root())

    assert all(
        ".py::test_" in mapping.selector and "\\" not in mapping.selector
        for requirement in registry.requirements
        for mapping in requirement.tests
    )


def test_missing_selector_fails_without_leaking_the_locator() -> None:
    payload = _payload()
    selector = "packages/contracts/tests/missing.py::test_private_value"
    test = cast(list[dict[str, Any]], _requirement(payload, "M0-C01")["tests"])[0]
    test["selector"] = selector
    registry = _parse_acceptance_registry_structure(canonical_json_bytes(payload))

    with pytest.raises(AcceptanceRegistryError, match="does not resolve") as captured:
        _validate_acceptance_registry_selectors_structure(registry, _repository_root())

    assert selector not in str(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__suppress_context__ is True


@pytest.mark.parametrize(
    "mutate",
    (
        lambda payload: _requirement(payload, "M0-C01").__setitem__(
            "statement", "A weaker remapped requirement is accepted."
        ),
        lambda payload: cast(dict[str, Any], _requirement(payload, "M0-C01")["source"]).__setitem__(
            "anchor", "M0 / Contracts / Remapped frozen instance"
        ),
        lambda payload: _requirement(payload, "M0-C01").__setitem__(
            "evidence", [{"path": "junit/unrelated.xml", "role": "test-report"}]
        ),
        lambda payload: _requirement(payload, "M0-C01").__setitem__(
            "tests",
            [
                {
                    "selector": (
                        "packages/contracts/tests/test_contracts.py::test_contracts_are_frozen"
                    ),
                    "suite": "pytest-offline",
                }
            ],
        ),
    ),
    ids=("statement", "source", "evidence", "selector"),
)
def test_public_registry_boundaries_reject_semantic_remapping(
    mutate: Callable[[dict[str, Any]], object],
) -> None:
    payload = _payload()
    mutate(payload)
    remapped = canonical_json_bytes(payload)
    structurally_valid = _parse_acceptance_registry_structure(remapped)

    _validate_acceptance_registry_selectors_structure(structurally_valid, _repository_root())
    with pytest.raises(AcceptanceRegistryError, match="digest does not match"):
        parse_acceptance_registry(remapped)
    with pytest.raises(AcceptanceRegistryError, match="digest does not match"):
        validate_acceptance_registry_selectors(structurally_valid, _repository_root())


@pytest.mark.parametrize(
    "mutate",
    (
        lambda payload: payload.__setitem__("status", "pass"),
        lambda payload: _requirement(payload, "M0-C01").__setitem__("status", "pass"),
        lambda payload: cast(dict[str, Any], _requirement(payload, "M0-C01")["source"]).__setitem__(
            "line", 140
        ),
        lambda payload: cast(list[dict[str, Any]], _requirement(payload, "M0-C01")["tests"])[
            0
        ].__setitem__("command", "pytest"),
        lambda payload: cast(list[dict[str, Any]], _requirement(payload, "M0-C01")["evidence"])[
            0
        ].__setitem__("sha256", "0" * 64),
    ),
)
def test_extra_fields_are_rejected_at_every_registry_level(
    mutate: Callable[[dict[str, Any]], object],
) -> None:
    payload = _payload()
    mutate(payload)

    with pytest.raises(AcceptanceRegistryError, match="schema or mapping"):
        _parse_acceptance_registry_structure(canonical_json_bytes(payload))


def test_duplicate_requirement_id_fails_closed_before_row_semantics() -> None:
    payload = _payload()
    requirements = cast(list[dict[str, Any]], payload["requirements"])
    requirements[-1]["id"] = requirements[0]["id"]

    with pytest.raises(AcceptanceRegistryError, match="duplicate requirement id"):
        _parse_acceptance_registry_structure(canonical_json_bytes(payload))


def test_missing_requirement_id_fails_closed() -> None:
    payload = _payload()
    requirements = cast(list[dict[str, Any]], payload["requirements"])
    requirements.pop()

    with pytest.raises(AcceptanceRegistryError, match="missing a required requirement id"):
        _parse_acceptance_registry_structure(canonical_json_bytes(payload))


def test_unknown_requirement_id_fails_closed_without_echoing_it() -> None:
    payload = _payload()
    requirements = cast(list[dict[str, Any]], payload["requirements"])
    requirements[-1]["id"] = "M9-Z99"

    with pytest.raises(AcceptanceRegistryError, match="unknown requirement id") as captured:
        _parse_acceptance_registry_structure(canonical_json_bytes(payload))

    assert "M9-Z99" not in str(captured.value)


def test_requirement_order_is_part_of_the_canonical_registry() -> None:
    payload = _payload()
    requirements = cast(list[dict[str, Any]], payload["requirements"])
    requirements[0], requirements[1] = requirements[1], requirements[0]

    with pytest.raises(AcceptanceRegistryError, match="canonical order"):
        _parse_acceptance_registry_structure(canonical_json_bytes(payload))


@pytest.mark.parametrize(
    ("requirement_id", "field", "replacement"),
    (
        ("M6-X01", "gate_class", "local_offline"),
        ("M8-X01", "gate_class", "local_in_process"),
        ("M7-X01", "platforms", ["python-3.12-plus"]),
        ("M8-U01", "milestone", "M7"),
        (
            "M8-U01",
            "source",
            {"anchor": "M8 / Deliverables / README starts lab", "path": "ARCHITECTURE.md"},
        ),
    ),
)
def test_gate_platform_milestone_and_source_tampering_fails_closed(
    requirement_id: str, field: str, replacement: object
) -> None:
    payload = _payload()
    _requirement(payload, requirement_id)[field] = replacement

    with pytest.raises(AcceptanceRegistryError, match="schema or mapping"):
        _parse_acceptance_registry_structure(canonical_json_bytes(payload))


def test_test_suite_cannot_be_downgraded_below_the_gate() -> None:
    payload = _payload()
    test = cast(list[dict[str, Any]], _requirement(payload, "M0-C01")["tests"])[0]
    test["suite"] = "pytest-local"

    with pytest.raises(AcceptanceRegistryError, match="schema or mapping"):
        _parse_acceptance_registry_structure(canonical_json_bytes(payload))


def test_testless_posture_is_closed_for_implemented_and_unimplemented_rows() -> None:
    payload = _payload()
    _requirement(payload, "M0-C01")["tests"] = []
    with pytest.raises(AcceptanceRegistryError, match="schema or mapping"):
        _parse_acceptance_registry_structure(canonical_json_bytes(payload))

    payload = _payload()
    _requirement(payload, "SW-M6-TRUST")["tests"] = [
        {
            "selector": (
                "packages/evidence/tests/test_acceptance_registry.py::"
                "test_packaged_registry_is_canonical_and_has_exact_required_ids"
            ),
            "suite": "pytest-external-trust",
        }
    ]
    with pytest.raises(AcceptanceRegistryError, match="schema or mapping"):
        _parse_acceptance_registry_structure(canonical_json_bytes(payload))


@pytest.mark.parametrize(
    "unsafe_path",
    (
        ".",
        "../escape.json",
        "/absolute.json",
        "C:/boot.ini",
        "runs\\escape.json",
        "runs/evidence?.json",
    ),
)
def test_source_and_evidence_paths_reject_escape_spellings(unsafe_path: str) -> None:
    payload = _payload()
    evidence = cast(list[dict[str, Any]], _requirement(payload, "M0-C01")["evidence"])[0]
    evidence["path"] = unsafe_path

    with pytest.raises(AcceptanceRegistryError, match="schema or mapping"):
        _parse_acceptance_registry_structure(canonical_json_bytes(payload))


@pytest.mark.parametrize(
    "payload",
    (
        json.dumps(_payload(), indent=2).encode("utf-8"),
        _packaged_bytes() + b"\n",
    ),
    ids=("pretty", "trailing-newline"),
)
def test_noncanonical_serializations_are_rejected(payload: bytes) -> None:
    with pytest.raises(AcceptanceRegistryError, match="not canonical"):
        _parse_acceptance_registry_structure(payload)


def test_only_immutable_serialized_bytes_cross_the_registry_boundary() -> None:
    with pytest.raises(AcceptanceRegistryError, match="bytes are invalid"):
        parse_acceptance_registry(bytearray(_packaged_bytes()))  # type: ignore[arg-type]
