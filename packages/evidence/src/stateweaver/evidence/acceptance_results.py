"""Fail-closed row results derived from the exact M0-M8 registry and proof inputs."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Sequence
from enum import StrEnum
from pathlib import PurePosixPath
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from ._io import canonical_json_bytes
from .acceptance_registry import (
    ARCHITECTURE_BASELINE,
    EXPECTED_ACCEPTANCE_REGISTRY_SHA256,
    EXPECTED_REQUIREMENT_IDS,
    EXPECTED_TESTLESS_REQUIREMENT_IDS,
    REGISTRY_VERSION,
    AcceptanceRegistry,
    GateClass,
    load_acceptance_registry,
)

REGISTRY_CLOSURE_SCHEMA_VERSION = "stateweaver-acceptance-registry-closure-v1"
ACCEPTANCE_RESULTS_SCHEMA_VERSION = "stateweaver-acceptance-results-v1"
EXPECTED_ACCEPTANCE_SELECTOR_COUNT = 65

_LOCAL_RESULT_GATES = frozenset({GateClass.LOCAL_OFFLINE, GateClass.LOCAL_IN_PROCESS})
_PATH_PART_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class AcceptanceResultsError(ValueError):
    """A value-safe error raised when row results cannot be derived exactly."""


class AcceptanceResultStatus(StrEnum):
    """Closed status vocabulary for one required acceptance row."""

    PASS = "PASS"
    FAIL = "FAIL"
    NOT_RUN = "NOT_RUN"
    BLOCKED = "BLOCKED"


class _ResultModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)


def _require_exact_registry(registry: AcceptanceRegistry) -> bytes:
    try:
        payload = canonical_json_bytes(registry.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError, RecursionError):
        raise AcceptanceResultsError("acceptance registry identity is invalid") from None
    if hashlib.sha256(payload).hexdigest() != EXPECTED_ACCEPTANCE_REGISTRY_SHA256:
        raise AcceptanceResultsError("acceptance registry identity is invalid")
    return payload


class AcceptanceRegistryClosure(_ResultModel):
    """Exact registry identity and selector coverage retained in every proof."""

    architecture_baseline: str
    registry_sha256: str
    registry_version: str
    requirement_count: int
    requirement_ids: tuple[str, ...]
    schema_version: str
    selector_count: int
    testless_requirement_ids: tuple[str, ...]

    @model_validator(mode="after")
    def _validate_exact_closure(self) -> AcceptanceRegistryClosure:
        if (
            self.schema_version != REGISTRY_CLOSURE_SCHEMA_VERSION
            or self.architecture_baseline != ARCHITECTURE_BASELINE
            or self.registry_version != REGISTRY_VERSION
            or self.registry_sha256 != EXPECTED_ACCEPTANCE_REGISTRY_SHA256
            or self.requirement_ids != EXPECTED_REQUIREMENT_IDS
            or self.requirement_count != len(EXPECTED_REQUIREMENT_IDS)
            or self.testless_requirement_ids != tuple(sorted(EXPECTED_TESTLESS_REQUIREMENT_IDS))
            or self.selector_count != EXPECTED_ACCEPTANCE_SELECTOR_COUNT
        ):
            raise ValueError("acceptance registry closure is invalid")
        return self


class AcceptanceRequirementResult(_ResultModel):
    """One result derived from observed passing tests and admitted proof paths."""

    evidence_missing: tuple[str, ...]
    evidence_observed: tuple[str, ...]
    gate_class: GateClass
    requirement_id: str
    status: AcceptanceResultStatus
    tests_missing: tuple[str, ...]
    tests_observed: tuple[str, ...]

    @field_validator(
        "evidence_missing",
        "evidence_observed",
        "tests_missing",
        "tests_observed",
    )
    @classmethod
    def _validate_sorted_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(set(value))) != value:
            raise ValueError("acceptance result collections must be sorted and unique")
        return value

    @model_validator(mode="after")
    def _validate_status_semantics(self) -> AcceptanceRequirementResult:
        if self.requirement_id not in EXPECTED_REQUIREMENT_IDS:
            raise ValueError("acceptance result requirement id is invalid")
        if set(self.evidence_missing) & set(self.evidence_observed):
            raise ValueError("acceptance evidence result sets overlap")
        if set(self.tests_missing) & set(self.tests_observed):
            raise ValueError("acceptance test result sets overlap")
        has_missing = bool(self.evidence_missing or self.tests_missing)
        expected_status = (
            AcceptanceResultStatus.PASS
            if self.gate_class in _LOCAL_RESULT_GATES and not has_missing
            else (
                AcceptanceResultStatus.NOT_RUN
                if self.gate_class in _LOCAL_RESULT_GATES
                else AcceptanceResultStatus.BLOCKED
            )
        )
        if self.status is not expected_status:
            raise ValueError("acceptance result status is inconsistent with its observed inputs")
        return self


class AcceptanceResultSummary(_ResultModel):
    """Closed counts over the exact required result set."""

    blocked: int
    failed: int
    not_run: int
    passed: int
    required: int

    @model_validator(mode="after")
    def _validate_counts(self) -> AcceptanceResultSummary:
        counts = (self.blocked, self.failed, self.not_run, self.passed, self.required)
        if any(type(value) is not int or value < 0 for value in counts):
            raise ValueError("acceptance result counts are invalid")
        if self.required != len(EXPECTED_REQUIREMENT_IDS) or sum(counts[:4]) != self.required:
            raise ValueError("acceptance result counts do not cover the exact registry")
        return self


class AcceptanceResults(_ResultModel):
    """Machine-derived result ledger for every required M0-M8 row."""

    architecture_baseline: str
    registry_sha256: str
    registry_version: str
    release_eligible: bool
    requirements: tuple[AcceptanceRequirementResult, ...]
    schema_version: str
    summary: AcceptanceResultSummary

    @model_validator(mode="after")
    def _validate_result_closure(self) -> AcceptanceResults:
        if (
            self.schema_version != ACCEPTANCE_RESULTS_SCHEMA_VERSION
            or self.architecture_baseline != ARCHITECTURE_BASELINE
            or self.registry_version != REGISTRY_VERSION
            or self.registry_sha256 != EXPECTED_ACCEPTANCE_REGISTRY_SHA256
            or tuple(row.requirement_id for row in self.requirements) != EXPECTED_REQUIREMENT_IDS
        ):
            raise ValueError("acceptance results do not match the exact registry")
        registry = load_acceptance_registry()
        for row, requirement in zip(self.requirements, registry.requirements, strict=True):
            required_tests = {mapping.selector for mapping in requirement.tests}
            required_evidence = {mapping.path for mapping in requirement.evidence}
            if (
                row.gate_class is not requirement.gate_class
                or set(row.tests_missing) | set(row.tests_observed) != required_tests
                or set(row.evidence_missing) | set(row.evidence_observed) != required_evidence
            ):
                raise ValueError("acceptance result row does not match its registry requirement")
        counts = {
            AcceptanceResultStatus.BLOCKED: 0,
            AcceptanceResultStatus.FAIL: 0,
            AcceptanceResultStatus.NOT_RUN: 0,
            AcceptanceResultStatus.PASS: 0,
        }
        for row in self.requirements:
            counts[row.status] += 1
        expected_summary = AcceptanceResultSummary(
            blocked=counts[AcceptanceResultStatus.BLOCKED],
            failed=counts[AcceptanceResultStatus.FAIL],
            not_run=counts[AcceptanceResultStatus.NOT_RUN],
            passed=counts[AcceptanceResultStatus.PASS],
            required=len(self.requirements),
        )
        if self.summary != expected_summary:
            raise ValueError("acceptance result summary is inconsistent")
        if self.release_eligible is not (
            self.summary.passed == self.summary.required
            and not self.summary.blocked
            and not self.summary.failed
            and not self.summary.not_run
        ):
            raise ValueError("acceptance release eligibility is inconsistent")
        return self


def build_acceptance_registry_closure(
    registry: AcceptanceRegistry,
) -> AcceptanceRegistryClosure:
    """Build the exact immutable closure record for a reviewed registry."""

    _require_exact_registry(registry)
    return AcceptanceRegistryClosure(
        architecture_baseline=registry.architecture_baseline,
        registry_sha256=EXPECTED_ACCEPTANCE_REGISTRY_SHA256,
        registry_version=registry.registry_version,
        requirement_count=len(registry.requirements),
        requirement_ids=tuple(row.id for row in registry.requirements),
        schema_version=REGISTRY_CLOSURE_SCHEMA_VERSION,
        selector_count=sum(len(row.tests) for row in registry.requirements),
        testless_requirement_ids=tuple(sorted(EXPECTED_TESTLESS_REQUIREMENT_IDS)),
    )


def _selector_module_candidates(selector_path: str) -> frozenset[str]:
    path = PurePosixPath(selector_path)
    parts = (*path.parts[:-1], path.stem)
    candidates = {".".join(parts)}
    candidates.update(
        ".".join(parts[index:]) for index, part in enumerate(parts) if part == "tests"
    )
    return frozenset(candidates)


def _is_canonical_evidence_path(value: str) -> bool:
    if (
        not value
        or value in {".", ".."}
        or value != value.strip()
        or "\\" in value
        or ":" in value
        or "%" in value
    ):
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and not value.startswith("/")
        and "//" not in value
        and bool(path.parts)
        and all(
            part not in {"", ".", ".."} and _PATH_PART_RE.fullmatch(part) is not None
            for part in path.parts
        )
        and str(path) == value
    )


def _selector_is_observed(selector: str, identities: Sequence[str]) -> bool:
    selector_path, _, selector_name = selector.partition("::")
    module_candidates = _selector_module_candidates(selector_path)
    parameterized = "[" in selector_name
    base_name = selector_name.partition("[")[0]
    for identity in identities:
        classname, separator, testcase_name = identity.partition("::")
        if not separator or classname not in module_candidates:
            continue
        if testcase_name == selector_name or (
            not parameterized and testcase_name.startswith(f"{base_name}[")
        ):
            return True
    return False


def derive_acceptance_results(
    registry: AcceptanceRegistry,
    *,
    passing_test_identities: Sequence[str],
    observed_evidence_paths: Iterable[str],
) -> AcceptanceResults:
    """Derive every row without allowing local inputs to promote non-local gates."""

    _require_exact_registry(registry)
    if any(not isinstance(identity, str) or not identity for identity in passing_test_identities):
        raise AcceptanceResultsError("passing test identities are invalid")
    identities = tuple(sorted(set(passing_test_identities)))
    if len(identities) != len(passing_test_identities):
        raise AcceptanceResultsError("passing test identities must be unique")
    raw_paths = tuple(observed_evidence_paths)
    if any(
        not isinstance(path, str) or not _is_canonical_evidence_path(path) for path in raw_paths
    ):
        raise AcceptanceResultsError("observed evidence paths are invalid")
    if len(set(raw_paths)) != len(raw_paths):
        raise AcceptanceResultsError("observed evidence paths must be unique")
    observed_paths = frozenset(raw_paths)

    rows: list[AcceptanceRequirementResult] = []
    for requirement in registry.requirements:
        required_tests = tuple(sorted(mapping.selector for mapping in requirement.tests))
        tests_observed = tuple(
            selector for selector in required_tests if _selector_is_observed(selector, identities)
        )
        tests_missing = tuple(sorted(set(required_tests) - set(tests_observed)))
        required_evidence = tuple(sorted({mapping.path for mapping in requirement.evidence}))
        evidence_observed = tuple(path for path in required_evidence if path in observed_paths)
        evidence_missing = tuple(sorted(set(required_evidence) - set(evidence_observed)))
        status = (
            AcceptanceResultStatus.PASS
            if requirement.gate_class in _LOCAL_RESULT_GATES
            and not tests_missing
            and not evidence_missing
            else (
                AcceptanceResultStatus.NOT_RUN
                if requirement.gate_class in _LOCAL_RESULT_GATES
                else AcceptanceResultStatus.BLOCKED
            )
        )
        rows.append(
            AcceptanceRequirementResult(
                evidence_missing=evidence_missing,
                evidence_observed=evidence_observed,
                gate_class=requirement.gate_class,
                requirement_id=requirement.id,
                status=status,
                tests_missing=tests_missing,
                tests_observed=tests_observed,
            )
        )

    counts = {
        status: sum(row.status is status for row in rows) for status in AcceptanceResultStatus
    }
    summary = AcceptanceResultSummary(
        blocked=counts[AcceptanceResultStatus.BLOCKED],
        failed=counts[AcceptanceResultStatus.FAIL],
        not_run=counts[AcceptanceResultStatus.NOT_RUN],
        passed=counts[AcceptanceResultStatus.PASS],
        required=len(rows),
    )
    return AcceptanceResults(
        architecture_baseline=registry.architecture_baseline,
        registry_sha256=EXPECTED_ACCEPTANCE_REGISTRY_SHA256,
        registry_version=registry.registry_version,
        release_eligible=summary.passed == summary.required,
        requirements=tuple(rows),
        schema_version=ACCEPTANCE_RESULTS_SCHEMA_VERSION,
        summary=summary,
    )
