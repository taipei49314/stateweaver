"""Canonical, fail-closed registry for the M0-M8 acceptance surface."""

from __future__ import annotations

import ast
import hashlib
import json
import re
from enum import StrEnum
from importlib import resources
from pathlib import Path, PurePosixPath
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator, model_validator

from ._io import canonical_json_bytes

SCHEMA_VERSION = "stateweaver-acceptance-registry-v2"
REGISTRY_VERSION = "2026-08-09.3"
ARCHITECTURE_BASELINE = "stateweaver-m0-m8-2026-08-09"
MAX_REGISTRY_BYTES = 256 * 1024
EXPECTED_ACCEPTANCE_REGISTRY_SHA256 = (
    "616dab7af859bcbfd3bf8df35b46ae321dda5e116b40abce1eb6567acdc2bc48"
)


def _numbered_ids(milestone: int, category: str, count: int) -> tuple[str, ...]:
    return tuple(f"M{milestone}-{category}{number:02d}" for number in range(1, count + 1))


ARCHITECTURE_REQUIREMENT_IDS = (
    *_numbered_ids(0, "C", 8),
    *_numbered_ids(0, "L", 10),
    *_numbered_ids(1, "R", 12),
    *_numbered_ids(2, "W", 5),
    "M2-X01",
    *_numbered_ids(3, "T", 5),
    "M3-X01",
    *_numbered_ids(4, "S", 5),
    "M4-X01",
    *_numbered_ids(5, "C", 5),
    "M5-X01",
    *_numbered_ids(6, "R", 5),
    "M6-X01",
    *_numbered_ids(7, "B", 6),
    "M7-X01",
    *_numbered_ids(8, "U", 4),
    "M8-X01",
)
QUALIFICATION_REQUIREMENT_IDS = (
    "SW-REGISTRY",
    "SW-M2-LIVE",
    "SW-M2-4WAY",
    "SW-M2-PROVIDERS",
    "SW-M2-CLEANUP",
    "SW-M3-OBSERVED",
    "SW-M4-MATERIALIZED",
    "SW-M5-CHAIN",
    "SW-M6-ACQUIRE",
    "SW-M6-TRUST",
    "SW-M6-ISSUE",
    "SW-M6-REPLAY",
    "SW-M6-PROMOTE",
    "SW-M7-FAIR",
    "SW-M7-PREREG",
    "SW-M7-HOLDOUT",
    "SW-M7-REPRO",
    "SW-M8-NEWUSER",
    "SW-M8-PACKAGE",
    "SW-M8-PROVIDER",
)
EXPECTED_REQUIREMENT_IDS = (*ARCHITECTURE_REQUIREMENT_IDS, *QUALIFICATION_REQUIREMENT_IDS)
EXPECTED_REQUIREMENT_ID_SET = frozenset(EXPECTED_REQUIREMENT_IDS)

EXPECTED_TESTLESS_REQUIREMENT_IDS = frozenset(
    {
        "M2-X01",
        "M3-X01",
        "M4-X01",
        "M5-X01",
        "M6-R01",
        "M6-X01",
        "M7-X01",
        "M8-U01",
        "M8-U02",
        "M8-U03",
        "M8-U04",
        "M8-X01",
        "SW-M2-LIVE",
        "SW-M2-PROVIDERS",
        "SW-M2-CLEANUP",
        "SW-M3-OBSERVED",
        "SW-M5-CHAIN",
        "SW-M6-ACQUIRE",
        "SW-M6-TRUST",
        "SW-M6-ISSUE",
        "SW-M6-REPLAY",
        "SW-M6-PROMOTE",
        "SW-M7-FAIR",
        "SW-M7-PREREG",
        "SW-M7-HOLDOUT",
        "SW-M7-REPRO",
        "SW-M8-NEWUSER",
        "SW-M8-PACKAGE",
        "SW-M8-PROVIDER",
    }
)

_REQUIREMENT_ID_RE = re.compile(r"^M([0-8])-([A-Z])(\d{2})$")
_PATH_PART_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_PLATFORM_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,63}$")
_SUITE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_SELECTOR_RE = re.compile(
    r"^(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.py"
    r"::[A-Za-z_][A-Za-z0-9_]*(?:\[[A-Za-z0-9_.-]+\])?$"
)


class AcceptanceRegistryError(ValueError):
    """A public, value-safe error for an invalid acceptance registry."""


class RequirementKind(StrEnum):
    """The normative role of a registry row."""

    ACCEPTANCE = "acceptance"
    DELIVERABLE = "deliverable"
    EXIT = "exit"
    QUALIFICATION = "qualification"


class GateClass(StrEnum):
    """The strongest environment needed to satisfy a registry row."""

    LOCAL_OFFLINE = "local_offline"
    LOCAL_IN_PROCESS = "local_in_process"
    LIVE_PROVIDER = "live_provider"
    RUNTIME_OBSERVATION = "runtime_observation"
    MATERIALIZED_RUNTIME = "materialized_runtime"
    LIVE_MODEL_PROVIDER = "live_model_provider"
    CLEAN_MACHINE = "clean_machine"
    EXTERNAL_TRUST = "external_trust"
    INDEPENDENT_BENCHMARK = "independent_benchmark"
    EXTERNAL_NEW_USER = "external_new_user"


class _RegistryModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)


def _validate_relative_path(value: str) -> str:
    if (
        not value
        or value in {".", ".."}
        or value != value.strip()
        or "\\" in value
        or ":" in value
        or "%" in value
    ):
        raise ValueError("path must use a canonical relative POSIX spelling")
    path = PurePosixPath(value)
    if path.is_absolute() or value.startswith("/") or "//" in value:
        raise ValueError("path must be relative")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("path traversal is forbidden")
    if not path.parts or any(_PATH_PART_RE.fullmatch(part) is None for part in path.parts):
        raise ValueError("path components must use the closed ASCII spelling")
    if str(path) != value:
        raise ValueError("path must be canonical")
    return value


class SourceMapping(_RegistryModel):
    """A stable locator into a normative architecture document."""

    anchor: str
    path: str

    @field_validator("anchor")
    @classmethod
    def _validate_anchor(cls, value: str) -> str:
        if value != value.strip() or not 5 <= len(value) <= 160 or "\n" in value:
            raise ValueError("source anchor must be a bounded single line")
        return value

    @field_validator("path")
    @classmethod
    def _validate_path(cls, value: str) -> str:
        return _validate_relative_path(value)


class TestMapping(_RegistryModel):
    """A test selector and the execution suite that owns it."""

    selector: str
    suite: str

    @field_validator("selector")
    @classmethod
    def _validate_selector(cls, value: str) -> str:
        if not _SELECTOR_RE.fullmatch(value):
            raise ValueError("test selector must be a repo-relative pytest node selector")
        path, _, _ = value.partition("::")
        _validate_relative_path(path)
        return value

    @field_validator("suite")
    @classmethod
    def _validate_suite(cls, value: str) -> str:
        if not _SUITE_RE.fullmatch(value):
            raise ValueError("test suite must be a canonical slug")
        return value


class EvidenceMapping(_RegistryModel):
    """An artifact path and its semantic role in satisfying a row."""

    path: str
    role: str

    @field_validator("path")
    @classmethod
    def _validate_path(cls, value: str) -> str:
        return _validate_relative_path(value)

    @field_validator("role")
    @classmethod
    def _validate_role(cls, value: str) -> str:
        if not _SLUG_RE.fullmatch(value):
            raise ValueError("evidence role must be a canonical slug")
        return value


def _expected_kind(requirement_id: str) -> RequirementKind:
    if requirement_id in QUALIFICATION_REQUIREMENT_IDS:
        return RequirementKind.QUALIFICATION
    milestone = int(requirement_id[1])
    if milestone <= 1:
        return RequirementKind.ACCEPTANCE
    if requirement_id.endswith("-X01"):
        return RequirementKind.EXIT
    return RequirementKind.DELIVERABLE


_QUALIFICATION_GATE_BY_ID: dict[str, GateClass] = {
    "SW-REGISTRY": GateClass.LOCAL_OFFLINE,
    "SW-M2-LIVE": GateClass.LIVE_PROVIDER,
    "SW-M2-4WAY": GateClass.LIVE_PROVIDER,
    "SW-M2-PROVIDERS": GateClass.MATERIALIZED_RUNTIME,
    "SW-M2-CLEANUP": GateClass.MATERIALIZED_RUNTIME,
    "SW-M3-OBSERVED": GateClass.RUNTIME_OBSERVATION,
    "SW-M4-MATERIALIZED": GateClass.MATERIALIZED_RUNTIME,
    "SW-M5-CHAIN": GateClass.MATERIALIZED_RUNTIME,
    "SW-M6-ACQUIRE": GateClass.EXTERNAL_TRUST,
    "SW-M6-TRUST": GateClass.EXTERNAL_TRUST,
    "SW-M6-ISSUE": GateClass.EXTERNAL_TRUST,
    "SW-M6-REPLAY": GateClass.CLEAN_MACHINE,
    "SW-M6-PROMOTE": GateClass.EXTERNAL_TRUST,
    "SW-M7-FAIR": GateClass.INDEPENDENT_BENCHMARK,
    "SW-M7-PREREG": GateClass.INDEPENDENT_BENCHMARK,
    "SW-M7-HOLDOUT": GateClass.INDEPENDENT_BENCHMARK,
    "SW-M7-REPRO": GateClass.INDEPENDENT_BENCHMARK,
    "SW-M8-NEWUSER": GateClass.EXTERNAL_NEW_USER,
    "SW-M8-PACKAGE": GateClass.CLEAN_MACHINE,
    "SW-M8-PROVIDER": GateClass.LIVE_MODEL_PROVIDER,
}


def _expected_gate(requirement_id: str) -> GateClass:
    if requirement_id in _QUALIFICATION_GATE_BY_ID:
        return _QUALIFICATION_GATE_BY_ID[requirement_id]
    milestone = int(requirement_id[1])
    if requirement_id.startswith("M0-C"):
        return GateClass.LOCAL_OFFLINE
    if milestone <= 1:
        return GateClass.LOCAL_IN_PROCESS
    if milestone == 2:
        return GateClass.LIVE_PROVIDER
    if milestone == 3:
        if requirement_id in {"M3-T01", "M3-T02"}:
            return GateClass.LOCAL_IN_PROCESS
        return GateClass.RUNTIME_OBSERVATION
    if milestone == 4:
        return (
            GateClass.MATERIALIZED_RUNTIME
            if requirement_id == "M4-X01"
            else GateClass.LOCAL_OFFLINE
        )
    if milestone == 5:
        if requirement_id == "M5-X01":
            return GateClass.MATERIALIZED_RUNTIME
        if requirement_id == "M5-C04":
            return GateClass.LOCAL_IN_PROCESS
        return GateClass.LOCAL_OFFLINE
    if milestone == 6:
        if requirement_id == "M6-R01":
            return GateClass.EXTERNAL_TRUST
        if requirement_id in {"M6-R02", "M6-R03"}:
            return GateClass.LOCAL_IN_PROCESS
        if requirement_id == "M6-X01":
            return GateClass.CLEAN_MACHINE
        return GateClass.LOCAL_OFFLINE
    if milestone == 7:
        return (
            GateClass.INDEPENDENT_BENCHMARK
            if requirement_id == "M7-X01"
            else GateClass.LOCAL_OFFLINE
        )
    return GateClass.EXTERNAL_NEW_USER


_PLATFORMS_BY_GATE: dict[GateClass, tuple[str, ...]] = {
    GateClass.LOCAL_OFFLINE: ("python-3.12-plus",),
    GateClass.LOCAL_IN_PROCESS: ("localhost", "python-3.12-plus"),
    GateClass.LIVE_PROVIDER: ("docker-linux",),
    GateClass.RUNTIME_OBSERVATION: ("localhost", "python-3.12-plus"),
    GateClass.MATERIALIZED_RUNTIME: ("docker-linux",),
    GateClass.LIVE_MODEL_PROVIDER: ("allowlisted-private-lab", "live-model-provider"),
    GateClass.CLEAN_MACHINE: ("clean-machine", "python-3.12-plus"),
    GateClass.EXTERNAL_TRUST: (
        "clean-machine",
        "external-trust-root",
        "python-3.12-plus",
    ),
    GateClass.INDEPENDENT_BENCHMARK: (
        "clean-machine",
        "external-reviewer",
        "python-3.12-plus",
    ),
    GateClass.EXTERNAL_NEW_USER: ("browser-desktop-mobile", "clean-machine"),
}

_TEST_SUITE_BY_GATE: dict[GateClass, str] = {
    GateClass.LOCAL_OFFLINE: "pytest-offline",
    GateClass.LOCAL_IN_PROCESS: "pytest-local",
    GateClass.LIVE_PROVIDER: "pytest-live-provider",
    GateClass.RUNTIME_OBSERVATION: "pytest-runtime-observation",
    GateClass.MATERIALIZED_RUNTIME: "pytest-materialized-runtime",
    GateClass.LIVE_MODEL_PROVIDER: "pytest-live-model-provider",
    GateClass.CLEAN_MACHINE: "pytest-clean-machine",
    GateClass.EXTERNAL_TRUST: "pytest-external-trust",
    GateClass.INDEPENDENT_BENCHMARK: "pytest-independent-benchmark",
    GateClass.EXTERNAL_NEW_USER: "pytest-external-new-user",
}


_PLATFORM_OVERRIDES: dict[str, tuple[str, ...]] = {
    "SW-M2-LIVE": ("clean-machine", "docker-linux", "github-hosted"),
    "SW-M2-PROVIDERS": ("clean-machine", "docker-linux"),
    "SW-M2-CLEANUP": ("clean-machine", "docker-linux"),
}


def _expected_platforms(requirement_id: str, gate: GateClass) -> tuple[str, ...]:
    return _PLATFORM_OVERRIDES.get(requirement_id, _PLATFORMS_BY_GATE[gate])


def _expected_milestone(requirement_id: str) -> str:
    if requirement_id == "SW-REGISTRY":
        return "GLOBAL"
    if requirement_id.startswith("SW-M"):
        return requirement_id.split("-", 2)[1]
    match = _REQUIREMENT_ID_RE.fullmatch(requirement_id)
    if match is None:
        raise ValueError("requirement id is invalid")
    return f"M{match.group(1)}"


def _expected_source_path(requirement_id: str) -> str:
    if requirement_id in QUALIFICATION_REQUIREMENT_IDS:
        return "BLOCKERS.md"
    milestone = int(requirement_id[1])
    if milestone <= 1:
        return "docs/architecture/M0_M1_ACCEPTANCE.md"
    if milestone == 8:
        return "docs/architecture/TRACEABILITY.md"
    return "ARCHITECTURE.md"


class AcceptanceRequirement(_RegistryModel):
    """One closed, required acceptance row."""

    evidence: tuple[EvidenceMapping, ...]
    gate_class: GateClass
    id: str
    kind: RequirementKind
    milestone: str
    platforms: tuple[str, ...]
    required: bool
    source: SourceMapping
    statement: str
    tests: tuple[TestMapping, ...]

    @field_validator("statement")
    @classmethod
    def _validate_statement(cls, value: str) -> str:
        if value != value.strip() or not 8 <= len(value) <= 240 or "\n" in value:
            raise ValueError("requirement statement must be a bounded single line")
        return value

    @field_validator("platforms")
    @classmethod
    def _validate_platforms(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or tuple(sorted(set(value))) != value:
            raise ValueError("platforms must be non-empty, unique, and sorted")
        if any(not _PLATFORM_RE.fullmatch(platform) for platform in value):
            raise ValueError("platforms must be canonical slugs")
        return value

    @field_validator("tests")
    @classmethod
    def _validate_tests(cls, value: tuple[TestMapping, ...]) -> tuple[TestMapping, ...]:
        if tuple(sorted(value, key=lambda item: (item.suite, item.selector))) != value:
            raise ValueError("test mappings must be sorted")
        if len(set(value)) != len(value):
            raise ValueError("test mappings must be unique")
        return value

    @field_validator("evidence")
    @classmethod
    def _validate_evidence(cls, value: tuple[EvidenceMapping, ...]) -> tuple[EvidenceMapping, ...]:
        if not value or tuple(sorted(value, key=lambda item: (item.path, item.role))) != value:
            raise ValueError("evidence mappings must be non-empty and sorted")
        if len(set(value)) != len(value):
            raise ValueError("evidence mappings must be unique")
        return value

    @model_validator(mode="after")
    def _validate_closed_semantics(self) -> AcceptanceRequirement:
        if self.id not in EXPECTED_REQUIREMENT_ID_SET:
            raise ValueError("requirement id is not part of the closed registry")
        expected_milestone = _expected_milestone(self.id)
        if self.milestone != expected_milestone:
            raise ValueError("requirement milestone does not match its id")
        expected_kind = _expected_kind(self.id)
        if self.kind is not expected_kind:
            raise ValueError("requirement kind does not match its id")
        expected_gate = _expected_gate(self.id)
        if self.gate_class is not expected_gate:
            raise ValueError("requirement gate class is weaker or different than required")
        if self.platforms != _expected_platforms(self.id, expected_gate):
            raise ValueError("requirement platforms do not match its gate class")
        if self.source.path != _expected_source_path(self.id):
            raise ValueError("requirement source does not match its normative milestone document")
        if not self.source.anchor.startswith(f"{expected_milestone} / "):
            raise ValueError("requirement source anchor does not match its milestone")
        expected_suite = _TEST_SUITE_BY_GATE[expected_gate]
        if any(test.suite != expected_suite for test in self.tests):
            raise ValueError("requirement test suite does not match its gate class")
        should_be_testless = self.id in EXPECTED_TESTLESS_REQUIREMENT_IDS
        if should_be_testless != (not self.tests):
            raise ValueError("requirement implementation-test posture does not match the registry")
        if self.required is not True:
            raise ValueError("every canonical registry row must be required")
        return self


class AcceptanceRegistry(_RegistryModel):
    """The immutable architecture and qualification registry for M0-M8."""

    architecture_baseline: str
    registry_version: str
    requirements: tuple[AcceptanceRequirement, ...]
    schema_version: str

    @model_validator(mode="after")
    def _validate_registry_closure(self) -> AcceptanceRegistry:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported acceptance registry schema")
        if self.registry_version != REGISTRY_VERSION:
            raise ValueError("unsupported acceptance registry revision")
        if self.architecture_baseline != ARCHITECTURE_BASELINE:
            raise ValueError("acceptance registry architecture baseline does not match")
        ids = tuple(requirement.id for requirement in self.requirements)
        if len(ids) != len(set(ids)):
            raise ValueError("acceptance registry contains a duplicate requirement id")
        if set(ids) - EXPECTED_REQUIREMENT_ID_SET:
            raise ValueError("acceptance registry contains an unknown requirement id")
        if EXPECTED_REQUIREMENT_ID_SET - set(ids):
            raise ValueError("acceptance registry is missing a required requirement id")
        if ids != EXPECTED_REQUIREMENT_IDS:
            raise ValueError("acceptance registry requirements are not in canonical order")
        return self


def _validate_raw_id_closure(value: object) -> None:
    if not isinstance(value, dict):
        raise AcceptanceRegistryError("acceptance registry must be a JSON object")
    requirements = value.get("requirements")
    if not isinstance(requirements, list):
        return
    ids: list[str] = []
    for requirement in requirements:
        if not isinstance(requirement, dict) or not isinstance(requirement.get("id"), str):
            return
        ids.append(requirement["id"])
    if len(ids) != len(set(ids)):
        raise AcceptanceRegistryError("acceptance registry contains a duplicate requirement id")
    if set(ids) - EXPECTED_REQUIREMENT_ID_SET:
        raise AcceptanceRegistryError("acceptance registry contains an unknown requirement id")
    if EXPECTED_REQUIREMENT_ID_SET - set(ids):
        raise AcceptanceRegistryError("acceptance registry is missing a required requirement id")
    if tuple(ids) != EXPECTED_REQUIREMENT_IDS:
        raise AcceptanceRegistryError("acceptance registry requirements are not in canonical order")


def _parse_acceptance_registry_structure(payload: bytes) -> AcceptanceRegistry:
    """Validate registry structure without establishing the packaged-resource identity."""

    if type(payload) is not bytes or not payload or len(payload) > MAX_REGISTRY_BYTES:
        raise AcceptanceRegistryError("acceptance registry bytes are invalid")
    try:
        decoded = payload.decode("utf-8")
        value: object = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise AcceptanceRegistryError("acceptance registry JSON could not be decoded") from None
    try:
        canonical = canonical_json_bytes(value)
    except (TypeError, ValueError, RecursionError):
        raise AcceptanceRegistryError("acceptance registry JSON is invalid") from None
    if canonical != payload:
        raise AcceptanceRegistryError("acceptance registry JSON is not canonical")
    _validate_raw_id_closure(value)
    try:
        return AcceptanceRegistry.model_validate_json(payload, strict=True)
    except ValidationError:
        raise AcceptanceRegistryError("acceptance registry schema or mapping is invalid") from None


def parse_acceptance_registry(payload: bytes) -> AcceptanceRegistry:
    """Parse only the exact, reviewed packaged registry resource."""

    if type(payload) is not bytes or not payload or len(payload) > MAX_REGISTRY_BYTES:
        raise AcceptanceRegistryError("acceptance registry bytes are invalid")
    if hashlib.sha256(payload).hexdigest() != EXPECTED_ACCEPTANCE_REGISTRY_SHA256:
        raise AcceptanceRegistryError("acceptance registry digest does not match")
    return _parse_acceptance_registry_structure(payload)


def _validate_acceptance_registry_selectors_structure(
    registry: AcceptanceRegistry, repository_root: str | Path
) -> None:
    """Resolve selectors after a caller has established registry identity."""

    try:
        root = Path(repository_root).resolve(strict=True)
        if not root.is_dir():
            raise OSError
        for requirement in registry.requirements:
            for mapping in requirement.tests:
                relative_path, _, raw_test_name = mapping.selector.partition("::")
                candidate = root.joinpath(*PurePosixPath(relative_path).parts).resolve(strict=True)
                if not candidate.is_relative_to(root) or not candidate.is_file():
                    raise OSError
                tree = ast.parse(candidate.read_text(encoding="utf-8"), filename=relative_path)
                test_name = raw_test_name.partition("[")[0]
                declared = {
                    node.name
                    for node in tree.body
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                }
                if test_name not in declared:
                    raise ValueError
    except (OSError, UnicodeError, SyntaxError, ValueError):
        raise AcceptanceRegistryError(
            "acceptance registry test selector does not resolve"
        ) from None


def validate_acceptance_registry_selectors(
    registry: AcceptanceRegistry, repository_root: str | Path
) -> None:
    """Require the exact registry and resolve every selector inside one repository root."""

    try:
        payload = canonical_json_bytes(registry.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError, RecursionError):
        raise AcceptanceRegistryError("acceptance registry digest does not match") from None
    if hashlib.sha256(payload).hexdigest() != EXPECTED_ACCEPTANCE_REGISTRY_SHA256:
        raise AcceptanceRegistryError("acceptance registry digest does not match")
    _validate_acceptance_registry_selectors_structure(registry, repository_root)


def load_acceptance_registry() -> AcceptanceRegistry:
    """Load and validate the registry distributed with ``stateweaver-evidence``."""

    try:
        payload = resources.files(__package__).joinpath("acceptance-registry.json").read_bytes()
    except (FileNotFoundError, OSError):
        raise AcceptanceRegistryError("packaged acceptance registry is unavailable") from None
    return parse_acceptance_registry(payload)
