"""One-command collection of a self-verifying local foundation proof bundle."""

from __future__ import annotations

import hashlib
import importlib.resources
import platform
from collections.abc import Iterator
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, distribution
from importlib.resources.abc import Traversable
from pathlib import Path, PurePosixPath
from typing import Final

from stateweaver.evidence import (
    ACCEPTANCE_TEST_COMMAND,
    AcceptanceEvidenceError,
    CollectionInput,
    ExpectedProvenance,
    VerificationResult,
    collect_acceptance_evidence,
    semantic_sha256,
    verify_acceptance_evidence,
)
from stateweaver.replay import canonical_sha256

from .foundation import verify_foundation
from .network_guard import NETWORK_GUARD_VERSION

_APP_SOURCE_PACKAGES: Final = (
    "stateweaver.adapters.in_process_lab",
    "stateweaver.cli",
    "stateweaver.contracts",
    "stateweaver.evidence",
    "stateweaver.policy",
    "stateweaver.replay",
    "stateweaver_lab",
)
_ORACLE_SOURCE_PACKAGES: Final = (
    "stateweaver.adapters.in_process_lab",
    "stateweaver.contracts",
    "stateweaver.evidence",
    "stateweaver.replay",
    "stateweaver_lab",
)
_RUNTIME_DISTRIBUTIONS: Final = (
    "annotated-doc",
    "annotated-types",
    "anyio",
    "fastapi",
    "idna",
    "pydantic",
    "pydantic-core",
    "starlette",
    "typing-extensions",
    "typing-inspection",
)
_GENERATED_DISTRIBUTION_FILES: Final = frozenset(
    {"INSTALLER", "RECORD", "REQUESTED", "direct_url.json"}
)


def collect_foundation_evidence(
    *,
    output_root: Path,
    run_id: str,
    repository_marker: str,
    junit_contracts: Path,
    junit_policy: Path,
    junit_lab: Path,
    junit_replay: Path,
    started_at: datetime,
) -> dict[str, object]:
    """Generate the proof once, bind supplied JUnit, then verify the resulting bundle."""

    foundation_started_at = datetime.now(UTC)
    if started_at.tzinfo is None or started_at.utcoffset() is None:
        raise AcceptanceEvidenceError("acceptance run start must include a UTC offset")
    started_at = started_at.astimezone(UTC)
    if started_at > foundation_started_at:
        raise AcceptanceEvidenceError("acceptance run start cannot follow foundation verification")
    report = verify_foundation()
    proof = report.to_json()
    completed_at = datetime.now(UTC)
    if not report.accepted:
        raise AcceptanceEvidenceError("foundation verification was not accepted")
    app_source_digest = _source_digest(_APP_SOURCE_PACKAGES)
    oracle_definition_hash = _source_digest(_ORACLE_SOURCE_PACKAGES)
    runtime_dependency_fingerprint = _runtime_dependency_fingerprint()
    foundation_semantic_sha256 = semantic_sha256(proof)

    result = collect_acceptance_evidence(
        input=CollectionInput(
            foundation=proof,
            junit_sources={
                "contracts": junit_contracts,
                "policy": junit_policy,
                "lab": junit_lab,
                "replay": junit_replay,
            },
            run_metadata={
                "repository_marker": repository_marker,
                "python_version": platform.python_version(),
                "docker_compose_version": "not-used-in-process",
                "target_mode": "differential",
                "root_seed": report.vulnerable[0].root_seed.root_seed_id,
                "controlled_clock_epoch": report.vulnerable[0].root_seed.clock_epoch.isoformat(),
                "test_command": ACCEPTANCE_TEST_COMMAND,
                "test_exit_code": 0,
                "app_source_digest": app_source_digest,
                "scope_manifest_hash": canonical_sha256(report.scope_manifest),
                "replay_plan_hash": canonical_sha256(report.canonical_plan),
                "oracle_definition_hash": oracle_definition_hash,
                "runtime_dependency_fingerprint": runtime_dependency_fingerprint,
                "network_mode": "offline-in-process",
                "network_guard": NETWORK_GUARD_VERSION,
                "model_calls": 0,
                "started_at": started_at.isoformat(),
                "completed_at": completed_at.isoformat(),
            },
        ),
        output_root=output_root,
        run_id=run_id,
    )
    provenance = ExpectedProvenance(
        repository_marker=repository_marker,
        app_source_digest=app_source_digest,
        oracle_definition_hash=oracle_definition_hash,
        runtime_dependency_fingerprint=runtime_dependency_fingerprint,
        foundation_semantic_sha256=foundation_semantic_sha256,
    )
    verification = verify_acceptance_evidence(result.run_directory, expected_provenance=provenance)
    if not verification.valid:
        raise AcceptanceEvidenceError("fresh evidence failed self-verification")
    return {
        "collected": True,
        "run_directory": str(result.run_directory),
        "semantic_sha256": result.semantic_sha256,
        "verified": True,
    }


def verify_foundation_evidence(
    run_directory: Path, *, repository_marker: str | None = None
) -> VerificationResult:
    """Verify a bundle against the installed execution and Oracle source bytes."""

    trusted_foundation = verify_foundation()
    if not trusted_foundation.accepted:
        return VerificationResult(False, ("trusted foundation re-execution was not accepted",))
    return verify_acceptance_evidence(
        run_directory,
        expected_provenance=ExpectedProvenance(
            repository_marker=repository_marker,
            app_source_digest=_source_digest(_APP_SOURCE_PACKAGES),
            oracle_definition_hash=_source_digest(_ORACLE_SOURCE_PACKAGES),
            runtime_dependency_fingerprint=_runtime_dependency_fingerprint(),
            foundation_semantic_sha256=semantic_sha256(trusted_foundation.to_json()),
        ),
    )


def _source_digest(package_names: tuple[str, ...]) -> str:
    digest = hashlib.sha256()
    resources: list[tuple[str, bytes]] = []
    for package_name in sorted(package_names):
        root = importlib.resources.files(package_name)
        resources.extend(_source_resources(root, package_name))
    for resource_key, content in sorted(resources):
        digest.update(len(resource_key).to_bytes(4, "big"))
        digest.update(resource_key.encode("utf-8"))
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return f"sha256:{digest.hexdigest()}"


def _source_resources(node: Traversable, prefix: str) -> Iterator[tuple[str, bytes]]:
    for child in sorted(node.iterdir(), key=lambda item: item.name):
        relative = f"{prefix}/{child.name}"
        if child.is_dir():
            yield from _source_resources(child, relative)
        elif child.name.endswith((".py", ".typed")):
            yield relative, child.read_bytes()


def _runtime_dependency_fingerprint() -> str:
    """Bind stable installed third-party runtime bytes for the M0/M1 closure."""

    records: list[dict[str, object]] = []
    for package_name in _RUNTIME_DISTRIBUTIONS:
        try:
            installed = distribution(package_name)
        except PackageNotFoundError as error:
            raise AcceptanceEvidenceError("runtime dependency closure is incomplete") from error
        metadata = installed.read_text("METADATA")
        installed_files = installed.files
        if not metadata or installed_files is None:
            raise AcceptanceEvidenceError("runtime dependency metadata is incomplete")
        files: list[dict[str, str]] = []
        for package_path in sorted(installed_files, key=lambda item: item.as_posix()):
            relative = PurePosixPath(package_path.as_posix())
            if (
                relative.is_absolute()
                or ".." in relative.parts
                or "__pycache__" in relative.parts
                or relative.suffix in {".pyc", ".pyo"}
                or (
                    relative.name in _GENERATED_DISTRIBUTION_FILES
                    and any(part.endswith(".dist-info") for part in relative.parts)
                )
            ):
                continue
            located = Path(str(installed.locate_file(package_path)))
            if not located.is_file():
                raise AcceptanceEvidenceError("runtime dependency file closure is incomplete")
            files.append(
                {
                    "path": relative.as_posix(),
                    "sha256": f"sha256:{hashlib.sha256(located.read_bytes()).hexdigest()}",
                }
            )
        if not files:
            raise AcceptanceEvidenceError("runtime dependency file closure is empty")
        records.append(
            {
                "name": package_name,
                "version": installed.version,
                "metadata_sha256": f"sha256:{hashlib.sha256(metadata.encode()).hexdigest()}",
                "installed_file_count": len(files),
                "installed_files_sha256": canonical_sha256(files),
            }
        )
    return canonical_sha256(records)
