"""One-command collection of a self-verifying local foundation proof bundle."""

from __future__ import annotations

import hashlib
import importlib.resources
import json
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
from stateweaver.evidence.hosted_qualification import (
    HostedQualificationAdmissionReceipt,
    load_hosted_qualification_admission,
)
from stateweaver.evidence.package_install import load_package_install_receipt
from stateweaver.evidence.runtime_observation import (
    RUNTIME_OBSERVATION_QUALIFICATION_PATH,
    RuntimeObservationQualificationError,
    RuntimeObservationQualificationReceipt,
    load_runtime_observation_qualification,
)
from stateweaver.replay import canonical_sha256

from .foundation import verify_foundation
from .network_guard import NETWORK_GUARD_VERSION
from .runtime_qualification import (
    qualify_runtime_observation,
    validate_runtime_qualification_against_adapter,
)

_APP_SOURCE_PACKAGES: Final = (
    "stateweaver.adapters.in_process_lab",
    "stateweaver.adapters.telemetry.opentelemetry",
    "stateweaver.cli",
    "stateweaver.contracts",
    "stateweaver.evidence",
    "stateweaver.policy",
    "stateweaver.replay",
    "stateweaver.twin",
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
    {"INSTALLER", "RECORD", "REQUESTED", "direct_url.json", "uv_cache.json"}
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
    package_install_receipt: Path | None = None,
    runtime_observation_receipt: Path | None = None,
    hosted_qualification_admission: Path | None = None,
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
    installed_contracts = (
        load_package_install_receipt(
            package_install_receipt,
            expected_repository_marker=repository_marker,
        )
        if package_install_receipt is not None
        else None
    )
    runtime_qualification: RuntimeObservationQualificationReceipt | None = None
    hosted_admission: HostedQualificationAdmissionReceipt | None = None
    if hosted_qualification_admission is not None:
        if runtime_observation_receipt is not None:
            raise AcceptanceEvidenceError(
                "hosted admission and standalone runtime admission are mutually exclusive"
            )
        hosted_admission = load_hosted_qualification_admission(
            hosted_qualification_admission,
            expected_repository_marker=repository_marker,
        )
    if runtime_observation_receipt is not None:
        runtime_qualification = load_runtime_observation_qualification(
            runtime_observation_receipt,
            expected_repository_marker=repository_marker,
        )
        validate_runtime_qualification_against_adapter(runtime_qualification)
        fresh_runtime_qualification = qualify_runtime_observation(repository_marker)
        if fresh_runtime_qualification.semantic_digest != runtime_qualification.semantic_digest:
            raise AcceptanceEvidenceError(
                "runtime observation qualification did not reproduce installed semantics"
            )

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
            package_install_receipt=installed_contracts,
            runtime_observation_receipt=(
                runtime_qualification.model_dump(mode="json")
                if runtime_qualification is not None
                else None
            ),
            hosted_qualification_admission=(
                hosted_admission.model_dump(mode="json") if hosted_admission is not None else None
            ),
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
    expected_provenance = ExpectedProvenance(
        repository_marker=repository_marker,
        app_source_digest=_source_digest(_APP_SOURCE_PACKAGES),
        oracle_definition_hash=_source_digest(_ORACLE_SOURCE_PACKAGES),
        runtime_dependency_fingerprint=_runtime_dependency_fingerprint(),
        foundation_semantic_sha256=semantic_sha256(trusted_foundation.to_json()),
    )
    verification = verify_acceptance_evidence(
        run_directory,
        expected_provenance=expected_provenance,
    )
    if not verification.valid:
        return verification
    runtime_receipt_path = run_directory / RUNTIME_OBSERVATION_QUALIFICATION_PATH
    if not runtime_receipt_path.exists():
        return verification
    try:
        if repository_marker is None:
            raw: object = json.loads(runtime_receipt_path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise RuntimeObservationQualificationError(
                    "runtime observation qualification receipt is invalid"
                )
            projection = raw.get("projection")
            if not isinstance(projection, dict) or not isinstance(
                projection.get("repository_marker"), str
            ):
                raise RuntimeObservationQualificationError(
                    "runtime observation qualification receipt is invalid"
                )
            marker = projection["repository_marker"]
        else:
            marker = repository_marker
        retained = load_runtime_observation_qualification(
            runtime_receipt_path,
            expected_repository_marker=marker,
        )
        validate_runtime_qualification_against_adapter(retained)
        reproduced = qualify_runtime_observation(marker)
        if reproduced.semantic_digest != retained.semantic_digest:
            raise RuntimeObservationQualificationError(
                "runtime observation semantic projection did not reproduce"
            )
    except (OSError, RuntimeObservationQualificationError):
        return VerificationResult(
            False,
            ("runtime observation qualification did not independently verify",),
        )
    final_verification = verify_acceptance_evidence(
        run_directory,
        expected_provenance=expected_provenance,
    )
    if (
        not final_verification.valid
        or final_verification.snapshot_sha256 != verification.snapshot_sha256
    ):
        return VerificationResult(
            False,
            ("evidence bundle changed during independent runtime verification",),
        )
    return final_verification


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
