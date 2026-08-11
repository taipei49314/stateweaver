"""Strict verification for acceptance artifact integrity and causal coherence."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeGuard

from ._io import (
    EvidenceInputError,
    canonical_json_bytes,
    semantic_sha256,
    sha256_bytes,
    validate_run_id,
)
from .acceptance_registry import load_acceptance_registry
from .acceptance_results import (
    AcceptanceRegistryClosure,
    AcceptanceResults,
    AcceptanceResultsError,
    build_acceptance_registry_closure,
    derive_acceptance_results,
)
from .collector import (
    _REQUIRED_RELATIVE,
    AcceptanceEvidenceError,
    CollectionInput,
    _JunitSummary,
    _local_deliverable_qualification_payloads,
    _m01_qualification_payloads,
    _metadata_datetime,
    _proof_artifact_payloads,
    _read_junit_payloads,
    _validate_foundation,
    _validate_supporting_inputs,
)
from .hosted_qualification import (
    HOSTED_QUALIFICATION_ADMISSION_PATH,
    HOSTED_QUALIFICATION_DERIVED_PATHS,
    HostedQualificationError,
    hosted_qualification_admissions,
    hosted_qualification_payloads,
    hosted_qualification_test_identities,
    validate_hosted_qualification_admission,
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

_RUN_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "run_id",
        "accepted",
        "foundation_semantic_sha256",
        "root_state_fingerprint",
        "plan_hash",
        "policy_semantic_sha256",
        "metadata",
        "collected_at",
        "redacted_values",
        "junit",
        "acceptance_registry",
    }
)
_INVALID = object()


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    errors: tuple[str, ...]
    snapshot_sha256: str | None = None


@dataclass(frozen=True)
class ExpectedProvenance:
    """Independent values supplied by the verifier, not copied from the bundle."""

    repository_marker: str | None = None
    app_source_digest: str | None = None
    oracle_definition_hash: str | None = None
    runtime_dependency_fingerprint: str | None = None
    foundation_semantic_sha256: str | None = None


class _ProvenanceMismatchError(AcceptanceEvidenceError):
    """The bundle is coherent, but an independently derived provenance value differs."""


def verify_acceptance_evidence(
    run_directory: Path, *, expected_provenance: ExpectedProvenance | None = None
) -> VerificationResult:
    """Verify hashes, canonical encoding, required coverage, and all causal bindings."""

    errors: list[str] = []
    if run_directory.is_symlink():
        return VerificationResult(False, ("artifact run directory must not be a symlink",))
    manifest = run_directory / "artifact-manifest.sha256"
    if manifest.is_symlink():
        return VerificationResult(False, ("artifact manifest must not be a symlink",))
    if not manifest.is_file():
        return VerificationResult(False, ("artifact manifest is missing",))

    try:
        paths = tuple(run_directory.rglob("*"))
    except OSError:
        return VerificationResult(False, ("artifact tree is unreadable",))
    if any(path.is_symlink() for path in paths):
        errors.append("artifact tree must not contain symlinks")
    actual = {
        path.relative_to(run_directory).as_posix()
        for path in paths
        if path.is_file() and path != manifest
    }
    try:
        manifest_bytes = manifest.read_bytes()
    except OSError:
        errors.append("artifact manifest is unreadable")
        manifest_bytes = b""
    expected = _parse_manifest(manifest_bytes, errors)
    required = set(_REQUIRED_RELATIVE)
    if PACKAGE_INSTALL_QUALIFICATION_PATH in expected:
        required.add(PACKAGE_INSTALL_QUALIFICATION_PATH)
    hosted_only_paths = set(HOSTED_QUALIFICATION_DERIVED_PATHS).difference(
        {RUNTIME_OBSERVATION_QUALIFICATION_PATH, OBSERVED_FRAGMENT_QUALIFICATION_PATH}
    )
    if set(expected).intersection(hosted_only_paths):
        required.update(HOSTED_QUALIFICATION_DERIVED_PATHS)
    if (
        RUNTIME_OBSERVATION_QUALIFICATION_PATH in expected
        or OBSERVED_FRAGMENT_QUALIFICATION_PATH in expected
    ):
        required.update(
            {
                RUNTIME_OBSERVATION_QUALIFICATION_PATH,
                OBSERVED_FRAGMENT_QUALIFICATION_PATH,
            }
        )
    if set(expected) != required:
        errors.append("artifact manifest does not cover exactly the required artifacts")
    if actual != required:
        errors.append("artifact tree contains missing or untracked artifacts")

    snapshot: dict[str, bytes] = {}
    for relative in sorted(required):
        target = run_directory / relative
        expected_hash = expected.get(relative)
        if target.is_symlink():
            errors.append("required artifact must not be a symlink")
        elif not target.is_file():
            errors.append("artifact listed by manifest is missing")
        elif expected_hash is not None:
            try:
                content = target.read_bytes()
            except OSError:
                errors.append("artifact listed by manifest is unreadable")
            else:
                snapshot[relative] = content
                if sha256_bytes(content) != expected_hash:
                    errors.append("artifact digest does not match manifest")

    parsed: dict[str, object] = {}
    for relative in sorted(required):
        if relative.endswith(".json") and relative in snapshot:
            value = _read_canonical_json(snapshot[relative], errors)
            if value is not _INVALID:
                parsed[relative] = value
    if all(relative in parsed for relative in required if relative.endswith(".json")):
        _verify_coherence(
            run_directory,
            parsed,
            snapshot,
            errors,
            expected_provenance,
        )
    unique_errors = tuple(dict.fromkeys(errors))
    snapshot_sha256 = (
        _snapshot_sha256(run_directory.name, manifest_bytes, snapshot)
        if not unique_errors and set(snapshot) == required
        else None
    )
    return VerificationResult(not unique_errors, unique_errors, snapshot_sha256)


def _read_canonical_json(content: bytes, errors: list[str]) -> object:
    try:
        parsed: object = json.loads(content.decode("utf-8"))
        canonical = canonical_json_bytes(parsed)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, EvidenceInputError, ValueError):
        errors.append("JSON artifact is unreadable or contains invalid values")
        return _INVALID
    if canonical != content:
        errors.append("JSON artifact is not canonical UTF-8")
        return _INVALID
    return parsed


def _verify_coherence(
    run_directory: Path,
    parsed: Mapping[str, object],
    snapshot: Mapping[str, bytes],
    errors: list[str],
    expected_provenance: ExpectedProvenance | None,
) -> None:
    source = parsed["foundation/source.json"]
    run_manifest = parsed["run-manifest.json"]
    if not _string_mapping(source) or not _string_mapping(run_manifest):
        errors.append("foundation source or run manifest is not an object")
        return
    try:
        foundation = _validate_foundation(source)
        proof_payloads = _proof_artifact_payloads(source)
        for relative, expected_payload in proof_payloads.items():
            actual_payload = parsed.get(relative, _INVALID)
            if actual_payload is _INVALID or canonical_json_bytes(
                actual_payload
            ) != canonical_json_bytes(expected_payload):
                raise AcceptanceEvidenceError("derived proof artifact does not match its source")

        junit_payloads = {
            name: snapshot[f"junit/{name}.xml"] for name in ("contracts", "policy", "lab", "replay")
        }
        junit_results = _read_junit_payloads(junit_payloads)
        metadata = run_manifest.get("metadata")
        if not _string_mapping(metadata):
            raise AcceptanceEvidenceError("run manifest metadata is invalid")
        qualification_payloads = _m01_qualification_payloads(foundation, junit_results)
        qualification_payloads.update(
            _local_deliverable_qualification_payloads(junit_results, metadata)
        )
        for relative, expected_payload in qualification_payloads.items():
            actual_payload = parsed.get(relative, _INVALID)
            if actual_payload is _INVALID or canonical_json_bytes(
                actual_payload
            ) != canonical_json_bytes(expected_payload):
                raise AcceptanceEvidenceError(
                    "derived qualification artifact does not match its validated inputs"
                )
        observed_evidence_paths: tuple[str, ...] = _REQUIRED_RELATIVE
        verified_admission_digests: dict[str, str] = {}
        hosted_test_identities: tuple[str, ...] = ()
        package_receipt = parsed.get(PACKAGE_INSTALL_QUALIFICATION_PATH, _INVALID)
        if package_receipt is not _INVALID:
            if not _string_mapping(package_receipt):
                raise AcceptanceEvidenceError("package install qualification is invalid")
            repository_marker = metadata.get("repository_marker")
            if not isinstance(repository_marker, str):
                raise AcceptanceEvidenceError("package install qualification marker is invalid")
            try:
                expected_package_receipt = validate_package_install_receipt(
                    package_receipt,
                    expected_repository_marker=repository_marker,
                )
            except PackageInstallQualificationError:
                raise AcceptanceEvidenceError("package install qualification is invalid") from None
            if canonical_json_bytes(package_receipt) != canonical_json_bytes(
                expected_package_receipt
            ):
                raise AcceptanceEvidenceError("package install qualification is inconsistent")
            observed_evidence_paths = (
                *_REQUIRED_RELATIVE,
                PACKAGE_INSTALL_QUALIFICATION_PATH,
            )
        hosted_payload = parsed.get(HOSTED_QUALIFICATION_ADMISSION_PATH, _INVALID)
        if hosted_payload is not _INVALID:
            if not _string_mapping(hosted_payload):
                raise AcceptanceEvidenceError("hosted qualification admission is invalid")
            repository_marker = metadata.get("repository_marker")
            if not isinstance(repository_marker, str):
                raise AcceptanceEvidenceError("hosted qualification marker is invalid")
            try:
                hosted_admission = validate_hosted_qualification_admission(
                    hosted_payload,
                    expected_repository_marker=repository_marker,
                )
            except HostedQualificationError:
                raise AcceptanceEvidenceError("hosted qualification admission is invalid") from None
            expected_hosted_payloads = hosted_qualification_payloads(hosted_admission)
            for relative, expected_payload in expected_hosted_payloads.items():
                actual_payload = parsed.get(relative, _INVALID)
                if actual_payload is _INVALID or canonical_json_bytes(
                    actual_payload
                ) != canonical_json_bytes(expected_payload):
                    raise AcceptanceEvidenceError("hosted qualification artifact is inconsistent")
            observed_evidence_paths = tuple(
                dict.fromkeys((*observed_evidence_paths, *HOSTED_QUALIFICATION_DERIVED_PATHS))
            )
            verified_admission_digests.update(hosted_qualification_admissions(hosted_admission))
            hosted_test_identities = hosted_qualification_test_identities(hosted_admission)
        runtime_receipt_payload = parsed.get(
            RUNTIME_OBSERVATION_QUALIFICATION_PATH,
            _INVALID,
        )
        observed_fragment_payload = parsed.get(
            OBSERVED_FRAGMENT_QUALIFICATION_PATH,
            _INVALID,
        )
        if runtime_receipt_payload is not _INVALID or observed_fragment_payload is not _INVALID:
            if not _string_mapping(runtime_receipt_payload) or not _string_mapping(
                observed_fragment_payload
            ):
                raise AcceptanceEvidenceError(
                    "runtime observation qualification artifacts are invalid"
                )
            repository_marker = metadata.get("repository_marker")
            if not isinstance(repository_marker, str):
                raise AcceptanceEvidenceError("runtime observation qualification marker is invalid")
            try:
                expected_runtime_receipt = validate_runtime_observation_qualification(
                    runtime_receipt_payload,
                    expected_repository_marker=repository_marker,
                )
            except RuntimeObservationQualificationError:
                raise AcceptanceEvidenceError(
                    "runtime observation qualification is invalid"
                ) from None
            if canonical_json_bytes(runtime_receipt_payload) != canonical_json_bytes(
                expected_runtime_receipt.model_dump(mode="json")
            ) or canonical_json_bytes(observed_fragment_payload) != canonical_json_bytes(
                observed_fragment_qualification_payload(expected_runtime_receipt)
            ):
                raise AcceptanceEvidenceError(
                    "runtime observation qualification artifacts are inconsistent"
                )
            observed_evidence_paths = (
                *observed_evidence_paths,
                RUNTIME_OBSERVATION_QUALIFICATION_PATH,
                OBSERVED_FRAGMENT_QUALIFICATION_PATH,
            )
            verified_admission_digests.update(
                runtime_observation_admissions(expected_runtime_receipt)
            )
        registry = load_acceptance_registry()
        expected_closure = build_acceptance_registry_closure(registry)
        passing_test_identities = (
            tuple(
                identity
                for name in ("contracts", "policy", "lab", "replay")
                for identity in junit_results[name]["testcase_identities"]
            )
            + hosted_test_identities
        )
        expected_results = derive_acceptance_results(
            registry,
            passing_test_identities=passing_test_identities,
            observed_evidence_paths=observed_evidence_paths,
            verified_admission_digests=verified_admission_digests,
        )
        if canonical_json_bytes(parsed["qualification/registry/closure.json"]) != (
            canonical_json_bytes(expected_closure.model_dump(mode="json"))
        ):
            raise AcceptanceEvidenceError("acceptance registry closure is inconsistent")
        if canonical_json_bytes(parsed["qualification/registry/results.json"]) != (
            canonical_json_bytes(expected_results.model_dump(mode="json"))
        ):
            raise AcceptanceEvidenceError("acceptance registry results are inconsistent")
        _validate_supporting_inputs(
            CollectionInput(
                foundation=source,
                junit_sources={},
                run_metadata=metadata,
            ),
            foundation,
            junit_results,
        )
        _validate_run_manifest(
            run_directory,
            run_manifest,
            foundation.raw,
            junit_results,
            expected_provenance,
            expected_closure,
            expected_results,
        )
    except _ProvenanceMismatchError:
        errors.append("artifact provenance does not match independent expectations")
    except (
        AcceptanceEvidenceError,
        AcceptanceResultsError,
        EvidenceInputError,
        KeyError,
        TypeError,
        ValueError,
    ):
        errors.append("artifact bundle is not causally coherent")


def _validate_run_manifest(
    run_directory: Path,
    manifest: Mapping[str, Any],
    foundation: Mapping[str, Any],
    junit_results: Mapping[str, _JunitSummary],
    expected_provenance: ExpectedProvenance | None,
    registry_closure: AcceptanceRegistryClosure,
    acceptance_results: AcceptanceResults,
) -> None:
    if set(manifest) != _RUN_MANIFEST_FIELDS:
        raise AcceptanceEvidenceError("run manifest fields are invalid")
    try:
        validate_run_id(run_directory.name)
    except EvidenceInputError as error:
        raise AcceptanceEvidenceError("run directory has an invalid id") from error
    collected_at = _metadata_datetime(manifest.get("collected_at"))
    metadata = manifest.get("metadata")
    if not _string_mapping(metadata):
        raise AcceptanceEvidenceError("run manifest metadata is invalid")
    completed_at = _metadata_datetime(metadata.get("completed_at"))
    redacted_values = manifest.get("redacted_values")
    if (
        manifest.get("schema_version") != "acceptance-evidence-v1"
        or manifest.get("run_id") != run_directory.name
        or manifest.get("accepted") is not True
        or manifest.get("foundation_semantic_sha256") != semantic_sha256(foundation)
        or manifest.get("root_state_fingerprint")
        != foundation["root_state"]["capture"]["fingerprint"]
        or manifest.get("plan_hash") != foundation["plan_hash"]
        or manifest.get("policy_semantic_sha256") != semantic_sha256(foundation["policy_decisions"])
        or type(redacted_values) is not int
        or redacted_values != 0
        or collected_at < completed_at
        or canonical_json_bytes(manifest.get("junit")) != canonical_json_bytes(junit_results)
        or canonical_json_bytes(manifest.get("acceptance_registry"))
        != canonical_json_bytes(
            {
                "closure_sha256": sha256_bytes(
                    canonical_json_bytes(registry_closure.model_dump(mode="json"))
                ),
                "registry_sha256": registry_closure.registry_sha256,
                "results_sha256": sha256_bytes(
                    canonical_json_bytes(acceptance_results.model_dump(mode="json"))
                ),
                "summary": acceptance_results.summary.model_dump(mode="json"),
            }
        )
    ):
        raise AcceptanceEvidenceError("run manifest does not match the proof bundle")
    if expected_provenance is not None and (
        (
            expected_provenance.repository_marker is not None
            and metadata.get("repository_marker") != expected_provenance.repository_marker
        )
        or (
            expected_provenance.app_source_digest is not None
            and metadata.get("app_source_digest") != expected_provenance.app_source_digest
        )
        or (
            expected_provenance.oracle_definition_hash is not None
            and metadata.get("oracle_definition_hash") != expected_provenance.oracle_definition_hash
        )
        or (
            expected_provenance.runtime_dependency_fingerprint is not None
            and metadata.get("runtime_dependency_fingerprint")
            != expected_provenance.runtime_dependency_fingerprint
        )
        or (
            expected_provenance.foundation_semantic_sha256 is not None
            and manifest.get("foundation_semantic_sha256")
            != expected_provenance.foundation_semantic_sha256
        )
    ):
        raise _ProvenanceMismatchError("run provenance does not match independent expectations")


def _string_mapping(value: object) -> TypeGuard[Mapping[str, Any]]:
    return isinstance(value, Mapping) and all(isinstance(key, str) for key in value)


def _parse_manifest(content: bytes, errors: list[str]) -> dict[str, str]:
    try:
        lines = content.decode("ascii").splitlines()
    except UnicodeDecodeError:
        errors.append("artifact manifest is unreadable")
        return {}
    entries: dict[str, str] = {}
    for line in lines:
        try:
            digest, relative = line.split("  ", 1)
        except ValueError:
            errors.append("artifact manifest has an invalid entry")
            continue
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            errors.append("artifact manifest has an invalid digest")
        parts = relative.split("/")
        unsafe_path = (
            not relative
            or relative.startswith("/")
            or "\\" in relative
            or ":" in relative
            or any(part in {"", ".", ".."} for part in parts)
        )
        if unsafe_path:
            errors.append("artifact manifest has an unsafe path")
            continue
        if relative in entries:
            errors.append("artifact manifest has duplicate entries")
        entries[relative] = digest
    return entries


def _snapshot_sha256(
    run_id: str,
    manifest: bytes,
    artifacts: Mapping[str, bytes],
) -> str:
    digest = hashlib.sha256()
    components = (("@run-id", run_id.encode("utf-8")), ("@manifest", manifest))
    for relative, content in (*components, *sorted(artifacts.items())):
        encoded = relative.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return f"sha256:{digest.hexdigest()}"
