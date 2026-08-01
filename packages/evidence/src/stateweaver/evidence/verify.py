"""Strict verification for acceptance artifact integrity and causal coherence."""

from __future__ import annotations

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
from .collector import (
    _REQUIRED_RELATIVE,
    AcceptanceEvidenceError,
    CollectionInput,
    _JunitSummary,
    _metadata_datetime,
    _proof_artifact_payloads,
    _read_junit_sources,
    _validate_foundation,
    _validate_supporting_inputs,
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
    }
)
_INVALID = object()


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    errors: tuple[str, ...]


@dataclass(frozen=True)
class ExpectedProvenance:
    """Independent values supplied by the verifier, not copied from the bundle."""

    repository_marker: str | None = None
    app_source_digest: str | None = None
    oracle_definition_hash: str | None = None
    runtime_dependency_fingerprint: str | None = None
    foundation_semantic_sha256: str | None = None


def verify_acceptance_evidence(
    run_directory: Path, *, expected_provenance: ExpectedProvenance | None = None
) -> VerificationResult:
    """Verify hashes, canonical encoding, required coverage, and all causal bindings."""

    errors: list[str] = []
    manifest = run_directory / "artifact-manifest.sha256"
    if manifest.is_symlink():
        return VerificationResult(False, ("artifact manifest must not be a symlink",))
    if not manifest.is_file():
        return VerificationResult(False, ("artifact manifest is missing",))

    expected = _parse_manifest(manifest, errors)
    required = set(_REQUIRED_RELATIVE)
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
    if set(expected) != required:
        errors.append("artifact manifest does not cover exactly the required artifacts")
    if actual != required:
        errors.append("artifact tree contains missing or untracked artifacts")

    for relative in _REQUIRED_RELATIVE:
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
                if sha256_bytes(content) != expected_hash:
                    errors.append("artifact digest does not match manifest")

    parsed: dict[str, object] = {}
    for relative in _REQUIRED_RELATIVE:
        if relative.endswith(".json"):
            value = _read_canonical_json(run_directory / relative, errors)
            if value is not _INVALID:
                parsed[relative] = value
    if all(relative in parsed for relative in _REQUIRED_RELATIVE if relative.endswith(".json")):
        _verify_coherence(run_directory, parsed, errors, expected_provenance)
    return VerificationResult(not errors, tuple(dict.fromkeys(errors)))


def _read_canonical_json(path: Path, errors: list[str]) -> object:
    try:
        content = path.read_bytes()
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

        junit_sources = {
            name: run_directory / "junit" / f"{name}.xml"
            for name in ("contracts", "policy", "lab", "replay")
        }
        _, junit_results = _read_junit_sources(junit_sources)
        metadata = run_manifest.get("metadata")
        if not _string_mapping(metadata):
            raise AcceptanceEvidenceError("run manifest metadata is invalid")
        _validate_supporting_inputs(
            CollectionInput(
                foundation=source,
                junit_sources=junit_sources,
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
        )
    except (AcceptanceEvidenceError, EvidenceInputError, KeyError, TypeError, ValueError):
        errors.append("artifact bundle is not causally coherent")


def _validate_run_manifest(
    run_directory: Path,
    manifest: Mapping[str, Any],
    foundation: Mapping[str, Any],
    junit_results: Mapping[str, _JunitSummary],
    expected_provenance: ExpectedProvenance | None,
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
        raise AcceptanceEvidenceError("run provenance does not match independent expectations")


def _string_mapping(value: object) -> TypeGuard[Mapping[str, Any]]:
    return isinstance(value, Mapping) and all(isinstance(key, str) for key in value)


def _parse_manifest(manifest: Path, errors: list[str]) -> dict[str, str]:
    try:
        lines = manifest.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeDecodeError):
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
