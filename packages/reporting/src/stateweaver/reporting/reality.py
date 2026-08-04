"""Deterministic publication candidates for immutable-byte Reality evidence.

The publication layer closes a reporting and payload-manifest boundary only. It deliberately
does not authenticate an issuer, reopen filesystem paths, or authorize Finding promotion.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)
from stateweaver.contracts import (
    RealityReplayReceipt,
    Sha256Digest,
    canonical_json_bytes,
)
from stateweaver.evidence import (
    RealityArtifactRole,
    RealityEvidenceManifestV2,
    RealityManifestEntry,
    verify_reality_pre_receipt_bundle,
)

_PROFILE: Literal["source-backed-synthetic-v2"] = "source-backed-synthetic-v2"
_PATH_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)*$")
_PRE_MANIFEST_PATH = "meta/pre-receipt-manifest.json"
_RECEIPT_PATH = "claims/reality-replay-receipt.json"
_REPORT_PATH = "reports/reality-publication-report.md"

SafePublicationPath = Annotated[
    str,
    StringConstraints(min_length=3, max_length=255, pattern=_PATH_RE.pattern),
]


class _PublicationModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
        str_strip_whitespace=True,
    )

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self)


class PublicationArtifactRole(StrEnum):
    PRE_RECEIPT_ARTIFACT = "pre-receipt-artifact"
    PRE_RECEIPT_MANIFEST = "pre-receipt-manifest"
    RECEIPT = "receipt"
    REPORT = "report"


class RealityPublicationManifestEntry(_PublicationModel):
    """One exact publication payload entry; the manifest itself is out of its payload."""

    path: SafePublicationPath
    role: PublicationArtifactRole
    sha256: Sha256Digest
    source_path: SafePublicationPath | None = None
    source_role: RealityArtifactRole | None = None
    run_id: str | None = None
    control_name: str | None = None

    @model_validator(mode="after")
    def source_metadata_has_exact_shape(self) -> Self:
        if self.role is PublicationArtifactRole.PRE_RECEIPT_ARTIFACT:
            if self.source_path is None or self.source_role is None:
                raise ValueError("pre-receipt artifacts require source path and role")
        elif any(
            value is not None
            for value in (self.source_path, self.source_role, self.run_id, self.control_name)
        ):
            raise ValueError("publication metadata artifacts cannot carry source identity")
        return self


class RealityPublicationManifest(_PublicationModel):
    """Canonical payload manifest for a non-authoritative publication candidate."""

    schema_version: Literal["reality-publication-candidate-v1"] = "reality-publication-candidate-v1"
    profile: Literal["source-backed-synthetic-v2"] = _PROFILE
    authoritative: Literal[False] = False
    promotable: Literal[False] = False
    attested: Literal[False] = False
    control_kind_semantics_attested: Literal[False] = False
    receipt_hash: Sha256Digest
    receipt_sha256: Sha256Digest
    pre_receipt_manifest_sha256: Sha256Digest
    pre_receipt_snapshot_sha256: Sha256Digest
    report_sha256: Sha256Digest
    entries: Annotated[tuple[RealityPublicationManifestEntry, ...], Field(min_length=4)]

    @field_validator("entries")
    @classmethod
    def entries_are_canonical_and_unique(
        cls, value: tuple[RealityPublicationManifestEntry, ...]
    ) -> tuple[RealityPublicationManifestEntry, ...]:
        paths = tuple(entry.path for entry in value)
        if paths != tuple(sorted(paths)):
            raise ValueError("publication entries must use canonical path order")
        if len(paths) != len(set(paths)):
            raise ValueError("publication entry paths must be unique")
        return value

    @model_validator(mode="after")
    def payload_has_exact_metadata_closure(self) -> Self:
        fixed = {
            PublicationArtifactRole.PRE_RECEIPT_MANIFEST: (
                _PRE_MANIFEST_PATH,
                self.pre_receipt_manifest_sha256,
            ),
            PublicationArtifactRole.RECEIPT: (_RECEIPT_PATH, self.receipt_sha256),
            PublicationArtifactRole.REPORT: (_REPORT_PATH, self.report_sha256),
        }
        for role, expected in fixed.items():
            matches = tuple(entry for entry in self.entries if entry.role is role)
            if len(matches) != 1 or (matches[0].path, matches[0].sha256) != expected:
                raise ValueError("publication metadata closure is invalid")
        if not any(
            entry.role is PublicationArtifactRole.PRE_RECEIPT_ARTIFACT for entry in self.entries
        ):
            raise ValueError("publication must retain pre-receipt artifacts")
        return self


@dataclass(frozen=True)
class RealityPublication:
    """Immutable in-memory publication payload plus its out-of-band manifest digest."""

    manifest_json: bytes
    artifacts: Mapping[str, bytes]
    publication_sha256: str
    receipt_sha256: str
    pre_receipt_manifest_sha256: str
    pre_receipt_snapshot_sha256: str
    report_sha256: str

    @property
    def authoritative(self) -> Literal[False]:
        return False

    @property
    def promotable(self) -> Literal[False]:
        return False

    @property
    def attested(self) -> Literal[False]:
        return False

    @property
    def control_kind_semantics_attested(self) -> Literal[False]:
        return False


@dataclass(frozen=True)
class RealityPublicationVerificationResult:
    valid: bool
    errors: tuple[str, ...]
    publication_sha256: str | None = None
    receipt_sha256: str | None = None
    pre_receipt_manifest_sha256: str | None = None
    pre_receipt_snapshot_sha256: str | None = None
    report_sha256: str | None = None

    @property
    def authoritative(self) -> Literal[False]:
        return False

    @property
    def promotable(self) -> Literal[False]:
        return False

    @property
    def attested(self) -> Literal[False]:
        return False

    @property
    def control_kind_semantics_attested(self) -> Literal[False]:
        return False


class RealityPublicationError(ValueError):
    """Stable build-time rejection for an invalid pre-receipt candidate."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _PublicationVerificationError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _tagged_sha256(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def _safe_publication_path(path: object) -> bool:
    if type(path) is not str or not path.isascii() or _PATH_RE.fullmatch(path) is None:
        return False
    return all(part not in {"", ".", ".."} for part in path.split("/"))


def _snapshot_mapping(
    artifacts: Mapping[str, bytes],
    *,
    require_publication_paths: bool,
) -> dict[str, bytes]:
    try:
        keys = tuple(artifacts)
    except (RuntimeError, TypeError) as error:
        raise _PublicationVerificationError("artifact-snapshot-invalid") from error
    if not keys or len(keys) != len(set(keys)):
        raise _PublicationVerificationError("artifact-snapshot-invalid")
    snapshot: dict[str, bytes] = {}
    try:
        for path in keys:
            if type(path) is not str or (
                require_publication_paths and not _safe_publication_path(path)
            ):
                raise _PublicationVerificationError("artifact-path-invalid")
            content = artifacts[path]
            if type(content) is not bytes:
                raise _PublicationVerificationError("artifact-snapshot-invalid")
            snapshot[path] = content
    except (KeyError, RuntimeError, TypeError) as error:
        raise _PublicationVerificationError("artifact-snapshot-invalid") from error
    return snapshot


def _parse_canonical_model[ModelT: BaseModel](
    model_type: type[ModelT],
    content: bytes,
    *,
    invalid_code: str,
    noncanonical_code: str,
) -> ModelT:
    if type(content) is not bytes:
        raise _PublicationVerificationError("serialized-input-required")
    try:
        model = model_type.model_validate_json(content)
    except (ValidationError, ValueError) as error:
        raise _PublicationVerificationError(invalid_code) from error
    if canonical_json_bytes(model) != content:
        raise _PublicationVerificationError(noncanonical_code)
    return model


def _receipt_digest_claims(
    receipt: RealityReplayReceipt,
    entry: RealityManifestEntry,
) -> tuple[str, ...]:
    claims: list[tuple[str, str]] = []

    def claim(pointer: str, digest: str) -> None:
        claims.append((pointer, digest))

    static = {
        RealityArtifactRole.SCOPE: ("#/scope_manifest_sha256", receipt.scope_manifest_sha256),
        RealityArtifactRole.TARGET_LOCK: ("#/target_lock_sha256", receipt.target_lock_sha256),
        RealityArtifactRole.ADAPTER_LOCK: (
            "#/adapter_lock_sha256",
            receipt.adapter_lock_sha256,
        ),
        RealityArtifactRole.PLAN: ("#/plan_hash", receipt.plan_hash),
    }
    if entry.role in static:
        claim(*static[entry.role])

    if entry.role is RealityArtifactRole.PRIMARY_ORACLES:
        for index, attempt in enumerate(receipt.attempts):
            claim(f"#/attempts/{index}/oracle_results_hash", attempt.oracle_results_hash)

    for index, attempt in enumerate(receipt.attempts):
        if entry.run_id != attempt.replay_run_id:
            continue
        attempt_claims = {
            RealityArtifactRole.PRIMARY_RESULT: attempt.replay_result_sha256,
            RealityArtifactRole.PRIMARY_ACTION_LOG: attempt.action_log_sha256,
        }
        digest = attempt_claims.get(entry.role)
        if digest is not None:
            claim(f"#/attempts/{index}/{_attempt_digest_field(entry.role)}", digest)

    for index, control in enumerate(receipt.negative_controls):
        if entry.control_name != control.name or entry.run_id != control.replay_run_id:
            continue
        control_claims = {
            RealityArtifactRole.CONTROL_PLAN: ("plan_hash", control.plan_hash),
            RealityArtifactRole.CONTROL_RESULT: (
                "replay_result_sha256",
                control.replay_result_sha256,
            ),
            RealityArtifactRole.CONTROL_ACTION_LOG: (
                "action_log_sha256",
                control.action_log_sha256,
            ),
            RealityArtifactRole.CONTROL_ORACLES: (
                "oracle_results_hash",
                control.oracle_results_hash,
            ),
            RealityArtifactRole.CONTROL_DELTA: (
                "control_delta_sha256",
                control.control_delta_sha256,
            ),
        }
        selected = control_claims.get(entry.role)
        if selected is not None:
            field, digest = selected
            claim(f"#/negative_controls/{index}/{field}", digest)

    patch = receipt.patched_version
    if patch is not None and entry.run_id == patch.replay_run_id:
        patch_claims = {
            RealityArtifactRole.PATCH_TARGET_LOCK: (
                "target_lock_sha256",
                patch.target_lock_sha256,
            ),
            RealityArtifactRole.PATCH_RESULT: (
                "replay_result_sha256",
                patch.replay_result_sha256,
            ),
            RealityArtifactRole.PATCH_ACTION_LOG: (
                "action_log_sha256",
                patch.action_log_sha256,
            ),
            RealityArtifactRole.PATCH_ORACLES: (
                "oracle_results_hash",
                patch.oracle_results_hash,
            ),
        }
        selected = patch_claims.get(entry.role)
        if selected is not None:
            field, digest = selected
            claim(f"#/patched_version/{field}", digest)

    return tuple(pointer for pointer, digest in claims if digest == entry.sha256)


def _attempt_digest_field(role: RealityArtifactRole) -> str:
    return {
        RealityArtifactRole.PRIMARY_RESULT: "replay_result_sha256",
        RealityArtifactRole.PRIMARY_ACTION_LOG: "action_log_sha256",
    }[role]


def _build_report(
    *,
    receipt: RealityReplayReceipt,
    pre_manifest: RealityEvidenceManifestV2,
    receipt_sha256: str,
    pre_manifest_sha256: str,
    pre_snapshot_sha256: str,
) -> bytes:
    receipt_link = f"[`{receipt.receipt_id}`](../{_RECEIPT_PATH})"
    pre_manifest_link = f"[`{pre_manifest_sha256}`](../{_PRE_MANIFEST_PATH})"
    lines = [
        "# StateWeaver Reality Publication Candidate",
        "",
        "> Internal-coherence candidate only. This report is not an issuer attestation, "
        "Finding promotion credential, M6 certification, or proof of external execution.",
        "",
        "## Bound candidate",
        "",
        f"- Receipt ID: {receipt_link}",
        f"- Receipt semantic hash: `{receipt.receipt_hash}` ({receipt_link})",
        f"- Exact receipt bytes: `{receipt_sha256}` ({receipt_link})",
        f"- Pre-receipt manifest: {pre_manifest_link}",
        f"- Verified pre-receipt snapshot: `{pre_snapshot_sha256}`",
        f"- Target: `{receipt.target_id}` at `{receipt.target_version}` ({receipt_link})",
        f"- Chain / plan / root: `{receipt.chain_id}` / `{receipt.plan_id}` / "
        f"`{receipt.root_seed_id}` ({receipt_link})",
        f"- Primary attempts / controls / patch: `{len(receipt.attempts)}` / "
        f"`{len(receipt.negative_controls)}` / "
        f"`{'present' if receipt.patched_version is not None else 'absent'}`",
        "",
        "## Trust boundary",
        "",
        "| Property | Value |",
        "| --- | --- |",
        "| Event semantics derived from typed replay results | `true` |",
        "| Control delta derived from exact plan/root/result artifacts | `true` |",
        "| Control-kind semantics attested | `false` |",
        "| Producer or issuer attested | `false` |",
        "| Authoritative | `false` |",
        "| Promotable | `false` |",
        "",
        "## Artifact trace",
        "",
        "Every row links the report claim to the exact retained artifact. `receipt-exact-digest` "
        "means the receipt also carries that raw digest; `causal-verifier` means the immutable "
        "pre-receipt resolver validated the typed relation without claiming a direct raw digest.",
        "",
        "| Artifact | Role | Exact SHA-256 | Run | Control | Binding | Receipt claim(s) |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for index, entry in enumerate(pre_manifest.entries):
        receipt_claims = _receipt_digest_claims(receipt, entry)
        binding = (
            "manifest-exact + receipt-exact-digest"
            if receipt_claims
            else ("manifest-exact + causal-verifier")
        )
        claim_text = "<br>".join(f"`{pointer}`" for pointer in receipt_claims) or "—"
        run_id = f"`{entry.run_id}`" if entry.run_id is not None else "—"
        control_name = f"`{entry.control_name}`" if entry.control_name is not None else "—"
        artifact_link = f"[`{entry.path}`](../artifacts/{entry.path})"
        manifest_pointer = f"pre-manifest `#/entries/{index}`"
        lines.append(
            f"| {artifact_link} | `{entry.role.value}` | `{entry.sha256}` | {run_id} | "
            f"{control_name} | `{binding}`; {manifest_pointer} | {claim_text} |"
        )
    lines.extend(
        [
            "",
            "The final publication manifest is intentionally not listed inside itself. Its exact "
            "digest is an out-of-band candidate identifier for a future trusted attestation layer.",
            "",
        ]
    )
    return "\n".join(lines).encode("utf-8")


def _source_publication_entry(entry: RealityManifestEntry) -> RealityPublicationManifestEntry:
    return RealityPublicationManifestEntry(
        path=f"artifacts/{entry.path}",
        role=PublicationArtifactRole.PRE_RECEIPT_ARTIFACT,
        sha256=entry.sha256,
        source_path=entry.path,
        source_role=entry.role,
        run_id=entry.run_id,
        control_name=entry.control_name,
    )


def _derive_publication_manifest(
    *,
    receipt: RealityReplayReceipt,
    pre_manifest: RealityEvidenceManifestV2,
    receipt_sha256: str,
    pre_manifest_sha256: str,
    pre_snapshot_sha256: str,
    report_sha256: str,
) -> RealityPublicationManifest:
    entries = [*(_source_publication_entry(entry) for entry in pre_manifest.entries)]
    entries.extend(
        (
            RealityPublicationManifestEntry(
                path=_PRE_MANIFEST_PATH,
                role=PublicationArtifactRole.PRE_RECEIPT_MANIFEST,
                sha256=pre_manifest_sha256,
            ),
            RealityPublicationManifestEntry(
                path=_RECEIPT_PATH,
                role=PublicationArtifactRole.RECEIPT,
                sha256=receipt_sha256,
            ),
            RealityPublicationManifestEntry(
                path=_REPORT_PATH,
                role=PublicationArtifactRole.REPORT,
                sha256=report_sha256,
            ),
        )
    )
    return RealityPublicationManifest(
        receipt_hash=receipt.receipt_hash,
        receipt_sha256=receipt_sha256,
        pre_receipt_manifest_sha256=pre_manifest_sha256,
        pre_receipt_snapshot_sha256=pre_snapshot_sha256,
        report_sha256=report_sha256,
        entries=tuple(sorted(entries, key=lambda item: item.path)),
    )


def _validated_pre_receipt_models(
    *,
    receipt_json: bytes,
    pre_manifest_json: bytes,
) -> tuple[RealityReplayReceipt, RealityEvidenceManifestV2]:
    receipt = _parse_canonical_model(
        RealityReplayReceipt,
        receipt_json,
        invalid_code="receipt-invalid",
        noncanonical_code="receipt-not-canonical",
    )
    pre_manifest = _parse_canonical_model(
        RealityEvidenceManifestV2,
        pre_manifest_json,
        invalid_code="pre-receipt-manifest-invalid",
        noncanonical_code="pre-receipt-manifest-not-canonical",
    )
    return receipt, pre_manifest


def build_reality_publication(
    *,
    receipt_json: bytes,
    pre_receipt_manifest_json: bytes,
    pre_receipt_artifacts: Mapping[str, bytes],
) -> RealityPublication:
    """Build one closed, deterministic, non-authoritative publication candidate in memory."""

    try:
        if type(receipt_json) is not bytes or type(pre_receipt_manifest_json) is not bytes:
            raise _PublicationVerificationError("serialized-input-required")
        source_snapshot = _snapshot_mapping(
            pre_receipt_artifacts,
            require_publication_paths=False,
        )
        verification = verify_reality_pre_receipt_bundle(
            receipt_json=receipt_json,
            manifest_json=pre_receipt_manifest_json,
            artifacts=source_snapshot,
        )
        if not verification.valid:
            detail = verification.errors[0] if verification.errors else "unknown"
            raise _PublicationVerificationError(f"pre-receipt-{detail}")
        receipt, pre_manifest = _validated_pre_receipt_models(
            receipt_json=receipt_json,
            pre_manifest_json=pre_receipt_manifest_json,
        )
        pre_snapshot_sha256 = verification.snapshot_sha256
        if pre_snapshot_sha256 is None:
            raise _PublicationVerificationError("pre-receipt-result-incomplete")
        receipt_sha256 = _tagged_sha256(receipt_json)
        pre_manifest_sha256 = _tagged_sha256(pre_receipt_manifest_json)
        report = _build_report(
            receipt=receipt,
            pre_manifest=pre_manifest,
            receipt_sha256=receipt_sha256,
            pre_manifest_sha256=pre_manifest_sha256,
            pre_snapshot_sha256=pre_snapshot_sha256,
        )
        report_sha256 = _tagged_sha256(report)
        manifest = _derive_publication_manifest(
            receipt=receipt,
            pre_manifest=pre_manifest,
            receipt_sha256=receipt_sha256,
            pre_manifest_sha256=pre_manifest_sha256,
            pre_snapshot_sha256=pre_snapshot_sha256,
            report_sha256=report_sha256,
        )
        manifest_json = manifest.canonical_bytes()
        publication_artifacts = {
            **{
                f"artifacts/{entry.path}": source_snapshot[entry.path]
                for entry in pre_manifest.entries
            },
            _PRE_MANIFEST_PATH: pre_receipt_manifest_json,
            _RECEIPT_PATH: receipt_json,
            _REPORT_PATH: report,
        }
        return RealityPublication(
            manifest_json=manifest_json,
            artifacts=MappingProxyType(dict(sorted(publication_artifacts.items()))),
            publication_sha256=_tagged_sha256(manifest_json),
            receipt_sha256=receipt_sha256,
            pre_receipt_manifest_sha256=pre_manifest_sha256,
            pre_receipt_snapshot_sha256=pre_snapshot_sha256,
            report_sha256=report_sha256,
        )
    except _PublicationVerificationError as error:
        raise RealityPublicationError(error.code) from error


def _source_projection(
    manifest: RealityPublicationManifest,
    snapshot: Mapping[str, bytes],
) -> tuple[RealityEvidenceManifestV2, dict[str, bytes]]:
    entries: list[RealityManifestEntry] = []
    artifacts: dict[str, bytes] = {}
    for publication_entry in manifest.entries:
        if publication_entry.role is not PublicationArtifactRole.PRE_RECEIPT_ARTIFACT:
            continue
        source_path = publication_entry.source_path
        source_role = publication_entry.source_role
        if source_path is None or source_role is None:
            raise _PublicationVerificationError("publication-source-projection-invalid")
        if publication_entry.path != f"artifacts/{source_path}":
            raise _PublicationVerificationError("publication-source-projection-invalid")
        try:
            source_entry = RealityManifestEntry(
                role=source_role,
                path=source_path,
                sha256=publication_entry.sha256,
                run_id=publication_entry.run_id,
                control_name=publication_entry.control_name,
            )
        except ValidationError as error:
            raise _PublicationVerificationError("publication-source-projection-invalid") from error
        entries.append(source_entry)
        artifacts[source_path] = snapshot[publication_entry.path]
    try:
        pre_manifest = RealityEvidenceManifestV2(entries=tuple(entries))
    except ValidationError as error:
        raise _PublicationVerificationError("publication-source-projection-invalid") from error
    return pre_manifest, artifacts


def verify_reality_publication(
    *,
    manifest_json: bytes,
    artifacts: Mapping[str, bytes],
) -> RealityPublicationVerificationResult:
    """Verify exact publication bytes and re-derive the report from the pre-receipt candidate."""

    try:
        if type(manifest_json) is not bytes:
            raise _PublicationVerificationError("serialized-input-required")
        snapshot = _snapshot_mapping(artifacts, require_publication_paths=True)
        manifest = _parse_canonical_model(
            RealityPublicationManifest,
            manifest_json,
            invalid_code="publication-manifest-invalid",
            noncanonical_code="publication-manifest-not-canonical",
        )
        if set(snapshot) != {entry.path for entry in manifest.entries}:
            raise _PublicationVerificationError("publication-artifact-coverage-mismatch")
        for entry in manifest.entries:
            if _tagged_sha256(snapshot[entry.path]) != entry.sha256:
                raise _PublicationVerificationError("publication-artifact-digest-mismatch")

        projected_manifest, projected_artifacts = _source_projection(manifest, snapshot)
        retained_pre_manifest_json = snapshot[_PRE_MANIFEST_PATH]
        if projected_manifest.canonical_bytes() != retained_pre_manifest_json:
            raise _PublicationVerificationError("pre-receipt-manifest-projection-mismatch")
        receipt_json = snapshot[_RECEIPT_PATH]
        receipt, retained_pre_manifest = _validated_pre_receipt_models(
            receipt_json=receipt_json,
            pre_manifest_json=retained_pre_manifest_json,
        )
        verification = verify_reality_pre_receipt_bundle(
            receipt_json=receipt_json,
            manifest_json=retained_pre_manifest_json,
            artifacts=projected_artifacts,
        )
        if not verification.valid:
            detail = verification.errors[0] if verification.errors else "unknown"
            raise _PublicationVerificationError(f"pre-receipt-{detail}")
        pre_snapshot_sha256 = verification.snapshot_sha256
        if pre_snapshot_sha256 is None:
            raise _PublicationVerificationError("pre-receipt-result-incomplete")
        receipt_sha256 = _tagged_sha256(receipt_json)
        pre_manifest_sha256 = _tagged_sha256(retained_pre_manifest_json)
        expected_report = _build_report(
            receipt=receipt,
            pre_manifest=retained_pre_manifest,
            receipt_sha256=receipt_sha256,
            pre_manifest_sha256=pre_manifest_sha256,
            pre_snapshot_sha256=pre_snapshot_sha256,
        )
        if snapshot[_REPORT_PATH] != expected_report:
            raise _PublicationVerificationError("report-derivation-mismatch")
        report_sha256 = _tagged_sha256(expected_report)
        expected_manifest = _derive_publication_manifest(
            receipt=receipt,
            pre_manifest=retained_pre_manifest,
            receipt_sha256=receipt_sha256,
            pre_manifest_sha256=pre_manifest_sha256,
            pre_snapshot_sha256=pre_snapshot_sha256,
            report_sha256=report_sha256,
        )
        if expected_manifest.canonical_bytes() != manifest_json:
            raise _PublicationVerificationError("publication-manifest-derivation-mismatch")
        return RealityPublicationVerificationResult(
            valid=True,
            errors=(),
            publication_sha256=_tagged_sha256(manifest_json),
            receipt_sha256=receipt_sha256,
            pre_receipt_manifest_sha256=pre_manifest_sha256,
            pre_receipt_snapshot_sha256=pre_snapshot_sha256,
            report_sha256=report_sha256,
        )
    except _PublicationVerificationError as error:
        return RealityPublicationVerificationResult(valid=False, errors=(error.code,))
    except (KeyError, TypeError, ValueError):
        return RealityPublicationVerificationResult(
            valid=False,
            errors=("publication-resolution-failed",),
        )


__all__ = [
    "PublicationArtifactRole",
    "RealityPublication",
    "RealityPublicationError",
    "RealityPublicationManifest",
    "RealityPublicationManifestEntry",
    "RealityPublicationVerificationResult",
    "build_reality_publication",
    "verify_reality_publication",
]
