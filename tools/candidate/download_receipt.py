"""Build a detached receipt after fresh download, attestation, and offline installation."""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .common import (
    GIT_SHA_RE,
    MAX_METADATA_JSON_BYTES,
    SHA256_RE,
    VERSION_RE,
    CandidateError,
    atomic_write,
    canonical_json_bytes,
    parse_canonical_json,
    require_mapping,
    sha256_bytes,
    snapshot_tree,
)
from .receipt import (
    command_records_are_within,
    load_command_records,
    validate_download_command_policy,
    validate_utc_timestamp,
)
from .verify import verify_candidate

DOWNLOAD_RECEIPT_SCHEMA: Final = "stateweaver-download-verification-receipt-v1"
DOWNLOAD_RECEIPT_NAME: Final = "DOWNLOAD_VERIFICATION_RECEIPT.json"


@dataclass(frozen=True)
class DownloadReceiptRequest:
    candidate_root: Path
    attestation_bundle: Path
    command_records: Path
    output: Path
    workspace: Path
    canonical_source_archive: Path
    verifier_source: Path
    install_root: Path
    repository_url: str
    source_sha: str
    source_ref: str
    manifest_sha256: str
    actions_artifact_sha256: str
    workflow_run_id: str
    workflow_run_attempt: int
    workflow_run_url: str
    signer_workflow: str
    version: str
    started_at: str
    completed_at: str
    runner_os: str
    runner_arch: str


def _read_regular(path: Path, *, code: str) -> bytes:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise CandidateError(code)
        if metadata.st_size > MAX_METADATA_JSON_BYTES:
            raise CandidateError(code)
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            descriptor_metadata = os.fstat(descriptor)
            if not stat.S_ISREG(descriptor_metadata.st_mode):
                raise CandidateError(code)
            content = os.read(descriptor, MAX_METADATA_JSON_BYTES + 1)
            if len(content) != descriptor_metadata.st_size:
                raise CandidateError(code)
            return content
        finally:
            os.close(descriptor)
    except OSError as error:
        raise CandidateError(code) from error


def build_download_receipt(request: DownloadReceiptRequest) -> bytes:
    started_at = validate_utc_timestamp(request.started_at, code="download-receipt-invalid")
    completed_at = validate_utc_timestamp(request.completed_at, code="download-receipt-invalid")
    if completed_at < started_at or request.workflow_run_attempt < 1:
        raise CandidateError("download-receipt-invalid")
    if (
        not GIT_SHA_RE.fullmatch(request.source_sha)
        or not SHA256_RE.fullmatch(request.manifest_sha256)
        or not SHA256_RE.fullmatch(request.actions_artifact_sha256)
        or request.source_ref != "refs/heads/main"
        or re.fullmatch(r"[1-9][0-9]*", request.workflow_run_id) is None
        or request.workflow_run_url
        != f"{request.repository_url}/actions/runs/{request.workflow_run_id}"
        or request.signer_workflow
        != (f"{request.repository_url.removeprefix('https://')}/.github/workflows/candidate.yml")
        or not VERSION_RE.fullmatch(request.version)
        or request.runner_os != "Linux"
        or request.runner_arch != "X64"
    ):
        raise CandidateError("download-receipt-invalid")
    snapshot = snapshot_tree(request.candidate_root)
    manifest = snapshot.get("PAYLOAD_MANIFEST.json")
    if manifest is None or sha256_bytes(manifest) != request.manifest_sha256:
        raise CandidateError("download-manifest-digest-invalid")
    verification = verify_candidate(
        request.candidate_root,
        expected_repository_url=request.repository_url,
        expected_source_sha=request.source_sha,
    )
    if not verification.valid or verification.manifest_sha256 != request.manifest_sha256:
        raise CandidateError("download-candidate-verification-invalid")
    manifest_value = require_mapping(
        parse_canonical_json(manifest, code="download-manifest-invalid"),
        code="download-manifest-invalid",
    )
    build_value = require_mapping(manifest_value.get("build"), code="download-manifest-invalid")
    if build_value.get("version") != request.version:
        raise CandidateError("download-version-mismatch")
    bundle = _read_regular(request.attestation_bundle, code="download-attestation-bundle-invalid")
    records = load_command_records(
        _read_regular(request.command_records, code="download-command-records-invalid")
    )
    if not command_records_are_within(
        records,
        started_at=started_at,
        completed_at=completed_at,
    ):
        raise CandidateError("download-command-coverage-invalid")
    candidate_root = request.candidate_root.resolve(strict=True).as_posix()
    workspace = request.workspace.resolve(strict=True).as_posix()
    bundle_path = request.attestation_bundle.resolve(strict=True).as_posix()
    canonical_source = request.canonical_source_archive.resolve(strict=False).as_posix()
    verifier_source = request.verifier_source.resolve(strict=True).as_posix()
    install_root = request.install_root.resolve(strict=False).as_posix()
    wheel_paths = tuple(
        f"{candidate_root}/{path}"
        for path in sorted(snapshot)
        if path.startswith("payload/python/") and path.endswith(".whl")
    )
    if len(wheel_paths) != 18:
        raise CandidateError("download-command-policy-invalid")
    proof_roots = {
        f"{candidate_root}/{'/'.join(path.split('/')[:5])}"
        for path in snapshot
        if path.startswith("payload/evidence/foundation/runs/") and len(path.split("/")) > 5
    }
    if len(proof_roots) != 1:
        raise CandidateError("download-command-policy-invalid")
    repository_slug = request.repository_url.removeprefix("https://github.com/")
    if repository_slug.count("/") != 1:
        raise CandidateError("download-command-policy-invalid")
    validate_download_command_policy(
        records,
        workspace=workspace,
        candidate_root=candidate_root,
        canonical_source_archive=canonical_source,
        attestation_bundle=bundle_path,
        verifier_source=verifier_source,
        install_root=install_root,
        repository_url=request.repository_url,
        repository_slug=repository_slug,
        source_sha=request.source_sha,
        source_ref=request.source_ref,
        signer_workflow=request.signer_workflow,
        version=request.version,
        workspace_wheels=wheel_paths,
        proof_run=next(iter(proof_roots)),
    )
    receipt = {
        "artifacts": [
            {
                "path": "PAYLOAD_MANIFEST.json",
                "role": "payload-manifest",
                "sha256": request.manifest_sha256,
                "size": len(manifest),
            },
            {
                "path": request.attestation_bundle.name,
                "role": "oidc-attestation-bundle",
                "sha256": sha256_bytes(bundle),
                "size": len(bundle),
            },
        ],
        "cleanup": {
            "after": [],
            "before": [],
            "reason": "The hosted job is ephemeral; cleanup inventory was not measured.",
            "status": "NOT_MEASURED",
        },
        "dirty": False,
        "execution": {"commands": records},
        "limitations": [
            "Verification ran on a GitHub-hosted job, not an independent M8 clean machine.",
            (
                "Host egress remained available; artifact installation was constrained by "
                "offline/no-index flags."
            ),
            "The receipt does not qualify M2-M8 or authorize a tag or GitHub Release.",
        ],
        "manual_steps": ["workflow_dispatch:source_sha"],
        "network": {
            "egress": "AVAILABLE_NOT_DISABLED",
            "installation": "OFFLINE_NO_INDEX_NO_CACHE",
        },
        "payload": {
            "actions_artifact_sha256": request.actions_artifact_sha256,
            "candidate_file_count": len(snapshot),
            "manifest_sha256": request.manifest_sha256,
        },
        "provenance": {
            "attestation_bundle_sha256": sha256_bytes(bundle),
            "deny_self_hosted_runners": True,
            "signer_workflow": request.signer_workflow,
            "source_digest": request.source_sha,
            "source_ref": request.source_ref,
            "status": "PASS",
        },
        "redaction": {"status": "PASS", "method": "candidate-verifier-secret-patterns-v1"},
        "retries": request.workflow_run_attempt - 1,
        "schema_version": DOWNLOAD_RECEIPT_SCHEMA,
        "source": {
            "commit_sha": request.source_sha,
            "ref": request.source_ref,
            "repository_url": request.repository_url,
        },
        "status": "PASS",
        "workflow": {
            "completed_at": completed_at,
            "run_id": request.workflow_run_id,
            "run_attempt": request.workflow_run_attempt,
            "run_url": request.workflow_run_url,
            "runner": {"arch": request.runner_arch, "os": request.runner_os},
            "started_at": started_at,
        },
    }
    return canonical_json_bytes(receipt)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate_root", type=Path)
    parser.add_argument("--attestation-bundle", type=Path, required=True)
    parser.add_argument("--command-records", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--canonical-source-archive", type=Path, required=True)
    parser.add_argument("--verifier-source", type=Path, required=True)
    parser.add_argument("--install-root", type=Path, required=True)
    parser.add_argument("--repository-url", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--actions-artifact-sha256", required=True)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--workflow-run-attempt", type=int, required=True)
    parser.add_argument("--workflow-run-url", required=True)
    parser.add_argument("--signer-workflow", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--completed-at", required=True)
    parser.add_argument("--runner-os", required=True)
    parser.add_argument("--runner-arch", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        content = build_download_receipt(
            DownloadReceiptRequest(
                candidate_root=arguments.candidate_root,
                attestation_bundle=arguments.attestation_bundle,
                command_records=arguments.command_records,
                output=arguments.output,
                workspace=arguments.workspace,
                canonical_source_archive=arguments.canonical_source_archive,
                verifier_source=arguments.verifier_source,
                install_root=arguments.install_root,
                repository_url=arguments.repository_url,
                source_sha=arguments.source_sha,
                source_ref=arguments.source_ref,
                manifest_sha256=arguments.manifest_sha256,
                actions_artifact_sha256=arguments.actions_artifact_sha256,
                workflow_run_id=arguments.workflow_run_id,
                workflow_run_attempt=arguments.workflow_run_attempt,
                workflow_run_url=arguments.workflow_run_url,
                signer_workflow=arguments.signer_workflow,
                version=arguments.version,
                started_at=arguments.started_at,
                completed_at=arguments.completed_at,
                runner_os=arguments.runner_os,
                runner_arch=arguments.runner_arch,
            )
        )
        atomic_write(arguments.output, content)
    except (CandidateError, MemoryError, OverflowError, RecursionError) as error:
        code = error.code if isinstance(error, CandidateError) else "download-resource-limit"
        print(canonical_json_bytes({"error": code, "valid": False}).decode(), end="")
        return 1
    print(canonical_json_bytes({"sha256": sha256_bytes(content), "valid": True}).decode(), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
