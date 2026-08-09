"""Assemble a deterministic, non-releasable StateWeaver candidate envelope."""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit

from .common import (
    CANDIDATE_STATUS,
    CHECKSUMS_NAME,
    GIT_COMMIT_OBJECT_PATH,
    GIT_SHA_RE,
    MANIFEST_NAME,
    MAX_CANDIDATE_FILE_BYTES,
    RECEIPT_NAME,
    RECEIPT_SCHEMA_VERSION,
    SBOM_PATH,
    SCHEMA_VERSION,
    VERSION_RE,
    CandidateError,
    assert_secret_free,
    atomic_write,
    canonical_json_bytes,
    sha256_bytes,
    snapshot_tree,
    verify_archives,
    verify_git_commit_object,
    verify_source_archive,
)
from .policy import LIMITATIONS, REQUIRED_GATES
from .receipt import (
    command_records_are_within,
    load_command_records,
    validate_build_command_policy,
)
from .runtime import (
    RUNTIME_REQUIREMENTS_PATH,
    VENDOR_WHEEL_PREFIX,
    RuntimeTarget,
    canonical_runtime_requirements,
    parse_runtime_lock,
    validate_inventory,
)
from .sbom import build_spdx_sbom

_UTC_TIMESTAMP_RE: Final = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_PYTHON_LOCK_PATH: Final = "payload/locks/uv.lock"
_NODE_LOCK_PATH: Final = "payload/locks/apps-web-package-lock.json"


@dataclass(frozen=True)
class BuildRequest:
    candidate_root: Path
    python_lock: Path
    node_lock: Path
    git_commit_object: Path
    command_records: Path
    repository_url: str
    source_sha: str
    tree_sha: str
    version: str
    source_date_epoch: int
    started_at: str
    completed_at: str
    workflow_run_id: str
    workflow_run_attempt: int
    workflow_run_url: str
    runner_os: str
    runner_arch: str
    python_version: str
    python_full_version: str
    pip_version: str
    node_version: str
    uv_version: str
    reproducibility_verified: bool


@dataclass(frozen=True)
class BuildResult:
    manifest_sha256: str
    checksums_sha256: str
    source_sha: str
    status: str


def _read_regular(path: Path, *, code: str) -> bytes:
    try:
        metadata = path.lstat()
        attributes = getattr(metadata, "st_file_attributes", 0)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise CandidateError(code)
        if attributes & reparse_flag:
            raise CandidateError(code)
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            descriptor_metadata = os.fstat(descriptor)
            if not stat.S_ISREG(descriptor_metadata.st_mode):
                raise CandidateError(code)
            if descriptor_metadata.st_size > MAX_CANDIDATE_FILE_BYTES:
                raise CandidateError(code)
            chunks: list[bytes] = []
            actual_size = 0
            while chunk := os.read(descriptor, 1024 * 1024):
                actual_size += len(chunk)
                if actual_size > MAX_CANDIDATE_FILE_BYTES:
                    raise CandidateError(code)
                chunks.append(chunk)
            if actual_size != descriptor_metadata.st_size:
                raise CandidateError(code)
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise CandidateError(code) from error


def _validate_repository_url(value: str) -> None:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise CandidateError("repository-url-invalid") from None
    parts = tuple(part for part in parsed.path.split("/") if part)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
        or len(parts) != 2
        or value.endswith("/")
    ):
        raise CandidateError("repository-url-invalid")


def _validate_timestamp(value: str) -> None:
    if not _UTC_TIMESTAMP_RE.fullmatch(value):
        raise CandidateError("workflow-timestamp-invalid")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        raise CandidateError("workflow-timestamp-invalid") from None
    if parsed.isoformat(timespec="seconds").replace("+00:00", "Z") != value:
        raise CandidateError("workflow-timestamp-invalid")


def _artifact_role(path: str) -> str:
    lower = path.lower()
    if path == _PYTHON_LOCK_PATH:
        return "python-lockfile"
    if path == _NODE_LOCK_PATH:
        return "node-lockfile"
    if path == SBOM_PATH:
        return "spdx-sbom"
    if path == GIT_COMMIT_OBJECT_PATH:
        return "git-commit-object"
    if path == RUNTIME_REQUIREMENTS_PATH:
        return "runtime-requirements"
    if path.startswith(VENDOR_WHEEL_PREFIX) and lower.endswith(".whl"):
        return "third-party-wheel"
    if path.startswith("payload/python/") and lower.endswith(".whl"):
        return "python-wheel"
    if path.startswith("payload/python/") and lower.endswith((".tar.gz", ".tgz")):
        return "python-sdist"
    if path.startswith("payload/web/") and lower.endswith((".tar.gz", ".tgz")):
        return "web-archive"
    if path.startswith("payload/source/") and lower.endswith((".tar.gz", ".tgz")):
        return "source-archive"
    if path.startswith("payload/evidence/foundation/"):
        return "foundation-proof"
    if path.startswith("payload/metadata/"):
        return "installation-metadata"
    if path.startswith("payload/qualification-inputs/m6/"):
        return "m6-qualification-input"
    if path.startswith("payload/qualification-inputs/m7/"):
        return "m7-qualification-input"
    return "supporting-artifact"


def _validate_request(request: BuildRequest) -> None:
    _validate_repository_url(request.repository_url)
    if not GIT_SHA_RE.fullmatch(request.source_sha) or not GIT_SHA_RE.fullmatch(request.tree_sha):
        raise CandidateError("source-identity-invalid")
    if not VERSION_RE.fullmatch(request.version):
        raise CandidateError("version-invalid")
    if request.source_date_epoch < 0 or request.source_date_epoch > 253402300799:
        raise CandidateError("source-date-epoch-invalid")
    _validate_timestamp(request.started_at)
    _validate_timestamp(request.completed_at)
    if request.completed_at < request.started_at:
        raise CandidateError("workflow-timestamp-order-invalid")
    if (
        re.fullmatch(r"[1-9][0-9]*", request.workflow_run_id) is None
        or request.workflow_run_url
        != f"{request.repository_url}/actions/runs/{request.workflow_run_id}"
    ):
        raise CandidateError("workflow-identity-invalid")
    runtime_values = (
        request.runner_os,
        request.runner_arch,
        request.python_version,
        request.python_full_version,
        request.pip_version,
        request.node_version,
        request.uv_version,
    )
    if any(not value or "\n" in value or "\r" in value for value in runtime_values):
        raise CandidateError("workflow-runtime-invalid")
    if (
        request.runner_os != "Linux"
        or request.runner_arch != "X64"
        or request.python_version
        not in {request.python_full_version, f"Python {request.python_full_version}"}
    ):
        raise CandidateError("workflow-runtime-invalid")
    if request.workflow_run_attempt < 1:
        raise CandidateError("workflow-identity-invalid")
    if not request.reproducibility_verified:
        raise CandidateError("reproducibility-not-verified")


def _checksum_file(snapshot: dict[str, bytes], manifest: bytes, receipt: bytes) -> bytes:
    digests = {path: sha256_bytes(content) for path, content in snapshot.items()}
    digests[MANIFEST_NAME] = sha256_bytes(manifest)
    digests[RECEIPT_NAME] = sha256_bytes(receipt)
    return "".join(f"{digest}  {path}\n" for path, digest in sorted(digests.items())).encode()


def build_candidate(request: BuildRequest) -> BuildResult:
    """Create a closed candidate envelope and verify it before returning."""

    _validate_request(request)
    root = request.candidate_root
    root.mkdir(parents=True, exist_ok=True)
    payload = root / "payload"
    if not payload.is_dir():
        raise CandidateError("candidate-payload-missing")
    if any((root / name).exists() for name in (MANIFEST_NAME, CHECKSUMS_NAME, RECEIPT_NAME)):
        raise CandidateError("candidate-output-already-exists")
    initial_snapshot = snapshot_tree(root)
    if any(not path.startswith("payload/") for path in initial_snapshot):
        raise CandidateError("candidate-payload-invalid")

    python_lock = _read_regular(request.python_lock, code="python-lockfile-invalid")
    node_lock = _read_regular(request.node_lock, code="node-lockfile-invalid")
    git_commit_object = _read_regular(request.git_commit_object, code="git-commit-object-invalid")
    command_records_content = _read_regular(
        request.command_records,
        code="command-records-invalid",
    )
    command_records = load_command_records(command_records_content)
    if not command_records_are_within(
        command_records,
        started_at=request.started_at,
        completed_at=request.completed_at,
    ):
        raise CandidateError("command-records-invalid")
    validate_build_command_policy(command_records, source_sha=request.source_sha)
    target = RuntimeTarget.create(request.python_full_version)
    runtime_lock = parse_runtime_lock(python_lock, target)
    verify_archives(initial_snapshot)
    initial_inventory = validate_inventory(
        initial_snapshot, runtime_lock, require_requirements=False
    )
    verify_git_commit_object(
        git_commit_object,
        source_sha=request.source_sha,
        tree_sha=request.tree_sha,
    )
    atomic_write(root / _PYTHON_LOCK_PATH, python_lock)
    atomic_write(root / _NODE_LOCK_PATH, node_lock)
    atomic_write(root / GIT_COMMIT_OBJECT_PATH, git_commit_object)
    atomic_write(
        root / RUNTIME_REQUIREMENTS_PATH,
        canonical_runtime_requirements(runtime_lock),
    )
    sbom = build_spdx_sbom(
        python_lock=python_lock,
        node_lock=node_lock,
        repository_url=request.repository_url,
        source_sha=request.source_sha,
        source_date_epoch=request.source_date_epoch,
        vendored_wheels=dict(initial_inventory.vendored_wheels),
    )
    atomic_write(root / SBOM_PATH, sbom)

    payload_snapshot = snapshot_tree(root)
    if not payload_snapshot or any(not path.startswith("payload/") for path in payload_snapshot):
        raise CandidateError("candidate-payload-invalid")
    assert_secret_free(payload_snapshot)
    verify_archives(payload_snapshot)
    inventory = validate_inventory(payload_snapshot, runtime_lock, require_requirements=True)
    artifacts = [
        {
            "path": path,
            "role": _artifact_role(path),
            "sha256": sha256_bytes(content),
            "size": len(content),
        }
        for path, content in payload_snapshot.items()
    ]
    roles = {str(artifact["role"]) for artifact in artifacts}
    required_roles = {
        "foundation-proof",
        "git-commit-object",
        "node-lockfile",
        "python-lockfile",
        "python-sdist",
        "python-wheel",
        "source-archive",
        "spdx-sbom",
        "runtime-requirements",
        "third-party-wheel",
        "web-archive",
    }
    if not required_roles <= roles:
        raise CandidateError("candidate-required-artifact-missing")
    source_archives = [
        content
        for path, content in payload_snapshot.items()
        if _artifact_role(path) == "source-archive"
    ]
    if len(source_archives) != 1:
        raise CandidateError("candidate-source-archive-count-invalid")
    verify_source_archive(
        source_archives[0],
        python_lock=python_lock,
        node_lock=node_lock,
        expected_tree_sha=request.tree_sha,
        expected_prefix=f"stateweaver-{request.version}",
    )

    locks = [
        {
            "ecosystem": "python-uv",
            "path": _PYTHON_LOCK_PATH,
            "sha256": sha256_bytes(python_lock),
        },
        {
            "ecosystem": "node-npm",
            "path": _NODE_LOCK_PATH,
            "sha256": sha256_bytes(node_lock),
        },
    ]
    source = {
        "commit_sha": request.source_sha,
        "repository_url": request.repository_url,
        "tree_sha": request.tree_sha,
    }
    receipt_value = {
        "artifacts": artifacts,
        "cleanup": {
            "after": [],
            "before": [],
            "reason": (
                "The hosted job is ephemeral; resource inventory was not measured by this "
                "candidate gate."
            ),
            "status": "NOT_MEASURED",
        },
        "dirty": False,
        "execution": {"commands": command_records},
        "gates": list(REQUIRED_GATES),
        "limitations": list(LIMITATIONS),
        "manual_steps": ["workflow_dispatch:source_sha"],
        "network": {
            "dependency_acquisition": "HTTPS_USED_WITH_LOCKED_HASHES",
            "egress": "AVAILABLE_NOT_DISABLED",
            "offline_install_required_after_download": True,
        },
        "payload": {
            "checksums_path": CHECKSUMS_NAME,
            "manifest_path": MANIFEST_NAME,
        },
        "privacy_scan": {
            "method": "high-confidence-secret-patterns-v1",
            "status": "PASS",
        },
        "redaction": {
            "method": "PUBLIC_ALLOWLIST_AND_HIGH_CONFIDENCE_SECRET_PATTERNS",
            "status": "PASS",
        },
        "provenance": {
            "attestation_requirement": "SEPARATE_WORKFLOW_OIDC_ATTESTATION_REQUIRED",
            "does_not_prove": [
                "external M6-M8 qualification",
                "release eligibility",
                "trusted acquisition before verification",
            ],
            "proves_when_verified": [
                "the workflow identity attested PAYLOAD_MANIFEST.json",
                "the manifest digest was bound to the workflow run",
            ],
            "subject_path": MANIFEST_NAME,
            "verification_receipt": "DETACHED_DOWNLOAD_VERIFICATION_RECEIPT_REQUIRED",
        },
        "release_created": False,
        "release_eligible": False,
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "retries": request.workflow_run_attempt - 1,
        "skips": [
            {
                "gate_id": str(gate["gate_id"]),
                "required_for_release": True,
                "status": str(gate["status"]),
            }
            for gate in REQUIRED_GATES
            if gate["status"] != "PASS"
        ],
        "source": source,
        "status": CANDIDATE_STATUS,
        "tag_created": False,
        "workflow": {
            "evidence_cutoff_at": request.completed_at,
            "run_id": request.workflow_run_id,
            "run_attempt": request.workflow_run_attempt,
            "run_url": request.workflow_run_url,
            "runner": {"arch": request.runner_arch, "os": request.runner_os},
            "started_at": request.started_at,
            "tools": {
                "node": request.node_version,
                "pip": request.pip_version,
                "python": request.python_version,
                "uv": request.uv_version,
            },
        },
    }
    receipt = canonical_json_bytes(receipt_value)
    manifest_value = {
        "artifacts": artifacts,
        "build": {
            "inventory": inventory.as_dict(),
            "reproducibility_verified": True,
            "runtime_target": target.as_dict(),
            "source_date_epoch": request.source_date_epoch,
            "version": request.version,
        },
        "locks": locks,
        "receipt": {
            "path": RECEIPT_NAME,
            "sha256": sha256_bytes(receipt),
        },
        "release_eligible": False,
        "sbom": {
            "format": "SPDX-2.3",
            "path": SBOM_PATH,
            "sha256": sha256_bytes(sbom),
        },
        "schema_version": SCHEMA_VERSION,
        "source": source,
        "status": CANDIDATE_STATUS,
    }
    manifest = canonical_json_bytes(manifest_value)
    checksums = _checksum_file(payload_snapshot, manifest, receipt)
    atomic_write(root / RECEIPT_NAME, receipt)
    atomic_write(root / MANIFEST_NAME, manifest)
    atomic_write(root / CHECKSUMS_NAME, checksums)

    from .verify import verify_candidate

    verification = verify_candidate(
        root,
        expected_repository_url=request.repository_url,
        expected_source_sha=request.source_sha,
    )
    if not verification.valid:
        raise CandidateError(verification.errors[0])
    return BuildResult(
        manifest_sha256=sha256_bytes(manifest),
        checksums_sha256=sha256_bytes(checksums),
        source_sha=request.source_sha,
        status=CANDIDATE_STATUS,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate_root", type=Path)
    parser.add_argument("--python-lock", type=Path, required=True)
    parser.add_argument("--node-lock", type=Path, required=True)
    parser.add_argument("--git-commit-object", type=Path, required=True)
    parser.add_argument("--command-records", type=Path, required=True)
    parser.add_argument("--repository-url", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--tree-sha", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-date-epoch", type=int, required=True)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--completed-at", required=True)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--workflow-run-attempt", type=int, required=True)
    parser.add_argument("--workflow-run-url", required=True)
    parser.add_argument("--runner-os", required=True)
    parser.add_argument("--runner-arch", required=True)
    parser.add_argument("--python-version", required=True)
    parser.add_argument("--python-full-version", required=True)
    parser.add_argument("--pip-version", required=True)
    parser.add_argument("--node-version", required=True)
    parser.add_argument("--uv-version", required=True)
    parser.add_argument("--reproducibility-verified", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        result = build_candidate(
            BuildRequest(
                candidate_root=arguments.candidate_root,
                python_lock=arguments.python_lock,
                node_lock=arguments.node_lock,
                git_commit_object=arguments.git_commit_object,
                command_records=arguments.command_records,
                repository_url=arguments.repository_url,
                source_sha=arguments.source_sha,
                tree_sha=arguments.tree_sha,
                version=arguments.version,
                source_date_epoch=arguments.source_date_epoch,
                started_at=arguments.started_at,
                completed_at=arguments.completed_at,
                workflow_run_id=arguments.workflow_run_id,
                workflow_run_attempt=arguments.workflow_run_attempt,
                workflow_run_url=arguments.workflow_run_url,
                runner_os=arguments.runner_os,
                runner_arch=arguments.runner_arch,
                python_version=arguments.python_version,
                python_full_version=arguments.python_full_version,
                pip_version=arguments.pip_version,
                node_version=arguments.node_version,
                uv_version=arguments.uv_version,
                reproducibility_verified=arguments.reproducibility_verified,
            )
        )
    except (CandidateError, MemoryError, OverflowError, RecursionError) as error:
        code = error.code if isinstance(error, CandidateError) else "candidate-resource-limit"
        print(canonical_json_bytes({"error": code, "valid": False}).decode(), end="")
        return 1
    print(canonical_json_bytes({**result.__dict__, "valid": True}).decode(), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
