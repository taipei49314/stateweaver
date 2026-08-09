"""Fail-closed verification for a StateWeaver candidate directory."""

from __future__ import annotations

import argparse
import re
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
    MAX_SBOM_JSON_BYTES,
    RECEIPT_NAME,
    RECEIPT_SCHEMA_VERSION,
    SBOM_PATH,
    SCHEMA_VERSION,
    SHA256_RE,
    VERSION_RE,
    CandidateError,
    assert_secret_free,
    canonical_json_bytes,
    exact_keys,
    parse_canonical_json,
    require_list,
    require_mapping,
    safe_relative_path,
    sha256_bytes,
    snapshot_tree,
    verify_archives,
    verify_git_commit_object,
    verify_source_archive,
)
from .policy import LIMITATIONS, REQUIRED_GATES
from .receipt import (
    command_records_are_within,
    validate_build_command_policy,
    validate_command_records,
)
from .runtime import (
    EXPECTED_WORKSPACE_DISTRIBUTIONS,
    RUNTIME_REQUIREMENTS_PATH,
    VENDOR_WHEEL_PREFIX,
    Inventory,
    RuntimeTarget,
    parse_runtime_lock,
    validate_inventory,
)
from .sbom import build_spdx_sbom

_UTC_TIMESTAMP_RE: Final = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_PYTHON_LOCK_PATH: Final = "payload/locks/uv.lock"
_NODE_LOCK_PATH: Final = "payload/locks/apps-web-package-lock.json"


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    errors: tuple[str, ...]
    manifest_sha256: str | None
    source_sha: str | None
    status: str | None


def _fail(condition: bool, code: str) -> None:
    if condition:
        raise CandidateError(code)


def _repository_url(value: object, *, code: str) -> str:
    if not isinstance(value, str):
        raise CandidateError(code)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise CandidateError(code) from None
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
        raise CandidateError(code)
    return value


def _timestamp(value: object) -> str:
    if not isinstance(value, str) or not _UTC_TIMESTAMP_RE.fullmatch(value):
        raise CandidateError("candidate-receipt-timestamp-invalid")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        raise CandidateError("candidate-receipt-timestamp-invalid") from None
    if parsed.isoformat(timespec="seconds").replace("+00:00", "Z") != value:
        raise CandidateError("candidate-receipt-timestamp-invalid")
    return value


def _role(path: str) -> str:
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


def _verify_source(
    value: object, *, expected_repository_url: str, expected_source_sha: str
) -> tuple[dict[str, object], str]:
    source = dict(require_mapping(value, code="candidate-source-invalid"))
    exact_keys(
        source,
        ("commit_sha", "repository_url", "tree_sha"),
        code="candidate-source-invalid",
    )
    repository_url = _repository_url(source["repository_url"], code="candidate-source-invalid")
    commit_sha = source["commit_sha"]
    tree_sha = source["tree_sha"]
    if (
        not isinstance(commit_sha, str)
        or not GIT_SHA_RE.fullmatch(commit_sha)
        or not isinstance(tree_sha, str)
        or not GIT_SHA_RE.fullmatch(tree_sha)
    ):
        raise CandidateError("candidate-source-invalid")
    if repository_url != expected_repository_url or commit_sha != expected_source_sha:
        raise CandidateError("candidate-source-mismatch")
    return source, commit_sha


def _verify_build(value: object) -> tuple[int, str, RuntimeTarget, dict[str, int]]:
    build = require_mapping(value, code="candidate-build-invalid")
    exact_keys(
        build,
        (
            "inventory",
            "reproducibility_verified",
            "runtime_target",
            "source_date_epoch",
            "version",
        ),
        code="candidate-build-invalid",
    )
    if build["reproducibility_verified"] is not True:
        raise CandidateError("candidate-reproducibility-invalid")
    epoch = build["source_date_epoch"]
    version = build["version"]
    if isinstance(epoch, bool) or not isinstance(epoch, int) or not 0 <= epoch <= 253402300799:
        raise CandidateError("candidate-build-invalid")
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise CandidateError("candidate-build-invalid")
    target_value = require_mapping(build["runtime_target"], code="candidate-runtime-target-invalid")
    python_full_version = target_value.get("python_full_version")
    if not isinstance(python_full_version, str):
        raise CandidateError("candidate-runtime-target-invalid")
    target = RuntimeTarget.create(python_full_version)
    if target_value != target.as_dict():
        raise CandidateError("candidate-runtime-target-invalid")
    inventory_value = require_mapping(build["inventory"], code="candidate-inventory-invalid")
    exact_keys(
        inventory_value,
        ("runtime_wheels", "workspace_sdists", "workspace_wheels"),
        code="candidate-inventory-invalid",
    )
    inventory: dict[str, int] = {}
    for key in ("runtime_wheels", "workspace_sdists", "workspace_wheels"):
        item = inventory_value[key]
        if isinstance(item, bool) or not isinstance(item, int):
            raise CandidateError("candidate-inventory-invalid")
        inventory[key] = item
    if (
        inventory["runtime_wheels"] < 1
        or inventory["workspace_sdists"] != EXPECTED_WORKSPACE_DISTRIBUTIONS
        or inventory["workspace_wheels"] != EXPECTED_WORKSPACE_DISTRIBUTIONS
    ):
        raise CandidateError("candidate-inventory-invalid")
    return epoch, version, target, inventory


def _verify_artifacts(
    value: object, snapshot: dict[str, bytes]
) -> tuple[list[dict[str, object]], dict[str, str]]:
    entries = require_list(value, code="candidate-artifacts-invalid")
    artifacts: list[dict[str, object]] = []
    digests: dict[str, str] = {}
    folded: set[str] = set()
    roles: set[str] = set()
    for raw_entry in entries:
        entry = dict(require_mapping(raw_entry, code="candidate-artifact-invalid"))
        exact_keys(entry, ("path", "role", "sha256", "size"), code="candidate-artifact-invalid")
        path = safe_relative_path(entry["path"])
        if not path.startswith("payload/"):
            raise CandidateError("candidate-artifact-path-invalid")
        if path.casefold() in folded or path in digests:
            raise CandidateError("candidate-artifact-duplicate")
        folded.add(path.casefold())
        role = entry["role"]
        digest = entry["sha256"]
        size = entry["size"]
        if role != _role(path):
            raise CandidateError("candidate-artifact-role-invalid")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise CandidateError("candidate-artifact-digest-invalid")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise CandidateError("candidate-artifact-size-invalid")
        content = snapshot.get(path)
        if content is None or len(content) != size or sha256_bytes(content) != digest:
            raise CandidateError("candidate-artifact-content-mismatch")
        roles.add(str(role))
        digests[path] = digest
        artifacts.append(entry)
    if [entry["path"] for entry in artifacts] != sorted(digests):
        raise CandidateError("candidate-artifact-order-invalid")
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
    expected_files = {*digests, MANIFEST_NAME, CHECKSUMS_NAME, RECEIPT_NAME}
    if set(snapshot) != expected_files:
        raise CandidateError("candidate-file-coverage-mismatch")
    return artifacts, digests


def _verify_locks(value: object, snapshot: dict[str, bytes]) -> tuple[bytes, bytes]:
    locks = require_list(value, code="candidate-locks-invalid")
    expected = [
        {
            "ecosystem": "python-uv",
            "path": _PYTHON_LOCK_PATH,
            "sha256": sha256_bytes(snapshot[_PYTHON_LOCK_PATH]),
        },
        {
            "ecosystem": "node-npm",
            "path": _NODE_LOCK_PATH,
            "sha256": sha256_bytes(snapshot[_NODE_LOCK_PATH]),
        },
    ]
    if locks != expected:
        raise CandidateError("candidate-locks-invalid")
    return snapshot[_PYTHON_LOCK_PATH], snapshot[_NODE_LOCK_PATH]


def _verify_sbom(
    value: object,
    *,
    snapshot: dict[str, bytes],
    python_lock: bytes,
    node_lock: bytes,
    repository_url: str,
    source_sha: str,
    source_date_epoch: int,
    inventory: Inventory,
) -> None:
    descriptor = require_mapping(value, code="candidate-sbom-invalid")
    expected_digest = sha256_bytes(snapshot[SBOM_PATH])
    expected_descriptor = {"format": "SPDX-2.3", "path": SBOM_PATH, "sha256": expected_digest}
    if descriptor != expected_descriptor:
        raise CandidateError("candidate-sbom-invalid")
    expected_sbom = build_spdx_sbom(
        python_lock=python_lock,
        node_lock=node_lock,
        repository_url=repository_url,
        source_sha=source_sha,
        source_date_epoch=source_date_epoch,
        vendored_wheels=dict(inventory.vendored_wheels),
    )
    parse_canonical_json(
        snapshot[SBOM_PATH],
        code="candidate-sbom-invalid",
        max_bytes=MAX_SBOM_JSON_BYTES,
    )
    if snapshot[SBOM_PATH] != expected_sbom:
        raise CandidateError("candidate-sbom-lock-closure-mismatch")


def _checksums(snapshot: dict[str, bytes]) -> bytes:
    paths = sorted(path for path in snapshot if path.startswith("payload/"))
    paths.extend((MANIFEST_NAME, RECEIPT_NAME))
    return "".join(f"{sha256_bytes(snapshot[path])}  {path}\n" for path in sorted(paths)).encode()


def _verify_receipt(
    content: bytes,
    *,
    source: dict[str, object],
    target: RuntimeTarget,
    artifacts: list[dict[str, object]],
) -> None:
    receipt = require_mapping(
        parse_canonical_json(content, code="candidate-receipt-invalid"),
        code="candidate-receipt-invalid",
    )
    exact_keys(
        receipt,
        (
            "artifacts",
            "cleanup",
            "dirty",
            "execution",
            "gates",
            "limitations",
            "manual_steps",
            "network",
            "payload",
            "privacy_scan",
            "provenance",
            "redaction",
            "release_created",
            "release_eligible",
            "retries",
            "schema_version",
            "skips",
            "source",
            "status",
            "tag_created",
            "workflow",
        ),
        code="candidate-receipt-invalid",
    )
    if (
        receipt["schema_version"] != RECEIPT_SCHEMA_VERSION
        or receipt["status"] != CANDIDATE_STATUS
        or receipt["release_eligible"] is not False
        or receipt["tag_created"] is not False
        or receipt["release_created"] is not False
        or receipt["dirty"] is not False
        or receipt["artifacts"] != artifacts
        or receipt["source"] != source
        or receipt["gates"] != list(REQUIRED_GATES)
        or receipt["limitations"] != list(LIMITATIONS)
    ):
        raise CandidateError("candidate-receipt-policy-invalid")
    expected_payload = {
        "checksums_path": CHECKSUMS_NAME,
        "manifest_path": MANIFEST_NAME,
    }
    if receipt["payload"] != expected_payload:
        raise CandidateError("candidate-receipt-payload-invalid")
    if receipt["privacy_scan"] != {
        "method": "high-confidence-secret-patterns-v1",
        "status": "PASS",
    }:
        raise CandidateError("candidate-receipt-privacy-invalid")
    if receipt["redaction"] != {
        "method": "PUBLIC_ALLOWLIST_AND_HIGH_CONFIDENCE_SECRET_PATTERNS",
        "status": "PASS",
    }:
        raise CandidateError("candidate-receipt-privacy-invalid")
    if receipt["cleanup"] != {
        "after": [],
        "before": [],
        "reason": (
            "The hosted job is ephemeral; resource inventory was not measured by this candidate "
            "gate."
        ),
        "status": "NOT_MEASURED",
    }:
        raise CandidateError("candidate-receipt-cleanup-invalid")
    if receipt["network"] != {
        "dependency_acquisition": "HTTPS_USED_WITH_LOCKED_HASHES",
        "egress": "AVAILABLE_NOT_DISABLED",
        "offline_install_required_after_download": True,
    }:
        raise CandidateError("candidate-receipt-network-invalid")
    retries = receipt["retries"]
    if isinstance(retries, bool) or not isinstance(retries, int) or retries < 0:
        raise CandidateError("candidate-receipt-workflow-invalid")
    if receipt["manual_steps"] != ["workflow_dispatch:source_sha"]:
        raise CandidateError("candidate-receipt-workflow-invalid")
    expected_skips = [
        {
            "gate_id": str(gate["gate_id"]),
            "required_for_release": True,
            "status": str(gate["status"]),
        }
        for gate in REQUIRED_GATES
        if gate["status"] != "PASS"
    ]
    if receipt["skips"] != expected_skips:
        raise CandidateError("candidate-receipt-policy-invalid")
    expected_provenance = {
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
    }
    if receipt["provenance"] != expected_provenance:
        raise CandidateError("candidate-receipt-provenance-invalid")
    workflow = require_mapping(receipt["workflow"], code="candidate-receipt-workflow-invalid")
    exact_keys(
        workflow,
        (
            "evidence_cutoff_at",
            "run_attempt",
            "run_id",
            "run_url",
            "runner",
            "started_at",
            "tools",
        ),
        code="candidate-receipt-workflow-invalid",
    )
    started_at = _timestamp(workflow["started_at"])
    evidence_cutoff_at = _timestamp(workflow["evidence_cutoff_at"])
    if evidence_cutoff_at < started_at:
        raise CandidateError("candidate-receipt-timestamp-invalid")
    execution = require_mapping(receipt["execution"], code="candidate-receipt-workflow-invalid")
    exact_keys(execution, ("commands",), code="candidate-receipt-workflow-invalid")
    commands = validate_command_records(execution["commands"])
    if not command_records_are_within(
        commands,
        started_at=started_at,
        completed_at=evidence_cutoff_at,
    ):
        raise CandidateError("candidate-receipt-workflow-invalid")
    run_id = workflow["run_id"]
    run_attempt = workflow["run_attempt"]
    if (
        not isinstance(run_id, str)
        or re.fullmatch(r"[1-9][0-9]*", run_id) is None
        or isinstance(run_attempt, bool)
        or not isinstance(run_attempt, int)
        or run_attempt != retries + 1
    ):
        raise CandidateError("candidate-receipt-workflow-invalid")
    if workflow["run_url"] != f"{source['repository_url']}/actions/runs/{run_id}":
        raise CandidateError("candidate-receipt-workflow-invalid")
    validate_build_command_policy(commands, source_sha=str(source["commit_sha"]))
    runner = require_mapping(workflow["runner"], code="candidate-receipt-workflow-invalid")
    tools = require_mapping(workflow["tools"], code="candidate-receipt-workflow-invalid")
    exact_keys(runner, ("arch", "os"), code="candidate-receipt-workflow-invalid")
    exact_keys(
        tools,
        ("node", "pip", "python", "uv"),
        code="candidate-receipt-workflow-invalid",
    )
    values = (*runner.values(), *tools.values())
    if any(not isinstance(value, str) or not value or "\n" in value for value in values):
        raise CandidateError("candidate-receipt-workflow-invalid")
    if runner != {"arch": "X64", "os": "Linux"} or tools["python"] not in {
        target.python_full_version,
        f"Python {target.python_full_version}",
    }:
        raise CandidateError("candidate-receipt-workflow-invalid")


def _verify(
    root: Path, *, expected_repository_url: str, expected_source_sha: str
) -> VerificationResult:
    _repository_url(expected_repository_url, code="expected-repository-invalid")
    if not GIT_SHA_RE.fullmatch(expected_source_sha):
        raise CandidateError("expected-source-sha-invalid")
    snapshot = snapshot_tree(root)
    assert_secret_free(snapshot)
    manifest_content = snapshot.get(MANIFEST_NAME)
    checksums_content = snapshot.get(CHECKSUMS_NAME)
    receipt_content = snapshot.get(RECEIPT_NAME)
    if manifest_content is None or checksums_content is None or receipt_content is None:
        raise CandidateError("candidate-envelope-file-missing")
    manifest = require_mapping(
        parse_canonical_json(manifest_content, code="candidate-manifest-invalid"),
        code="candidate-manifest-invalid",
    )
    exact_keys(
        manifest,
        (
            "artifacts",
            "build",
            "locks",
            "receipt",
            "release_eligible",
            "sbom",
            "schema_version",
            "source",
            "status",
        ),
        code="candidate-manifest-invalid",
    )
    if (
        manifest["schema_version"] != SCHEMA_VERSION
        or manifest["status"] != CANDIDATE_STATUS
        or manifest["release_eligible"] is not False
    ):
        raise CandidateError("candidate-manifest-policy-invalid")
    source, source_sha = _verify_source(
        manifest["source"],
        expected_repository_url=expected_repository_url,
        expected_source_sha=expected_source_sha,
    )
    source_date_epoch, _version, target, declared_inventory = _verify_build(manifest["build"])
    artifacts, _digests = _verify_artifacts(manifest["artifacts"], snapshot)
    expected_receipt_descriptor = {
        "path": RECEIPT_NAME,
        "sha256": sha256_bytes(receipt_content),
    }
    if manifest["receipt"] != expected_receipt_descriptor:
        raise CandidateError("candidate-receipt-digest-invalid")
    verify_git_commit_object(
        snapshot[GIT_COMMIT_OBJECT_PATH],
        source_sha=source_sha,
        tree_sha=str(source["tree_sha"]),
    )
    python_lock, node_lock = _verify_locks(manifest["locks"], snapshot)
    verify_archives(
        {path: content for path, content in snapshot.items() if path.startswith("payload/")}
    )
    runtime_lock = parse_runtime_lock(python_lock, target)
    inventory = validate_inventory(snapshot, runtime_lock, require_requirements=True)
    if declared_inventory != inventory.as_dict():
        raise CandidateError("candidate-inventory-invalid")
    source_archives = [
        content for path, content in snapshot.items() if _role(path) == "source-archive"
    ]
    if len(source_archives) != 1:
        raise CandidateError("candidate-source-archive-count-invalid")
    verify_source_archive(
        source_archives[0],
        python_lock=python_lock,
        node_lock=node_lock,
        expected_tree_sha=str(source["tree_sha"]),
        expected_prefix=f"stateweaver-{_version}",
    )
    _verify_sbom(
        manifest["sbom"],
        snapshot=snapshot,
        python_lock=python_lock,
        node_lock=node_lock,
        repository_url=expected_repository_url,
        source_sha=source_sha,
        source_date_epoch=source_date_epoch,
        inventory=inventory,
    )
    expected_checksums = _checksums(snapshot)
    if checksums_content != expected_checksums:
        raise CandidateError("candidate-checksums-invalid")
    manifest_digest = sha256_bytes(manifest_content)
    _verify_receipt(
        receipt_content,
        source=source,
        target=target,
        artifacts=artifacts,
    )
    return VerificationResult(
        valid=True,
        errors=(),
        manifest_sha256=manifest_digest,
        source_sha=source_sha,
        status=CANDIDATE_STATUS,
    )


def verify_candidate(
    root: Path, *, expected_repository_url: str, expected_source_sha: str
) -> VerificationResult:
    """Verify one snapshot against explicit repository and commit trust anchors."""

    try:
        return _verify(
            root,
            expected_repository_url=expected_repository_url,
            expected_source_sha=expected_source_sha,
        )
    except (CandidateError, KeyError, MemoryError, OverflowError, RecursionError) as error:
        code = (
            error.code
            if isinstance(error, CandidateError)
            else (
                "candidate-required-field-missing"
                if isinstance(error, KeyError)
                else "candidate-resource-limit"
            )
        )
        return VerificationResult(
            valid=False,
            errors=(code,),
            manifest_sha256=None,
            source_sha=None,
            status=None,
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate_root", type=Path)
    parser.add_argument("--expected-repository-url", required=True)
    parser.add_argument("--expected-source-sha", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    result = verify_candidate(
        arguments.candidate_root,
        expected_repository_url=arguments.expected_repository_url,
        expected_source_sha=arguments.expected_source_sha,
    )
    print(canonical_json_bytes(result.__dict__).decode(), end="")
    return 0 if result.valid else 1


if __name__ == "__main__":
    sys.exit(main())
