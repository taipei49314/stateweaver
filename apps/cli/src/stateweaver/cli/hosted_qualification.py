"""Build hosted M2-M4 admission with an exact retained M5 receipt."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from xml.etree import ElementTree

from pydantic import BaseModel, ValidationError
from stateweaver.contracts import canonical_json_bytes as contract_json_bytes
from stateweaver.contracts import sha256_digest
from stateweaver.evidence.hosted_qualification import (
    HostedArtifactEntry,
    HostedAttestationVerification,
    HostedDockerQualificationReceipt,
    HostedInventoryBinding,
    HostedJunitBinding,
    HostedQualificationAdmissionReceipt,
    HostedQualificationError,
    M2CleanupCase,
    M2HostedProjection,
    M2RealProviderObservation,
    M4HostedProjection,
    M5HostedProjection,
    load_hosted_docker_qualification,
)

from .materialized_chain_qualification import ActualMaterializedChainQualificationReceipt
from .materialized_search_qualification import MaterializedSearchQualificationReceipt
from .observed_chain_qualification import ObservedChainQualificationReceipt

# The actual-ASGI composite retains ten bounded checkpoint lineages.  Its own
# nested models cap every checkpoint at 128 KiB; these outer limits leave room
# for the exact repeated request/trace bytes while remaining below the
# candidate payload's independent 64 MiB per-file ceiling.
_MAX_FILE_BYTES = 64 * 1_048_576
_MAX_PRODUCER_BYTES = 64 * 1_048_576
_M2_FILES = (
    "cleanup-cancellation.json",
    "cleanup-partial-failure.json",
    "cleanup-success.json",
    "cleanup-timeout.json",
    "commit.txt",
    "compose-version.txt",
    "containers-after.txt",
    "containers-before.txt",
    "dirty-after.txt",
    "dirty-before.txt",
    "docker-version.txt",
    "junit.xml",
    "managed-processes-after.txt",
    "managed-processes-before.txt",
    "networks-after.txt",
    "networks-before.txt",
    "processes-after.txt",
    "processes-before.txt",
    "real-provider-images-inspect.json",
    "real-provider-junit.xml",
    "real-provider-receipt.json",
    "source-sha256.txt",
    "swm2-containers-after.txt",
    "swm2-networks-after.txt",
    "swm2-volumes-after.txt",
    "synthetic-image-inspect.json",
    "tree.txt",
    "volumes-after.txt",
    "volumes-before.txt",
)
_M4_FILES = ("junit.xml", "materialized-search-receipt.json")
_M5_FILES = ("materialized-chain-replay.json", "observed-chain-receipt.json")
_LEGACY_M5_FILES = ("materialized-provider-receipt.json", "observed-chain-receipt.json")
_CLEANUP_CASE_FILES = (
    "cleanup-success.json",
    "cleanup-timeout.json",
    "cleanup-cancellation.json",
    "cleanup-partial-failure.json",
)
_LIMITATIONS = (
    "This admission proves repository-controlled GitHub-hosted M2 through M5 execution for one "
    "exact SHA.",
    "A separate clean host and external M6-M8 trust remain pending.",
)


def _read_regular(
    path: Path,
    *,
    allow_empty: bool = False,
    max_bytes: int = _MAX_FILE_BYTES,
) -> bytes:
    try:
        if path.is_symlink() or not path.is_file():
            raise HostedQualificationError("hosted qualification artifact is not a regular file")
        size = path.stat().st_size
        if size > max_bytes or (not allow_empty and size == 0):
            raise HostedQualificationError("hosted qualification artifact size is invalid")
        content = path.read_bytes()
    except OSError:
        raise HostedQualificationError("hosted qualification artifact is unreadable") from None
    if len(content) != size:
        raise HostedQualificationError("hosted qualification artifact changed while reading")
    return content


def _sha256(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def _require_exact_tree(root: Path, names: tuple[str, ...]) -> dict[str, bytes]:
    if root.is_symlink() or not root.is_dir():
        raise HostedQualificationError("hosted qualification root is invalid")
    try:
        entries = tuple(sorted(path.name for path in root.iterdir()))
    except OSError:
        raise HostedQualificationError("hosted qualification root is unreadable") from None
    if entries != tuple(sorted(names)):
        raise HostedQualificationError("hosted qualification artifact set is not exact")
    return {name: _read_regular(root / name, allow_empty=True) for name in names}


def _json_model[T: BaseModel](content: bytes, model: type[T]) -> T:
    try:
        raw: object = json.loads(content.decode("utf-8"))
        if contract_json_bytes(raw) + b"\n" != content:
            raise ValueError("JSON is not canonical")
        return model.model_validate_json(content)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValidationError,
        TypeError,
        ValueError,
        RecursionError,
    ):
        raise HostedQualificationError("hosted qualification JSON is invalid") from None


def _actual_materialized_m5(
    files: dict[str, bytes],
    *,
    m4_bytes: bytes,
    process_receipt: ObservedChainQualificationReceipt,
    repository_marker: str,
) -> ActualMaterializedChainQualificationReceipt:
    """Parse and cross-bind the exact Phase-D Docker application composite."""

    if tuple(sorted(files)) != tuple(sorted(_M5_FILES)):
        raise HostedQualificationError("hosted actual M5 artifact set is not exact")
    actual = _json_model(
        files["materialized-chain-replay.json"],
        ActualMaterializedChainQualificationReceipt,
    )
    process_bytes = contract_json_bytes(process_receipt) + b"\n"
    if (
        actual.repository_marker != repository_marker
        or actual.m4_receipt_json.encode("utf-8") != m4_bytes
        or actual.process_receipt_json.encode("utf-8") != process_bytes
        or actual.m4_receipt_digest != process_receipt.m4_receipt_digest
        or actual.process_receipt_digest != process_receipt.receipt_digest
        or actual.cleanup_count != 10
        or actual.all_cleanups_passed is not True
        or actual.all_projects_destroyed is not True
    ):
        raise HostedQualificationError("hosted actual M5 composite is not cross-bound")
    return actual


def _hosted_artifact_role(name: str) -> str:
    """Classify only the fixed hosted artifact filenames."""

    if name.endswith("junit.xml") or name == "junit.xml":
        return "junit"
    if name.endswith("receipt.json") or name == "materialized-chain-replay.json":
        return "qualification-receipt"
    if name.endswith("after.txt") or name.endswith("before.txt"):
        return "cleanup-inventory"
    return "runtime-provenance"


def _junit(content: bytes, *, artifact_path: str) -> HostedJunitBinding:
    try:
        root = ElementTree.fromstring(content)
    except ElementTree.ParseError:
        raise HostedQualificationError("hosted qualification JUnit is invalid") from None
    suites = (root,) if root.tag == "testsuite" else tuple(root.findall("testsuite"))
    if root.tag not in {"testsuite", "testsuites"} or not suites:
        raise HostedQualificationError("hosted qualification JUnit is invalid")
    testcases = tuple(case for suite in suites for case in suite.findall("testcase"))
    identities: list[str] = []
    for case in testcases:
        classname = case.attrib.get("classname")
        name = case.attrib.get("name")
        if not classname or not name:
            raise HostedQualificationError("hosted qualification JUnit identity is invalid")
        identities.append(f"{classname}::{name}")
    failures = sum(len(case.findall("failure")) for case in testcases)
    errors = sum(len(case.findall("error")) for case in testcases)
    skipped = sum(len(case.findall("skipped")) for case in testcases)
    try:
        declared = {
            field: sum(int(suite.attrib.get(field, "0")) for suite in suites)
            for field in ("tests", "failures", "errors", "skipped")
        }
    except ValueError:
        raise HostedQualificationError("hosted qualification JUnit counters are invalid") from None
    observed = {
        "tests": len(testcases),
        "failures": failures,
        "errors": errors,
        "skipped": skipped,
    }
    if declared != observed:
        raise HostedQualificationError("hosted qualification JUnit counters are inconsistent")
    if errors != 0 or failures != 0 or skipped != 0:
        raise HostedQualificationError("hosted qualification JUnit did not pass")
    return HostedJunitBinding(
        artifact_path=artifact_path,
        artifact_sha256=_sha256(content),
        errors=0,
        failures=0,
        skipped=0,
        tests=len(testcases),
        testcase_identities=tuple(sorted(identities)),
    )


def _text_sha(content: bytes) -> str:
    return _sha256(content)


def _exact_sha_text(content: bytes, expected: str) -> None:
    try:
        value = content.decode("ascii").strip()
    except UnicodeDecodeError:
        raise HostedQualificationError("hosted Git identity is invalid") from None
    if value != expected or content != f"{expected}\n".encode("ascii"):
        raise HostedQualificationError("hosted Git identity does not match the expected SHA")


def build_hosted_docker_qualification(
    *,
    m2_root: Path,
    m4_root: Path,
    m5_root: Path,
    repository_marker: str,
    tree_sha: str,
    workflow_run_id: int,
    workflow_run_attempt: int,
    workflow_run_url: str,
    runner_os: str,
    runner_arch: str,
) -> HostedDockerQualificationReceipt:
    """Validate the exact workflow output set and create its typed producer receipt."""

    m2_files = _require_exact_tree(m2_root, _M2_FILES)
    m4_files = _require_exact_tree(m4_root, _M4_FILES)
    m5_files = _require_exact_tree(m5_root, _M5_FILES)
    _exact_sha_text(m2_files["commit.txt"], repository_marker)
    _exact_sha_text(m2_files["tree.txt"], tree_sha)
    real_provider = _json_model(m2_files["real-provider-receipt.json"], M2RealProviderObservation)
    assert isinstance(real_provider, M2RealProviderObservation)
    cleanup_cases = tuple(
        _json_model(m2_files[name], M2CleanupCase) for name in _CLEANUP_CASE_FILES
    )
    try:
        m4_receipt = MaterializedSearchQualificationReceipt.model_validate_json(
            m4_files["materialized-search-receipt.json"]
        )
    except (ValidationError, TypeError, ValueError, RecursionError):
        raise HostedQualificationError("hosted M4 receipt is invalid") from None
    canonical_m4 = contract_json_bytes(m4_receipt)
    if canonical_m4 + b"\n" != m4_files["materialized-search-receipt.json"]:
        raise HostedQualificationError("hosted M4 receipt is not canonical")
    if m4_receipt.residual_allocation_ids:
        raise HostedQualificationError("hosted M4 receipt retained residual allocations")
    m5_receipt = _json_model(
        m5_files["observed-chain-receipt.json"], ObservedChainQualificationReceipt
    )
    if (
        m5_receipt.repository_marker != repository_marker
        or m5_receipt.m4_receipt_json.encode("utf-8")
        != m4_files["materialized-search-receipt.json"]
        or m5_receipt.m4_receipt_digest != m4_receipt.receipt_digest
    ):
        raise HostedQualificationError("hosted M5 receipt is not bound to exact M4 bytes")
    canonical_m5 = contract_json_bytes(m5_receipt) + b"\n"
    actual_m5 = _actual_materialized_m5(
        m5_files,
        m4_bytes=m4_files["materialized-search-receipt.json"],
        process_receipt=m5_receipt,
        repository_marker=repository_marker,
    )

    def artifact_entries(prefix: str, files: dict[str, bytes]) -> list[HostedArtifactEntry]:
        return [
            HostedArtifactEntry(
                path=f"{prefix}/{name}",
                role=_hosted_artifact_role(name),
                sha256=_sha256(content),
                size=len(content),
            )
            for name, content in files.items()
        ]

    artifacts = tuple(
        sorted(
            (
                *artifact_entries("m2-live", m2_files),
                *artifact_entries("m4-live", m4_files),
                *artifact_entries("m5-clean-root", m5_files),
            ),
            key=lambda item: item.path,
        )
    )
    zero_inventory_names = (
        "dirty-before.txt",
        "dirty-after.txt",
        "managed-processes-before.txt",
        "managed-processes-after.txt",
        "swm2-containers-after.txt",
        "swm2-networks-after.txt",
        "swm2-volumes-after.txt",
    )
    if any(m2_files[name] for name in zero_inventory_names):
        raise HostedQualificationError("hosted qualification retained dirty state or residue")
    m2 = M2HostedProjection(
        synthetic_junit=_junit(m2_files["junit.xml"], artifact_path="m2-live/junit.xml"),
        real_provider_junit=_junit(
            m2_files["real-provider-junit.xml"],
            artifact_path="m2-live/real-provider-junit.xml",
        ),
        real_provider=real_provider,
        cleanup_cases=cleanup_cases,
        inventory=HostedInventoryBinding(
            containers_before_sha256=_text_sha(m2_files["containers-before.txt"]),
            containers_after_sha256=_text_sha(m2_files["containers-after.txt"]),
            networks_before_sha256=_text_sha(m2_files["networks-before.txt"]),
            networks_after_sha256=_text_sha(m2_files["networks-after.txt"]),
            volumes_before_sha256=_text_sha(m2_files["volumes-before.txt"]),
            volumes_after_sha256=_text_sha(m2_files["volumes-after.txt"]),
            dirty_before_bytes=0,
            dirty_after_bytes=0,
            managed_processes_before_bytes=0,
            managed_processes_after_bytes=0,
            residual_containers_bytes=0,
            residual_networks_bytes=0,
            residual_volumes_bytes=0,
        ),
    )
    m4 = M4HostedProjection(
        m3_qualification=m4_receipt.m3_qualification,
        m3_semantic_digest=m4_receipt.m3_semantic_digest,
        observed_chain_digest=m4_receipt.observed_chain_digest,
        observed_transition_digest=m4_receipt.observed_transition_digest,
        ghost_evaluation_count=m4_receipt.ghost_evaluation_count,
        promotion_counts=m4_receipt.promotion_counts,
        materialized_world_count=m4_receipt.materialized_world_count,
        peak_live_allocations=m4_receipt.peak_live_allocations,
        provider_receipt_digests=tuple(
            item.receipt_digest for item in m4_receipt.provider_receipts
        ),
        released_allocation_ids=m4_receipt.released_allocation_ids,
        residual_allocation_ids=(),
        winner_candidate_id=m4_receipt.winner.candidate_id,
        receipt_digest=m4_receipt.receipt_digest,
    )
    patched_step = m5_receipt.patched_run.steps[-1]
    if (
        m5_receipt.patched_run.failed_step_id != "step.08"
        or patched_step.failure_code != "ORACLE_EXPECTATION_MISMATCH"
    ):
        raise HostedQualificationError("hosted M5 receipt lacks its boundary result")
    m5 = M5HostedProjection(
        m4_receipt_sha256=actual_m5.m4_receipt_sha256,
        m4_receipt_digest=actual_m5.m4_receipt_digest,
        process_receipt_sha256=actual_m5.process_receipt_sha256,
        process_receipt_digest=actual_m5.process_receipt_digest,
        actual_receipt_digest=actual_m5.receipt_digest,
        runtime=actual_m5.runtime,
        m4_winner_state_binding_digest=actual_m5.m4_winner_state_binding_digest,
        m4_source_snapshot_digest=actual_m5.m4_source_snapshot_digest,
        m4_after_archive_digest=actual_m5.m4_after_archive_digest,
        m4_provider_state_digest=actual_m5.m4_provider_state_digest,
        execution_plan_digest=actual_m5.execution_plan_digest,
        primary_plan_digest=actual_m5.primary_plan_digest,
        application_image_binding_digest=actual_m5.application_image_binding.binding_digest,
        clean_root_run_ids=tuple(item.run_id for item in actual_m5.clean_root_runs),
        clean_root_materialized_receipt_digests=tuple(
            item.materialized_run_receipt_digest for item in actual_m5.clean_root_runs
        ),
        vulnerable_deterministic_signatures=actual_m5.vulnerable_deterministic_signatures,
        initial_checkpoint_bytes_digest=actual_m5.initial_checkpoint_bytes_digest,
        patched_run_id="run.m5.patched-01",
        patched_materialized_receipt_digest=(actual_m5.patched_run.materialized_run_receipt_digest),
        negative_control_names=tuple(item.name for item in actual_m5.negative_controls),
        negative_control_materialized_receipt_digests=tuple(
            item.materialized_run_receipt_digest for item in actual_m5.negative_controls
        ),
        cleanup_count=actual_m5.cleanup_count,
        receipt_digest=actual_m5.receipt_digest,
    )
    values: dict[str, object] = {
        "schema_version": "stateweaver-hosted-docker-qualification-v3",
        "status": "HOSTED_M2_M5_QUALIFIED",
        "repository_url": "https://github.com/taipei49314/stateweaver",
        "repository_marker": repository_marker,
        "tree_sha": tree_sha,
        "source_ref": "refs/heads/main",
        "workflow_path": ".github/workflows/docker-compose-live.yml",
        "workflow_run_id": workflow_run_id,
        "workflow_run_attempt": workflow_run_attempt,
        "workflow_run_url": workflow_run_url,
        "runner_environment": "github-hosted",
        "runner_os": runner_os,
        "runner_arch": runner_arch,
        "artifact_manifest": artifacts,
        "m2": m2,
        "m4_junit": _junit(m4_files["junit.xml"], artifact_path="m4-live/junit.xml"),
        "m4_receipt_json": (canonical_m4 + b"\n").decode("utf-8"),
        "m4_receipt_sha256": _sha256(canonical_m4 + b"\n"),
        "m4": m4,
        "m5_receipt_json": canonical_m5.decode("utf-8"),
        "m5_receipt_sha256": _sha256(canonical_m5),
        "m5_actual_receipt_json": m5_files["materialized-chain-replay.json"].decode("utf-8"),
        "m5_actual_receipt_sha256": _sha256(m5_files["materialized-chain-replay.json"]),
        "m5": m5,
        "release_eligible": False,
        "limitations": _LIMITATIONS,
    }
    return HostedDockerQualificationReceipt.model_validate(
        {**values, "receipt_digest": sha256_digest(values)}
    )


def build_hosted_qualification_admission(
    *,
    qualification_receipt: HostedDockerQualificationReceipt,
    attestation_bundle: Path,
) -> HostedQualificationAdmissionReceipt:
    """Bind one already constrained ``gh attestation verify`` success to the producer receipt."""

    bundle = _read_regular(attestation_bundle)
    qualification_json = (
        contract_json_bytes(qualification_receipt.model_dump(mode="json")) + b"\n"
    ).decode("utf-8")
    qualification_sha = _sha256(qualification_json.encode("utf-8"))
    attestation = HostedAttestationVerification(
        verifier="gh-attestation",
        repository="taipei49314/stateweaver",
        signer_workflow=(
            "github.com/taipei49314/stateweaver/.github/workflows/docker-compose-live.yml"
        ),
        signer_digest=qualification_receipt.repository_marker,
        source_digest=qualification_receipt.repository_marker,
        source_ref="refs/heads/main",
        deny_self_hosted_runners=True,
        subject_sha256=qualification_sha,
        attestation_bundle_sha256=_sha256(bundle),
        exit_code=0,
    )
    values: dict[str, object] = {
        "schema_version": "stateweaver-hosted-qualification-admission-v3",
        "status": "HOSTED_M2_M5_ADMITTED",
        "qualification_receipt_json": qualification_json,
        "qualification_receipt_sha256": qualification_sha,
        "attestation": attestation,
        "release_eligible": False,
        "limitations": _LIMITATIONS,
    }
    return HostedQualificationAdmissionReceipt.model_validate(
        {**values, "admission_digest": sha256_digest(values)}
    )


def admit_hosted_qualification(
    *,
    qualification_receipt_path: Path,
    attestation_bundle_path: Path,
    expected_repository_marker: str,
) -> HostedQualificationAdmissionReceipt:
    """Constrain ``gh attestation verify`` before constructing an admission receipt."""

    qualification = load_hosted_docker_qualification(
        qualification_receipt_path,
        expected_repository_marker=expected_repository_marker,
    )
    qualification_bytes = contract_json_bytes(qualification.model_dump(mode="json")) + b"\n"
    if (
        _read_regular(qualification_receipt_path, max_bytes=_MAX_PRODUCER_BYTES)
        != qualification_bytes
    ):
        raise HostedQualificationError("hosted Docker qualification receipt changed")
    bundle_bytes = _read_regular(attestation_bundle_path)
    executable_name = shutil.which("gh")
    if executable_name is None:
        raise HostedQualificationError("hosted attestation verifier is unavailable")
    try:
        executable = Path(executable_name).resolve(strict=True)
    except OSError:
        raise HostedQualificationError("hosted attestation verifier is unavailable") from None
    if not executable.is_file():
        raise HostedQualificationError("hosted attestation verifier is unavailable")
    with tempfile.TemporaryDirectory(prefix="stateweaver-hosted-admission-") as temporary_name:
        temporary = Path(temporary_name)
        subject = temporary / "qualification-receipt.json"
        bundle = temporary / "attestation.json"
        subject.write_bytes(qualification_bytes)
        bundle.write_bytes(bundle_bytes)
        argv = (
            str(executable),
            "attestation",
            "verify",
            str(subject),
            "--repo",
            "taipei49314/stateweaver",
            "--bundle",
            str(bundle),
            "--signer-workflow",
            "github.com/taipei49314/stateweaver/.github/workflows/docker-compose-live.yml",
            "--signer-digest",
            expected_repository_marker,
            "--source-digest",
            expected_repository_marker,
            "--source-ref",
            "refs/heads/main",
            "--deny-self-hosted-runners",
        )
        try:
            completed = subprocess.run(
                argv,
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=120,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise HostedQualificationError("hosted attestation verification failed") from None
        if completed.returncode != 0:
            raise HostedQualificationError("hosted attestation verification failed")
        return build_hosted_qualification_admission(
            qualification_receipt=qualification,
            attestation_bundle=bundle,
        )


def write_hosted_receipt(path: Path, receipt: BaseModel) -> None:
    """Write a validated receipt in the repository canonical wire form."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(contract_json_bytes(receipt.model_dump(mode="json")) + b"\n")


__all__ = [
    "admit_hosted_qualification",
    "build_hosted_docker_qualification",
    "write_hosted_receipt",
]
