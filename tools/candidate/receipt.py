"""Typed command-record parsing shared by candidate and detached receipts."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Final

from .common import (
    CandidateError,
    exact_keys,
    parse_canonical_json,
    require_list,
    require_mapping,
)

MAX_COMMAND_RECORDS_BYTES: Final = 1024 * 1024
MAX_COMMAND_RECORDS: Final = 256
MAX_COMMAND_ARGUMENTS: Final = 256
MAX_COMMAND_ARGUMENT_BYTES: Final = 16 * 1024
_STAGE_RE: Final = re.compile(r"^[a-z0-9][a-z0-9-]{0,79}$")
_UTC_TIMESTAMP_RE: Final = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_WINDOWS_ABSOLUTE_RE: Final = re.compile(r"^[A-Z]:/(?:[^/]+(?:/|$))*")
BUILD_COMMAND_STAGES: Final = (
    "compare-python-distributions",
    "compare-web-archives",
    "compare-vendored-runtime",
    "verify-foundation-proof",
    "verify-source-worktree-clean",
)
DOWNLOAD_COMMAND_STAGES: Final = (
    "compare-canonical-source-archive",
    "verify-downloaded-candidate",
    "verify-oidc-attestation",
    "create-clean-install-environment",
    "install-runtime-closure-offline",
    "install-workspace-wheels-offline",
    "check-offline-install",
    "smoke-imports",
    "smoke-doctor",
    "smoke-foundation",
    "smoke-foundation-evidence",
    "verify-verifier-source-clean",
)
_SMOKE_IMPORTS: Final = (
    "from stateweaver.reporting import RealityPublicationManifest; "
    "import statechainbench; import stateweaver_api"
)


def validate_utc_timestamp(value: object, *, code: str) -> str:
    if not isinstance(value, str) or not _UTC_TIMESTAMP_RE.fullmatch(value):
        raise CandidateError(code)
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except (MemoryError, OverflowError, RecursionError, ValueError):
        raise CandidateError(code) from None
    if parsed.isoformat(timespec="seconds").replace("+00:00", "Z") != value:
        raise CandidateError(code)
    return value


def validate_command_record(value: object) -> dict[str, object]:
    record = dict(require_mapping(value, code="command-record-invalid"))
    exact_keys(
        record,
        ("argv", "completed_at", "cwd", "exit_code", "stage", "started_at", "status"),
        code="command-record-invalid",
    )
    argv_values = require_list(record["argv"], code="command-record-invalid")
    if not 0 < len(argv_values) <= MAX_COMMAND_ARGUMENTS:
        raise CandidateError("command-record-invalid")
    argv: list[str] = []
    aggregate = 0
    for value_item in argv_values:
        if not isinstance(value_item, str) or not value_item or "\0" in value_item:
            raise CandidateError("command-record-invalid")
        aggregate += len(value_item.encode("utf-8"))
        if aggregate > MAX_COMMAND_ARGUMENT_BYTES:
            raise CandidateError("command-record-invalid")
        argv.append(value_item)
    cwd = record["cwd"]
    stage = record["stage"]
    exit_code = record["exit_code"]
    if (
        not isinstance(cwd, str)
        or not _is_canonical_absolute_path(cwd)
        or "\0" in cwd
        or len(cwd) > 4096
    ):
        raise CandidateError("command-record-invalid")
    if not isinstance(stage, str) or not _STAGE_RE.fullmatch(stage):
        raise CandidateError("command-record-invalid")
    if isinstance(exit_code, bool) or not isinstance(exit_code, int) or exit_code != 0:
        raise CandidateError("command-record-invalid")
    if record["status"] != "PASS":
        raise CandidateError("command-record-invalid")
    started_at = validate_utc_timestamp(record["started_at"], code="command-record-invalid")
    completed_at = validate_utc_timestamp(record["completed_at"], code="command-record-invalid")
    if completed_at < started_at:
        raise CandidateError("command-record-invalid")
    return {
        "argv": argv,
        "completed_at": completed_at,
        "cwd": cwd,
        "exit_code": exit_code,
        "stage": stage,
        "started_at": started_at,
        "status": "PASS",
    }


def load_command_records(content: bytes) -> list[dict[str, object]]:
    if not content or len(content) > MAX_COMMAND_RECORDS_BYTES:
        raise CandidateError("command-records-invalid")
    raw_lines = content.splitlines(keepends=True)
    if not 0 < len(raw_lines) <= MAX_COMMAND_RECORDS or any(
        not line.endswith(b"\n") for line in raw_lines
    ):
        raise CandidateError("command-records-invalid")
    records: list[dict[str, object]] = []
    stages: set[str] = set()
    previous_completed: str | None = None
    for line in raw_lines:
        parsed = parse_canonical_json(
            line,
            code="command-records-invalid",
            max_bytes=64 * 1024,
        )
        try:
            record = validate_command_record(parsed)
        except CandidateError:
            raise CandidateError("command-records-invalid") from None
        stage = str(record["stage"])
        if stage in stages:
            raise CandidateError("command-records-invalid")
        stages.add(stage)
        started_at = str(record["started_at"])
        if previous_completed is not None and started_at < previous_completed:
            raise CandidateError("command-records-invalid")
        previous_completed = str(record["completed_at"])
        records.append(record)
    return records


def validate_command_records(value: object) -> list[dict[str, object]]:
    values = require_list(value, code="command-records-invalid")
    if not 0 < len(values) <= MAX_COMMAND_RECORDS:
        raise CandidateError("command-records-invalid")
    records = [validate_command_record(item) for item in values]
    stages = [str(record["stage"]) for record in records]
    if len(set(stages)) != len(stages):
        raise CandidateError("command-records-invalid")
    return records


def command_records_are_within(
    records: Sequence[Mapping[str, object]], *, started_at: str, completed_at: str
) -> bool:
    return all(
        started_at <= str(record["started_at"]) and str(record["completed_at"]) <= completed_at
        for record in records
    )


def _is_canonical_absolute_path(value: str) -> bool:
    if "\\" in value or "\0" in value or "//" in value:
        return False
    if value.startswith("/"):
        path = PurePosixPath(value)
        return str(path) == value and all(part not in {".", ".."} for part in path.parts)
    return bool(_WINDOWS_ABSOLUTE_RE.fullmatch(value)) and all(
        part not in {".", ".."} for part in value[3:].split("/")
    )


def _require_executable(argv: list[str], pattern: str) -> None:
    if not argv or not _is_canonical_absolute_path(argv[0]):
        raise CandidateError("command-executable-invalid")
    if re.fullmatch(pattern, PurePosixPath(argv[0]).name) is None:
        raise CandidateError("command-executable-invalid")


def _require_paths(values: Sequence[str]) -> None:
    if any(not _is_canonical_absolute_path(value) for value in values):
        raise CandidateError("command-path-invalid")


def _argv(record: Mapping[str, object]) -> list[str]:
    value = record.get("argv")
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise CandidateError("command-record-invalid")
    return value


def validate_build_command_policy(records: list[dict[str, object]], *, source_sha: str) -> None:
    try:
        if tuple(str(record["stage"]) for record in records) != BUILD_COMMAND_STAGES:
            raise CandidateError("build-command-policy-invalid")
        cwd_values = {str(record["cwd"]) for record in records}
        if len(cwd_values) != 1:
            raise CandidateError("build-command-policy-invalid")
        repository_root = next(iter(cwd_values))
        _require_paths([repository_root])
        compare_suffixes = (("/dist", "/dist"), ("/web-artifact", "/web-artifact"))
        python_executable: str | None = None
        for index, record in enumerate(records[:3]):
            argv = _argv(record)
            _require_executable(argv, r"python(?:3(?:\.13)?)?")
            if argv[1:3] != ["-m", "tools.candidate.compare"] or len(argv) != 5:
                raise CandidateError("build-command-policy-invalid")
            left, right = argv[3:]
            _require_paths([left, right])
            correct_layout = (
                left.endswith(compare_suffixes[index][0])
                and right.endswith(compare_suffixes[index][1])
                if index < 2
                else PurePosixPath(left).name.startswith("vendor-a-")
                and PurePosixPath(right).name.startswith("vendor-b-")
            )
            if left == right or not correct_layout:
                raise CandidateError("build-command-policy-invalid")
            if python_executable is None:
                python_executable = argv[0]
            elif argv[0] != python_executable:
                raise CandidateError("build-command-policy-invalid")
        proof = _argv(records[3])
        _require_executable(proof, r"uv")
        if (
            len(proof) != 8
            or proof[1:5] != ["run", "stateweaver", "foundation", "verify-evidence"]
            or proof[6:] != ["--repository-marker", source_sha]
        ):
            raise CandidateError("build-command-policy-invalid")
        _require_paths([proof[5]])
        clean = _argv(records[4])
        _require_executable(clean, r"python(?:3(?:\.13)?)?")
        expected_clean = [
            python_executable,
            "-m",
            "tools.candidate.git_clean",
            "--repository-root",
            repository_root,
            "--allow-untracked",
            f"{repository_root}/artifacts/acceptance",
            "--allow-untracked",
            f"{repository_root}/candidate",
        ]
        if clean != expected_clean:
            raise CandidateError("build-command-policy-invalid")
    except (CandidateError, IndexError, TypeError):
        raise CandidateError("build-command-policy-invalid") from None


def validate_download_command_policy(
    records: list[dict[str, object]],
    *,
    workspace: str,
    candidate_root: str,
    canonical_source_archive: str,
    attestation_bundle: str,
    verifier_source: str,
    install_root: str,
    repository_url: str,
    repository_slug: str,
    source_sha: str,
    source_ref: str,
    signer_workflow: str,
    version: str,
    workspace_wheels: Sequence[str],
    proof_run: str,
) -> None:
    try:
        if tuple(str(record["stage"]) for record in records) != DOWNLOAD_COMMAND_STAGES:
            raise CandidateError("download-command-policy-invalid")
        _require_paths(
            [
                workspace,
                candidate_root,
                canonical_source_archive,
                attestation_bundle,
                verifier_source,
                install_root,
                proof_run,
                *workspace_wheels,
            ]
        )
        expected_wheel_prefix = f"{candidate_root}/payload/python/"
        if (
            len(workspace_wheels) != 18
            or tuple(workspace_wheels) != tuple(sorted(set(workspace_wheels)))
            or any(
                not path.startswith(expected_wheel_prefix) or not path.endswith(".whl")
                for path in workspace_wheels
            )
            or not proof_run.startswith(f"{candidate_root}/payload/evidence/foundation/runs/")
        ):
            raise CandidateError("download-command-policy-invalid")
        if any(str(record["cwd"]) != workspace for record in records):
            raise CandidateError("download-command-policy-invalid")
        candidate_source = f"{candidate_root}/payload/source/stateweaver-source-{version}.tar.gz"
        manifest = f"{candidate_root}/PAYLOAD_MANIFEST.json"
        vendor = f"{candidate_root}/payload/vendor/python"
        requirements = f"{candidate_root}/payload/metadata/runtime-requirements.txt"
        install_python = f"{install_root}/bin/python"
        stateweaver = f"{install_root}/bin/stateweaver"

        compare = _argv(records[0])
        _require_executable(compare, r"cmp")
        if compare[1:] != ["--silent", canonical_source_archive, candidate_source]:
            raise CandidateError("download-command-policy-invalid")

        verify = _argv(records[1])
        _require_executable(verify, r"python(?:3(?:\.13)?)?")
        if verify[1:] != [
            "-m",
            "tools.candidate.verify",
            candidate_root,
            "--expected-repository-url",
            repository_url,
            "--expected-source-sha",
            source_sha,
        ]:
            raise CandidateError("download-command-policy-invalid")

        attest = _argv(records[2])
        _require_executable(attest, r"gh")
        if attest[1:] != [
            "attestation",
            "verify",
            manifest,
            "--repo",
            repository_slug,
            "--bundle",
            attestation_bundle,
            "--signer-workflow",
            signer_workflow,
            "--signer-digest",
            source_sha,
            "--source-digest",
            source_sha,
            "--source-ref",
            source_ref,
            "--deny-self-hosted-runners",
        ]:
            raise CandidateError("download-command-policy-invalid")

        create = _argv(records[3])
        _require_executable(create, r"uv")
        if create[1:] != ["venv", "--python", "3.13", install_root]:
            raise CandidateError("download-command-policy-invalid")
        uv_executable = create[0]

        runtime = _argv(records[4])
        _require_executable(runtime, r"uv")
        if runtime[0] != uv_executable or runtime[1:] != [
            "pip",
            "install",
            "--python",
            install_python,
            "--offline",
            "--no-index",
            "--no-cache",
            "--find-links",
            vendor,
            "--require-hashes",
            "-r",
            requirements,
        ]:
            raise CandidateError("download-command-policy-invalid")

        workspace_install = _argv(records[5])
        _require_executable(workspace_install, r"uv")
        if workspace_install[0] != uv_executable or workspace_install[1:] != [
            "pip",
            "install",
            "--python",
            install_python,
            "--offline",
            "--no-index",
            "--no-cache",
            "--no-deps",
            *workspace_wheels,
        ]:
            raise CandidateError("download-command-policy-invalid")

        check = _argv(records[6])
        _require_executable(check, r"uv")
        if check != [uv_executable, "pip", "check", "--python", install_python]:
            raise CandidateError("download-command-policy-invalid")

        imports = _argv(records[7])
        if imports != [install_python, "-c", _SMOKE_IMPORTS]:
            raise CandidateError("download-command-policy-invalid")
        if _argv(records[8]) != [stateweaver, "--json", "doctor"]:
            raise CandidateError("download-command-policy-invalid")
        if _argv(records[9]) != [stateweaver, "--json", "foundation", "verify"]:
            raise CandidateError("download-command-policy-invalid")
        if _argv(records[10]) != [
            stateweaver,
            "foundation",
            "verify-evidence",
            proof_run,
            "--repository-marker",
            source_sha,
        ]:
            raise CandidateError("download-command-policy-invalid")
        clean = _argv(records[11])
        _require_executable(clean, r"python(?:3(?:\.13)?)?")
        if clean != [
            verify[0],
            "-m",
            "tools.candidate.git_clean",
            "--repository-root",
            verifier_source,
        ]:
            raise CandidateError("download-command-policy-invalid")
    except (CandidateError, IndexError, TypeError):
        raise CandidateError("download-command-policy-invalid") from None
