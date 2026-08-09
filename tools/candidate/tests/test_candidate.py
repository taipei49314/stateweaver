from __future__ import annotations

import gzip
import hashlib
import io
import json
import subprocess
import tarfile
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

from .. import common
from ..build import BuildRequest, build_candidate
from ..common import CandidateError, canonical_json_bytes, safe_relative_path
from ..compare import compare_roots
from ..download_receipt import DownloadReceiptRequest, build_download_receipt
from ..git_clean import check_git_clean
from ..normalize import normalize_distribution_root
from ..runtime import RuntimeTarget, evaluate_marker, inspect_wheel, parse_runtime_lock
from ..sbom import build_spdx_sbom
from ..verify import VerificationResult, verify_candidate

REPOSITORY_URL = "https://github.com/stateweaver/stateweaver"
WORKSPACE_PACKAGES = tuple(f"stateweaver-package-{index:02d}" for index in range(1, 19))


def _tar_gz(
    entries: dict[str, bytes],
    *,
    member_mtime: int = 1_700_000_000,
    gzip_mtime: int = 0,
) -> bytes:
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for path, content in sorted(entries.items()):
            info = tarfile.TarInfo(path)
            info.mode = 0o644
            info.mtime = member_mtime
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=gzip_mtime) as compressor:
        compressor.write(tar_buffer.getvalue())
    return output.getvalue()


def _wheel(
    *,
    name: str = "stateweaver",
    version: str = "0.1.0",
    date_time: tuple[int, int, int, int, int, int] = (1980, 1, 1, 0, 0, 0),
) -> bytes:
    output = io.BytesIO()
    distribution = name.replace("-", "_")
    module = distribution.replace(".", "_")
    entries = {
        f"{distribution}-{version}.dist-info/METADATA": (
            f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n\n"
        ).encode(),
        f"{distribution}-{version}.dist-info/RECORD": b"",
        f"{distribution}-{version}.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nGenerator: candidate-test\n"
            b"Root-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        f"{module}/__init__.py": f'__version__ = "{version}"\n'.encode(),
    }
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, content in sorted(entries.items()):
            info = zipfile.ZipInfo(path, date_time=date_time)
            info.external_attr = 0o100644 << 16
            archive.writestr(info, content)
    return output.getvalue()


VENDOR_FILENAME = "demo_dependency-1.2.3-py3-none-any.whl"
VENDOR_WHEEL = _wheel(name="demo-dependency", version="1.2.3")
VENDOR_SHA256 = hashlib.sha256(VENDOR_WHEEL).hexdigest()
_MEMBERS = ("stateweaver", *WORKSPACE_PACKAGES)
_LOCK_LINES = [
    'version = 1\nrevision = 3\nrequires-python = ">=3.12"\n\n',
    "[manifest]\nmembers = [\n",
    *(f'    "{name}",\n' for name in _MEMBERS),
    "]\n\n",
    '[[package]]\nname = "demo-dependency"\nversion = "1.2.3"\n',
    'source = { registry = "https://pypi.org/simple" }\n',
    "wheels = [\n",
    (
        '    { url = "https://files.pythonhosted.org/packages/test/'
        f'{VENDOR_FILENAME}", hash = "sha256:{VENDOR_SHA256}" }},\n'
    ),
    "]\n\n",
    '[[package]]\nname = "stateweaver"\nversion = "0.1.0"\n',
    'source = { virtual = "." }\n\n',
]
for _package_name in WORKSPACE_PACKAGES:
    _LOCK_LINES.extend(
        (
            "[[package]]\n",
            f'name = "{_package_name}"\n',
            'version = "0.1.0"\n',
            f'source = {{ editable = "packages/{_package_name}" }}\n',
            'dependencies = [{ name = "demo-dependency" }]\n\n',
        )
    )
PYTHON_LOCK = "".join(_LOCK_LINES).encode()
NODE_LOCK = canonical_json_bytes(
    {
        "lockfileVersion": 3,
        "name": "stateweaver-web",
        "packages": {
            "": {
                "license": "Apache-2.0",
                "name": "stateweaver-web",
                "version": "0.1.0",
            }
        },
        "requires": True,
        "version": "0.1.0",
    }
)


def _git_object_sha(kind: str, content: bytes) -> bytes:
    return hashlib.sha1(
        f"{kind} {len(content)}\0".encode() + content,
        usedforsecurity=False,
    ).digest()


def _git_tree_sha(entries: dict[str, tuple[int, bytes]]) -> str:
    tree: dict[str, object] = {}
    for path, value in entries.items():
        cursor = tree
        parts = path.split("/")
        for part in parts[:-1]:
            cursor = cursor.setdefault(part, {})  # type: ignore[assignment]
        cursor[parts[-1]] = value

    def digest(node: dict[str, object]) -> bytes:
        records: list[tuple[bytes, bytes]] = []
        for name, value in node.items():
            encoded = name.encode()
            if isinstance(value, dict):
                mode = b"40000"
                object_digest = digest(value)
                sort_key = encoded + b"/"
            else:
                assert isinstance(value, tuple)
                file_mode, content = value
                assert isinstance(file_mode, int)
                assert isinstance(content, bytes)
                mode = str(file_mode).encode()
                object_digest = _git_object_sha("blob", content)
                sort_key = encoded
            records.append((sort_key, mode + b" " + encoded + b"\0" + object_digest))
        payload = b"".join(record for _key, record in sorted(records))
        return _git_object_sha("tree", payload)

    return digest(tree).hex()


SOURCE_TREE_ENTRIES = {
    "apps/web/package-lock.json": (100644, NODE_LOCK),
    "uv.lock": (100644, PYTHON_LOCK),
}
TREE_SHA = _git_tree_sha(SOURCE_TREE_ENTRIES)
GIT_COMMIT_OBJECT = (
    f"tree {TREE_SHA}\nauthor Candidate <candidate@example.invalid> 1700000000 +0000\n"
    "committer Candidate <candidate@example.invalid> 1700000000 +0000\n\ncandidate\n"
).encode()
SOURCE_SHA = _git_object_sha("commit", GIT_COMMIT_OBJECT).hex()


def _source_tar(entries: dict[str, tuple[int, bytes]]) -> bytes:
    prefix = "stateweaver-0.1.0"
    tar_buffer = io.BytesIO()
    directories = {prefix}
    for relative in entries:
        parts = relative.split("/")
        directories.update(f"{prefix}/{'/'.join(parts[:index])}" for index in range(1, len(parts)))
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for directory in sorted(directories):
            info = tarfile.TarInfo(directory)
            info.mode = 0o775
            info.mtime = 1_700_000_000
            info.type = tarfile.DIRTYPE
            archive.addfile(info)
        for relative, (mode, content) in sorted(entries.items()):
            info = tarfile.TarInfo(f"{prefix}/{relative}")
            info.mtime = 1_700_000_000
            if mode == 120000:
                info.mode = 0o777
                info.type = tarfile.SYMTYPE
                info.linkname = content.decode()
                archive.addfile(info)
            else:
                info.mode = 0o775 if mode == 100755 else 0o664
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as compressor:
        compressor.write(tar_buffer.getvalue())
    return output.getvalue()


def _request(tmp_path: Path, *, name: str = "candidate") -> BuildRequest:
    inputs = tmp_path / f"{name}-inputs"
    inputs.mkdir()
    python_lock = inputs / "uv.lock"
    node_lock = inputs / "package-lock.json"
    git_commit_object = inputs / "git-commit-object"
    command_records = inputs / "command-records.jsonl"
    python_lock.write_bytes(PYTHON_LOCK)
    node_lock.write_bytes(NODE_LOCK)
    git_commit_object.write_bytes(GIT_COMMIT_OBJECT)
    command_records.write_bytes(
        b"".join(
            canonical_json_bytes(record)
            for index, (stage, argv) in enumerate(
                (
                    (
                        "compare-python-distributions",
                        [
                            "/opt/python/bin/python3.13",
                            "-m",
                            "tools.candidate.compare",
                            "/tmp/root-a/dist",
                            "/tmp/root-b/dist",
                        ],
                    ),
                    (
                        "compare-web-archives",
                        [
                            "/opt/python/bin/python3.13",
                            "-m",
                            "tools.candidate.compare",
                            "/tmp/root-a/web-artifact",
                            "/tmp/root-b/web-artifact",
                        ],
                    ),
                    (
                        "compare-vendored-runtime",
                        [
                            "/opt/python/bin/python3.13",
                            "-m",
                            "tools.candidate.compare",
                            "/tmp/vendor-a-123",
                            "/tmp/vendor-b-123",
                        ],
                    ),
                    (
                        "verify-foundation-proof",
                        [
                            "/usr/bin/uv",
                            "run",
                            "stateweaver",
                            "foundation",
                            "verify-evidence",
                            "/workspace/artifacts/acceptance/runs/run-1",
                            "--repository-marker",
                            SOURCE_SHA,
                        ],
                    ),
                    (
                        "verify-source-worktree-clean",
                        [
                            "/opt/python/bin/python3.13",
                            "-m",
                            "tools.candidate.git_clean",
                            "--repository-root",
                            "/workspace",
                            "--allow-untracked",
                            "/workspace/artifacts/acceptance",
                            "--allow-untracked",
                            "/workspace/candidate",
                        ],
                    ),
                )
            )
            for record in (
                {
                    "argv": argv,
                    "completed_at": f"2026-08-09T01:00:{index * 2 + 1:02d}Z",
                    "cwd": "/workspace",
                    "exit_code": 0,
                    "stage": stage,
                    "started_at": f"2026-08-09T01:00:{index * 2:02d}Z",
                    "status": "PASS",
                },
            )
        )
    )
    root = tmp_path / name
    payload = root / "payload"
    (payload / "python").mkdir(parents=True)
    (payload / "vendor" / "python").mkdir(parents=True)
    (payload / "web").mkdir()
    (payload / "source").mkdir()
    (payload / "evidence" / "foundation" / "runs" / "run-1").mkdir(parents=True)
    for package_name in WORKSPACE_PACKAGES:
        distribution = package_name.replace("-", "_")
        (payload / "python" / f"{distribution}-0.1.0-py3-none-any.whl").write_bytes(
            _wheel(name=package_name)
        )
        (payload / "python" / f"{distribution}-0.1.0.tar.gz").write_bytes(
            _tar_gz(
                {
                    f"{distribution}-0.1.0/PKG-INFO": (
                        f"Metadata-Version: 2.4\nName: {package_name}\nVersion: 0.1.0\n\n"
                    ).encode()
                }
            )
        )
    (payload / "vendor" / "python" / VENDOR_FILENAME).write_bytes(VENDOR_WHEEL)
    (payload / "web" / "stateweaver-web-0.1.0.tar.gz").write_bytes(
        _tar_gz({"stateweaver-web-0.1.0/index.html": b"<!doctype html>\n"})
    )
    (payload / "source" / "stateweaver-source-0.1.0.tar.gz").write_bytes(
        _source_tar(SOURCE_TREE_ENTRIES)
    )
    (payload / "evidence" / "foundation" / "runs" / "run-1" / "receipt.json").write_bytes(
        canonical_json_bytes({"repository_marker": SOURCE_SHA, "verified": True})
    )
    return BuildRequest(
        candidate_root=root,
        python_lock=python_lock,
        node_lock=node_lock,
        git_commit_object=git_commit_object,
        command_records=command_records,
        repository_url=REPOSITORY_URL,
        source_sha=SOURCE_SHA,
        tree_sha=TREE_SHA,
        version="0.1.0",
        source_date_epoch=1_700_000_000,
        started_at="2026-08-09T01:00:00Z",
        completed_at="2026-08-09T01:01:00Z",
        workflow_run_id="123",
        workflow_run_attempt=1,
        workflow_run_url="https://github.com/stateweaver/stateweaver/actions/runs/123",
        runner_os="Linux",
        runner_arch="X64",
        python_version="3.13.7",
        python_full_version="3.13.7",
        pip_version="26.1.2",
        node_version="24.5.0",
        uv_version="0.9.0",
        reproducibility_verified=True,
    )


def _built(tmp_path: Path, *, name: str = "candidate") -> BuildRequest:
    request = _request(tmp_path, name=name)
    build_candidate(request)
    return request


def _verify(request: BuildRequest) -> VerificationResult:
    return verify_candidate(
        request.candidate_root,
        expected_repository_url=request.repository_url,
        expected_source_sha=request.source_sha,
    )


def _rewrite_checksums(root: Path) -> None:
    paths = sorted(
        (path.relative_to(root).as_posix(), path)
        for path in root.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    )
    lines = []
    for relative, path in paths:
        lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative}\n")
    (root / "SHA256SUMS").write_text("".join(lines), encoding="utf-8", newline="")


def _rehash_manifest_artifact(root: Path, relative: str) -> None:
    target = root / relative
    manifest_path = root / "PAYLOAD_MANIFEST.json"
    manifest = json.loads(manifest_path.read_bytes())
    matches = [entry for entry in manifest["artifacts"] if entry["path"] == relative]
    assert len(matches) == 1
    matches[0]["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
    matches[0]["size"] = target.stat().st_size
    manifest_path.write_bytes(canonical_json_bytes(manifest))
    _rewrite_checksums(root)


def test_build_and_verify_candidate_round_trip(tmp_path: Path) -> None:
    request = _built(tmp_path)

    result = _verify(request)

    assert result.valid
    assert result.status == "CANDIDATE_READY_FOR_EXTERNAL_QUALIFICATION"
    assert result.source_sha == SOURCE_SHA


def test_manifest_and_sbom_cover_exact_distribution_inventory(tmp_path: Path) -> None:
    request = _built(tmp_path)
    manifest = json.loads((request.candidate_root / "PAYLOAD_MANIFEST.json").read_bytes())
    sbom = json.loads((request.candidate_root / "payload/sbom/stateweaver.spdx.json").read_bytes())

    assert manifest["build"]["inventory"] == {
        "runtime_wheels": 1,
        "workspace_sdists": 18,
        "workspace_wheels": 18,
    }
    vendor_files = [
        item for item in sbom["files"] if item["fileName"].startswith("./payload/vendor/")
    ]
    assert vendor_files == [
        {
            "SPDXID": vendor_files[0]["SPDXID"],
            "checksums": [{"algorithm": "SHA256", "checksumValue": VENDOR_SHA256}],
            "copyrightText": "NOASSERTION",
            "fileName": f"./payload/vendor/python/{VENDOR_FILENAME}",
            "licenseConcluded": "NOASSERTION",
        }
    ]


def test_candidate_receipt_uses_typed_execution_records(tmp_path: Path) -> None:
    request = _built(tmp_path)
    receipt = json.loads((request.candidate_root / "CANDIDATE_RECEIPT.json").read_bytes())

    assert receipt["dirty"] is False
    assert receipt["execution"]["commands"][0] == {
        "argv": [
            "/opt/python/bin/python3.13",
            "-m",
            "tools.candidate.compare",
            "/tmp/root-a/dist",
            "/tmp/root-b/dist",
        ],
        "completed_at": "2026-08-09T01:00:01Z",
        "cwd": "/workspace",
        "exit_code": 0,
        "stage": "compare-python-distributions",
        "started_at": "2026-08-09T01:00:00Z",
        "status": "PASS",
    }
    assert receipt["network"]["egress"] == "AVAILABLE_NOT_DISABLED"
    assert receipt["cleanup"]["status"] == "NOT_MEASURED"
    assert receipt["artifacts"]
    assert receipt["manual_steps"] == ["workflow_dispatch:source_sha"]
    assert receipt["retries"] == 0
    assert all(item["required_for_release"] is True for item in receipt["skips"])


def test_builder_rejects_forged_command_argv(tmp_path: Path) -> None:
    request = _request(tmp_path)
    records = [json.loads(line) for line in request.command_records.read_bytes().splitlines()]
    records[0]["argv"] = ["/attacker/false-proof"]
    request.command_records.write_bytes(
        b"".join(canonical_json_bytes(record) for record in records)
    )

    with pytest.raises(CandidateError, match="build-command-policy-invalid"):
        build_candidate(request)


def test_builder_rejects_unmeasured_dirty_claim(tmp_path: Path) -> None:
    request = _request(tmp_path)
    records = [json.loads(line) for line in request.command_records.read_bytes().splitlines()]
    records[-1]["argv"] = ["/usr/bin/git", "diff", "--quiet", "HEAD", "--"]
    request.command_records.write_bytes(
        b"".join(canonical_json_bytes(record) for record in records)
    )

    with pytest.raises(CandidateError, match="build-command-policy-invalid"):
        build_candidate(request)


def test_verifier_rejects_coherently_rehashed_forged_command_claim(tmp_path: Path) -> None:
    request = _built(tmp_path)
    receipt_path = request.candidate_root / "CANDIDATE_RECEIPT.json"
    receipt = json.loads(receipt_path.read_bytes())
    receipt["execution"]["commands"][3]["argv"][-1] = "f" * 40
    receipt_path.write_bytes(canonical_json_bytes(receipt))
    manifest_path = request.candidate_root / "PAYLOAD_MANIFEST.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["receipt"]["sha256"] = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    manifest_path.write_bytes(canonical_json_bytes(manifest))
    _rewrite_checksums(request.candidate_root)

    assert _verify(request).errors == ("build-command-policy-invalid",)


def test_git_clean_helper_measures_tracked_and_untracked_state(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=repository, check=True)
    subprocess.run(
        ["git", "config", "user.email", "candidate@example.invalid"],
        cwd=repository,
        check=True,
    )
    subprocess.run(["git", "config", "user.name", "Candidate Test"], cwd=repository, check=True)
    tracked = repository / "tracked.txt"
    tracked.write_text("bound\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked.txt"], cwd=repository, check=True)
    subprocess.run(["git", "commit", "--quiet", "-m", "fixture"], cwd=repository, check=True)

    assert check_git_clean(repository)
    generated = repository / "candidate" / "output.txt"
    generated.parent.mkdir()
    generated.write_text("generated\n", encoding="utf-8")
    assert not check_git_clean(repository)
    assert check_git_clean(repository, allowed_untracked=(repository / "candidate",))
    tracked.write_text("tampered\n", encoding="utf-8")
    assert not check_git_clean(repository, allowed_untracked=(repository / "candidate",))


def test_builder_rejects_noncanonical_workflow_run_id(tmp_path: Path) -> None:
    request = replace(_request(tmp_path), workflow_run_id="123-1")

    with pytest.raises(CandidateError, match="workflow-identity-invalid"):
        build_candidate(request)


def _download_records(
    path: Path,
    *,
    request: BuildRequest,
    bundle: Path,
    offline: bool = True,
) -> tuple[Path, Path, Path, Path]:
    workspace = path.parent.resolve()
    candidate = request.candidate_root.resolve()
    canonical_source = workspace / "canonical-source.tar.gz"
    canonical_source.write_bytes(b"canonical source placeholder\n")
    verifier_source = workspace / "verifier-source"
    verifier_source.mkdir(exist_ok=True)
    install_root = workspace / ".candidate-install"
    install_python = (install_root / "bin/python").as_posix()
    stateweaver = (install_root / "bin/stateweaver").as_posix()
    wheels = sorted(
        wheel.resolve().as_posix() for wheel in (candidate / "payload/python").glob("*.whl")
    )
    assert len(wheels) == 18
    proof_run = candidate / "payload/evidence/foundation/runs/run-1"
    stages = (
        (
            "compare-canonical-source-archive",
            [
                "/usr/bin/cmp",
                "--silent",
                canonical_source.as_posix(),
                (candidate / "payload/source/stateweaver-source-0.1.0.tar.gz").as_posix(),
            ],
        ),
        (
            "verify-downloaded-candidate",
            [
                "/usr/bin/python",
                "-m",
                "tools.candidate.verify",
                candidate.as_posix(),
                "--expected-repository-url",
                REPOSITORY_URL,
                "--expected-source-sha",
                SOURCE_SHA,
            ],
        ),
        (
            "verify-oidc-attestation",
            [
                "/usr/bin/gh",
                "attestation",
                "verify",
                (candidate / "PAYLOAD_MANIFEST.json").as_posix(),
                "--repo",
                "stateweaver/stateweaver",
                "--bundle",
                bundle.resolve().as_posix(),
                "--signer-workflow",
                "github.com/stateweaver/stateweaver/.github/workflows/candidate.yml",
                "--signer-digest",
                SOURCE_SHA,
                "--source-digest",
                SOURCE_SHA,
                "--source-ref",
                "refs/heads/main",
                "--deny-self-hosted-runners",
            ],
        ),
        (
            "create-clean-install-environment",
            ["/usr/bin/uv", "venv", "--python", "3.13", install_root.as_posix()],
        ),
        (
            "install-runtime-closure-offline",
            [
                "/usr/bin/uv",
                "pip",
                "install",
                "--python",
                install_python,
                *(["--offline"] if offline else []),
                "--no-index",
                "--no-cache",
                "--find-links",
                (candidate / "payload/vendor/python").as_posix(),
                "--require-hashes",
                "-r",
                (candidate / "payload/metadata/runtime-requirements.txt").as_posix(),
            ],
        ),
        (
            "install-workspace-wheels-offline",
            [
                "/usr/bin/uv",
                "pip",
                "install",
                "--python",
                install_python,
                "--offline",
                "--no-index",
                "--no-cache",
                "--no-deps",
                *wheels,
            ],
        ),
        (
            "check-offline-install",
            ["/usr/bin/uv", "pip", "check", "--python", install_python],
        ),
        (
            "smoke-imports",
            [
                install_python,
                "-c",
                (
                    "from stateweaver.reporting import RealityPublicationManifest; "
                    "import statechainbench; import stateweaver_api"
                ),
            ],
        ),
        ("smoke-doctor", [stateweaver, "--json", "doctor"]),
        ("smoke-foundation", [stateweaver, "--json", "foundation", "verify"]),
        (
            "smoke-foundation-evidence",
            [
                stateweaver,
                "foundation",
                "verify-evidence",
                proof_run.as_posix(),
                "--repository-marker",
                SOURCE_SHA,
            ],
        ),
        (
            "verify-verifier-source-clean",
            [
                "/usr/bin/python",
                "-m",
                "tools.candidate.git_clean",
                "--repository-root",
                verifier_source.as_posix(),
            ],
        ),
    )
    lines = []
    for index, (stage, argv) in enumerate(stages):
        lines.append(
            canonical_json_bytes(
                {
                    "argv": argv,
                    "completed_at": f"2026-08-09T01:00:{index * 2 + 1:02d}Z",
                    "cwd": workspace.as_posix(),
                    "exit_code": 0,
                    "stage": stage,
                    "started_at": f"2026-08-09T01:00:{index * 2:02d}Z",
                    "status": "PASS",
                }
            )
        )
    path.write_bytes(b"".join(lines))
    return workspace, canonical_source, verifier_source, install_root


def test_detached_download_receipt_binds_attestation_and_offline_install(tmp_path: Path) -> None:
    request = _built(tmp_path)
    bundle = tmp_path / "bundle.json"
    bundle.write_bytes(b'{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}\n')
    records = tmp_path / "download-records.jsonl"
    workspace, canonical_source, verifier_source, install_root = _download_records(
        records, request=request, bundle=bundle
    )
    manifest_sha = hashlib.sha256(
        (request.candidate_root / "PAYLOAD_MANIFEST.json").read_bytes()
    ).hexdigest()

    receipt = json.loads(
        build_download_receipt(
            DownloadReceiptRequest(
                candidate_root=request.candidate_root,
                attestation_bundle=bundle,
                command_records=records,
                output=tmp_path / "DOWNLOAD_VERIFICATION_RECEIPT.json",
                workspace=workspace,
                canonical_source_archive=canonical_source,
                verifier_source=verifier_source,
                install_root=install_root,
                repository_url=REPOSITORY_URL,
                source_sha=SOURCE_SHA,
                source_ref="refs/heads/main",
                manifest_sha256=manifest_sha,
                actions_artifact_sha256="a" * 64,
                workflow_run_id="123",
                workflow_run_attempt=1,
                workflow_run_url="https://github.com/stateweaver/stateweaver/actions/runs/123",
                signer_workflow=(
                    "github.com/stateweaver/stateweaver/.github/workflows/candidate.yml"
                ),
                version="0.1.0",
                started_at="2026-08-09T01:00:00Z",
                completed_at="2026-08-09T01:01:00Z",
                runner_os="Linux",
                runner_arch="X64",
            )
        )
    )

    assert receipt["status"] == "PASS"
    assert receipt["payload"]["manifest_sha256"] == manifest_sha
    assert (
        receipt["provenance"]["attestation_bundle_sha256"]
        == hashlib.sha256(bundle.read_bytes()).hexdigest()
    )
    assert receipt["network"]["installation"] == "OFFLINE_NO_INDEX_NO_CACHE"


def test_detached_download_receipt_rejects_missing_offline_flag(tmp_path: Path) -> None:
    request = _built(tmp_path)
    bundle = tmp_path / "bundle.json"
    bundle.write_bytes(b"{}\n")
    records = tmp_path / "download-records.jsonl"
    workspace, canonical_source, verifier_source, install_root = _download_records(
        records, request=request, bundle=bundle, offline=False
    )
    manifest_sha = hashlib.sha256(
        (request.candidate_root / "PAYLOAD_MANIFEST.json").read_bytes()
    ).hexdigest()

    with pytest.raises(CandidateError, match="download-command-policy-invalid"):
        build_download_receipt(
            DownloadReceiptRequest(
                candidate_root=request.candidate_root,
                attestation_bundle=bundle,
                command_records=records,
                output=tmp_path / "receipt.json",
                workspace=workspace,
                canonical_source_archive=canonical_source,
                verifier_source=verifier_source,
                install_root=install_root,
                repository_url=REPOSITORY_URL,
                source_sha=SOURCE_SHA,
                source_ref="refs/heads/main",
                manifest_sha256=manifest_sha,
                actions_artifact_sha256="a" * 64,
                workflow_run_id="123",
                workflow_run_attempt=1,
                workflow_run_url="https://github.com/stateweaver/stateweaver/actions/runs/123",
                signer_workflow=(
                    "github.com/stateweaver/stateweaver/.github/workflows/candidate.yml"
                ),
                version="0.1.0",
                started_at="2026-08-09T01:00:00Z",
                completed_at="2026-08-09T01:01:00Z",
                runner_os="Linux",
                runner_arch="X64",
            )
        )


@pytest.mark.parametrize("option", ["--bundle", "--source-digest"])
def test_detached_download_receipt_rejects_wrong_attestation_binding(
    tmp_path: Path, option: str
) -> None:
    request = _built(tmp_path)
    bundle = tmp_path / "bundle.json"
    bundle.write_bytes(b"{}\n")
    records_path = tmp_path / "download-records.jsonl"
    workspace, canonical_source, verifier_source, install_root = _download_records(
        records_path, request=request, bundle=bundle
    )
    records = [json.loads(line) for line in records_path.read_bytes().splitlines()]
    attestation = next(record for record in records if record["stage"] == "verify-oidc-attestation")
    value_index = attestation["argv"].index(option) + 1
    attestation["argv"][value_index] = (
        (tmp_path / "wrong-bundle.json").resolve().as_posix() if option == "--bundle" else "f" * 40
    )
    records_path.write_bytes(b"".join(canonical_json_bytes(record) for record in records))
    manifest_sha = hashlib.sha256(
        (request.candidate_root / "PAYLOAD_MANIFEST.json").read_bytes()
    ).hexdigest()

    with pytest.raises(CandidateError, match="download-command-policy-invalid"):
        build_download_receipt(
            DownloadReceiptRequest(
                candidate_root=request.candidate_root,
                attestation_bundle=bundle,
                command_records=records_path,
                output=tmp_path / "receipt.json",
                workspace=workspace,
                canonical_source_archive=canonical_source,
                verifier_source=verifier_source,
                install_root=install_root,
                repository_url=REPOSITORY_URL,
                source_sha=SOURCE_SHA,
                source_ref="refs/heads/main",
                manifest_sha256=manifest_sha,
                actions_artifact_sha256="a" * 64,
                workflow_run_id="123",
                workflow_run_attempt=1,
                workflow_run_url="https://github.com/stateweaver/stateweaver/actions/runs/123",
                signer_workflow=(
                    "github.com/stateweaver/stateweaver/.github/workflows/candidate.yml"
                ),
                version="0.1.0",
                started_at="2026-08-09T01:00:00Z",
                completed_at="2026-08-09T01:01:00Z",
                runner_os="Linux",
                runner_arch="X64",
            )
        )


def test_detached_download_receipt_rejects_composite_run_id(tmp_path: Path) -> None:
    with pytest.raises(CandidateError, match="download-receipt-invalid"):
        build_download_receipt(
            DownloadReceiptRequest(
                candidate_root=tmp_path / "candidate",
                attestation_bundle=tmp_path / "bundle.json",
                command_records=tmp_path / "records.jsonl",
                output=tmp_path / "receipt.json",
                workspace=tmp_path,
                canonical_source_archive=tmp_path / "source.tar.gz",
                verifier_source=tmp_path / "verifier-source",
                install_root=tmp_path / ".candidate-install",
                repository_url=REPOSITORY_URL,
                source_sha=SOURCE_SHA,
                source_ref="refs/heads/main",
                manifest_sha256="a" * 64,
                actions_artifact_sha256="b" * 64,
                workflow_run_id="123-1",
                workflow_run_attempt=1,
                workflow_run_url=("https://github.com/stateweaver/stateweaver/actions/runs/123"),
                signer_workflow=(
                    "github.com/stateweaver/stateweaver/.github/workflows/candidate.yml"
                ),
                version="0.1.0",
                started_at="2026-08-09T01:00:00Z",
                completed_at="2026-08-09T01:01:00Z",
                runner_os="Linux",
                runner_arch="X64",
            )
        )


def test_coherently_rehashed_runtime_requirements_tamper_is_rejected(tmp_path: Path) -> None:
    request = _built(tmp_path)
    relative = "payload/metadata/runtime-requirements.txt"
    requirements = request.candidate_root / relative
    requirements.write_bytes(requirements.read_bytes() + b"# attacker-controlled\n")
    _rehash_manifest_artifact(request.candidate_root, relative)

    assert _verify(request).errors == ("runtime-requirements-lock-mismatch",)


@pytest.mark.parametrize("suffix", ["-py3-none-any.whl", ".tar.gz"])
def test_builder_requires_exact_workspace_distribution_inventory(
    tmp_path: Path, suffix: str
) -> None:
    request = _request(tmp_path)
    distribution = WORKSPACE_PACKAGES[0].replace("-", "_")
    (request.candidate_root / "payload/python" / f"{distribution}-0.1.0{suffix}").unlink()

    with pytest.raises(CandidateError, match="workspace-distribution-inventory-invalid"):
        build_candidate(request)


def test_builder_rejects_missing_vendored_runtime_wheel(tmp_path: Path) -> None:
    request = _request(tmp_path)
    (request.candidate_root / "payload/vendor/python" / VENDOR_FILENAME).unlink()

    with pytest.raises(CandidateError, match="runtime-vendor-inventory-invalid"):
        build_candidate(request)


def test_builder_rejects_vendored_wheel_not_matching_lock_hash(tmp_path: Path) -> None:
    request = _request(tmp_path)
    target = request.candidate_root / "payload/vendor/python" / VENDOR_FILENAME
    target.write_bytes(
        _wheel(name="demo-dependency", version="1.2.3", date_time=(2025, 1, 1, 0, 0, 0))
    )

    with pytest.raises(CandidateError, match="runtime-vendor-lock-mismatch"):
        build_candidate(request)


def test_runtime_wheel_must_match_fixed_linux_cpython_target() -> None:
    with pytest.raises(CandidateError, match="wheel-identity-invalid"):
        inspect_wheel(
            "demo_dependency-1.2.3-cp313-cp313-win_amd64.whl",
            _wheel(name="demo-dependency", version="1.2.3"),
        )


def test_runtime_marker_parser_rejects_executable_syntax() -> None:
    with pytest.raises(CandidateError, match="python-lock-marker-unsupported"):
        evaluate_marker("__import__('os').system('echo unsafe')", RuntimeTarget.create("3.13.7"))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("runner_os", "Windows"),
        ("runner_arch", "ARM64"),
        ("python_version", "Python 3.13.8"),
    ],
)
def test_builder_rejects_runtime_provenance_mismatch(
    tmp_path: Path, field: str, value: str
) -> None:
    base = _request(tmp_path)
    if field == "runner_os":
        request = replace(base, runner_os=value)
    elif field == "runner_arch":
        request = replace(base, runner_arch=value)
    else:
        request = replace(base, python_version=value)

    with pytest.raises(CandidateError, match="workflow-runtime-invalid"):
        build_candidate(request)


def test_payload_is_deterministic_while_content_address_is_run_bound(tmp_path: Path) -> None:
    first = _built(tmp_path, name="first")
    second_request = _request(tmp_path, name="second")
    second = replace(
        second_request,
        workflow_run_id="456",
        workflow_run_url="https://github.com/stateweaver/stateweaver/actions/runs/456",
    )
    build_candidate(second)

    assert (first.candidate_root / "payload/sbom/stateweaver.spdx.json").read_bytes() == (
        second.candidate_root / "payload/sbom/stateweaver.spdx.json"
    ).read_bytes()
    first_manifest = json.loads((first.candidate_root / "PAYLOAD_MANIFEST.json").read_bytes())
    second_manifest = json.loads((second.candidate_root / "PAYLOAD_MANIFEST.json").read_bytes())
    for field in ("artifacts", "build", "locks", "sbom", "source", "status"):
        assert first_manifest[field] == second_manifest[field]
    assert first_manifest["receipt"] != second_manifest["receipt"]
    assert (first.candidate_root / "PAYLOAD_MANIFEST.json").read_bytes() != (
        second.candidate_root / "PAYLOAD_MANIFEST.json"
    ).read_bytes()
    assert (first.candidate_root / "SHA256SUMS").read_bytes() != (
        second.candidate_root / "SHA256SUMS"
    ).read_bytes()
    assert (first.candidate_root / "CANDIDATE_RECEIPT.json").read_bytes() != (
        second.candidate_root / "CANDIDATE_RECEIPT.json"
    ).read_bytes()


@pytest.mark.parametrize("relative", ["payload/web/unlisted.txt", "surprise.txt"])
def test_extra_file_is_rejected(tmp_path: Path, relative: str) -> None:
    request = _built(tmp_path)
    extra = request.candidate_root / relative
    extra.parent.mkdir(parents=True, exist_ok=True)
    extra.write_text("not declared", encoding="utf-8")

    assert _verify(request).errors == ("candidate-file-coverage-mismatch",)


def test_missing_file_is_rejected(tmp_path: Path) -> None:
    request = _built(tmp_path)
    (request.candidate_root / "payload/web/stateweaver-web-0.1.0.tar.gz").unlink()

    assert _verify(request).errors == ("candidate-artifact-content-mismatch",)


def test_payload_tamper_is_rejected(tmp_path: Path) -> None:
    request = _built(tmp_path)
    artifact = request.candidate_root / "payload/evidence/foundation/runs/run-1/receipt.json"
    artifact.write_bytes(artifact.read_bytes() + b" ")

    assert _verify(request).errors == ("candidate-artifact-content-mismatch",)


def test_checksums_cover_every_file_except_themselves(tmp_path: Path) -> None:
    request = _built(tmp_path)
    root = request.candidate_root
    covered = {
        line.split("  ", 1)[1]
        for line in (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    }
    expected = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    }

    assert covered == expected


def test_sbom_must_match_lockfile(tmp_path: Path) -> None:
    request = _built(tmp_path)
    lock = request.candidate_root / "payload/locks/uv.lock"
    lock.write_bytes(lock.read_bytes().replace(b"0.1.0", b"0.2.0"))

    assert _verify(request).errors == ("candidate-artifact-content-mismatch",)


@pytest.mark.parametrize(
    ("field", "value"),
    [("status", "RELEASE_READY"), ("release_eligible", True), ("tag_created", True)],
)
def test_receipt_cannot_promote_candidate(tmp_path: Path, field: str, value: object) -> None:
    request = _built(tmp_path)
    receipt_path = request.candidate_root / "CANDIDATE_RECEIPT.json"
    receipt = json.loads(receipt_path.read_bytes())
    receipt[field] = value
    receipt_path.write_bytes(canonical_json_bytes(receipt))

    assert _verify(request).errors == ("candidate-receipt-digest-invalid",)


def test_coherently_rehashed_receipt_still_cannot_promote_candidate(tmp_path: Path) -> None:
    request = _built(tmp_path)
    root = request.candidate_root
    receipt_path = root / "CANDIDATE_RECEIPT.json"
    receipt = json.loads(receipt_path.read_bytes())
    receipt["status"] = "RELEASE_READY"
    receipt_path.write_bytes(canonical_json_bytes(receipt))
    manifest_path = root / "PAYLOAD_MANIFEST.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["receipt"]["sha256"] = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    manifest_path.write_bytes(canonical_json_bytes(manifest))
    _rewrite_checksums(root)

    assert _verify(request).errors == ("candidate-receipt-policy-invalid",)


def test_wrong_expected_source_sha_is_rejected(tmp_path: Path) -> None:
    request = _built(tmp_path)

    result = verify_candidate(
        request.candidate_root,
        expected_repository_url=request.repository_url,
        expected_source_sha="3" * 40,
    )

    assert result.errors == ("candidate-source-mismatch",)


def test_noncanonical_or_duplicate_manifest_is_rejected(tmp_path: Path) -> None:
    request = _built(tmp_path)
    manifest = request.candidate_root / "PAYLOAD_MANIFEST.json"
    manifest.write_bytes(b'{"schema_version":"x","schema_version":"y"}\n')

    assert _verify(request).errors == ("candidate-manifest-invalid",)


@pytest.mark.parametrize(
    "content",
    [
        (b"[" * 10_000) + b"0" + (b"]" * 10_000) + b"\n",
        canonical_json_bytes({"value": "x" * (2 * 1024 * 1024 + 1)}),
        canonical_json_bytes([0] * 200_001),
    ],
    ids=("depth", "string", "nodes"),
)
def test_manifest_json_structure_limits_fail_closed(tmp_path: Path, content: bytes) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    (root / "PAYLOAD_MANIFEST.json").write_bytes(content)
    (root / "SHA256SUMS").write_bytes(b"")
    (root / "CANDIDATE_RECEIPT.json").write_bytes(b"{}\n")

    result = verify_candidate(
        root,
        expected_repository_url=REPOSITORY_URL,
        expected_source_sha=SOURCE_SHA,
    )

    assert result.valid is False
    assert result.errors == ("candidate-manifest-invalid",)


def test_manifest_5000_digit_integer_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    (root / "PAYLOAD_MANIFEST.json").write_bytes(b'{"value":' + b"9" * 5_000 + b"}\n")
    (root / "SHA256SUMS").write_bytes(b"")
    (root / "CANDIDATE_RECEIPT.json").write_bytes(b"{}\n")

    result = verify_candidate(
        root,
        expected_repository_url=REPOSITORY_URL,
        expected_source_sha=SOURCE_SHA,
    )

    assert result.errors == ("candidate-manifest-invalid",)


def test_python_lock_5000_digit_integer_fails_closed() -> None:
    hostile = PYTHON_LOCK.replace(b"revision = 3", b"revision = " + b"9" * 5_000)

    with pytest.raises(CandidateError, match="python-lockfile-invalid"):
        parse_runtime_lock(hostile, RuntimeTarget.create("3.13.7"))


def test_manifest_parser_memory_failure_is_stable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _built(tmp_path)

    def fail_loads(*_args: object, **_kwargs: object) -> object:
        raise MemoryError

    monkeypatch.setattr(json, "loads", fail_loads)

    assert _verify(request).errors == ("candidate-manifest-invalid",)


def test_node_lock_json_structure_limits_fail_closed() -> None:
    hostile_node_lock = canonical_json_bytes({"packages": [0] * 200_001})

    with pytest.raises(CandidateError, match="node-lockfile-invalid"):
        build_spdx_sbom(
            python_lock=PYTHON_LOCK,
            node_lock=hostile_node_lock,
            repository_url=REPOSITORY_URL,
            source_sha=SOURCE_SHA,
            source_date_epoch=1_700_000_000,
            vendored_wheels={},
        )


def test_builder_rejects_archive_traversal(tmp_path: Path) -> None:
    request = _request(tmp_path)
    target = request.candidate_root / "payload/web/stateweaver-web-0.1.0.tar.gz"
    target.write_bytes(_tar_gz({"../escape": b"bad"}))

    with pytest.raises(CandidateError, match="unsafe-relative-path"):
        build_candidate(request)


def test_builder_rejects_source_archive_lock_divergence(tmp_path: Path) -> None:
    request = _request(tmp_path)
    target = request.candidate_root / "payload/source/stateweaver-source-0.1.0.tar.gz"
    target.write_bytes(
        _source_tar(
            {
                "apps/web/package-lock.json": (100644, NODE_LOCK),
                "uv.lock": (100644, PYTHON_LOCK.replace(b"0.1.0", b"0.2.0")),
            }
        )
    )

    with pytest.raises(CandidateError, match="source-archive-lock-closure-invalid"):
        build_candidate(request)


def test_builder_rejects_source_archive_not_matching_claimed_tree(tmp_path: Path) -> None:
    request = _request(tmp_path)
    target = request.candidate_root / "payload/source/stateweaver-source-0.1.0.tar.gz"
    target.write_bytes(
        _source_tar(
            {
                **SOURCE_TREE_ENTRIES,
                "backdoor.py": (100644, b'print("not in claimed tree")\n'),
            }
        )
    )

    with pytest.raises(CandidateError, match="source-archive-tree-mismatch"):
        build_candidate(request)


def test_source_archive_tree_supports_executable_and_symlink(tmp_path: Path) -> None:
    entries = {
        **SOURCE_TREE_ENTRIES,
        "bin/run": (100755, b"#!/bin/sh\nexit 0\n"),
        "run-link": (120000, b"bin/run"),
    }
    tree_sha = _git_tree_sha(entries)
    commit = (
        f"tree {tree_sha}\nauthor Candidate <candidate@example.invalid> 1700000000 +0000\n"
        "committer Candidate <candidate@example.invalid> 1700000000 +0000\n\ncandidate\n"
    ).encode()
    request = _request(tmp_path)
    request.git_commit_object.write_bytes(commit)
    target = request.candidate_root / "payload/source/stateweaver-source-0.1.0.tar.gz"
    target.write_bytes(_source_tar(entries))
    request = replace(
        request,
        tree_sha=tree_sha,
        source_sha=_git_object_sha("commit", commit).hex(),
    )
    records = [json.loads(line) for line in request.command_records.read_bytes().splitlines()]
    records[3]["argv"][-1] = request.source_sha
    request.command_records.write_bytes(
        b"".join(canonical_json_bytes(record) for record in records)
    )

    result = build_candidate(request)

    assert result.source_sha == request.source_sha


def test_builder_rejects_git_commit_object_divergence(tmp_path: Path) -> None:
    request = _request(tmp_path)
    request.git_commit_object.write_bytes(GIT_COMMIT_OBJECT + b"tampered\n")

    with pytest.raises(CandidateError, match="git-commit-object-source-mismatch"):
        build_candidate(request)


@pytest.mark.parametrize(
    "value",
    ["", "/absolute", "../escape", "a/../b", "a\\b", "C:/drive", "a//b", "./a"],
)
def test_unsafe_relative_paths_fail_closed(value: str) -> None:
    with pytest.raises(CandidateError, match="unsafe-relative-path"):
        safe_relative_path(value)


def test_compare_roots_detects_file_set_and_content_changes(tmp_path: Path) -> None:
    left = tmp_path / "left"
    right = tmp_path / "right"
    left.mkdir()
    right.mkdir()
    (left / "artifact").write_bytes(b"same")
    (right / "artifact").write_bytes(b"same")
    assert compare_roots(left, right) == (True, None)

    (right / "artifact").write_bytes(b"different")
    assert compare_roots(left, right) == (
        False,
        "reproducibility-content-mismatch:artifact",
    )
    (right / "extra").write_bytes(b"extra")
    assert compare_roots(left, right) == (False, "reproducibility-file-set-mismatch")


def test_distribution_normalization_removes_container_metadata_variance(tmp_path: Path) -> None:
    left = tmp_path / "left-dist"
    right = tmp_path / "right-dist"
    left.mkdir()
    right.mkdir()
    payload = {"stateweaver-0.1.0/PKG-INFO": b"Name: stateweaver\nVersion: 0.1.0\n"}
    (left / "stateweaver-0.1.0.tar.gz").write_bytes(
        _tar_gz(payload, member_mtime=1_700_000_001, gzip_mtime=1)
    )
    (right / "stateweaver-0.1.0.tar.gz").write_bytes(
        _tar_gz(payload, member_mtime=1_700_000_999, gzip_mtime=2)
    )
    (left / "stateweaver-0.1.0-py3-none-any.whl").write_bytes(
        _wheel(date_time=(2024, 1, 1, 0, 0, 0))
    )
    (right / "stateweaver-0.1.0-py3-none-any.whl").write_bytes(
        _wheel(date_time=(2025, 1, 1, 0, 0, 0))
    )

    normalize_distribution_root(left, source_date_epoch=1_700_000_000)
    normalize_distribution_root(right, source_date_epoch=1_700_000_000)

    assert compare_roots(left, right) == (True, None)


def test_distribution_normalization_rejects_unexpected_files(tmp_path: Path) -> None:
    root = tmp_path / "dist"
    root.mkdir()
    (root / "stateweaver-0.1.0.tar.gz").write_bytes(
        _tar_gz({"stateweaver-0.1.0/PKG-INFO": b"Name: stateweaver\n"})
    )
    (root / "stateweaver-0.1.0-py3-none-any.whl").write_bytes(_wheel())
    (root / "unexpected.txt").write_text("unexpected", encoding="utf-8")

    with pytest.raises(CandidateError, match="distribution-file-unexpected"):
        normalize_distribution_root(root, source_date_epoch=1_700_000_000)


def test_snapshot_rejects_file_count_before_reading_all_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "snapshot"
    root.mkdir()
    (root / "one").write_bytes(b"1")
    (root / "two").write_bytes(b"2")
    monkeypatch.setattr(common, "MAX_CANDIDATE_FILES", 1)

    with pytest.raises(CandidateError, match="candidate-file-count-limit"):
        common.snapshot_tree(root)


def test_snapshot_rejects_single_file_and_aggregate_size_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    single = tmp_path / "single"
    single.mkdir()
    (single / "large").write_bytes(b"123")
    monkeypatch.setattr(common, "MAX_CANDIDATE_FILE_BYTES", 2)
    with pytest.raises(CandidateError, match="candidate-file-size-limit"):
        common.snapshot_tree(single)

    aggregate = tmp_path / "aggregate"
    aggregate.mkdir()
    (aggregate / "one").write_bytes(b"12")
    (aggregate / "two").write_bytes(b"34")
    monkeypatch.setattr(common, "MAX_CANDIDATE_FILE_BYTES", 10)
    monkeypatch.setattr(common, "MAX_CANDIDATE_TOTAL_BYTES", 3)
    with pytest.raises(CandidateError, match="candidate-total-size-limit"):
        common.snapshot_tree(aggregate)


def test_zip_metadata_limits_are_enforced_before_expansion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, mode="w", compression=zipfile.ZIP_DEFLATED) as output:
        output.writestr("one", b"1")
        output.writestr("two", b"2")
    monkeypatch.setattr(common, "MAX_ARCHIVE_MEMBERS", 1)

    with pytest.raises(CandidateError, match="archive-member-count-limit"):
        common.verify_archive("hostile.zip", archive.getvalue())

    monkeypatch.setattr(common, "MAX_ARCHIVE_MEMBERS", 10)
    monkeypatch.setattr(common, "MAX_ARCHIVE_CENTRAL_DIRECTORY_BYTES", 1)
    with pytest.raises(CandidateError, match="archive-central-directory-size-limit"):
        common.verify_archive("hostile.zip", archive.getvalue())


def test_archive_single_and_aggregate_expanded_size_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(common, "MAX_ARCHIVE_MEMBER_BYTES", 2)
    with pytest.raises(CandidateError, match="archive-member-size-limit"):
        common.verify_archive("hostile.tar.gz", _tar_gz({"large": b"123"}))

    archive = io.BytesIO()
    with zipfile.ZipFile(archive, mode="w", compression=zipfile.ZIP_DEFLATED) as output:
        output.writestr("one", b"12")
        output.writestr("two", b"34")
    monkeypatch.setattr(common, "MAX_ARCHIVE_MEMBER_BYTES", 10)
    monkeypatch.setattr(common, "MAX_ARCHIVE_EXPANDED_BYTES", 3)
    with pytest.raises(CandidateError, match="archive-expanded-size-limit"):
        common.verify_archive("hostile.zip", archive.getvalue())


def test_all_archive_aggregate_expansion_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    def zipped(name: str) -> bytes:
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, mode="w", compression=zipfile.ZIP_DEFLATED) as output:
            output.writestr(name, b"12")
        return archive.getvalue()

    monkeypatch.setattr(common, "MAX_ALL_ARCHIVE_EXPANDED_BYTES", 3)
    with pytest.raises(CandidateError, match="archive-aggregate-expanded-size-limit"):
        common.verify_archives({"one.zip": zipped("one"), "two.zip": zipped("two")})
