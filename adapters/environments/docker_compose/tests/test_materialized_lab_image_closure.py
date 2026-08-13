from __future__ import annotations

import re
import shutil
import subprocess
import tomllib
from pathlib import Path

_REPOSITORY = Path(__file__).resolve().parents[4]
_IMAGE_DIRECTORY = (
    _REPOSITORY
    / "adapters"
    / "environments"
    / "docker_compose"
    / "src"
    / "stateweaver"
    / "adapters"
    / "docker_compose"
)
_DOCKERFILE = _IMAGE_DIRECTORY / "MaterializedLabDockerfile"
_REQUIREMENTS = _IMAGE_DIRECTORY / "materialized_lab_requirements.txt"
_EXPECTED_PACKAGES = {
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
}
_HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})(?:\s|$)")


def _logical_requirements() -> tuple[str, ...]:
    logical: list[str] = []
    pending = ""
    for raw in _REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        pending += line[:-1].rstrip() + " " if line.endswith("\\") else line
        if not line.endswith("\\"):
            logical.append(pending.strip())
            pending = ""
    assert not pending
    return tuple(logical)


def test_materialized_lab_requirements_are_the_exact_locked_workspace_export() -> None:
    uv = shutil.which("uv")
    assert uv is not None, "uv is required to validate the checked-in lock export"
    exported = subprocess.run(
        (
            uv,
            "export",
            "--locked",
            "--no-dev",
            "--package",
            "stateweaver-lab-multitenant-saas",
            "--package",
            "stateweaver-contracts",
            "--package",
            "stateweaver-policy",
            "--package",
            "stateweaver-adapter-docker-compose",
            "--no-emit-workspace",
            "--no-annotate",
            "--no-header",
            "--format",
            "requirements.txt",
            "--quiet",
        ),
        cwd=_REPOSITORY,
        check=True,
        capture_output=True,
        encoding="utf-8",
    ).stdout.replace("\r\n", "\n")

    assert _REQUIREMENTS.read_text(encoding="utf-8").replace("\r\n", "\n") == exported


def test_materialized_lab_requirements_are_closed_and_alpine_installable() -> None:
    requirements = _logical_requirements()
    names = {requirement.split("==", 1)[0] for requirement in requirements}
    assert names == _EXPECTED_PACKAGES
    assert all("==" in requirement and _HASH.search(requirement) for requirement in requirements)

    raw = _REQUIREMENTS.read_text(encoding="utf-8").lower()
    assert all(
        forbidden not in raw for forbidden in ("-e ", "--editable", "file:", "../", "stateweaver-")
    )

    with (_REPOSITORY / "uv.lock").open("rb") as stream:
        locked = tomllib.load(stream)["package"]
    locked_by_name = {package["name"]: package for package in locked}
    for requirement in requirements:
        name, tail = requirement.split("==", 1)
        version = tail.split(maxsplit=1)[0]
        package = locked_by_name[name]
        assert package["version"] == version
        lock_hashes = {
            artifact["hash"].removeprefix("sha256:")
            for artifact in [*package.get("wheels", []), package["sdist"]]
        }
        assert set(_HASH.findall(requirement)) <= lock_hashes

    core = locked_by_name["pydantic-core"]
    requirement = next(item for item in requirements if item.startswith("pydantic-core=="))
    requirement_hashes = set(_HASH.findall(requirement))
    for architecture in ("aarch64", "x86_64"):
        wheel = next(
            item
            for item in core["wheels"]
            if f"cp313-cp313-musllinux_1_1_{architecture}.whl" in item["url"]
        )
        assert wheel["hash"].removeprefix("sha256:") in requirement_hashes


def test_materialized_lab_dockerfile_installs_only_the_hashed_binary_closure() -> None:
    dockerfile = _DOCKERFILE.read_text(encoding="utf-8")
    for option in ("--require-hashes", "--no-deps", "--only-binary=:all:"):
        assert option in dockerfile
    for workspace_source in (
        "packages/contracts/src/stateweaver/contracts",
        "packages/policy/src/stateweaver/policy",
        "labs/multitenant-saas/stateweaver_lab",
        "materialized_lab_runtime.py",
    ):
        assert workspace_source in dockerfile
    assert "pip install --no-cache-dir" not in dockerfile
    assert '"fastapi==' not in dockerfile
    assert "COPY labs/multitenant-saas /opt/stateweaver/lab" not in dockerfile
    assert "src/stateweaver/adapters /opt/stateweaver/adapter" not in dockerfile
