"""Derive and verify an artifact-only Python runtime closure from ``uv.lock``."""

from __future__ import annotations

import argparse
import ast
import io
import re
import sys
import tarfile
import tomllib
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final
from urllib.parse import unquote, urlsplit

from .common import (
    MAX_LOCKFILE_BYTES,
    CandidateError,
    atomic_write,
    canonical_json_bytes,
    sha256_bytes,
)

RUNTIME_REQUIREMENTS_PATH: Final = "payload/metadata/runtime-requirements.txt"
VENDOR_WHEEL_PREFIX: Final = "payload/vendor/python/"
WORKSPACE_DISTRIBUTION_PREFIX: Final = "payload/python/"
EXPECTED_WORKSPACE_DISTRIBUTIONS: Final = 18
RUNTIME_REQUIREMENTS_SCHEMA: Final = "stateweaver-runtime-requirements-v1"
_HASH_RE: Final = re.compile(r"^sha256:([0-9a-f]{64})$")
_NAME_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
_VERSION_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.!+_-]{0,199}$")
_PYTHON_FULL_VERSION_RE: Final = re.compile(r"^3\.13\.([0-9]+)$")
_MANYLINUX_RE: Final = re.compile(r"^manylinux_2_([0-9]+)_x86_64$")
_MAX_TOML_LINES: Final = 200_000
_MAX_TOML_LINE_BYTES: Final = 64 * 1024
_MAX_TOML_TOKENS: Final = 500_000
_MAX_TOML_TABLES: Final = 20_000
_MAX_TOML_DEPTH: Final = 64
_MAX_TOML_KEY_BYTES: Final = 1024
_MAX_TOML_STRING_BYTES: Final = 2 * 1024 * 1024
_MAX_TOML_NUMBER_BYTES: Final = 1024


@dataclass(frozen=True)
class RuntimeTarget:
    """The one candidate install target supported by this workflow."""

    python_full_version: str

    @classmethod
    def create(cls, python_full_version: str) -> RuntimeTarget:
        if not _PYTHON_FULL_VERSION_RE.fullmatch(python_full_version):
            raise CandidateError("runtime-target-invalid")
        return cls(python_full_version=python_full_version)

    @property
    def python_version(self) -> str:
        return "3.13"

    def marker_environment(self) -> dict[str, str]:
        return {
            "extra": "",
            "implementation_name": "cpython",
            "implementation_version": self.python_full_version,
            "os_name": "posix",
            "platform_machine": "x86_64",
            "platform_python_implementation": "CPython",
            "platform_release": "",
            "platform_system": "Linux",
            "platform_version": "",
            "python_full_version": self.python_full_version,
            "python_version": self.python_version,
            "sys_platform": "linux",
        }

    def as_dict(self) -> dict[str, str]:
        return {
            "implementation": "cpython",
            "os_name": "posix",
            "platform_machine": "x86_64",
            "platform_system": "Linux",
            "python_full_version": self.python_full_version,
            "python_version": self.python_version,
            "sys_platform": "linux",
        }


@dataclass(frozen=True)
class LockedDependency:
    name: str
    marker: str | None


@dataclass(frozen=True)
class LockedWheel:
    filename: str
    sha256: str


@dataclass(frozen=True)
class LockedPackage:
    name: str
    version: str
    source_kind: str
    dependencies: tuple[LockedDependency, ...]
    wheels: tuple[LockedWheel, ...]


@dataclass(frozen=True)
class RuntimeLock:
    target: RuntimeTarget
    members: tuple[str, ...]
    workspace: tuple[LockedPackage, ...]
    runtime: tuple[LockedPackage, ...]


@dataclass(frozen=True)
class DistributionIdentity:
    name: str
    version: str


@dataclass(frozen=True)
class Inventory:
    runtime_wheels: int
    workspace_sdists: int
    workspace_wheels: int
    vendored_wheels: tuple[tuple[str, bytes], ...]

    def as_dict(self) -> dict[str, int]:
        return {
            "runtime_wheels": self.runtime_wheels,
            "workspace_sdists": self.workspace_sdists,
            "workspace_wheels": self.workspace_wheels,
        }


def canonicalize_name(name: str) -> str:
    if not _NAME_RE.fullmatch(name):
        raise CandidateError("python-lockfile-invalid")
    return re.sub(r"[-_.]+", "-", name).lower()


def _version_tuple(value: str) -> tuple[int, ...]:
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", value):
        raise CandidateError("python-lock-marker-unsupported")
    return tuple(int(part) for part in value.split("."))


def _compare_values(left: str, operator: ast.cmpop, right: str, *, versioned: bool) -> bool:
    if isinstance(operator, ast.In):
        return left in right
    if isinstance(operator, ast.NotIn):
        return left not in right
    if versioned:
        return _compare_ordered(_version_tuple(left), operator, _version_tuple(right))
    return _compare_ordered(left, operator, right)


def _compare_ordered(
    left: str | tuple[int, ...], operator: ast.cmpop, right: str | tuple[int, ...]
) -> bool:
    if type(left) is not type(right):
        raise CandidateError("python-lock-marker-unsupported")
    if isinstance(operator, ast.Eq):
        return left == right
    if isinstance(operator, ast.NotEq):
        return left != right
    if isinstance(operator, ast.Lt):
        return left < right  # type: ignore[operator]
    if isinstance(operator, ast.LtE):
        return left <= right  # type: ignore[operator]
    if isinstance(operator, ast.Gt):
        return left > right  # type: ignore[operator]
    if isinstance(operator, ast.GtE):
        return left >= right  # type: ignore[operator]
    raise CandidateError("python-lock-marker-unsupported")


def _marker_operand(node: ast.expr, environment: Mapping[str, str]) -> tuple[str, bool]:
    if isinstance(node, ast.Name):
        if node.id not in environment:
            raise CandidateError("python-lock-marker-unsupported")
        return environment[node.id], node.id in {
            "implementation_version",
            "python_full_version",
            "python_version",
        }
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value, False
    raise CandidateError("python-lock-marker-unsupported")


def _evaluate_marker_node(node: ast.expr, environment: Mapping[str, str]) -> bool:
    if isinstance(node, ast.BoolOp):
        values = [_evaluate_marker_node(value, environment) for value in node.values]
        if isinstance(node.op, ast.And):
            return all(values)
        if isinstance(node.op, ast.Or):
            return any(values)
        raise CandidateError("python-lock-marker-unsupported")
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not _evaluate_marker_node(node.operand, environment)
    if isinstance(node, ast.Compare):
        left, left_versioned = _marker_operand(node.left, environment)
        result = True
        for operator, comparator in zip(node.ops, node.comparators, strict=True):
            right, right_versioned = _marker_operand(comparator, environment)
            result = result and _compare_values(
                left,
                operator,
                right,
                versioned=left_versioned or right_versioned,
            )
            left, left_versioned = right, right_versioned
        return result
    raise CandidateError("python-lock-marker-unsupported")


def evaluate_marker(marker: str, target: RuntimeTarget) -> bool:
    if not marker or len(marker) > 4_096:
        raise CandidateError("python-lock-marker-unsupported")
    try:
        parsed = ast.parse(marker, mode="eval")
    except (SyntaxError, ValueError):
        raise CandidateError("python-lock-marker-unsupported") from None
    return _evaluate_marker_node(parsed.body, target.marker_environment())


def _locked_wheels(raw: object, *, package_name: str) -> tuple[LockedWheel, ...]:
    if not isinstance(raw, list) or not raw:
        raise CandidateError("python-lockfile-invalid")
    wheels: dict[str, LockedWheel] = {}
    for item in raw:
        if not isinstance(item, dict):
            raise CandidateError("python-lockfile-invalid")
        url = item.get("url")
        digest = item.get("hash")
        if not isinstance(url, str) or not isinstance(digest, str):
            raise CandidateError("python-lockfile-invalid")
        match = _HASH_RE.fullmatch(digest)
        parsed = urlsplit(url)
        filename = unquote(PurePosixPath(parsed.path).name)
        if (
            match is None
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or not filename.endswith(".whl")
            or "/" in filename
            or "\\" in filename
            or len(filename) > 512
        ):
            raise CandidateError("python-lockfile-invalid")
        wheel = LockedWheel(filename=filename, sha256=match.group(1))
        previous = wheels.get(filename)
        if previous is not None and previous != wheel:
            raise CandidateError("python-lockfile-invalid")
        wheels[filename] = wheel
    result = tuple(sorted(wheels.values(), key=lambda wheel: wheel.filename))
    if not result or any(package_name not in canonicalize_name(wheel.filename) for wheel in result):
        raise CandidateError("python-lockfile-invalid")
    return result


def _dependencies(raw: object) -> tuple[LockedDependency, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise CandidateError("python-lockfile-invalid")
    dependencies: list[LockedDependency] = []
    for item in raw:
        if not isinstance(item, dict) or not set(item) <= {"marker", "name"}:
            raise CandidateError("python-lockfile-invalid")
        name = item.get("name")
        marker = item.get("marker")
        if not isinstance(name, str) or (marker is not None and not isinstance(marker, str)):
            raise CandidateError("python-lockfile-invalid")
        dependencies.append(LockedDependency(canonicalize_name(name), marker))
    return tuple(dependencies)


def _requires_python_allows(value: object, target: RuntimeTarget) -> bool:
    if not isinstance(value, str) or not value:
        raise CandidateError("python-lockfile-invalid")
    target_version = _version_tuple(target.python_full_version)
    for raw_clause in value.split(","):
        match = re.fullmatch(r"\s*(==|!=|<=|>=|<|>)\s*([0-9]+(?:\.[0-9]+)*)\s*", raw_clause)
        if match is None:
            raise CandidateError("python-lockfile-invalid")
        operator = match.group(1)
        required = _version_tuple(match.group(2))
        comparisons = {
            "==": target_version == required,
            "!=": target_version != required,
            "<": target_version < required,
            "<=": target_version <= required,
            ">": target_version > required,
            ">=": target_version >= required,
        }
        if not comparisons[operator]:
            return False
    return True


def preflight_toml_structure(content: bytes) -> None:
    """Apply allocation bounds before ``tomllib`` constructs the lock object graph."""

    if len(content) > MAX_LOCKFILE_BYTES:
        raise CandidateError("python-lockfile-invalid")
    lines = content.splitlines()
    if len(lines) > _MAX_TOML_LINES:
        raise CandidateError("python-lockfile-invalid")
    table_count = 0
    token_count = 0
    depth = 0
    index = 0
    in_string: int | None = None
    string_start = 0
    while index < len(content):
        value = content[index]
        if in_string is not None:
            if value == in_string and (in_string == ord("'") or content[index - 1] != ord("\\")):
                if index - string_start > _MAX_TOML_STRING_BYTES:
                    raise CandidateError("python-lockfile-invalid")
                in_string = None
            index += 1
            continue
        if value in (ord('"'), ord("'")):
            in_string = value
            string_start = index
            token_count += 1
            index += 1
            continue
        if value == ord("#"):
            newline = content.find(b"\n", index)
            index = len(content) if newline < 0 else newline + 1
            continue
        if value in (ord("["), ord("{")):
            depth += 1
            token_count += 1
            if depth > _MAX_TOML_DEPTH:
                raise CandidateError("python-lockfile-invalid")
            index += 1
            continue
        if value in (ord("]"), ord("}")):
            depth -= 1
            if depth < 0:
                raise CandidateError("python-lockfile-invalid")
            index += 1
            continue
        if value in b"+-0123456789":
            start = index
            index += 1
            while index < len(content) and content[index] in b"0123456789_+-.eEoxabcdefABCDEF":
                index += 1
            token_count += 1
            if index - start > _MAX_TOML_NUMBER_BYTES:
                raise CandidateError("python-lockfile-invalid")
            continue
        if value not in b" \t\r\n,=":
            token_count += 1
            while index < len(content) and content[index] not in b" \t\r\n,=[]{}#":
                index += 1
            continue
        index += 1
    if in_string is not None or depth != 0 or token_count > _MAX_TOML_TOKENS:
        raise CandidateError("python-lockfile-invalid")
    for line in lines:
        if len(line) > _MAX_TOML_LINE_BYTES:
            raise CandidateError("python-lockfile-invalid")
        stripped = line.lstrip()
        if stripped.startswith(b"["):
            table_count += 1
            if table_count > _MAX_TOML_TABLES or len(stripped) > _MAX_TOML_KEY_BYTES:
                raise CandidateError("python-lockfile-invalid")
        elif b"=" in stripped:
            key = stripped.split(b"=", 1)[0].strip()
            if not key or len(key) > _MAX_TOML_KEY_BYTES:
                raise CandidateError("python-lockfile-invalid")


def parse_runtime_lock(content: bytes, target: RuntimeTarget) -> RuntimeLock:
    """Resolve the no-dev registry closure rooted at every editable workspace package."""

    preflight_toml_structure(content)
    try:
        parsed = tomllib.loads(content.decode("utf-8"))
    except (
        UnicodeDecodeError,
        tomllib.TOMLDecodeError,
        MemoryError,
        OverflowError,
        RecursionError,
        ValueError,
    ):
        raise CandidateError("python-lockfile-invalid") from None
    if (
        not isinstance(parsed, dict)
        or parsed.get("version") != 1
        or parsed.get("revision") != 3
        or not _requires_python_allows(parsed.get("requires-python"), target)
    ):
        raise CandidateError("python-lockfile-invalid")
    manifest = parsed.get("manifest")
    raw_packages = parsed.get("package")
    if not isinstance(manifest, dict) or not isinstance(raw_packages, list) or not raw_packages:
        raise CandidateError("python-lockfile-invalid")
    raw_members = manifest.get("members")
    if not isinstance(raw_members, list) or not all(isinstance(item, str) for item in raw_members):
        raise CandidateError("python-lockfile-invalid")
    members = tuple(canonicalize_name(item) for item in raw_members)
    if members != tuple(sorted(set(members))):
        raise CandidateError("python-lockfile-invalid")

    packages: dict[str, LockedPackage] = {}
    for raw_package in raw_packages:
        if not isinstance(raw_package, dict):
            raise CandidateError("python-lockfile-invalid")
        raw_name = raw_package.get("name")
        version = raw_package.get("version")
        source = raw_package.get("source")
        if (
            not isinstance(raw_name, str)
            or not isinstance(version, str)
            or not _VERSION_RE.fullmatch(version)
            or not isinstance(source, dict)
            or len(source) != 1
        ):
            raise CandidateError("python-lockfile-invalid")
        name = canonicalize_name(raw_name)
        source_kind = next(iter(source))
        source_value = source[source_kind]
        if source_kind not in {"editable", "registry", "virtual"} or not isinstance(
            source_value, str
        ):
            raise CandidateError("python-lockfile-invalid")
        if source_kind == "registry" and source_value != "https://pypi.org/simple":
            raise CandidateError("python-lockfile-invalid")
        wheels = (
            _locked_wheels(raw_package.get("wheels"), package_name=name)
            if source_kind == "registry"
            else ()
        )
        package = LockedPackage(
            name=name,
            version=version,
            source_kind=source_kind,
            dependencies=_dependencies(raw_package.get("dependencies")),
            wheels=wheels,
        )
        if name in packages:
            raise CandidateError("python-lock-package-ambiguity")
        packages[name] = package

    workspace = tuple(
        sorted(
            (package for package in packages.values() if package.source_kind == "editable"),
            key=lambda package: package.name,
        )
    )
    if len(workspace) != EXPECTED_WORKSPACE_DISTRIBUTIONS:
        raise CandidateError("workspace-lock-inventory-invalid")
    declared_members = tuple(
        sorted(
            package.name
            for package in packages.values()
            if package.source_kind in {"editable", "virtual"}
        )
    )
    if members != declared_members:
        raise CandidateError("workspace-lock-members-invalid")

    pending = [package.name for package in workspace]
    visited: set[str] = set()
    registry: dict[str, LockedPackage] = {}
    while pending:
        name = pending.pop()
        if name in visited:
            continue
        visited.add(name)
        current_package = packages.get(name)
        if current_package is None:
            raise CandidateError("python-lock-dependency-missing")
        if current_package.source_kind == "registry":
            registry[name] = current_package
        for dependency in current_package.dependencies:
            if dependency.marker is not None and not evaluate_marker(dependency.marker, target):
                continue
            if dependency.name not in packages:
                raise CandidateError("python-lock-dependency-missing")
            pending.append(dependency.name)
    runtime = tuple(sorted(registry.values(), key=lambda package: package.name))
    return RuntimeLock(target=target, members=members, workspace=workspace, runtime=runtime)


def canonical_runtime_requirements(lock: RuntimeLock) -> bytes:
    lines = [
        f"# {RUNTIME_REQUIREMENTS_SCHEMA}\n",
        (
            "# target: implementation=cpython; python_full_version="
            f"{lock.target.python_full_version}; sys_platform=linux; "
            "platform_machine=x86_64\n"
        ),
    ]
    for package in lock.runtime:
        hashes = sorted({wheel.sha256 for wheel in package.wheels})
        if not hashes:
            raise CandidateError("runtime-requirements-invalid")
        lines.append(f"{package.name}=={package.version} \\\n")
        for index, digest in enumerate(hashes):
            suffix = " \\\n" if index + 1 < len(hashes) else "\n"
            lines.append(f"    --hash=sha256:{digest}{suffix}")
    return "".join(lines).encode("utf-8")


def _metadata_identity(content: bytes, *, code: str) -> DistributionIdentity:
    if len(content) > 1024 * 1024:
        raise CandidateError(code)
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        raise CandidateError(code) from None
    names = [line.removeprefix("Name: ") for line in lines if line.startswith("Name: ")]
    versions = [line.removeprefix("Version: ") for line in lines if line.startswith("Version: ")]
    if len(names) != 1 or len(versions) != 1 or not _VERSION_RE.fullmatch(versions[0]):
        raise CandidateError(code)
    return DistributionIdentity(canonicalize_name(names[0]), versions[0])


def inspect_wheel(filename: str, content: bytes) -> DistributionIdentity:
    try:
        prefix, python_tags, abi_tags, platform_tags = filename.removesuffix(".whl").rsplit("-", 3)
        filename_name, filename_version = prefix.rsplit("-", 1)
    except ValueError:
        raise CandidateError("wheel-filename-invalid") from None
    if not filename.endswith(".whl") or filename_version != filename_version.strip():
        raise CandidateError("wheel-filename-invalid")
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            metadata_members = [
                member
                for member in archive.infolist()
                if not member.is_dir() and member.filename.endswith(".dist-info/METADATA")
            ]
            if len(metadata_members) != 1 or metadata_members[0].file_size > 1024 * 1024:
                raise CandidateError("wheel-metadata-invalid")
            metadata = archive.read(metadata_members[0])
    except CandidateError:
        raise
    except (KeyError, OSError, RuntimeError, zipfile.BadZipFile):
        raise CandidateError("wheel-metadata-invalid") from None
    identity = _metadata_identity(metadata, code="wheel-metadata-invalid")
    if (
        canonicalize_name(filename_name) != identity.name
        or filename_version != identity.version
        or not _wheel_tags_compatible(python_tags, abi_tags, platform_tags)
    ):
        raise CandidateError("wheel-identity-invalid")
    return identity


def _wheel_tags_compatible(python_tags: str, abi_tags: str, platform_tags: str) -> bool:
    python_values = python_tags.split(".")
    abi_values = abi_tags.split(".")
    platform_values = platform_tags.split(".")
    exact_python = any(value in {"cp313", "py3", "py2.py3"} for value in python_values)
    abi3_python = any(
        match is not None and int(match.group(1)) <= 13
        for value in python_values
        if (match := re.fullmatch(r"cp3([0-9]+)", value)) is not None
    )
    abi_compatible = any(
        (value == "none" and exact_python)
        or (value == "cp313" and "cp313" in python_values)
        or (value == "abi3" and abi3_python)
        for value in abi_values
    )
    platform_compatible = False
    for value in platform_values:
        if value in {
            "any",
            "linux_x86_64",
            "manylinux1_x86_64",
            "manylinux2010_x86_64",
            "manylinux2014_x86_64",
        }:
            platform_compatible = True
        else:
            match = _MANYLINUX_RE.fullmatch(value)
            if match is not None and int(match.group(1)) <= 39:
                platform_compatible = True
    return abi_compatible and platform_compatible


def inspect_sdist(filename: str, content: bytes) -> DistributionIdentity:
    if not filename.endswith((".tar.gz", ".tgz")):
        raise CandidateError("sdist-filename-invalid")
    metadata: list[bytes] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:*") as archive:
            for member in archive:
                member_path = PurePosixPath(member.name)
                if (
                    not member.isfile()
                    or member_path.name != "PKG-INFO"
                    or len(member_path.parts) != 2
                ):
                    continue
                if member.size > 1024 * 1024:
                    raise CandidateError("sdist-metadata-invalid")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise CandidateError("sdist-metadata-invalid")
                value = extracted.read(1024 * 1024 + 1)
                if len(value) != member.size:
                    raise CandidateError("sdist-metadata-invalid")
                metadata.append(value)
    except CandidateError:
        raise
    except (EOFError, OSError, tarfile.TarError):
        raise CandidateError("sdist-metadata-invalid") from None
    if len(metadata) != 1:
        raise CandidateError("sdist-metadata-invalid")
    return _metadata_identity(metadata[0], code="sdist-metadata-invalid")


def validate_inventory(
    snapshot: Mapping[str, bytes], lock: RuntimeLock, *, require_requirements: bool
) -> Inventory:
    expected_workspace = {package.name: package.version for package in lock.workspace}
    workspace_wheels: dict[str, str] = {}
    workspace_sdists: dict[str, str] = {}
    vendor_files: list[tuple[str, bytes]] = []
    for path, content in snapshot.items():
        if path.startswith(WORKSPACE_DISTRIBUTION_PREFIX):
            filename = path.removeprefix(WORKSPACE_DISTRIBUTION_PREFIX)
            if not filename or "/" in filename:
                raise CandidateError("workspace-distribution-layout-invalid")
            if filename.endswith(".whl"):
                identity = inspect_wheel(filename, content)
                target = workspace_wheels
            elif filename.endswith((".tar.gz", ".tgz")):
                identity = inspect_sdist(filename, content)
                target = workspace_sdists
            else:
                raise CandidateError("workspace-distribution-layout-invalid")
            if identity.name in target:
                raise CandidateError("workspace-distribution-duplicate")
            target[identity.name] = identity.version
        elif path.startswith("payload/vendor/"):
            filename = path.removeprefix(VENDOR_WHEEL_PREFIX)
            if not path.startswith(VENDOR_WHEEL_PREFIX) or not filename or "/" in filename:
                raise CandidateError("runtime-vendor-layout-invalid")
            vendor_files.append((path, content))

    if workspace_wheels != expected_workspace or workspace_sdists != expected_workspace:
        raise CandidateError("workspace-distribution-inventory-invalid")

    expected_runtime = {package.name: package for package in lock.runtime}
    seen_runtime: dict[str, str] = {}
    for path, content in sorted(vendor_files):
        filename = path.removeprefix(VENDOR_WHEEL_PREFIX)
        identity = inspect_wheel(filename, content)
        package = expected_runtime.get(identity.name)
        digest = sha256_bytes(content)
        if package is None or identity.version != package.version:
            raise CandidateError("runtime-vendor-identity-invalid")
        allowed = {wheel.filename: wheel.sha256 for wheel in package.wheels}
        if allowed.get(filename) != digest:
            raise CandidateError("runtime-vendor-lock-mismatch")
        if identity.name in seen_runtime:
            raise CandidateError("runtime-vendor-duplicate")
        seen_runtime[identity.name] = digest
    if set(seen_runtime) != set(expected_runtime):
        raise CandidateError("runtime-vendor-inventory-invalid")

    expected_requirements = canonical_runtime_requirements(lock)
    requirements = snapshot.get(RUNTIME_REQUIREMENTS_PATH)
    if require_requirements and requirements != expected_requirements:
        raise CandidateError("runtime-requirements-lock-mismatch")
    if not require_requirements and requirements is not None:
        raise CandidateError("runtime-requirements-preexisting")
    return Inventory(
        runtime_wheels=len(seen_runtime),
        workspace_sdists=len(workspace_sdists),
        workspace_wheels=len(workspace_wheels),
        vendored_wheels=tuple(sorted(vendor_files)),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lockfile", type=Path)
    parser.add_argument("--python-full-version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        content = arguments.lockfile.read_bytes()
        target = RuntimeTarget.create(arguments.python_full_version)
        lock = parse_runtime_lock(content, target)
        requirements = canonical_runtime_requirements(lock)
        atomic_write(arguments.output, requirements)
    except (CandidateError, OSError) as error:
        code = error.code if isinstance(error, CandidateError) else "runtime-lock-read-failed"
        print(canonical_json_bytes({"error": code, "valid": False}).decode(), end="")
        return 1
    print(
        canonical_json_bytes(
            {
                "runtime_packages": len(lock.runtime),
                "target": target.as_dict(),
                "valid": True,
                "workspace_packages": len(lock.workspace),
            }
        ).decode(),
        end="",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
