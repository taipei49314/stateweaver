"""Clean-wheel qualification for the public M0 contracts surface."""

from __future__ import annotations

import hashlib
import importlib
import json
import platform
import re
import sys
from collections.abc import Mapping
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path, PurePosixPath
from typing import Final

from stateweaver.replay import canonical_sha256

from ._io import EvidenceInputError, atomic_json, canonical_json_bytes

PACKAGE_INSTALL_QUALIFICATION_PATH: Final = "qualification/m0/package-install.json"
_SCHEMA_VERSION: Final = "stateweaver-package-install-qualification-v1"
_PRODUCER_COMMAND: Final = "stateweaver foundation qualify-package-install"
_DISTRIBUTION_NAME: Final = "stateweaver-contracts"
_PUBLIC_FAMILIES: Final = (
    ("scope", ("ScopeManifest",)),
    ("action", ("ActionEnvelope",)),
    ("security-state-ir", ("Entity", "Fact", "Relation")),
    ("transition", ("TransitionFragment",)),
    ("world", ("WorldManifest",)),
    ("oracle", ("OracleResult",)),
)
_SYMBOL_MODULES: Final = {
    "ScopeManifest": "stateweaver.contracts.scope",
    "ActionEnvelope": "stateweaver.contracts.actions",
    "Entity": "stateweaver.contracts.state_ir",
    "Fact": "stateweaver.contracts.state_ir",
    "Relation": "stateweaver.contracts.state_ir",
    "TransitionFragment": "stateweaver.contracts.state_ir",
    "WorldManifest": "stateweaver.contracts.worlds",
    "OracleResult": "stateweaver.contracts.oracles",
}
_SHA256_RE: Final = re.compile(r"sha256:[0-9a-f]{64}")
_PYTHON_VERSION_RE: Final = re.compile(r"3\.(?P<minor>[0-9]+)\.(?P<patch>[0-9]+)")


class PackageInstallQualificationError(EvidenceInputError):
    """Raised without exposing environment paths or untrusted receipt values."""


def _error(message: str) -> PackageInstallQualificationError:
    return PackageInstallQualificationError(f"package install qualification {message}")


def _mapping(value: object, message: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise _error(message)
    return value


def _digest_text(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _safe_relative_path(value: object, *, site_packages: bool = False) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise _error("receipt path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or "." in path.parts or ".." in path.parts:
        raise _error("receipt path is unsafe")
    if site_packages and "site-packages" not in tuple(part.lower() for part in path.parts):
        raise _error("receipt is not rooted in site-packages")
    return path


def validate_package_install_receipt(
    value: Mapping[str, object], *, expected_repository_marker: str
) -> dict[str, object]:
    """Validate a transported clean-wheel receipt and return canonical JSON data."""

    try:
        normalized = json.loads(canonical_json_bytes(value))
    except (EvidenceInputError, json.JSONDecodeError, UnicodeDecodeError, ValueError):
        raise _error("receipt is not canonical JSON data") from None
    receipt = _mapping(normalized, "receipt is not an object")
    if set(receipt) != {
        "all_symbols_exported",
        "families",
        "installation",
        "producer_command",
        "public_all_sha256",
        "python",
        "repository_marker",
        "requirement_id",
        "schema_version",
        "source_root_excluded",
    }:
        raise _error("receipt schema is invalid")
    marker = receipt.get("repository_marker")
    if (
        receipt.get("schema_version") != _SCHEMA_VERSION
        or receipt.get("requirement_id") != "M0-C07"
        or receipt.get("producer_command") != _PRODUCER_COMMAND
        or not isinstance(marker, str)
        or not 1 <= len(marker) <= 128
        or marker != expected_repository_marker
        or receipt.get("source_root_excluded") is not True
        or receipt.get("all_symbols_exported") is not True
        or not _is_sha256(receipt.get("public_all_sha256"))
    ):
        raise _error("receipt claims do not match the accepted run")

    python = _mapping(receipt.get("python"), "Python observation is invalid")
    version = python.get("version")
    version_match = _PYTHON_VERSION_RE.fullmatch(version) if isinstance(version, str) else None
    if (
        set(python) != {"implementation", "version", "virtual_environment"}
        or python.get("implementation") != "CPython"
        or version_match is None
        or int(version_match.group("minor")) < 12
        or python.get("virtual_environment") is not True
    ):
        raise _error("Python observation is not an isolated supported runtime")

    installation = _mapping(receipt.get("installation"), "installation observation is invalid")
    if set(installation) != {
        "distribution",
        "editable",
        "installed_from_wheel",
        "metadata_sha256",
        "module_relative_path",
        "record_sha256",
        "site_packages_relative_path",
        "version",
        "wheel_sha256",
    }:
        raise _error("installation observation schema is invalid")
    site_path = _safe_relative_path(
        installation.get("site_packages_relative_path"), site_packages=True
    )
    module_path = _safe_relative_path(installation.get("module_relative_path"), site_packages=True)
    if (
        installation.get("distribution") != _DISTRIBUTION_NAME
        or installation.get("version") != "0.1.0"
        or installation.get("editable") is not False
        or installation.get("installed_from_wheel") is not True
        or module_path.parts[: len(site_path.parts)] != site_path.parts
        or module_path.parts[-3:] != ("stateweaver", "contracts", "__init__.py")
        or any(
            not _is_sha256(installation.get(field))
            for field in ("metadata_sha256", "record_sha256", "wheel_sha256")
        )
    ):
        raise _error("installation is not a closed non-editable wheel installation")

    families = receipt.get("families")
    expected_families = [
        {"family": family, "symbols": list(symbols)} for family, symbols in _PUBLIC_FAMILIES
    ]
    if families != expected_families:
        raise _error("public contract families are incomplete")
    return dict(receipt)


def create_package_install_receipt(
    *, repository_marker: str, source_root: Path
) -> dict[str, object]:
    """Inspect the current interpreter and qualify only a clean wheel installation."""

    if not isinstance(repository_marker, str) or not 1 <= len(repository_marker) <= 128:
        raise _error("repository marker is invalid")
    try:
        resolved_source = source_root.resolve(strict=True)
        prefix = Path(sys.prefix).resolve(strict=True)
    except OSError:
        raise _error("runtime roots are unreadable") from None
    if not resolved_source.is_dir() or sys.prefix == sys.base_prefix:
        raise _error("runtime is not an isolated virtual environment")

    try:
        contracts = importlib.import_module("stateweaver.contracts")
        installed = distribution(_DISTRIBUTION_NAME)
    except (ImportError, PackageNotFoundError):
        raise _error("contracts distribution is not installed") from None
    module_file_value = getattr(contracts, "__file__", None)
    if not isinstance(module_file_value, str):
        raise _error("contracts public module has no installed file")
    try:
        module_file = Path(module_file_value).resolve(strict=True)
        site_root = Path(str(installed.locate_file(""))).resolve(strict=True)
        module_relative = module_file.relative_to(prefix)
        site_relative = site_root.relative_to(prefix)
    except (OSError, ValueError):
        raise _error("contracts distribution is outside the isolated environment") from None
    if "site-packages" not in tuple(part.lower() for part in site_relative.parts):
        raise _error("contracts distribution is not installed in site-packages")

    observed_paths: list[Path] = [module_file, site_root]
    for entry in sys.path:
        try:
            observed_paths.append(Path(entry or Path.cwd()).resolve(strict=False))
        except OSError:
            raise _error("interpreter search path is unreadable") from None
    if any(path == resolved_source or resolved_source in path.parents for path in observed_paths):
        raise _error("source tree remains on the interpreter search path")

    metadata = installed.read_text("METADATA")
    wheel = installed.read_text("WHEEL")
    record = installed.read_text("RECORD")
    if not metadata or not wheel or not record:
        raise _error("wheel metadata is incomplete")
    direct_url = installed.read_text("direct_url.json")
    editable = False
    if direct_url is not None:
        try:
            direct_payload = _mapping(json.loads(direct_url), "direct URL metadata is invalid")
        except (json.JSONDecodeError, ValueError):
            raise _error("direct URL metadata is invalid") from None
        directory = direct_payload.get("dir_info")
        if directory is not None:
            editable = (
                _mapping(directory, "direct URL directory metadata is invalid").get("editable")
                is True
            )
    if editable:
        raise _error("editable installation is not qualified")

    exports = getattr(contracts, "__all__", None)
    if not isinstance(exports, list) or any(not isinstance(item, str) for item in exports):
        raise _error("contracts public export list is invalid")
    exported_names = set(exports)
    for _, symbols in _PUBLIC_FAMILIES:
        for symbol in symbols:
            exported = getattr(contracts, symbol, None)
            if (
                symbol not in exported_names
                or getattr(exported, "__module__", None) != _SYMBOL_MODULES[symbol]
            ):
                raise _error("public contract families are incomplete")

    receipt: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "requirement_id": "M0-C07",
        "repository_marker": repository_marker,
        "producer_command": _PRODUCER_COMMAND,
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
            "virtual_environment": True,
        },
        "source_root_excluded": True,
        "installation": {
            "distribution": _DISTRIBUTION_NAME,
            "version": installed.version,
            "editable": False,
            "installed_from_wheel": True,
            "site_packages_relative_path": site_relative.as_posix(),
            "module_relative_path": module_relative.as_posix(),
            "metadata_sha256": _digest_text(metadata),
            "wheel_sha256": _digest_text(wheel),
            "record_sha256": _digest_text(record),
        },
        "families": [
            {"family": family, "symbols": list(symbols)} for family, symbols in _PUBLIC_FAMILIES
        ],
        "public_all_sha256": canonical_sha256(sorted(exported_names)),
        "all_symbols_exported": True,
    }
    return validate_package_install_receipt(receipt, expected_repository_marker=repository_marker)


def write_package_install_receipt(
    *, output: Path, repository_marker: str, source_root: Path
) -> dict[str, object]:
    """Create and atomically retain one package-install receipt."""

    receipt = create_package_install_receipt(
        repository_marker=repository_marker,
        source_root=source_root,
    )
    atomic_json(output, receipt)
    return receipt


def load_package_install_receipt(
    path: Path, *, expected_repository_marker: str
) -> dict[str, object]:
    """Read one bounded canonical receipt without following a final symlink."""

    if path.is_symlink():
        raise _error("receipt must not be a symlink")
    try:
        size = path.stat().st_size
        content = path.read_bytes()
    except OSError:
        raise _error("receipt is unreadable") from None
    if size != len(content) or not 1 <= size <= 64 * 1024:
        raise _error("receipt size is invalid")
    try:
        parsed = json.loads(content.decode("utf-8"))
        if canonical_json_bytes(parsed) != content:
            raise _error("receipt encoding is not canonical")
        mapping = _mapping(parsed, "receipt is not an object")
    except (UnicodeDecodeError, json.JSONDecodeError, EvidenceInputError, ValueError):
        raise _error("receipt is invalid JSON") from None
    return validate_package_install_receipt(
        mapping,
        expected_repository_marker=expected_repository_marker,
    )
