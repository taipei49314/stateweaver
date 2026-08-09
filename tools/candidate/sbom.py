"""Deterministic SPDX 2.3 SBOM derivation from the committed Python and Node lockfiles."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import tomllib
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from .common import (
    MAX_LOCKFILE_BYTES,
    CandidateError,
    canonical_json_bytes,
    preflight_json_structure,
    sha256_bytes,
)
from .runtime import canonicalize_name, inspect_wheel, preflight_toml_structure

_SPDX_SAFE_RE = re.compile(r"[^A-Za-z0-9.-]+")


def _spdx_id(ecosystem: str, name: str, version: str) -> str:
    semantic = f"{ecosystem}\0{name}\0{version}".encode()
    suffix = hashlib.sha256(semantic).hexdigest()[:12]
    safe = _SPDX_SAFE_RE.sub("-", f"{ecosystem}-{name}-{version}").strip("-.")
    return f"SPDXRef-Package-{safe[:120]}-{suffix}"


def _spdx_file_id(path: str) -> str:
    suffix = hashlib.sha256(path.encode()).hexdigest()[:16]
    safe = _SPDX_SAFE_RE.sub("-", path).strip("-.")
    return f"SPDXRef-File-{safe[:120]}-{suffix}"


def _python_packages(content: bytes) -> list[dict[str, object]]:
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
    packages = parsed.get("package")
    if not isinstance(packages, list) or not packages:
        raise CandidateError("python-lockfile-invalid")
    result: list[dict[str, object]] = []
    for item in packages:
        if not isinstance(item, dict):
            raise CandidateError("python-lockfile-invalid")
        name = item.get("name")
        version = item.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise CandidateError("python-lockfile-invalid")
        result.append(_package("pypi", name, version, license_value="NOASSERTION"))
    return result


def _npm_name(path: str, item: dict[str, Any]) -> str:
    declared = item.get("name")
    if isinstance(declared, str) and declared:
        return declared
    if "node_modules/" not in path:
        raise CandidateError("node-lockfile-invalid")
    name = path.rsplit("node_modules/", 1)[1]
    if not name or name.endswith("/node_modules"):
        raise CandidateError("node-lockfile-invalid")
    return name


def _node_packages(content: bytes) -> list[dict[str, object]]:
    def reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise CandidateError("node-lockfile-invalid")
            result[key] = value
        return result

    def reject_constant(_value: str) -> object:
        raise CandidateError("node-lockfile-invalid")

    preflight_json_structure(
        content,
        code="node-lockfile-invalid",
        max_bytes=MAX_LOCKFILE_BYTES,
    )
    try:
        parsed = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=reject_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        MemoryError,
        OverflowError,
        RecursionError,
        ValueError,
    ):
        raise CandidateError("node-lockfile-invalid") from None
    if not isinstance(parsed, dict) or parsed.get("lockfileVersion") != 3:
        raise CandidateError("node-lockfile-invalid")
    packages = parsed.get("packages")
    if not isinstance(packages, dict) or not packages:
        raise CandidateError("node-lockfile-invalid")
    result: list[dict[str, object]] = []
    for path, raw_item in packages.items():
        if not isinstance(path, str) or not isinstance(raw_item, dict):
            raise CandidateError("node-lockfile-invalid")
        item: dict[str, Any] = raw_item
        name = _npm_name(path, item)
        version = item.get("version")
        if not isinstance(version, str):
            raise CandidateError("node-lockfile-invalid")
        license_value = item.get("license")
        license_declared = license_value if isinstance(license_value, str) else "NOASSERTION"
        package = _package("npm", name, version, license_value=license_declared)
        integrity = item.get("integrity")
        if isinstance(integrity, str) and integrity.startswith("sha512-"):
            try:
                digest = base64.b64decode(integrity.removeprefix("sha512-"), validate=True).hex()
            except ValueError:
                raise CandidateError("node-lockfile-invalid") from None
            package["checksums"] = [{"algorithm": "SHA512", "checksumValue": digest}]
        result.append(package)
    return result


def _package(ecosystem: str, name: str, version: str, *, license_value: str) -> dict[str, object]:
    purl_name = quote(name, safe="/")
    return {
        "SPDXID": _spdx_id(ecosystem, name, version),
        "copyrightText": "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceLocator": f"pkg:{ecosystem}/{purl_name}@{quote(version, safe='')}",
                "referenceType": "purl",
            }
        ],
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": license_value,
        "name": name,
        "versionInfo": version,
    }


def build_spdx_sbom(
    *,
    python_lock: bytes,
    node_lock: bytes,
    repository_url: str,
    source_sha: str,
    source_date_epoch: int,
    vendored_wheels: Mapping[str, bytes],
) -> bytes:
    """Derive one canonical SPDX document without clock- or host-dependent fields."""

    raw_packages = _python_packages(python_lock) + _node_packages(node_lock)
    unique_packages: dict[str, dict[str, object]] = {}
    for package in raw_packages:
        identifier = str(package["SPDXID"])
        previous = unique_packages.get(identifier)
        if previous is not None and previous != package:
            raise CandidateError("sbom-component-collision")
        unique_packages[identifier] = package
    packages = list(unique_packages.values())
    packages.sort(
        key=lambda item: (
            str(item["name"]).casefold(),
            str(item["versionInfo"]),
            str(item["SPDXID"]),
        )
    )
    python_identifiers = {
        (canonicalize_name(str(package["name"])), str(package["versionInfo"])): str(
            package["SPDXID"]
        )
        for package in packages
        if str(package["SPDXID"]).startswith("SPDXRef-Package-pypi-")
    }
    files: list[dict[str, object]] = []
    file_relationships: list[dict[str, str]] = []
    for path, content in sorted(vendored_wheels.items()):
        identity = inspect_wheel(path.rsplit("/", 1)[-1], content)
        package_identifier = python_identifiers.get((identity.name, identity.version))
        if package_identifier is None:
            raise CandidateError("sbom-vendor-package-missing")
        file_identifier = _spdx_file_id(path)
        files.append(
            {
                "SPDXID": file_identifier,
                "checksums": [{"algorithm": "SHA256", "checksumValue": sha256_bytes(content)}],
                "copyrightText": "NOASSERTION",
                "fileName": f"./{path}",
                "licenseConcluded": "NOASSERTION",
            }
        )
        file_relationships.append(
            {
                "relatedSpdxElement": file_identifier,
                "relationshipType": "CONTAINS",
                "spdxElementId": package_identifier,
            }
        )
    lock_closure = sha256_bytes(python_lock + b"\0" + node_lock)
    created = datetime.fromtimestamp(source_date_epoch, tz=UTC).isoformat().replace("+00:00", "Z")
    document = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": created,
            "creators": ["Tool: stateweaver-candidate-stdlib-v1"],
        },
        "dataLicense": "CC0-1.0",
        "documentNamespace": f"{repository_url.rstrip('/')}/sbom/{source_sha}/{lock_closure}",
        "files": files,
        "name": f"stateweaver-candidate-{source_sha}",
        "packages": packages,
        "relationships": [
            *(
                {
                    "relatedSpdxElement": str(item["SPDXID"]),
                    "relationshipType": "DESCRIBES",
                    "spdxElementId": "SPDXRef-DOCUMENT",
                }
                for item in packages
            ),
            *file_relationships,
        ],
        "spdxVersion": "SPDX-2.3",
    }
    return canonical_json_bytes(document)
