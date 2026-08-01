"""Small, dependency-free primitives for canonical evidence artifacts."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SENSITIVE_KEY_RE = re.compile(
    r"(?:authorization|cookie|password|secret|credential|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|raw[_-]?token)",
    re.IGNORECASE,
)
SENSITIVE_TEXT_RE = re.compile(
    r"(?:\b(?:authorization|cookie|password)\s*[:=]|\bbearer\s+[A-Za-z0-9._~+/-]+|"
    r"\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token)\s*[:=])",
    re.IGNORECASE,
)
HASH_KEY_RE = re.compile(r"(?:sha(?:256|512)?|hash|digest)$", re.IGNORECASE)


class EvidenceInputError(ValueError):
    """A public, value-safe validation error for untrusted collector input."""


def validate_run_id(run_id: str) -> str:
    if not RUN_ID_RE.fullmatch(run_id) or run_id in {".", ".."} or ".." in run_id:
        raise EvidenceInputError("invalid run id")
    return run_id


def canonical_json_bytes(value: object) -> bytes:
    """Return the repository's stable UTF-8 JSON representation."""

    rendered = (
        json.dumps(
            _json_ready(value),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    return rendered.encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def semantic_sha256(value: object) -> str:
    """Hash a projection which deliberately ignores non-semantic timestamps."""

    return sha256_bytes(canonical_json_bytes(_without_audit_metadata(_json_ready(value))))


def _json_ready(value: object) -> object:
    if isinstance(value, Mapping):
        converted: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise EvidenceInputError("canonical JSON mapping keys must be strings")
            if key in converted:
                raise EvidenceInputError("canonical JSON mapping keys must not collide")
            converted[key] = _json_ready(item)
        return converted
    if isinstance(value, list | tuple):
        return [_json_ready(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        raise EvidenceInputError("canonical JSON numbers must be finite")
    if value is None or isinstance(value, str | int | float | bool):
        return value
    raise EvidenceInputError("canonical evidence contains a non-JSON value")


def _without_audit_metadata(value: object, path: tuple[str, ...] = ()) -> object:
    """Remove only known run-level audit clocks, never nested semantic timestamps."""

    if isinstance(value, dict):
        ignored = (
            {"collected_at", "started_at", "completed_at"} if path in {(), ("metadata",)} else set()
        )
        return {
            key: _without_audit_metadata(item, (*path, key))
            for key, item in value.items()
            if key.lower() not in ignored
        }
    if isinstance(value, list):
        return [_without_audit_metadata(item, (*path, "[]")) for item in value]
    return value


def redact(value: object) -> tuple[object, int]:
    """Recursively remove credential-like values without retaining their plaintext."""

    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        count = 0
        for key, item in value.items():
            text_key = str(key)
            if SENSITIVE_KEY_RE.search(text_key) and not HASH_KEY_RE.search(text_key):
                result[text_key] = "[REDACTED]"
                count += 1
            else:
                cleaned, nested_count = redact(item)
                result[text_key] = cleaned
                count += nested_count
        return result, count
    if isinstance(value, list | tuple):
        items = [redact(item) for item in value]
        return [item for item, _ in items], sum(count for _, count in items)
    if isinstance(value, str) and SENSITIVE_TEXT_RE.search(value):
        return "[REDACTED]", 1
    return value, 0


def assert_secret_free(value: object) -> None:
    """Fail without echoing a potentially secret source value."""

    _, redacted_count = redact(value)
    if redacted_count:
        raise EvidenceInputError("secret-like input is not permitted in copied evidence")


def atomic_write(path: Path, data: bytes) -> None:
    """Write a file atomically, never leaving a partial evidence artifact."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def atomic_json(path: Path, value: object) -> None:
    atomic_write(path, canonical_json_bytes(value))


def json_mapping(path: Path) -> Mapping[str, Any]:
    try:
        parsed: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceInputError("foundation JSON could not be read") from error
    if not isinstance(parsed, Mapping):
        raise EvidenceInputError("foundation JSON must be an object")
    return parsed
