"""Fixed in-container state bridge for the repository-owned synthetic M2 fixture."""

from __future__ import annotations

import json
import os
import re
import signal
import sys
import time
from hashlib import sha256
from pathlib import Path
from typing import Final

_MAX_ARCHIVE_BYTES: Final = 1_048_576
_GENERATION_PATTERN: Final = re.compile(r"^[0-9a-f]{64}$")
_ACTIVE_GENERATION_PATH: Final = Path("/state/storage/active-generation")
_COMPONENT_PATHS: Final = {
    "filesystem": Path("/state/storage/state.json"),
    "database": Path("/state/database/state.json"),
    "cache": Path("/state/cache/state.json"),
    "queue": Path("/state/queue/state.json"),
    "session": Path("/state/session/state.json"),
    "clock": Path("/state/clock/state.json"),
}
_SEED: Final = {
    "filesystem": {"files": [{"path": "/fixture/version", "value": "1.0.0"}]},
    "database": {"rows": [{"id": "root-row", "value": "clean"}]},
    "cache": {"entries": []},
    "queue": {"jobs": []},
    "session": {"sessions": []},
    "clock": {"mode": "controlled", "now": "2026-07-29T12:00:00Z"},
}


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object key")
        value[key] = item
    return value


def _reject_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON constant is forbidden: {value}")


def _parse(raw: bytes) -> object:
    if not raw or len(raw) > _MAX_ARCHIVE_BYTES:
        raise ValueError("state archive exceeds its fixed boundary")
    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )


def _write_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    staged = path.with_suffix(".next")
    with staged.open("wb") as handle:
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())
    staged.replace(path)
    if os.name != "nt":
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _write_object(path: Path, value: object) -> None:
    _write_bytes(path, _canonical(value))


def _generation_path(path: Path, generation: str) -> Path:
    return path.with_name(f"{path.stem}.{generation}{path.suffix}")


def _read_generation() -> str:
    raw = _ACTIVE_GENERATION_PATH.read_bytes()
    try:
        generation = raw.decode("ascii").removesuffix("\n")
    except UnicodeDecodeError as error:
        raise ValueError("active state generation is invalid") from error
    if raw != f"{generation}\n".encode("ascii") or not _GENERATION_PATTERN.fullmatch(generation):
        raise ValueError("active state generation is invalid")
    return generation


def _commit_components(components: dict[str, object]) -> str:
    generation = sha256(_canonical(components)).hexdigest()
    for component, path in _COMPONENT_PATHS.items():
        _write_object(_generation_path(path, generation), components[component])
    for component, path in _COMPONENT_PATHS.items():
        restored = _parse(_generation_path(path, generation).read_bytes())
        if restored != components[component]:
            raise ValueError("staged state generation failed identity verification")
    _write_bytes(_ACTIVE_GENERATION_PATH, f"{generation}\n".encode("ascii"))
    return generation


def _initialize() -> None:
    if _ACTIVE_GENERATION_PATH.exists():
        _read_components()
        return
    _commit_components(dict(_SEED))


def _read_components() -> dict[str, object]:
    generation = _read_generation()
    components: dict[str, object] = {}
    for component, path in _COMPONENT_PATHS.items():
        value = _parse(_generation_path(path, generation).read_bytes())
        if not isinstance(value, dict):
            raise ValueError("component state must be a JSON object")
        components[component] = value
    return components


def _archive() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "target": {
            "target_id": "synthetic-demo",
            "target_version": "1.0.0",
        },
        "components": _read_components(),
    }


def _validate_archive(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "target",
        "components",
    }:
        raise ValueError("state archive shape is invalid")
    if value["schema_version"] != "1.0" or value["target"] != {
        "target_id": "synthetic-demo",
        "target_version": "1.0.0",
    }:
        raise ValueError("state archive target binding is invalid")
    components = value["components"]
    if not isinstance(components, dict) or set(components) != set(_COMPONENT_PATHS):
        raise ValueError("state archive component coverage is invalid")
    if any(not isinstance(component, dict) for component in components.values()):
        raise ValueError("state archive components must be JSON objects")
    return components


def _serve() -> int:
    _initialize()
    stopped = False

    def stop(_signum: int, _frame: object) -> None:
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not stopped:
        time.sleep(0.2)
    return 0


def _health() -> int:
    _initialize()
    _read_components()
    sys.stdout.write('{"healthy":true}\n')
    return 0


def _export() -> int:
    _initialize()
    sys.stdout.buffer.write(_canonical(_archive()) + b"\n")
    return 0


def _import() -> int:
    _initialize()
    components = _validate_archive(_parse(sys.stdin.buffer.read(_MAX_ARCHIVE_BYTES + 1)))
    _commit_components(components)
    sys.stdout.write('{"accepted":true,"schema_version":"1.0"}\n')
    return 0


def main(argv: list[str]) -> int:
    if argv == ["serve"]:
        return _serve()
    if argv == ["health"]:
        return _health()
    if argv == ["export"]:
        return _export()
    if argv == ["import"]:
        return _import()
    return 64


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
