from __future__ import annotations

import io
import json
import signal
import sys
import time
from pathlib import Path
from typing import cast

import pytest
from stateweaver.adapters.docker_compose import state_bridge


class _Input:
    def __init__(self, payload: bytes) -> None:
        self.buffer = io.BytesIO(payload)


class _Output:
    def __init__(self) -> None:
        self.buffer = io.BytesIO()
        self.text = ""

    def write(self, value: str) -> int:
        self.text += value
        return len(value)


@pytest.fixture
def component_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, Path]:
    paths = {
        component: tmp_path / component / "state.json"
        for component in state_bridge._COMPONENT_PATHS
    }
    monkeypatch.setattr(state_bridge, "_COMPONENT_PATHS", paths)
    monkeypatch.setattr(
        state_bridge,
        "_ACTIVE_GENERATION_PATH",
        tmp_path / "active-generation",
    )
    return paths


def _active_path(component_paths: dict[str, Path], component: str) -> Path:
    return state_bridge._generation_path(
        component_paths[component],
        state_bridge._read_generation(),
    )


def test_bridge_initializes_exports_and_atomically_imports_all_components(
    component_paths: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_bridge._initialize()
    initial = state_bridge._archive()
    initial_components = cast(dict[str, object], initial["components"])
    assert set(initial_components) == set(component_paths)

    exported = _Output()
    monkeypatch.setattr(sys, "stdout", exported)
    assert state_bridge._export() == 0
    exported_payload = json.loads(exported.buffer.getvalue())
    exported_payload["components"]["database"] = {"rows": [{"value": "restored"}]}

    imported = _Output()
    monkeypatch.setattr(
        sys,
        "stdin",
        _Input(state_bridge._canonical(exported_payload)),
    )
    monkeypatch.setattr(sys, "stdout", imported)
    assert state_bridge._import() == 0
    assert json.loads(_active_path(component_paths, "database").read_text(encoding="utf-8")) == {
        "rows": [{"value": "restored"}]
    }
    assert json.loads(imported.text) == {"accepted": True, "schema_version": "1.0"}
    assert not list(component_paths["database"].parent.glob("*.next"))


def test_bridge_import_commits_all_components_with_one_generation_pointer(
    component_paths: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_bridge._initialize()
    before = state_bridge._archive()
    replacement = state_bridge._archive()
    replacement_components = cast(dict[str, object], replacement["components"])
    replacement_components["filesystem"] = {"files": [{"value": "new"}]}
    replacement_components["database"] = {"rows": [{"value": "new"}]}
    original_write = state_bridge._write_object
    writes = 0

    def fail_during_staging(path: Path, value: object) -> None:
        nonlocal writes
        writes += 1
        if writes == 3:
            raise OSError("injected staging failure")
        original_write(path, value)

    monkeypatch.setattr(state_bridge, "_write_object", fail_during_staging)
    with pytest.raises(OSError, match="staging failure"):
        state_bridge._commit_components(replacement_components)

    assert state_bridge._archive() == before


def test_bridge_health_serve_and_command_dispatch_are_deterministic(
    component_paths: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = _Output()
    monkeypatch.setattr(sys, "stdout", output)
    assert state_bridge.main(["health"]) == 0
    assert json.loads(output.text) == {"healthy": True}

    handlers: dict[int, object] = {}

    def remember(signum: int, handler: object) -> None:
        handlers[signum] = handler

    def stop_after_one_tick(_seconds: float) -> None:
        handler = handlers[signal.SIGTERM]
        assert callable(handler)
        handler(signal.SIGTERM, None)

    monkeypatch.setattr(signal, "signal", remember)
    monkeypatch.setattr(time, "sleep", stop_after_one_tick)
    assert state_bridge.main(["serve"]) == 0
    assert signal.SIGINT in handlers
    assert state_bridge.main(["unknown"]) == 64


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"{}", id="missing-shape"),
        pytest.param(b'{"duplicate":1,"duplicate":2}', id="duplicate-key"),
        pytest.param(b'{"value":NaN}', id="non-finite"),
        pytest.param(b"x" * 1_048_577, id="oversized"),
    ],
)
def test_bridge_rejects_invalid_archives(
    payload: bytes,
    component_paths: dict[str, Path],
) -> None:
    del component_paths
    with pytest.raises((ValueError, json.JSONDecodeError, UnicodeDecodeError)):
        state_bridge._validate_archive(state_bridge._parse(payload))


def test_bridge_rejects_non_object_component_and_preserves_existing_seed(
    component_paths: dict[str, Path],
) -> None:
    state_bridge._initialize()
    original = _active_path(component_paths, "queue").read_bytes()
    malformed = state_bridge._archive()
    malformed_components = cast(dict[str, object], malformed["components"])
    malformed_components["queue"] = []
    with pytest.raises(ValueError, match="JSON objects"):
        state_bridge._validate_archive(malformed)
    assert _active_path(component_paths, "queue").read_bytes() == original
