from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path

import pytest
from stateweaver.adapters.docker_compose import real_provider_bridge as bridge


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _checkpoint(*, marker: str = "clean") -> bytes:
    generation_payload = {
        "schema_version": "stateweaver-lab-checkpoint-v1",
        "mode": "vulnerable",
        "seed": "m0-canonical-v1",
        "state": {"marker": marker},
        "state_fingerprint": "sha256:" + ("1" * 64),
    }
    generation = hashlib.sha256(_canonical(generation_payload)).hexdigest()
    payload = {**generation_payload, "generation": generation}
    return _canonical({**payload, "checkpoint_digest": _digest(payload)})


def _fake_providers(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[dict[str, dict[str, bytes]], dict[str, str | None]]:
    states = {provider: {} for provider in bridge._CHECKPOINT_PROVIDERS}
    active: dict[str, str | None] = {"generation": None}

    for provider in bridge._CHECKPOINT_PROVIDERS:
        state = states[provider]

        def read(generation: str, state: dict[str, bytes] = state) -> bytes | None:
            return state.get(generation)

        def stage(
            raw: bytes,
            generation: str,
            _digest: str,
            state: dict[str, bytes] = state,
        ) -> bool:
            previous = state.setdefault(generation, raw)
            if previous != raw:
                raise bridge.ProviderCheckpointError("checkpoint-readback-failed")
            return previous is raw

        def delete(generation: str, state: dict[str, bytes] = state) -> None:
            state.pop(generation, None)

        monkeypatch.setitem(bridge._CHECKPOINT_READERS, provider, read)
        monkeypatch.setitem(bridge._CHECKPOINT_STAGERS, provider, stage)
        monkeypatch.setitem(bridge._CHECKPOINT_DELETERS, provider, delete)

    monkeypatch.setattr(bridge, "_checkpoint_pg_active", lambda: active["generation"])

    def cas(expected: str | None, next_generation: str) -> None:
        if active["generation"] != expected:
            raise bridge.ProviderCheckpointConflictError("checkpoint-cas-conflict")
        active["generation"] = next_generation

    monkeypatch.setattr(bridge, "_checkpoint_pg_cas", cas)
    return states, active


def test_all_six_providers_roundtrip_and_postgres_pointer_cas(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    states, active = _fake_providers(monkeypatch)
    raw = _checkpoint()
    _raw, generation, digest = bridge._validate_checkpoint_bytes(raw)
    store = bridge.RealProviderLabStateStore()

    staged = store.stage(raw)
    assert active["generation"] is None
    assert staged.checkpoint_bytes == raw
    assert [item.provider for item in staged.observations] == list(bridge._CHECKPOINT_PROVIDERS)
    assert all(item.generation == generation for item in staged.observations)
    assert all(item.checkpoint_digest == digest for item in staged.observations)
    assert all(states[name][generation] == raw for name in bridge._CHECKPOINT_PROVIDERS)

    promoted = store.compare_and_swap(None, generation)
    assert promoted == store.load_active()
    assert active["generation"] == generation


def test_stale_active_generation_conflicts_without_changing_pointer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _states, active = _fake_providers(monkeypatch)
    raw = _checkpoint()
    _, generation, _ = bridge._validate_checkpoint_bytes(raw)
    store = bridge.RealProviderLabStateStore()
    store.stage(raw)
    active["generation"] = "a" * 64

    with pytest.raises(bridge.ProviderCheckpointConflictError, match="cas-conflict"):
        store.compare_and_swap(None, generation)
    assert active["generation"] == "a" * 64
    assert not store.poisoned


def test_post_cas_capture_failure_poison_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    states, active = _fake_providers(monkeypatch)
    raw = _checkpoint()
    _, generation, _ = bridge._validate_checkpoint_bytes(raw)
    store = bridge.RealProviderLabStateStore()
    store.stage(raw)

    original_cas = bridge._checkpoint_pg_cas

    def cas_then_remove(expected: str | None, next_generation: str) -> None:
        original_cas(expected, next_generation)
        states["selenium"].pop(next_generation)

    monkeypatch.setattr(bridge, "_checkpoint_pg_cas", cas_then_remove)
    with pytest.raises(bridge.ProviderCheckpointPoisonedError, match="store-poisoned"):
        store.compare_and_swap(None, generation)
    assert active["generation"] == generation
    assert store.poisoned


def test_provider_substitution_poison_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    states, _active = _fake_providers(monkeypatch)
    raw = _checkpoint()
    _, generation, _ = bridge._validate_checkpoint_bytes(raw)
    store = bridge.RealProviderLabStateStore()
    store.stage(raw)
    states["rabbitmq"][generation] = _checkpoint(marker="substituted")

    with pytest.raises(bridge.ProviderCheckpointPoisonedError, match="store-poisoned"):
        store.capture(generation)
    with pytest.raises(bridge.ProviderCheckpointPoisonedError, match="store-poisoned"):
        store.stage(raw)


@pytest.mark.parametrize("rollback_fails", [False, True])
def test_partial_stage_attempts_cleanup_and_poison(
    monkeypatch: pytest.MonkeyPatch, rollback_fails: bool
) -> None:
    states, _active = _fake_providers(monkeypatch)
    raw = _checkpoint()
    _, generation, _ = bridge._validate_checkpoint_bytes(raw)

    def fail_stage(_raw: bytes, _generation: str, _digest: str) -> bool:
        raise OSError("private provider detail")

    monkeypatch.setitem(bridge._CHECKPOINT_STAGERS, "rabbitmq", fail_stage)
    if rollback_fails:

        def fail_delete(_generation: str) -> None:
            raise OSError("private rollback detail")

        monkeypatch.setitem(bridge._CHECKPOINT_DELETERS, "redis", fail_delete)

    store = bridge.RealProviderLabStateStore()
    with pytest.raises(bridge.ProviderCheckpointPoisonedError) as failure:
        store.stage(raw)
    assert str(failure.value) == "checkpoint-store-poisoned"
    assert generation not in states["postgres"]
    if not rollback_fails:
        assert generation not in states["redis"]
    assert store.poisoned


def test_stage_failure_after_current_shard_creation_cleans_current_and_prior(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    states, _active = _fake_providers(monkeypatch)
    raw = _checkpoint()
    _, generation, _ = bridge._validate_checkpoint_bytes(raw)

    def create_then_fail(raw: bytes, generation: str, _digest: str) -> bool:
        states["rabbitmq"][generation] = raw
        raise OSError("private readback detail")

    monkeypatch.setitem(bridge._CHECKPOINT_STAGERS, "rabbitmq", create_then_fail)
    store = bridge.RealProviderLabStateStore()
    with pytest.raises(bridge.ProviderCheckpointPoisonedError):
        store.stage(raw)
    assert all(generation not in states[name] for name in bridge._CHECKPOINT_PROVIDERS)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda raw: raw + b" ",
        lambda raw: raw.replace(b'"mode":"vulnerable"', b'"mode":"patched"'),
        lambda raw: raw.replace(b'"state":{', b'"state":{},"state":{'),
        lambda _raw: b"x" * (bridge._MAX_CHECKPOINT_BYTES + 1),
    ],
    ids=("noncanonical", "digest-mismatch", "duplicate-key", "oversize"),
)
def test_checkpoint_boundary_rejects_noncanonical_or_inconsistent_bytes(
    mutate: Callable[[bytes], bytes],
) -> None:
    sentinel = "fixture-bearer-secret-never-public"
    with pytest.raises(bridge.ProviderCheckpointError) as failure:
        bridge._validate_checkpoint_bytes(mutate(_checkpoint(marker=sentinel)))
    assert sentinel not in str(failure.value)


def test_filesystem_and_clock_shards_are_immutable_and_exact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bridge, "_CHECKPOINT_FILES_PATH", tmp_path / "filesystem")
    monkeypatch.setattr(bridge, "_CHECKPOINT_CLOCK_PATH", tmp_path / "clock")
    raw = _checkpoint()
    _, generation, _ = bridge._validate_checkpoint_bytes(raw)
    assert bridge._checkpoint_filesystem_stage(raw, generation, "ignored")
    assert bridge._checkpoint_clock_stage(raw, generation, "ignored")
    assert bridge._checkpoint_filesystem_read(generation) == raw
    assert bridge._checkpoint_clock_read(generation) == raw
    assert not bridge._checkpoint_filesystem_stage(raw, generation, "ignored")

    with pytest.raises(bridge.ProviderCheckpointError, match="readback"):
        bridge._checkpoint_clock_stage(_checkpoint(marker="other"), generation, "ignored")


def test_selenium_checkpoint_persists_between_browser_sessions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bridge, "_CHECKPOINT_SESSION_PATH", tmp_path / "session")
    raw = _checkpoint()
    _, generation, _ = bridge._validate_checkpoint_bytes(raw)
    sessions: list[dict[str, str]] = []
    current: dict[str, str] = {}

    from collections.abc import Iterator
    from contextlib import contextmanager

    @contextmanager
    def browser_session() -> Iterator[tuple[str, str]]:
        nonlocal current
        current = {}
        sessions.append(current)
        yield f"{len(sessions):032x}", "fixture"

    def webdriver(method: str, path: str, payload: object | None = None) -> object:
        assert method == "POST"
        assert path.endswith("/execute/sync")
        assert isinstance(payload, dict)
        args = payload["args"]
        assert isinstance(args, list)
        if len(args) == 2:
            current[str(args[0])] = str(args[1])
            return True
        return current.get(str(args[0]))

    monkeypatch.setattr(bridge, "_browser_session", browser_session)
    monkeypatch.setattr(bridge, "_webdriver", webdriver)
    assert bridge._checkpoint_selenium_stage(raw, generation, "ignored")
    assert bridge._checkpoint_selenium_read(generation) == raw
    assert len(sessions) >= 3
    assert all(session[bridge._checkpoint_selenium_key(generation)] for session in sessions)
