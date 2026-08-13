from __future__ import annotations

import hashlib
import io
import json
import runpy
import socket
import struct
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast
from urllib.error import HTTPError

import pytest
from stateweaver.adapters.docker_compose import real_provider_bridge as bridge


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


class _Socket:
    def __init__(self, reply: bytes) -> None:
        self._reply = bytearray(reply)
        self.sent: list[bytes] = []
        self.timeout: float | None = None

    def __enter__(self) -> _Socket:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def recv(self, length: int) -> bytes:
        value = bytes(self._reply[:length])
        del self._reply[:length]
        return value

    def sendall(self, value: bytes) -> None:
        self.sent.append(value)

    def settimeout(self, value: float) -> None:
        self.timeout = value


class _HttpResponse:
    def __init__(self, *, status: int, payload: bytes) -> None:
        self.status = status
        self._payload = payload

    def __enter__(self) -> _HttpResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, limit: int) -> bytes:
        return self._payload[:limit]


def _postgres_message(kind: bytes, payload: bytes = b"") -> bytes:
    return kind + struct.pack("!I", len(payload) + 4) + payload


def _components(marker: str = "baseline", *, tick: int = 0) -> dict[str, Any]:
    return {
        "filesystem": {"files": {"marker.txt": marker, "tenant.txt": "alpha"}},
        "database": {"rows": [{"id": 1, "tenant": "alpha", "value": marker}]},
        "cache": {"entries": {"sw:marker": marker}},
        "queue": {"messages": [marker]},
        "session": {
            "cookies": [{"name": "sw_marker", "path": "/", "value": marker}],
            "local_storage": {"sw.marker": marker},
        },
        "clock": bridge._clock_component(tick),
    }


def _archive(marker: str = "baseline", *, tick: int = 0) -> dict[str, Any]:
    return {
        "schema_version": "2.0",
        "target": {"target_id": "real-provider-demo", "target_version": "1.0.0"},
        "components": _components(marker, tick=tick),
    }


def _m5_request(scenario: str, mode: str) -> dict[str, object]:
    actions: list[dict[str, object]] = []
    for sequence, ((method, path, identity), artifact) in enumerate(
        zip(bridge._M5_ROUTES[scenario], bridge._M5_ARTIFACTS[scenario], strict=True),
        start=1,
    ):
        envelope = {
            "action_id": f"action.step-{sequence}",
            "action": {
                "type": "http.request",
                "method": method,
                "target": {
                    "scheme": "http",
                    "host": "localhost",
                    "port": 80,
                    "path": path,
                },
                "identity_handle": identity,
                "body_artifact": artifact,
                "query": [],
                "headers": [],
                "template_ref": None,
            },
            "idempotency_key": "sha256:" + f"{sequence:064x}",
            "policy_decision_ref": f"policy:step-{sequence}",
            "sequence": sequence,
            "requested_by": {"type": "workflow", "role": "operator", "actor_id": None},
        }
        actions.append(
            {
                "envelope": envelope,
                "action_digest": "sha256:"
                + hashlib.sha256(bridge._canonical(envelope)).hexdigest(),
            }
        )
    return {"scenario": scenario, "mode": mode, "actions": actions}


def test_archive_validation_is_closed_and_canonical() -> None:
    value = _archive("sibling-1", tick=11)
    validated = bridge._validate_archive(value)
    assert validated == value
    assert json.loads(bridge._canonical(validated)) == value


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value.update(schema_version="1.0"), "binding"),
        (lambda value: value["components"].pop("queue"), "coverage"),
        (
            lambda value: value["components"]["filesystem"]["files"].update({"../escape": "x"}),
            "coverage",
        ),
        (
            lambda value: value["components"]["session"]["cookies"][0].update(
                {"value": "not valid"}
            ),
            "marker",
        ),
        (
            lambda value: value["components"]["clock"].update({"iso8601": "2026-01-01T00:00:02Z"}),
            "derived",
        ),
        (
            lambda value: value["components"]["database"]["rows"].append(
                {"id": 1, "tenant": "alpha", "value": "duplicate"}
            ),
            "identity",
        ),
    ],
)
def test_archive_validation_rejects_untrusted_shapes(
    mutate: Callable[[dict[str, Any]], None],
    message: str,
) -> None:
    value = _archive()
    mutate(value)
    with pytest.raises(ValueError, match=message):
        bridge._validate_archive(value)


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b' {"a":1,"a":2}',
        b'{"value":NaN}',
        b"x" * (bridge._MAX_DOCUMENT_BYTES + 1),
    ],
    ids=("empty", "duplicate", "nonfinite", "oversized"),
)
def test_json_boundary_rejects_empty_duplicate_nonfinite_and_oversized(payload: bytes) -> None:
    with pytest.raises((ValueError, json.JSONDecodeError)):
        bridge._parse(payload)


def test_archive_collects_all_provider_exports(monkeypatch: pytest.MonkeyPatch) -> None:
    components = _components()
    monkeypatch.setattr(bridge, "_filesystem_export", lambda: components["filesystem"])
    monkeypatch.setattr(bridge, "_database_export", lambda: components["database"])
    monkeypatch.setattr(bridge, "_cache_export", lambda: components["cache"])
    monkeypatch.setattr(bridge, "_queue_export", lambda: components["queue"])
    monkeypatch.setattr(bridge, "_session_export", lambda: components["session"])
    monkeypatch.setattr(bridge, "_clock_export", lambda: components["clock"])
    assert bridge._archive() == _archive()


def test_restore_calls_every_provider_in_fixed_order(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, object]] = []
    for name in ("database", "cache", "queue", "session", "filesystem", "clock"):
        monkeypatch.setattr(
            bridge,
            f"_{name}_import",
            lambda value, name=name: calls.append((name, value)),
        )
    value = bridge._validate_archive(_archive("restored", tick=9))
    bridge._restore(value)
    assert [name for name, _ in calls] == [
        "database",
        "cache",
        "queue",
        "session",
        "filesystem",
        "clock",
    ]


def test_filesystem_clock_and_session_use_real_persistent_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = {
        "marker.txt": tmp_path / "filesystem" / "marker.txt",
        "tenant.txt": tmp_path / "filesystem" / "tenant.txt",
    }
    monkeypatch.setattr(bridge, "_FILES", files)
    monkeypatch.setattr(bridge, "_CLOCK_PATH", tmp_path / "clock" / "state.json")
    monkeypatch.setattr(bridge, "_SESSION_PATH", tmp_path / "session" / "state.json")
    monkeypatch.setattr(
        bridge,
        "_browser_roundtrip",
        lambda marker: (
            {
                "cookies": [{"name": "sw_marker", "path": "/", "value": marker}],
                "local_storage": {"sw.marker": marker},
            },
            "fixture-browser",
        ),
    )

    assert bridge._filesystem_export() == _components()["filesystem"]
    assert bridge._clock_export() == _components()["clock"]
    assert bridge._session_export() == _components()["session"]

    mutated = _components("world-4", tick=44)
    bridge._filesystem_import(cast(dict[str, object], mutated["filesystem"]))
    bridge._clock_import(cast(dict[str, object], mutated["clock"]))
    bridge._session_import(cast(dict[str, object], mutated["session"]))
    assert bridge._filesystem_export() == mutated["filesystem"]
    assert bridge._clock_export() == mutated["clock"]
    assert bridge._session_export() == mutated["session"]


def test_database_and_cache_restore_require_readback(monkeypatch: pytest.MonkeyPatch) -> None:
    database = cast(dict[str, object], _components("world-2")["database"])
    queries: list[str] = []

    def postgres(sql: str) -> tuple[tuple[str | None, ...], ...]:
        queries.append(sql)
        if sql.startswith("SELECT"):
            return (("1", "alpha", "world-2"),)
        return ()

    monkeypatch.setattr(bridge, "_postgres_query", postgres)
    bridge._database_import(database)
    assert "TRUNCATE sw_state" in queries[0]
    assert bridge._database_export() == database

    cache = cast(dict[str, object], _components("world-2")["cache"])
    state = {"sw:marker": "baseline"}

    def redis(*parts: str) -> object:
        if parts[0] == "FLUSHDB":
            state.clear()
            return "OK"
        if parts[0] == "SET":
            state[parts[1]] = parts[2]
            return "OK"
        if parts[0] == "GET":
            return state.get(parts[1])
        raise AssertionError(parts)

    monkeypatch.setattr(bridge, "_redis_command", redis)
    bridge._cache_import(cache)
    assert bridge._cache_export() == cache


def test_postgres_wire_query_uses_fixed_startup_and_decodes_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fields = b"".join(name + b"\0" + (b"\0" * 18) for name in (b"id", b"tenant", b"value"))
    row_description = struct.pack("!H", 3) + fields
    data_row = struct.pack("!H", 3) + b"".join(
        struct.pack("!i", len(value)) + value for value in (b"1", b"alpha", b"baseline")
    )
    wire = b"".join(
        (
            _postgres_message(b"R", struct.pack("!I", 0)),
            _postgres_message(b"S"),
            _postgres_message(b"Z"),
            _postgres_message(b"T", row_description),
            _postgres_message(b"D", data_row),
            _postgres_message(b"C"),
            _postgres_message(b"Z"),
        )
    )
    connection = _Socket(wire)
    monkeypatch.setattr(socket, "create_connection", lambda *_args, **_kwargs: connection)

    assert bridge._postgres_query("SELECT 1;") == (("1", "alpha", "baseline"),)
    assert connection.timeout == bridge._SOCKET_TIMEOUT_SECONDS
    assert connection.sent[-1] == b"X\x00\x00\x00\x04"
    assert b"SELECT 1;" in connection.sent[1]


@pytest.mark.parametrize(
    ("reply", "expected"),
    [
        (b"+OK\r\n", "OK"),
        (b":7\r\n", 7),
        (b"$3\r\nabc\r\n", "abc"),
        (b"$-1\r\n", None),
        (b"*2\r\n+OK\r\n:1\r\n", ["OK", 1]),
    ],
)
def test_redis_wire_parser_accepts_only_closed_reply_types(
    reply: bytes,
    expected: object,
) -> None:
    assert bridge._redis_read(cast(Any, _Socket(reply))) == expected


def test_redis_command_writes_one_fixed_resp_request(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = _Socket(b"+PONG\r\n")
    monkeypatch.setattr(socket, "create_connection", lambda *_args, **_kwargs: connection)
    assert bridge._redis_command("PING") == "PONG"
    assert connection.timeout == bridge._SOCKET_TIMEOUT_SECONDS
    assert connection.sent == [b"*1\r\n$4\r\nPING\r\n"]


def test_http_json_binds_method_headers_status_and_canonical_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[Any] = []

    def open_url(request: object, *, timeout: float) -> _HttpResponse:
        requests.append(request)
        assert timeout == bridge._SOCKET_TIMEOUT_SECONDS
        return _HttpResponse(status=201, payload=b'{"accepted":true}')

    monkeypatch.setattr(bridge, "urlopen", open_url)
    assert bridge._http_json_response(
        "POST",
        "http://provider.invalid/fixed",
        {"value": "fixed"},
        authorization="Basic fixed",
        accepted_statuses=(201,),
    ) == (201, {"accepted": True})
    assert bridge._http_json(
        "POST",
        "http://provider.invalid/fixed",
        {"value": "fixed"},
        authorization="Basic fixed",
        accepted_statuses=(201,),
    ) == {"accepted": True}
    request = requests[0]
    assert request.get_method() == "POST"
    assert request.get_header("Authorization") == "Basic fixed"
    assert request.data == b'{"value":"fixed"}'


def test_http_json_converts_transport_and_shape_failures_to_closed_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_open(_request: object, *, timeout: float) -> _HttpResponse:
        del timeout
        raise OSError("untrusted transport detail")

    monkeypatch.setattr(bridge, "urlopen", fail_open)
    with pytest.raises(bridge.ProviderBridgeError, match="HTTP request failed") as failure:
        bridge._http_json("GET", "http://provider.invalid/fixed")
    assert failure.value.__cause__ is None

    monkeypatch.setattr(
        bridge,
        "urlopen",
        lambda *_args, **_kwargs: _HttpResponse(status=200, payload=b"not-json"),
    )
    with pytest.raises(bridge.ProviderBridgeError, match="HTTP reply was invalid"):
        bridge._http_json("GET", "http://provider.invalid/fixed")


def test_http_json_handles_only_explicitly_accepted_http_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def http_error(code: int, payload: bytes) -> Callable[..., object]:
        def fail(*_args: object, **_kwargs: object) -> object:
            raise HTTPError(
                "http://provider.invalid/fixed",
                code,
                "untrusted detail",
                cast(Any, None),
                io.BytesIO(payload),
            )

        return fail

    monkeypatch.setattr(bridge, "urlopen", http_error(404, b'{"missing":true}'))
    assert bridge._http_json_response(
        "GET", "http://provider.invalid/fixed", accepted_statuses=(404,)
    ) == (404, {"missing": True})

    monkeypatch.setattr(bridge, "urlopen", http_error(503, b'{"secret":true}'))
    with pytest.raises(bridge.ProviderBridgeError, match="HTTP request failed") as failure:
        bridge._http_json_response("GET", "http://provider.invalid/fixed")
    assert failure.value.__cause__ is None


def test_low_level_protocol_boundaries_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(bridge.ProviderBridgeError, match="closed a reply early"):
        bridge._read_exact(cast(Any, _Socket(b"")), 1)
    with pytest.raises(bridge.ProviderBridgeError, match="PostgreSQL reply exceeded"):
        bridge._postgres_message(cast(Any, _Socket(b"R" + struct.pack("!I", 3))))
    with pytest.raises(bridge.ProviderBridgeError, match="query is invalid"):
        bridge._postgres_query("")

    for reply, message in (
        (b"-ERR fixed\r\n", "rejected"),
        (b"$3\r\nabcxx", "bulk reply"),
        (b"*65\r\n", "array reply"),
        (b"?", "type"),
    ):
        with pytest.raises(bridge.ProviderBridgeError, match=message):
            bridge._redis_read(cast(Any, _Socket(reply)))
    with pytest.raises(bridge.ProviderBridgeError, match="command is invalid"):
        bridge._redis_command()

    monkeypatch.setattr(
        bridge,
        "urlopen",
        lambda *_args, **_kwargs: _HttpResponse(status=503, payload=b"{}"),
    )
    with pytest.raises(bridge.ProviderBridgeError, match="status was rejected"):
        bridge._http_json("GET", "http://provider.invalid/fixed")
    monkeypatch.setattr(
        bridge,
        "urlopen",
        lambda *_args, **_kwargs: _HttpResponse(
            status=200,
            payload=b"x" * (bridge._MAX_PROVIDER_REPLY_BYTES + 1),
        ),
    )
    with pytest.raises(bridge.ProviderBridgeError, match="exceeded its fixed boundary"):
        bridge._http_json("GET", "http://provider.invalid/fixed")
    monkeypatch.setattr(
        bridge,
        "urlopen",
        lambda *_args, **_kwargs: _HttpResponse(status=200, payload=b""),
    )
    assert bridge._http_json("GET", "http://provider.invalid/fixed") is None


def test_provider_acknowledgement_and_readback_failures_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bridge, "_postgres_query", lambda _sql: ((None, "alpha", "value"),))
    with pytest.raises(bridge.ProviderBridgeError, match="state row was invalid"):
        bridge._database_export()
    monkeypatch.setattr(bridge, "_postgres_query", lambda _sql: (("bad", "alpha", "value"),))
    with pytest.raises(bridge.ProviderBridgeError, match="state row was invalid"):
        bridge._database_export()

    def reject_redis(*parts: str) -> object:
        return None if parts[0] == "GET" else "NO"

    monkeypatch.setattr(bridge, "_redis_command", reject_redis)
    with pytest.raises(bridge.ProviderBridgeError, match="seed was not acknowledged"):
        bridge._cache_export()
    with pytest.raises(bridge.ProviderBridgeError, match="reset was not acknowledged"):
        bridge._cache_import(cast(dict[str, object], _components()["cache"]))

    monkeypatch.setattr(bridge, "_http_json", lambda *_args, **_kwargs: {"unexpected": True})
    with pytest.raises(bridge.ProviderBridgeError, match="queue creation reply"):
        bridge._queue_create()
    with pytest.raises(bridge.ProviderBridgeError, match="publish was not routed"):
        bridge._queue_publish("baseline")
    monkeypatch.setattr(bridge, "_http_json", lambda *_args, **_kwargs: None)
    with pytest.raises(bridge.ProviderBridgeError, match="queue metadata"):
        bridge._queue_export()

    monkeypatch.setattr(bridge, "_http_json", lambda *_args, **_kwargs: {"wrong": None})
    with pytest.raises(bridge.ProviderBridgeError, match="WebDriver reply"):
        bridge._webdriver("GET", "/status")
    monkeypatch.setattr(
        bridge,
        "_http_json",
        lambda *_args, **_kwargs: {"value": {"error": "fixed"}},
    )
    with pytest.raises(bridge.ProviderBridgeError, match="WebDriver rejected"):
        bridge._webdriver("GET", "/status")

    monkeypatch.setattr(bridge, "_SESSION_PATH", tmp_path / "session.json")
    bridge._SESSION_PATH.write_bytes(b'{"unexpected":true}')
    with pytest.raises(bridge.ProviderBridgeError, match="session state file"):
        bridge._session_export()

    files = {
        "marker.txt": tmp_path / "marker.txt",
        "tenant.txt": tmp_path / "tenant.txt",
    }
    monkeypatch.setattr(bridge, "_FILES", files)
    files["marker.txt"].write_bytes(b"\xff")
    files["tenant.txt"].write_text("alpha", encoding="ascii")
    with pytest.raises(bridge.ProviderBridgeError, match="filesystem provider content"):
        bridge._filesystem_export()

    monkeypatch.setattr(bridge, "_CLOCK_PATH", tmp_path / "clock.json")
    bridge._CLOCK_PATH.write_bytes(b"[]")
    with pytest.raises(bridge.ProviderBridgeError, match="controlled-clock state"):
        bridge._clock_export()


def test_provider_restore_readbacks_and_closed_reply_shapes_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        bridge,
        "_http_json",
        lambda method, url, *_args, **_kwargs: {} if method == "GET" else [],
    )
    with pytest.raises(bridge.ProviderBridgeError, match="queue capture"):
        bridge._queue_export()

    monkeypatch.setattr(bridge, "_http_json", lambda *_args, **_kwargs: {"unexpected": True})
    with pytest.raises(bridge.ProviderBridgeError, match="queue deletion reply"):
        bridge._queue_import(cast(dict[str, object], _components()["queue"]))

    monkeypatch.setattr(bridge, "_http_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(bridge, "_queue_create", lambda: None)
    monkeypatch.setattr(bridge, "_queue_publish", lambda _marker: None)
    monkeypatch.setattr(bridge, "_queue_export", lambda: _components("different")["queue"])
    with pytest.raises(bridge.ProviderBridgeError, match="RabbitMQ restore read-back"):
        bridge._queue_import(cast(dict[str, object], _components()["queue"]))

    monkeypatch.setattr(
        bridge,
        "_browser_roundtrip",
        lambda _marker: (cast(dict[str, object], _components("different")["session"]), "140"),
    )
    with pytest.raises(bridge.ProviderBridgeError, match="session restore read-back"):
        bridge._session_import(cast(dict[str, object], _components()["session"]))

    monkeypatch.setattr(
        bridge, "_filesystem_export", lambda: _components("different")["filesystem"]
    )
    monkeypatch.setattr(bridge, "_atomic_write", lambda *_args: None)
    with pytest.raises(bridge.ProviderBridgeError, match="filesystem restore read-back"):
        bridge._filesystem_import(cast(dict[str, object], _components()["filesystem"]))

    monkeypatch.setattr(bridge, "_clock_export", lambda: _components(tick=99)["clock"])
    with pytest.raises(bridge.ProviderBridgeError, match="clock restore read-back"):
        bridge._clock_import(cast(dict[str, object], _components()["clock"]))


@pytest.mark.parametrize(
    "session_reply",
    [None, {"sessionId": "bad", "capabilities": {"browserVersion": "140"}}],
)
def test_browser_session_rejects_unbound_session_identity(
    monkeypatch: pytest.MonkeyPatch,
    session_reply: object,
) -> None:
    monkeypatch.setattr(bridge, "_webdriver", lambda *_args, **_kwargs: session_reply)
    with (
        pytest.raises(bridge.ProviderBridgeError, match=r"session (reply|identity) was invalid"),
        bridge._browser_session(),
    ):
        pytest.fail("invalid browser session yielded")


def test_browser_roundtrip_rejects_cookie_or_storage_substitution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @contextmanager
    def session() -> Iterator[tuple[str, str]]:
        yield "a" * 32, "140"

    def webdriver(method: str, path: str, _payload: object | None = None) -> object:
        if method == "GET" and "/cookie/" in path:
            return {"name": "sw_marker", "value": "substituted"}
        if path.endswith("/execute/sync"):
            return "baseline"
        return None

    monkeypatch.setattr(bridge, "_browser_session", session)
    monkeypatch.setattr(bridge, "_webdriver", webdriver)
    with pytest.raises(bridge.ProviderBridgeError, match="session read-back differed"):
        bridge._browser_roundtrip("baseline")


@pytest.mark.parametrize("tick", [0, True, 1_000_001])
def test_mutated_archive_rejects_ticks_outside_closed_range(tick: object) -> None:
    with pytest.raises(ValueError, match="mutation tick is invalid"):
        bridge._mutated_archive("baseline", cast(int, tick))


def test_canonical_encoder_and_exact_reader_enforce_size_boundaries() -> None:
    with pytest.raises(ValueError, match="not JSON compliant"):
        bridge._canonical(float("nan"))
    with pytest.raises(bridge.ProviderBridgeError, match="fixed boundary"):
        bridge._read_exact(cast(Any, _Socket(b"")), bridge._MAX_PROVIDER_REPLY_BYTES + 1)


@pytest.mark.parametrize(
    ("validator", "value", "message"),
    [
        (bridge._validate_filesystem, [], "filesystem component shape"),
        (bridge._validate_database, [], "database component shape"),
        (bridge._validate_database, {"rows": []}, "database row coverage"),
        (bridge._validate_database, {"rows": [{}]}, "database row shape"),
        (
            bridge._validate_database,
            {"rows": [{"id": True, "tenant": "alpha", "value": "baseline"}]},
            "database row identity",
        ),
        (bridge._validate_cache, [], "cache component shape"),
        (bridge._validate_cache, {"entries": {}}, "cache component coverage"),
        (bridge._validate_queue, [], "queue component shape"),
        (bridge._validate_queue, {"messages": []}, "queue message coverage"),
        (bridge._validate_session, [], "browser-session component shape"),
        (
            bridge._validate_session,
            {"cookies": [], "local_storage": {"sw.marker": "baseline"}},
            "cookie coverage",
        ),
        (
            bridge._validate_session,
            {
                "cookies": [{"name": "wrong", "path": "/", "value": "baseline"}],
                "local_storage": {"sw.marker": "baseline"},
            },
            "cookie shape",
        ),
        (
            bridge._validate_session,
            {
                "cookies": [{"name": "sw_marker", "path": "/wrong", "value": "baseline"}],
                "local_storage": {"sw.marker": "baseline"},
            },
            "cookie path",
        ),
        (
            bridge._validate_session,
            {
                "cookies": [{"name": "sw_marker", "path": "/", "value": "baseline"}],
                "local_storage": {},
            },
            "storage coverage",
        ),
        (
            bridge._validate_session,
            {
                "cookies": [{"name": "sw_marker", "path": "/", "value": "baseline"}],
                "local_storage": {"sw.marker": "different"},
            },
            "providers disagree",
        ),
        (bridge._validate_clock, [], "controlled-clock component shape"),
        (
            bridge._validate_clock,
            {"iso8601": "2026-01-01T00:00:00Z", "tick": True},
            "controlled-clock tick",
        ),
        (bridge._validate_archive, [], "archive shape"),
    ],
)
def test_component_validators_reject_every_open_shape(
    validator: Callable[[object], dict[str, object]],
    value: object,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        validator(value)


def test_queue_restore_uses_rabbit_management_readback(monkeypatch: pytest.MonkeyPatch) -> None:
    state: list[str] = ["baseline"]

    def http(
        method: str,
        url: str,
        payload: object | None = None,
        **_kwargs: object,
    ) -> object:
        if method == "DELETE":
            state.clear()
            return None
        if method == "PUT":
            return None
        if url.endswith("/publish"):
            assert isinstance(payload, dict)
            state.append(cast(str, payload["payload"]))
            return {"routed": True}
        if url.endswith("/get"):
            assert isinstance(payload, dict)
            assert payload["count"] == 2
            assert payload["ackmode"] == "ack_requeue_true"
            return [{"payload": state[0]}]
        if method == "GET":
            # Management statistics are intentionally stale; the fixed `/get`
            # readback below is the authoritative queue data path.
            return {"messages": 0}
        raise AssertionError((method, url))

    monkeypatch.setattr(bridge, "_http_json", http)
    component = cast(dict[str, object], _components("world-3")["queue"])
    bridge._queue_import(component)
    assert bridge._queue_export() == component


def test_browser_roundtrip_uses_webdriver_cookie_and_storage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str, object | None]] = []
    marker = "world-browser"

    @contextmanager
    def session() -> Iterator[tuple[str, str]]:
        yield "a" * 32, "123.0"

    def webdriver(method: str, path: str, payload: object | None = None) -> object:
        calls.append((method, path, payload))
        if path.endswith("/cookie/sw_marker"):
            return {"name": "sw_marker", "value": marker}
        if path.endswith("/execute/sync") and isinstance(payload, dict):
            script = payload.get("script")
            if isinstance(script, str) and script.startswith("return"):
                return marker
        return None

    monkeypatch.setattr(bridge, "_browser_session", session)
    monkeypatch.setattr(bridge, "_webdriver", webdriver)
    observed, version = bridge._browser_roundtrip(marker)
    assert observed == _components(marker)["session"]
    assert version == "123.0"
    assert any(path.endswith("/cookie") and method == "POST" for method, path, _ in calls)


def test_webdriver_and_browser_session_validate_identity_and_always_delete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bridge, "_http_json", lambda *_args, **_kwargs: {"value": "ok"})
    assert bridge._webdriver("GET", "/status") == "ok"

    calls: list[tuple[str, str, object | None]] = []

    def webdriver(method: str, path: str, payload: object | None = None) -> object:
        calls.append((method, path, payload))
        if path == "/session":
            return {
                "sessionId": "a" * 32,
                "capabilities": {"browserVersion": "140.0"},
            }
        return None

    monkeypatch.setattr(bridge, "_webdriver", webdriver)
    for _ in range(2):
        with bridge._browser_session() as session:
            assert session == ("a" * 32, "140.0")
    assert [call[:2] for call in calls if call[0] == "DELETE"] == [
        ("DELETE", "/session/" + ("a" * 32)),
        ("DELETE", "/session/" + ("a" * 32)),
    ]
    session_payloads = [
        payload for method, path, payload in calls if (method, path) == ("POST", "/session")
    ]
    assert len(session_payloads) == 2
    for payload in session_payloads:
        assert isinstance(payload, dict)
        args = payload["capabilities"]["alwaysMatch"]["goog:chromeOptions"]["args"]
        assert all(not str(arg).startswith("--user-data-dir=") for arg in args)


def test_queue_export_bootstraps_only_the_fixed_queue(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []
    first_get = True

    def http(method: str, url: str, payload: object | None = None, **_kwargs: object) -> object:
        nonlocal first_get
        del payload
        calls.append((method, url))
        if method == "GET" and first_get:
            first_get = False
            raise bridge.ProviderBridgeError("missing")
        if method == "GET":
            return {"messages": 1}
        if url.endswith("/publish"):
            return {"routed": True}
        if url.endswith("/get"):
            return [{"payload": "baseline"}]
        return None

    monkeypatch.setattr(bridge, "_http_json", http)
    assert bridge._queue_export() == _components()["queue"]
    assert ("PUT", bridge._rabbit_path()) in calls
    assert any(url.endswith("/publish") for _method, url in calls)


def test_command_handlers_export_import_and_mutate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = bridge._validate_archive(_archive())

    def restore(value: dict[str, object]) -> None:
        nonlocal state
        state = value

    monkeypatch.setattr(bridge, "_archive", lambda: state)
    monkeypatch.setattr(bridge, "_restore", restore)

    output = _Output()
    monkeypatch.setattr(sys, "stdout", output)
    assert bridge._export() == 0
    assert json.loads(output.buffer.getvalue()) == _archive()

    output = _Output()
    monkeypatch.setattr(sys, "stdin", _Input(bridge._canonical(_archive("imported", tick=3))))
    monkeypatch.setattr(sys, "stdout", output)
    assert bridge._import() == 0
    assert json.loads(output.text) == {"accepted": True, "schema_version": "2.0"}
    assert state == _archive("imported", tick=3)

    output = _Output()
    monkeypatch.setattr(sys, "stdin", _Input(b'{"marker":"mutated","tick":7}'))
    monkeypatch.setattr(sys, "stdout", output)
    assert bridge._mutate() == 0
    assert json.loads(output.text) == {"accepted": True, "schema_version": "2.0"}
    assert state == _archive("mutated", tick=7)

    assert bridge.main(["unknown"]) == 64


def test_main_dispatches_only_the_five_closed_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[str] = []
    for command in ("serve", "health", "export", "import", "mutate"):

        def dispatch(command: str = command) -> int:
            called.append(command)
            return 0

        monkeypatch.setattr(bridge, f"_{command}", dispatch)
        assert bridge.main([command]) == 0
    assert called == ["serve", "health", "export", "import", "mutate"]


@pytest.mark.parametrize(
    ("scenario", "mode", "final_outcome", "final_status"),
    [
        ("primary_vulnerable", "vulnerable", "VIOLATED", 200),
        ("primary_patched", "patched", "SATISFIED", 403),
        ("masked_response", "vulnerable", "SATISFIED", 200),
        ("mock_only_response", "vulnerable", "INCONCLUSIVE", 200),
        ("fresh_session", "vulnerable", "SATISFIED", 403),
        ("same_tenant_document", "vulnerable", "SATISFIED", 200),
    ],
)
def test_m5_replay_traverses_every_action_and_emits_bound_witnesses(
    monkeypatch: pytest.MonkeyPatch,
    scenario: str,
    mode: str,
    final_outcome: str,
    final_status: int,
) -> None:
    request = _m5_request(scenario, mode)
    current = _archive()
    restorations: list[dict[str, object]] = []

    def archive() -> dict[str, object]:
        return current

    def restore(next_archive: dict[str, object]) -> None:
        nonlocal current
        restorations.append(next_archive)
        current = next_archive

    output = _Output()
    monkeypatch.setattr(bridge, "_archive", archive)
    monkeypatch.setattr(bridge, "_restore", restore)
    monkeypatch.setattr(sys, "stdin", _Input(bridge._canonical(request)))
    monkeypatch.setattr(sys, "stdout", output)

    assert bridge.main(["m5-replay"]) == 0

    receipt = json.loads(output.text)
    steps = receipt["steps"]
    assert receipt["accepted"] is True
    assert receipt["schema_version"] == "m5.1"
    assert len(steps) == len(bridge._M5_ROUTES[scenario])
    assert len(restorations) == len(steps)
    assert [step["step_id"] for step in steps] == [
        f"step.{sequence:02d}" for sequence in range(1, len(steps) + 1)
    ]
    assert steps[-1]["response_status"] == final_status
    assert steps[-1]["oracle_outcome"] == final_outcome
    assert all(step["before"] != step["after"] for step in steps)
    assert steps[0]["before"] == _archive()
    assert steps[-1]["after"] == restorations[-1]
    request_actions = cast(list[dict[str, object]], request["actions"])
    for sequence, (raw_action, step, restored) in enumerate(
        zip(request_actions, steps, restorations, strict=True), start=1
    ):
        assert isinstance(raw_action, dict)
        assert step["action_digest"] == raw_action["action_digest"]
        marker = step["after"]["components"]["cache"]["entries"]["sw:marker"]
        assert marker == bridge._m5_marker(raw_action, sequence=sequence)
        restored_value = cast(dict[str, Any], restored)
        assert restored_value["components"]["clock"] == bridge._clock_component(sequence)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value.update(extra=True), "request shape"),
        (lambda value: value.update(scenario="unknown"), "scenario"),
        (lambda value: value.update(mode="patched"), "scenario"),
        (lambda value: cast(list[object], value["actions"]).pop(), "scenario"),
        (
            lambda value: cast(dict[str, object], cast(list[object], value["actions"])[0]).update(
                extra=True
            ),
            "action shape",
        ),
        (
            lambda value: cast(dict[str, object], cast(list[object], value["actions"])[0]).update(
                envelope=[]
            ),
            "envelope is invalid",
        ),
        (
            lambda value: cast(
                dict[str, object],
                cast(dict[str, object], cast(list[object], value["actions"])[0])["envelope"],
            ).update(sequence=7),
            "outside the fixed provider scenario",
        ),
        (
            lambda value: cast(dict[str, object], cast(list[object], value["actions"])[0]).update(
                action_digest="sha256:" + ("0" * 64)
            ),
            "outside the fixed provider scenario",
        ),
    ],
)
def test_m5_replay_rejects_open_or_unbound_requests_before_provider_mutation(
    monkeypatch: pytest.MonkeyPatch,
    mutate: Callable[[dict[str, object]], object],
    message: str,
) -> None:
    request = _m5_request("same_tenant_document", "vulnerable")
    mutate(request)
    monkeypatch.setattr(sys, "stdin", _Input(bridge._canonical(request)))
    monkeypatch.setattr(bridge, "_restore", lambda _value: pytest.fail("provider state changed"))

    with pytest.raises(ValueError, match=message):
        bridge._m5_replay()


def test_m5_replay_fails_closed_when_provider_state_does_not_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _m5_request("same_tenant_document", "vulnerable")
    current = _archive()
    monkeypatch.setattr(sys, "stdin", _Input(bridge._canonical(request)))
    monkeypatch.setattr(bridge, "_archive", lambda: current)
    monkeypatch.setattr(bridge, "_restore", lambda _value: None)

    with pytest.raises(bridge.ProviderBridgeError, match="provider state did not change"):
        bridge._m5_replay()


def test_command_readback_mismatches_and_mutation_shape_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "stdin", _Input(bridge._canonical(_archive("requested", tick=1))))
    monkeypatch.setattr(bridge, "_restore", lambda _value: None)
    monkeypatch.setattr(bridge, "_archive", lambda: _archive("different", tick=2))
    with pytest.raises(bridge.ProviderBridgeError, match="restore identity verification"):
        bridge._import()

    monkeypatch.setattr(sys, "stdin", _Input(b'{"wrong":true}'))
    with pytest.raises(ValueError, match="mutation request shape"):
        bridge._mutate()

    monkeypatch.setattr(sys, "stdin", _Input(b'{"marker":"requested","tick":1}'))
    with pytest.raises(bridge.ProviderBridgeError, match="mutation identity verification"):
        bridge._mutate()


@pytest.mark.filterwarnings("ignore:.*found in sys.modules.*:RuntimeWarning")
@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b"", "fixed real-provider operation failed\n"),
        (
            bridge._canonical(_archive()),
            "fixed real-provider operation failed:restore-database-failed\n",
        ),
    ],
)
def test_main_module_redacts_provider_and_value_errors(
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
    expected: str,
) -> None:
    module_name = "stateweaver.adapters.docker_compose.real_provider_bridge"
    monkeypatch.setattr(sys, "argv", [module_name, "import"])
    monkeypatch.setattr(sys, "stdin", _Input(payload))
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("secret")),
    )
    stderr = io.StringIO()
    monkeypatch.setattr(sys, "stderr", stderr)
    with pytest.raises(SystemExit) as failure:
        runpy.run_module(module_name, run_name="__main__")
    assert failure.value.code == 65
    assert stderr.getvalue() == expected


def test_health_rejects_untrusted_provider_version_shapes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bridge, "_postgres_query", lambda _sql: ())
    monkeypatch.setattr(bridge, "_redis_command", lambda *_parts: "missing")
    monkeypatch.setattr(bridge, "_http_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(bridge, "_session_export", lambda: _components()["session"])
    monkeypatch.setattr(
        bridge,
        "_browser_roundtrip",
        lambda _marker: (cast(dict[str, object], _components()["session"]), "140.0"),
    )
    monkeypatch.setattr(bridge, "_filesystem_export", lambda: _components()["filesystem"])
    monkeypatch.setattr(bridge, "_clock_export", lambda: _components()["clock"])
    monkeypatch.setattr(bridge, "_queue_export", lambda: _components()["queue"])
    monkeypatch.setattr(bridge, "_cache_export", lambda: _components()["cache"])
    with pytest.raises(bridge.ProviderBridgeError, match="version discovery"):
        bridge._health()


@pytest.mark.parametrize(
    ("failed_component", "operation_name"),
    [
        ("database", "_database_import"),
        ("cache", "_cache_import"),
        ("queue", "_queue_import"),
        ("session", "_session_import"),
        ("filesystem", "_filesystem_import"),
        ("clock", "_clock_import"),
    ],
)
def test_restore_exports_only_closed_failure_stage(
    monkeypatch: pytest.MonkeyPatch,
    failed_component: str,
    operation_name: str,
) -> None:
    operation_names = (
        "_database_import",
        "_cache_import",
        "_queue_import",
        "_session_import",
        "_filesystem_import",
        "_clock_import",
    )

    def succeed(_component: dict[str, object]) -> None:
        return None

    def fail(_component: dict[str, object]) -> None:
        raise OSError("untrusted provider detail")

    for name in operation_names:
        monkeypatch.setattr(bridge, name, succeed)
    monkeypatch.setattr(bridge, operation_name, fail)
    with pytest.raises(
        bridge.ProviderBridgeError,
        match=rf"^restore-{failed_component}-failed$",
    ) as failure:
        bridge._restore(bridge._validate_archive(_archive()))
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None


def test_health_reports_only_provider_versions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bridge, "_postgres_query", lambda _sql: (("17.10",),))
    monkeypatch.setattr(bridge, "_redis_command", lambda *_parts: "redis_version:8.10.0\r\n")
    monkeypatch.setattr(
        bridge,
        "_http_json",
        lambda *_args, **_kwargs: {"rabbitmq_version": "4.3.4"},
    )
    monkeypatch.setattr(bridge, "_session_export", lambda: _components()["session"])
    monkeypatch.setattr(
        bridge,
        "_browser_roundtrip",
        lambda _marker: (cast(dict[str, object], _components()["session"]), "140.0"),
    )
    monkeypatch.setattr(bridge, "_filesystem_export", lambda: _components()["filesystem"])
    monkeypatch.setattr(bridge, "_clock_export", lambda: _components()["clock"])
    monkeypatch.setattr(bridge, "_queue_export", lambda: _components()["queue"])
    monkeypatch.setattr(bridge, "_cache_export", lambda: _components()["cache"])
    output = _Output()
    monkeypatch.setattr(sys, "stdout", output)
    assert bridge._health() == 0
    assert json.loads(output.text) == {
        "healthy": True,
        "providers": {
            "browser": "140.0",
            "postgres": "17.10",
            "rabbitmq": "4.3.4",
            "redis": "8.10.0",
        },
    }
