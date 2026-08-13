"""Fixed in-container bridge over six real, local-only provider boundaries.

The bridge accepts only three closed commands.  It never accepts an address, path,
query, or command from its caller; every provider endpoint and mutation schema is
fixed by this repository-owned fixture.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import signal
import socket
import struct
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Final, Never, cast
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

_MAX_DOCUMENT_BYTES: Final = 1_048_576
_MAX_PROVIDER_REPLY_BYTES: Final = 262_144
_MAX_CHECKPOINT_BYTES: Final = 131_072
_MAX_SQL_BYTES: Final = 524_288
_SOCKET_TIMEOUT_SECONDS: Final = 8.0
_TARGET: Final = {"target_id": "real-provider-demo", "target_version": "1.0.0"}
_COMPONENTS: Final = ("filesystem", "database", "cache", "queue", "session", "clock")
_MARKER_RE: Final = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_CACHE_KEY: Final = "sw:marker"
_QUEUE_NAME: Final = "stateweaver"
_COOKIE_NAME: Final = "sw_marker"
_STORAGE_KEY: Final = "sw.marker"
_BASE_TIME: Final = datetime(2026, 1, 1, tzinfo=UTC)
_FILES: Final = {
    "marker.txt": Path("/state/filesystem/marker.txt"),
    "tenant.txt": Path("/state/filesystem/tenant.txt"),
}
_CLOCK_PATH: Final = Path("/state/clock/state.json")
_SESSION_PATH: Final = Path("/state/session/state.json")
_CHECKPOINT_SESSION_PATH: Final = Path("/state/session/checkpoints")
_CHECKPOINT_FILES_PATH: Final = Path("/state/filesystem/checkpoints")
_CHECKPOINT_CLOCK_PATH: Final = Path("/state/clock/checkpoints")
_PAGE_URL: Final = "http://provider-bridge:8080/session"
_RABBIT_AUTHORIZATION: Final = "Basic " + base64.b64encode(b"swm2:swm2").decode("ascii")
_PUBLIC_FAILURE_CODES: Final = frozenset(f"restore-{component}-failed" for component in _COMPONENTS)
_M5_PRIMARY_ROUTES: Final = (
    ("POST", "/v1/lab/session/retain", "identity:test_user_a"),
    ("POST", "/v1/lab/authorization-cache/prime", "identity:test_user_a"),
    ("POST", "/v1/lab/admin/role-downgrade", "identity:test_admin"),
    ("POST", "/v1/lab/admin/queue/defer", "identity:test_admin"),
    ("POST", "/v1/lab/references/publish", "identity:test_user_b"),
    ("POST", "/v1/lab/references/claim", "identity:test_user_a"),
    ("POST", "/v1/lab/admin/clock/advance", "identity:test_admin"),
    ("GET", "/v1/lab/documents/doc-b-protected", "identity:test_user_a"),
)
_M5_ROUTES: Final = {
    "primary_vulnerable": _M5_PRIMARY_ROUTES,
    "primary_patched": _M5_PRIMARY_ROUTES,
    "masked_response": (("GET", "/v1/lab/decoys/masked/doc-b-protected", "identity:test_user_a"),),
    "mock_only_response": (
        ("GET", "/v1/lab/decoys/mock-policy/doc-b-protected", "identity:test_user_a"),
    ),
    "fresh_session": _M5_PRIMARY_ROUTES,
    "same_tenant_document": (("GET", "/v1/lab/documents/doc-a-owned", "identity:test_user_a"),),
}
_M5_BOUNDARIES: Final = {
    "primary_vulnerable": ("VIOLATED", 200),
    "primary_patched": ("SATISFIED", 403),
    "masked_response": ("SATISFIED", 200),
    "mock_only_response": ("INCONCLUSIVE", 200),
    "fresh_session": ("SATISFIED", 403),
    "same_tenant_document": ("SATISFIED", 200),
}
_M5_ARTIFACTS: Final = {
    "primary_vulnerable": (
        "artifact:lab-action/7eb1f0de12757921da8a4c72e6205da5c9eee1e91734f4366654944f63bbdb1c",
        "artifact:lab-action/b0ce666d62a32abda4c7d728015ad28c3ab8921076d6e809de07430b379f3529",
        "artifact:lab-action/eb306cd87f03c6effeefe57f28108524403b1a5b29879c2f6dcd2bdb1031f4ac",
        "artifact:lab-action/717cf353f0d600b8219233ff9d8c3b550d7d7732be451ba927ea69980377a23d",
        "artifact:lab-action/4239662eb56eacaf0f99ad44fbd07114e7a11dd7a8a22b0a2807187c96bddb6a",
        "artifact:lab-action/5561a3981cf6bd0787214e8df26bcdc920f94682a0cbf368f6551f6ba2caa1b9",
        "artifact:lab-action/c695724e7257cda434bc3af760f2c95c6076a62f19f0427bb1dbac412b828882",
        "artifact:lab-action/bfa39df7d04dfdb24507fff3bbe7a9737f9704aecbe91a0c0d7103dffc0db8a9",
    ),
    "primary_patched": (),
    "masked_response": (
        "artifact:lab-action/a26b4470b71167b2fd7366e88d17b14f31e161810f5795a21d058a8b2224b302",
    ),
    "mock_only_response": (
        "artifact:lab-action/1d321dfb30f46ada01af6fc3b8d7ecc1b6fc1c2210d9ea8c37ab6dfcc1259bf7",
    ),
    "fresh_session": (),
    "same_tenant_document": (
        "artifact:lab-action/8eb6a59216a2e0bcfbcf46a5af15e030cf144bf26fb703427ca17f31fd9c037d",
    ),
}
_M5_ARTIFACTS["primary_patched"] = _M5_ARTIFACTS["primary_vulnerable"]
_M5_ARTIFACTS["fresh_session"] = (
    *_M5_ARTIFACTS["primary_vulnerable"][:-1],
    "artifact:lab-action/23d872ae71058a53381dd529f18ee0cbd746601a5daac169d8fba8a9139d6877",
)


class ProviderBridgeError(RuntimeError):
    """A fixed provider failed or returned data outside the closed protocol."""


class ProviderCheckpointError(ProviderBridgeError):
    """The closed six-provider checkpoint boundary rejected an operation."""


class ProviderCheckpointConflictError(ProviderCheckpointError):
    """The PostgreSQL active-generation CAS pointer did not match."""


class ProviderCheckpointPoisonedError(ProviderCheckpointError):
    """A partial or inconsistent store is unavailable until reconstructed."""


class _ProviderCheckpointUnownedStageError(ProviderCheckpointError):
    """A competing writer owns a shard that this store must never delete."""


@dataclass(frozen=True)
class ProviderCheckpointObservation:
    provider: str
    generation: str
    checkpoint_digest: str
    storage_digest: str


@dataclass(frozen=True)
class ProviderCheckpointCapture:
    generation: str
    checkpoint_digest: str
    checkpoint_bytes: bytes
    observations: tuple[ProviderCheckpointObservation, ...]


def _canonical(value: object) -> bytes:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if not encoded or len(encoded) > _MAX_DOCUMENT_BYTES:
        raise ValueError("provider document exceeds its fixed size boundary")
    return encoded


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
    if not raw or len(raw) > _MAX_DOCUMENT_BYTES:
        raise ValueError("provider document exceeds its fixed size boundary")
    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )


def _require_marker(value: object) -> str:
    if not isinstance(value, str) or _MARKER_RE.fullmatch(value) is None:
        raise ValueError("provider marker is invalid")
    return value


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".next")
    with temporary.open("wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)


def _read_exact(connection: socket.socket, length: int) -> bytes:
    if length < 0 or length > _MAX_PROVIDER_REPLY_BYTES:
        raise ProviderBridgeError("provider reply exceeded its fixed boundary")
    output = bytearray()
    while len(output) < length:
        chunk = connection.recv(length - len(output))
        if not chunk:
            raise ProviderBridgeError("provider closed a reply early")
        output.extend(chunk)
    return bytes(output)


def _postgres_message(connection: socket.socket) -> tuple[bytes, bytes]:
    kind = _read_exact(connection, 1)
    length = struct.unpack("!I", _read_exact(connection, 4))[0]
    if length < 4 or length - 4 > _MAX_PROVIDER_REPLY_BYTES:
        raise ProviderBridgeError("PostgreSQL reply exceeded its fixed boundary")
    return kind, _read_exact(connection, length - 4)


def _postgres_query(sql: str) -> tuple[tuple[str | None, ...], ...]:
    if not sql or len(sql.encode("ascii")) > _MAX_SQL_BYTES or "\x00" in sql:
        raise ProviderBridgeError("fixed PostgreSQL query is invalid")
    with socket.create_connection(
        ("postgres", 5432), timeout=_SOCKET_TIMEOUT_SECONDS
    ) as connection:
        connection.settimeout(_SOCKET_TIMEOUT_SECONDS)
        parameters = b"user\0stateweaver\0database\0stateweaver\0client_encoding\0UTF8\0\0"
        connection.sendall(struct.pack("!II", len(parameters) + 8, 196608) + parameters)
        ready = False
        while not ready:
            kind, payload = _postgres_message(connection)
            if kind == b"R":
                if len(payload) != 4 or struct.unpack("!I", payload)[0] != 0:
                    raise ProviderBridgeError("PostgreSQL authentication was not fixed trust")
            elif kind == b"E":
                raise ProviderBridgeError("PostgreSQL rejected the fixed connection")
            elif kind == b"Z":
                ready = True
            elif kind not in {b"K", b"N", b"S"}:
                raise ProviderBridgeError("PostgreSQL startup reply was invalid")

        query = sql.encode("ascii")
        connection.sendall(b"Q" + struct.pack("!I", len(query) + 5) + query + b"\0")
        rows: list[tuple[str | None, ...]] = []
        field_count: int | None = None
        while True:
            kind, payload = _postgres_message(connection)
            if kind == b"T":
                if len(payload) < 2:
                    raise ProviderBridgeError("PostgreSQL row metadata was invalid")
                field_count = struct.unpack("!H", payload[:2])[0]
                cursor = 2
                for _ in range(field_count):
                    terminator = payload.find(b"\0", cursor)
                    if terminator < cursor or terminator + 19 > len(payload):
                        raise ProviderBridgeError("PostgreSQL row metadata was invalid")
                    cursor = terminator + 19
                if cursor != len(payload):
                    raise ProviderBridgeError("PostgreSQL row metadata was invalid")
            elif kind == b"D":
                if field_count is None or len(payload) < 2:
                    raise ProviderBridgeError("PostgreSQL row reply was invalid")
                count = struct.unpack("!H", payload[:2])[0]
                if count != field_count:
                    raise ProviderBridgeError("PostgreSQL row reply was invalid")
                cursor = 2
                values: list[str | None] = []
                for _ in range(count):
                    if cursor + 4 > len(payload):
                        raise ProviderBridgeError("PostgreSQL row reply was invalid")
                    size = struct.unpack("!i", payload[cursor : cursor + 4])[0]
                    cursor += 4
                    if size == -1:
                        values.append(None)
                        continue
                    if size < 0 or cursor + size > len(payload):
                        raise ProviderBridgeError("PostgreSQL row reply was invalid")
                    try:
                        values.append(payload[cursor : cursor + size].decode("utf-8"))
                    except UnicodeDecodeError:
                        raise ProviderBridgeError("PostgreSQL text reply was invalid") from None
                    cursor += size
                if cursor != len(payload):
                    raise ProviderBridgeError("PostgreSQL row reply was invalid")
                rows.append(tuple(values))
            elif kind == b"E":
                raise ProviderBridgeError("PostgreSQL rejected the fixed query")
            elif kind == b"Z":
                connection.sendall(b"X\x00\x00\x00\x04")
                return tuple(rows)
            elif kind not in {b"C", b"I", b"N"}:
                raise ProviderBridgeError("PostgreSQL query reply was invalid")


def _database_export() -> dict[str, object]:
    rows = _postgres_query("SELECT id::text, tenant, value FROM sw_state ORDER BY id;")
    output: list[dict[str, object]] = []
    for row in rows:
        if len(row) != 3 or None in row:
            raise ProviderBridgeError("PostgreSQL state row was invalid")
        assert row[0] is not None and row[1] is not None and row[2] is not None
        try:
            identifier = int(row[0])
        except ValueError:
            raise ProviderBridgeError("PostgreSQL state row was invalid") from None
        output.append(
            {
                "id": identifier,
                "tenant": _require_marker(row[1]),
                "value": _require_marker(row[2]),
            }
        )
    return _validate_database({"rows": output})


def _database_import(component: dict[str, object]) -> None:
    validated = _validate_database(component)
    rows = cast(list[dict[str, object]], validated["rows"])
    values = ",".join(f"({row['id']},'{row['tenant']}','{row['value']}')" for row in rows)
    _postgres_query(
        f"BEGIN;TRUNCATE sw_state;INSERT INTO sw_state(id,tenant,value) VALUES {values};COMMIT;"
    )
    if _database_export() != validated:
        raise ProviderBridgeError("PostgreSQL restore read-back differed")


def _redis_read(connection: socket.socket) -> object:
    prefix = _read_exact(connection, 1)

    def line() -> bytes:
        output = bytearray()
        while True:
            value = _read_exact(connection, 1)
            output.extend(value)
            if output.endswith(b"\r\n"):
                return bytes(output[:-2])
            if len(output) > _MAX_PROVIDER_REPLY_BYTES:
                raise ProviderBridgeError("Redis reply exceeded its fixed boundary")

    if prefix == b"+":
        return line().decode("utf-8")
    if prefix == b"-":
        line()
        raise ProviderBridgeError("Redis rejected the fixed command")
    if prefix == b":":
        return int(line())
    if prefix == b"$":
        length = int(line())
        if length == -1:
            return None
        value = _read_exact(connection, length)
        if _read_exact(connection, 2) != b"\r\n":
            raise ProviderBridgeError("Redis bulk reply was invalid")
        return value.decode("utf-8")
    if prefix == b"*":
        length = int(line())
        if length < 0 or length > 64:
            raise ProviderBridgeError("Redis array reply was invalid")
        return [_redis_read(connection) for _ in range(length)]
    raise ProviderBridgeError("Redis reply type was invalid")


def _redis_command(*parts: str) -> object:
    if (
        not parts
        or len(parts) > 8
        or any(len(part.encode("utf-8")) > _MAX_PROVIDER_REPLY_BYTES for part in parts)
    ):
        raise ProviderBridgeError("fixed Redis command is invalid")
    payload = [f"*{len(parts)}\r\n".encode()]
    for part in parts:
        encoded = part.encode("utf-8")
        payload.extend((f"${len(encoded)}\r\n".encode(), encoded, b"\r\n"))
    with socket.create_connection(("redis", 6379), timeout=_SOCKET_TIMEOUT_SECONDS) as connection:
        connection.settimeout(_SOCKET_TIMEOUT_SECONDS)
        connection.sendall(b"".join(payload))
        return _redis_read(connection)


def _cache_export() -> dict[str, object]:
    value = _redis_command("GET", _CACHE_KEY)
    if value is None:
        value = "baseline"
        if _redis_command("SET", _CACHE_KEY, value) != "OK":
            raise ProviderBridgeError("Redis seed was not acknowledged")
    return _validate_cache({"entries": {_CACHE_KEY: _require_marker(value)}})


def _cache_import(component: dict[str, object]) -> None:
    validated = _validate_cache(component)
    entries = cast(dict[str, str], validated["entries"])
    if _redis_command("FLUSHDB") != "OK":
        raise ProviderBridgeError("Redis reset was not acknowledged")
    if _redis_command("SET", _CACHE_KEY, entries[_CACHE_KEY]) != "OK":
        raise ProviderBridgeError("Redis restore was not acknowledged")
    if _cache_export() != validated:
        raise ProviderBridgeError("Redis restore read-back differed")


def _http_json_response(
    method: str,
    url: str,
    payload: object | None = None,
    *,
    authorization: str | None = None,
    accepted_statuses: tuple[int, ...] = (200,),
) -> tuple[int, object]:
    content = None if payload is None else _canonical(payload)
    headers = {"Accept": "application/json"}
    if content is not None:
        headers["Content-Type"] = "application/json"
    if authorization is not None:
        headers["Authorization"] = authorization
    request = Request(url, data=content, headers=headers, method=method)
    try:
        with urlopen(request, timeout=_SOCKET_TIMEOUT_SECONDS) as response:
            if response.status not in accepted_statuses:
                raise ProviderBridgeError("provider HTTP status was rejected")
            status = response.status
            raw = response.read(_MAX_PROVIDER_REPLY_BYTES + 1)
    except HTTPError as error:
        if error.code in accepted_statuses:
            status = error.code
            raw = error.read(_MAX_PROVIDER_REPLY_BYTES + 1)
        else:
            raise ProviderBridgeError("provider HTTP request failed") from None
    except (OSError, URLError):
        raise ProviderBridgeError("provider HTTP request failed") from None
    if len(raw) > _MAX_PROVIDER_REPLY_BYTES:
        raise ProviderBridgeError("provider HTTP reply exceeded its fixed boundary")
    if not raw:
        return status, None
    try:
        return status, _parse(raw)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        raise ProviderBridgeError("provider HTTP reply was invalid") from None


def _http_json(
    method: str,
    url: str,
    payload: object | None = None,
    *,
    authorization: str | None = None,
    accepted_statuses: tuple[int, ...] = (200,),
) -> object:
    return _http_json_response(
        method,
        url,
        payload,
        authorization=authorization,
        accepted_statuses=accepted_statuses,
    )[1]


def _rabbit_path() -> str:
    return f"http://rabbitmq:15672/api/queues/%2F/{quote(_QUEUE_NAME, safe='')}"


def _queue_create() -> None:
    response = _http_json(
        "PUT",
        _rabbit_path(),
        {"auto_delete": False, "durable": True, "arguments": {}},
        authorization=_RABBIT_AUTHORIZATION,
        accepted_statuses=(201, 204),
    )
    if response is not None:
        raise ProviderBridgeError("RabbitMQ queue creation reply was invalid")


def _queue_publish(marker: str) -> None:
    response = _http_json(
        "POST",
        "http://rabbitmq:15672/api/exchanges/%2F/amq.default/publish",
        {
            "properties": {"content_type": "text/plain", "delivery_mode": 2},
            "routing_key": _QUEUE_NAME,
            "payload": marker,
            "payload_encoding": "string",
        },
        authorization=_RABBIT_AUTHORIZATION,
    )
    if response != {"routed": True}:
        raise ProviderBridgeError("RabbitMQ publish was not routed")


def _queue_export() -> dict[str, object]:
    try:
        queue = _http_json(
            "GET",
            _rabbit_path(),
            authorization=_RABBIT_AUTHORIZATION,
        )
    except ProviderBridgeError:
        _queue_create()
        _queue_publish("baseline")
        queue = _http_json(
            "GET",
            _rabbit_path(),
            authorization=_RABBIT_AUTHORIZATION,
        )
    if not isinstance(queue, dict):
        raise ProviderBridgeError("RabbitMQ queue metadata was invalid")
    reply = _http_json(
        "POST",
        _rabbit_path() + "/get",
        {"count": 2, "ackmode": "ack_requeue_true", "encoding": "auto", "truncate": 128},
        authorization=_RABBIT_AUTHORIZATION,
    )
    if not isinstance(reply, list) or len(reply) != 1 or not isinstance(reply[0], dict):
        raise ProviderBridgeError("RabbitMQ queue capture was invalid")
    marker = _require_marker(reply[0].get("payload"))
    return _validate_queue({"messages": [marker]})


def _queue_import(component: dict[str, object]) -> None:
    validated = _validate_queue(component)
    try:
        response = _http_json(
            "DELETE",
            _rabbit_path(),
            authorization=_RABBIT_AUTHORIZATION,
            accepted_statuses=(204, 404),
        )
        if response is not None:
            raise ProviderBridgeError("RabbitMQ queue deletion reply was invalid")
    except ProviderBridgeError:
        raise
    _queue_create()
    messages = cast(list[str], validated["messages"])
    _queue_publish(messages[0])
    if _queue_export() != validated:
        raise ProviderBridgeError("RabbitMQ restore read-back differed")


def _webdriver(method: str, path: str, payload: object | None = None) -> object:
    response = _http_json(method, f"http://selenium:4444{path}", payload)
    if not isinstance(response, dict) or set(response) != {"value"}:
        raise ProviderBridgeError("WebDriver reply was invalid")
    value = response["value"]
    if isinstance(value, dict) and value.get("error"):
        raise ProviderBridgeError("WebDriver rejected the fixed operation")
    return value


@contextmanager
def _browser_session() -> Iterator[tuple[str, str]]:
    value = _webdriver(
        "POST",
        "/session",
        {
            "capabilities": {
                "alwaysMatch": {
                    "browserName": "chrome",
                    "goog:chromeOptions": {
                        "args": [
                            "--headless=new",
                            "--no-sandbox",
                            "--disable-dev-shm-usage",
                            "--disable-gpu",
                        ]
                    },
                }
            }
        },
    )
    if not isinstance(value, dict):
        raise ProviderBridgeError("WebDriver session reply was invalid")
    session_id = value.get("sessionId")
    capabilities = value.get("capabilities")
    if (
        not isinstance(session_id, str)
        or not re.fullmatch(r"[0-9a-f-]{16,64}", session_id)
        or not isinstance(capabilities, dict)
        or not isinstance(capabilities.get("browserVersion"), str)
    ):
        raise ProviderBridgeError("WebDriver session identity was invalid")
    try:
        _webdriver("POST", f"/session/{session_id}/url", {"url": _PAGE_URL})
        yield session_id, capabilities["browserVersion"]
    finally:
        with suppress(ProviderBridgeError):
            _webdriver("DELETE", f"/session/{session_id}")


def _browser_roundtrip(marker: str) -> tuple[dict[str, object], str]:
    marker = _require_marker(marker)
    with _browser_session() as session:
        session_id, browser_version = session
        _webdriver("DELETE", f"/session/{session_id}/cookie")
        _webdriver(
            "POST",
            f"/session/{session_id}/cookie",
            {
                "cookie": {
                    "name": _COOKIE_NAME,
                    "value": marker,
                    "path": "/",
                    "secure": False,
                    "httpOnly": True,
                    "sameSite": "Lax",
                }
            },
        )
        _webdriver(
            "POST",
            f"/session/{session_id}/execute/sync",
            {
                "script": (
                    "window.localStorage.removeItem(arguments[0]);"
                    "window.localStorage.setItem(arguments[0],arguments[1]);return true;"
                ),
                "args": [_STORAGE_KEY, marker],
            },
        )
        cookie = _webdriver("GET", f"/session/{session_id}/cookie/{_COOKIE_NAME}")
        storage = _webdriver(
            "POST",
            f"/session/{session_id}/execute/sync",
            {
                "script": "return window.localStorage.getItem(arguments[0]);",
                "args": [_STORAGE_KEY],
            },
        )
    if (
        not isinstance(cookie, dict)
        or cookie.get("name") != _COOKIE_NAME
        or cookie.get("value") != marker
        or storage != marker
    ):
        raise ProviderBridgeError("browser session read-back differed")
    return (
        {
            "cookies": [{"name": _COOKIE_NAME, "path": "/", "value": marker}],
            "local_storage": {_STORAGE_KEY: marker},
        },
        browser_version,
    )


def _session_marker(component: dict[str, object]) -> str:
    validated = _validate_session(component)
    cookies = cast(list[dict[str, str]], validated["cookies"])
    return cookies[0]["value"]


def _session_export() -> dict[str, object]:
    if not _SESSION_PATH.exists():
        _atomic_write(_SESSION_PATH, _canonical({"marker": "baseline"}))
    value = _parse(_SESSION_PATH.read_bytes())
    if not isinstance(value, dict) or set(value) != {"marker"}:
        raise ProviderBridgeError("browser session state file was invalid")
    component, _ = _browser_roundtrip(_require_marker(value["marker"]))
    return _validate_session(component)


def _session_import(component: dict[str, object]) -> None:
    validated = _validate_session(component)
    marker = _session_marker(validated)
    observed, _ = _browser_roundtrip(marker)
    if observed != validated:
        raise ProviderBridgeError("browser session restore read-back differed")
    _atomic_write(_SESSION_PATH, _canonical({"marker": marker}))


def _filesystem_export() -> dict[str, object]:
    for name, path in _FILES.items():
        if not path.exists():
            _atomic_write(path, b"baseline" if name == "marker.txt" else b"alpha")
    files: dict[str, str] = {}
    for name, path in _FILES.items():
        try:
            content = path.read_bytes()
            value = content.decode("ascii")
        except (OSError, UnicodeDecodeError):
            raise ProviderBridgeError("filesystem provider content was invalid") from None
        files[name] = _require_marker(value)
    return _validate_filesystem({"files": files})


def _filesystem_import(component: dict[str, object]) -> None:
    validated = _validate_filesystem(component)
    files = cast(dict[str, str], validated["files"])
    for name, path in _FILES.items():
        _atomic_write(path, files[name].encode("ascii"))
    if _filesystem_export() != validated:
        raise ProviderBridgeError("filesystem restore read-back differed")


def _clock_component(tick: int) -> dict[str, object]:
    timestamp = _BASE_TIME + timedelta(seconds=tick)
    return {
        "iso8601": timestamp.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "tick": tick,
    }


def _clock_export() -> dict[str, object]:
    if not _CLOCK_PATH.exists():
        _atomic_write(_CLOCK_PATH, _canonical(_clock_component(0)))
    value = _parse(_CLOCK_PATH.read_bytes())
    if not isinstance(value, dict):
        raise ProviderBridgeError("controlled-clock state was invalid")
    return _validate_clock(value)


def _clock_import(component: dict[str, object]) -> None:
    validated = _validate_clock(component)
    _atomic_write(_CLOCK_PATH, _canonical(validated))
    if _clock_export() != validated:
        raise ProviderBridgeError("controlled-clock restore read-back differed")


def _validate_filesystem(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {"files"}:
        raise ValueError("filesystem component shape is invalid")
    files = value["files"]
    if not isinstance(files, dict) or set(files) != set(_FILES):
        raise ValueError("filesystem component coverage is invalid")
    return {"files": {name: _require_marker(files[name]) for name in sorted(_FILES)}}


def _validate_database(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {"rows"}:
        raise ValueError("database component shape is invalid")
    rows = value["rows"]
    if not isinstance(rows, list) or not rows or len(rows) > 16:
        raise ValueError("database row coverage is invalid")
    output: list[dict[str, object]] = []
    identifiers: set[int] = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"id", "tenant", "value"}:
            raise ValueError("database row shape is invalid")
        identifier = row["id"]
        if (
            not isinstance(identifier, int)
            or isinstance(identifier, bool)
            or not 1 <= identifier <= 16
            or identifier in identifiers
        ):
            raise ValueError("database row identity is invalid")
        identifiers.add(identifier)
        output.append(
            {
                "id": identifier,
                "tenant": _require_marker(row["tenant"]),
                "value": _require_marker(row["value"]),
            }
        )
    return {"rows": sorted(output, key=lambda item: cast(int, item["id"]))}


def _validate_cache(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {"entries"}:
        raise ValueError("cache component shape is invalid")
    entries = value["entries"]
    if not isinstance(entries, dict) or set(entries) != {_CACHE_KEY}:
        raise ValueError("cache component coverage is invalid")
    return {"entries": {_CACHE_KEY: _require_marker(entries[_CACHE_KEY])}}


def _validate_queue(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {"messages"}:
        raise ValueError("queue component shape is invalid")
    messages = value["messages"]
    if not isinstance(messages, list) or len(messages) != 1:
        raise ValueError("queue message coverage is invalid")
    return {"messages": [_require_marker(messages[0])]}


def _validate_session(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {"cookies", "local_storage"}:
        raise ValueError("browser-session component shape is invalid")
    cookies = value["cookies"]
    storage = value["local_storage"]
    if not isinstance(cookies, list) or len(cookies) != 1 or not isinstance(cookies[0], dict):
        raise ValueError("browser-session cookie coverage is invalid")
    cookie = cookies[0]
    if set(cookie) != {"name", "path", "value"} or cookie.get("name") != _COOKIE_NAME:
        raise ValueError("browser-session cookie shape is invalid")
    if cookie.get("path") != "/":
        raise ValueError("browser-session cookie path is invalid")
    if not isinstance(storage, dict) or set(storage) != {_STORAGE_KEY}:
        raise ValueError("browser-session storage coverage is invalid")
    cookie_value = _require_marker(cookie["value"])
    storage_value = _require_marker(storage[_STORAGE_KEY])
    if cookie_value != storage_value:
        raise ValueError("browser-session providers disagree")
    return {
        "cookies": [{"name": _COOKIE_NAME, "path": "/", "value": cookie_value}],
        "local_storage": {_STORAGE_KEY: storage_value},
    }


def _validate_clock(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {"iso8601", "tick"}:
        raise ValueError("controlled-clock component shape is invalid")
    tick = value["tick"]
    if not isinstance(tick, int) or isinstance(tick, bool) or not 0 <= tick <= 1_000_000:
        raise ValueError("controlled-clock tick is invalid")
    expected = _clock_component(tick)
    if value != expected:
        raise ValueError("controlled-clock timestamp is not derived from its tick")
    return expected


def _validate_archive(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {"schema_version", "target", "components"}:
        raise ValueError("real-provider archive shape is invalid")
    if value["schema_version"] != "2.0" or value["target"] != _TARGET:
        raise ValueError("real-provider archive binding is invalid")
    components = value["components"]
    if not isinstance(components, dict) or set(components) != set(_COMPONENTS):
        raise ValueError("real-provider archive coverage is invalid")
    return {
        "schema_version": "2.0",
        "target": dict(_TARGET),
        "components": {
            "cache": _validate_cache(components["cache"]),
            "clock": _validate_clock(components["clock"]),
            "database": _validate_database(components["database"]),
            "filesystem": _validate_filesystem(components["filesystem"]),
            "queue": _validate_queue(components["queue"]),
            "session": _validate_session(components["session"]),
        },
    }


def _archive() -> dict[str, object]:
    return _validate_archive(
        {
            "schema_version": "2.0",
            "target": dict(_TARGET),
            "components": {
                "filesystem": _filesystem_export(),
                "database": _database_export(),
                "cache": _cache_export(),
                "queue": _queue_export(),
                "session": _session_export(),
                "clock": _clock_export(),
            },
        }
    )


def _restore(value: dict[str, object]) -> None:
    components = cast(dict[str, dict[str, object]], value["components"])
    operations = (
        ("database", _database_import),
        ("cache", _cache_import),
        ("queue", _queue_import),
        ("session", _session_import),
        ("filesystem", _filesystem_import),
        ("clock", _clock_import),
    )
    for component, operation in operations:
        failed = False
        try:
            operation(components[component])
        except Exception:
            # A provider may surface an HTTP, socket, filesystem, or protocol
            # exception containing untrusted data.  Export only this closed stage
            # code; never retain the exception as cause/context.
            failed = True
        if failed:
            raise ProviderBridgeError(f"restore-{component}-failed")


def _mutated_archive(marker: str, tick: int) -> dict[str, object]:
    marker = _require_marker(marker)
    if not isinstance(tick, int) or isinstance(tick, bool) or not 1 <= tick <= 1_000_000:
        raise ValueError("mutation tick is invalid")
    return _validate_archive(
        {
            "schema_version": "2.0",
            "target": dict(_TARGET),
            "components": {
                "filesystem": {"files": {"marker.txt": marker, "tenant.txt": "alpha"}},
                "database": {"rows": [{"id": 1, "tenant": "alpha", "value": marker}]},
                "cache": {"entries": {_CACHE_KEY: marker}},
                "queue": {"messages": [marker]},
                "session": {
                    "cookies": [{"name": _COOKIE_NAME, "path": "/", "value": marker}],
                    "local_storage": {_STORAGE_KEY: marker},
                },
                "clock": _clock_component(tick),
            },
        }
    )


_CHECKPOINT_PROVIDERS: Final = (
    "postgres",
    "redis",
    "rabbitmq",
    "browser_session",
    "filesystem",
    "clock",
)
_CHECKPOINT_SCHEMA: Final = "stateweaver-lab-checkpoint-v1"
_CHECKPOINT_KEYS: Final = {
    "schema_version",
    "generation",
    "mode",
    "seed",
    "state",
    "state_fingerprint",
    "checkpoint_digest",
}
_GENERATION_RE: Final = re.compile(r"^[0-9a-f]{64}$")
_SHA256_RE: Final = re.compile(r"^sha256:[0-9a-f]{64}$")


def _checkpoint_canonical(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise ProviderCheckpointError("checkpoint-invalid") from None
    if not encoded or len(encoded) > _MAX_CHECKPOINT_BYTES:
        raise ProviderCheckpointError("checkpoint-size-invalid")
    return encoded


def _checkpoint_hash(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _validate_checkpoint_bytes(raw: bytes) -> tuple[bytes, str, str]:
    """Recheck only the sealed storage binding, not LabState semantics."""

    if not raw or len(raw) > _MAX_CHECKPOINT_BYTES:
        raise ProviderCheckpointError("checkpoint-size-invalid")
    try:
        value = _parse(raw)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        raise ProviderCheckpointError("checkpoint-invalid") from None
    if not isinstance(value, dict) or set(value) != _CHECKPOINT_KEYS:
        raise ProviderCheckpointError("checkpoint-shape-invalid")
    generation = value["generation"]
    checkpoint_digest = value["checkpoint_digest"]
    if (
        value["schema_version"] != _CHECKPOINT_SCHEMA
        or value["mode"] not in {"vulnerable", "patched"}
        or value["seed"] != "m0-canonical-v1"
        or not isinstance(value["state"], dict)
        or not isinstance(generation, str)
        or _GENERATION_RE.fullmatch(generation) is None
        or not isinstance(value["state_fingerprint"], str)
        or _SHA256_RE.fullmatch(value["state_fingerprint"]) is None
        or not isinstance(checkpoint_digest, str)
        or _SHA256_RE.fullmatch(checkpoint_digest) is None
    ):
        raise ProviderCheckpointError("checkpoint-binding-invalid")
    if _checkpoint_canonical(value) != raw:
        raise ProviderCheckpointError("checkpoint-noncanonical")
    generation_payload = {
        key: item for key, item in value.items() if key not in {"generation", "checkpoint_digest"}
    }
    if hashlib.sha256(_checkpoint_canonical(generation_payload)).hexdigest() != generation:
        raise ProviderCheckpointError("checkpoint-generation-invalid")
    digest_payload = {key: item for key, item in value.items() if key != "checkpoint_digest"}
    if _checkpoint_hash(_checkpoint_canonical(digest_payload)) != checkpoint_digest:
        raise ProviderCheckpointError("checkpoint-digest-invalid")
    return raw, generation, checkpoint_digest


def _checkpoint_encoded(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _checkpoint_decoded(value: object) -> bytes:
    if not isinstance(value, str) or len(value) > 174_764:
        raise ProviderCheckpointError("checkpoint-storage-invalid")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise ProviderCheckpointError("checkpoint-storage-invalid") from None


def _checkpoint_pg_read(generation: str) -> bytes | None:
    rows = _postgres_query(
        f"SELECT checkpoint_base64 FROM sw_lab_checkpoint WHERE generation='{generation}';"
    )
    if not rows:
        return None
    if len(rows) != 1 or len(rows[0]) != 1 or rows[0][0] is None:
        raise ProviderCheckpointError("checkpoint-postgres-invalid")
    return _checkpoint_decoded(rows[0][0])


def _checkpoint_pg_stage(raw: bytes, generation: str, digest: str) -> bool:
    encoded = _checkpoint_encoded(raw)
    storage_digest = _checkpoint_hash(raw)
    rows = _postgres_query(
        "INSERT INTO sw_lab_checkpoint"
        "(generation,checkpoint_digest,storage_digest,checkpoint_base64) VALUES "
        f"('{generation}','{digest}','{storage_digest}','{encoded}') "
        "ON CONFLICT (generation) DO NOTHING RETURNING generation;"
    )
    if len(rows) > 1 or (rows and rows != ((generation,),)):
        raise ProviderCheckpointError("checkpoint-postgres-invalid")
    if _checkpoint_pg_read(generation) != raw:
        raise ProviderCheckpointError("checkpoint-postgres-readback-failed")
    return bool(rows)


def _checkpoint_pg_delete(generation: str) -> None:
    _postgres_query(f"DELETE FROM sw_lab_checkpoint WHERE generation='{generation}';")


def _checkpoint_pg_active() -> str | None:
    rows = _postgres_query(
        "SELECT active_generation FROM sw_lab_checkpoint_active WHERE singleton=true;"
    )
    if len(rows) != 1 or len(rows[0]) != 1:
        raise ProviderCheckpointError("checkpoint-active-pointer-invalid")
    value = rows[0][0]
    if value is not None and _GENERATION_RE.fullmatch(value) is None:
        raise ProviderCheckpointError("checkpoint-active-pointer-invalid")
    return value


def _checkpoint_pg_cas(expected: str | None, next_generation: str) -> None:
    condition = (
        "active_generation IS NULL" if expected is None else f"active_generation='{expected}'"
    )
    rows = _postgres_query(
        "BEGIN;UPDATE sw_lab_checkpoint_active "
        f"SET active_generation='{next_generation}' WHERE singleton=true AND {condition} "
        f"AND EXISTS(SELECT 1 FROM sw_lab_checkpoint WHERE generation='{next_generation}') "
        "RETURNING active_generation;COMMIT;"
    )
    if rows != ((next_generation,),):
        raise ProviderCheckpointConflictError("checkpoint-cas-conflict")


def _checkpoint_redis_key(generation: str) -> str:
    return f"sw:lab:checkpoint:{generation}"


def _checkpoint_redis_read(generation: str) -> bytes | None:
    value = _redis_command("GET", _checkpoint_redis_key(generation))
    return None if value is None else _checkpoint_decoded(value)


def _checkpoint_redis_stage(raw: bytes, generation: str, _digest: str) -> bool:
    reply = _redis_command("SET", _checkpoint_redis_key(generation), _checkpoint_encoded(raw), "NX")
    if reply not in {"OK", None}:
        raise ProviderCheckpointError("checkpoint-redis-invalid")
    if _checkpoint_redis_read(generation) != raw:
        raise ProviderCheckpointError("checkpoint-redis-readback-failed")
    return reply == "OK"


def _checkpoint_redis_delete(generation: str) -> None:
    reply = _redis_command("DEL", _checkpoint_redis_key(generation))
    if reply not in {0, 1}:
        raise ProviderCheckpointError("checkpoint-redis-cleanup-failed")


def _checkpoint_rabbit_name(generation: str) -> str:
    return f"sw-lab-checkpoint-{generation}"


def _checkpoint_rabbit_path(generation: str) -> str:
    return f"http://rabbitmq:15672/api/queues/%2F/{_checkpoint_rabbit_name(generation)}"


def _checkpoint_rabbit_read(generation: str) -> bytes | None:
    path = _checkpoint_rabbit_path(generation)
    status, metadata = _http_json_response(
        "GET",
        path,
        authorization=_RABBIT_AUTHORIZATION,
        accepted_statuses=(200, 404),
    )
    if status == 404:
        return None
    if not isinstance(metadata, dict):
        raise ProviderCheckpointError("checkpoint-rabbitmq-invalid")
    reply = _http_json(
        "POST",
        path + "/get",
        {
            "count": 2,
            "ackmode": "ack_requeue_true",
            "encoding": "auto",
            "truncate": 174_764,
        },
        authorization=_RABBIT_AUTHORIZATION,
    )
    if not isinstance(reply, list) or len(reply) != 1 or not isinstance(reply[0], dict):
        raise ProviderCheckpointError("checkpoint-rabbitmq-invalid")
    return _checkpoint_decoded(reply[0].get("payload"))


def _checkpoint_rabbit_stage(raw: bytes, generation: str, _digest: str) -> bool:
    existing = _checkpoint_rabbit_read(generation)
    if existing is not None:
        if existing != raw:
            raise ProviderCheckpointError("checkpoint-rabbitmq-readback-failed")
        return False
    status, response = _http_json_response(
        "PUT",
        _checkpoint_rabbit_path(generation),
        {"auto_delete": False, "durable": True, "arguments": {}},
        authorization=_RABBIT_AUTHORIZATION,
        accepted_statuses=(201, 204),
    )
    if response is not None:
        raise ProviderCheckpointError("checkpoint-rabbitmq-invalid")
    if status == 201:
        response = _http_json(
            "POST",
            "http://rabbitmq:15672/api/exchanges/%2F/amq.default/publish",
            {
                "properties": {"content_type": "text/plain", "delivery_mode": 2},
                "routing_key": _checkpoint_rabbit_name(generation),
                "payload": _checkpoint_encoded(raw),
                "payload_encoding": "string",
            },
            authorization=_RABBIT_AUTHORIZATION,
        )
        if response != {"routed": True}:
            raise ProviderCheckpointError("checkpoint-rabbitmq-invalid")
    try:
        observed = _checkpoint_rabbit_read(generation)
    except ProviderBridgeError:
        if status == 204:
            raise _ProviderCheckpointUnownedStageError("checkpoint-rabbitmq-unowned") from None
        raise
    if observed != raw:
        if status == 204:
            raise _ProviderCheckpointUnownedStageError("checkpoint-rabbitmq-unowned")
        raise ProviderCheckpointError("checkpoint-rabbitmq-readback-failed")
    return status == 201


def _checkpoint_rabbit_delete(generation: str) -> None:
    try:
        status, response = _http_json_response(
            "DELETE",
            _checkpoint_rabbit_path(generation),
            authorization=_RABBIT_AUTHORIZATION,
            accepted_statuses=(204, 404),
        )
    except ProviderBridgeError:
        raise ProviderCheckpointError("checkpoint-rabbitmq-cleanup-failed") from None
    if status == 204 and response is not None:
        raise ProviderCheckpointError("checkpoint-rabbitmq-cleanup-failed")


def _checkpoint_selenium_key(generation: str) -> str:
    return f"sw.checkpoint.{generation}"


def _checkpoint_selenium_roundtrip(raw: bytes, generation: str) -> bytes:
    with _browser_session() as (session_id, _version):
        accepted = _webdriver(
            "POST",
            f"/session/{session_id}/execute/sync",
            {
                "script": ("window.localStorage.setItem(arguments[0],arguments[1]);return true;"),
                "args": [_checkpoint_selenium_key(generation), _checkpoint_encoded(raw)],
            },
        )
        if accepted is not True:
            raise ProviderCheckpointError("checkpoint-selenium-invalid")
        value = _webdriver(
            "POST",
            f"/session/{session_id}/execute/sync",
            {
                "script": "return window.localStorage.getItem(arguments[0]);",
                "args": [_checkpoint_selenium_key(generation)],
            },
        )
    observed = _checkpoint_decoded(value)
    if observed != raw:
        raise ProviderCheckpointError("checkpoint-selenium-readback-failed")
    return observed


def _checkpoint_selenium_read(generation: str) -> bytes | None:
    raw = _checkpoint_path_read(_CHECKPOINT_SESSION_PATH, generation)
    if raw is None:
        return None
    return _checkpoint_selenium_roundtrip(raw, generation)


def _checkpoint_selenium_stage(raw: bytes, generation: str, _digest: str) -> bool:
    existing = _checkpoint_selenium_read(generation)
    created = existing is None
    if created:
        _checkpoint_selenium_roundtrip(raw, generation)
        _checkpoint_path_stage(_CHECKPOINT_SESSION_PATH, raw, generation)
    if _checkpoint_selenium_read(generation) != raw:
        raise ProviderCheckpointError("checkpoint-selenium-readback-failed")
    return created


def _checkpoint_selenium_delete(generation: str) -> None:
    _checkpoint_path_delete(_CHECKPOINT_SESSION_PATH, generation)
    with _browser_session() as (session_id, _version):
        _webdriver(
            "POST",
            f"/session/{session_id}/execute/sync",
            {
                "script": "window.localStorage.removeItem(arguments[0]);return true;",
                "args": [_checkpoint_selenium_key(generation)],
            },
        )


def _checkpoint_file(path: Path, generation: str) -> Path:
    if _GENERATION_RE.fullmatch(generation) is None:
        raise ProviderCheckpointError("checkpoint-generation-invalid")
    return path / f"{generation}.json"


def _checkpoint_path_read(path: Path, generation: str) -> bytes | None:
    target = _checkpoint_file(path, generation)
    try:
        raw = target.read_bytes()
    except FileNotFoundError:
        return None
    except OSError:
        raise ProviderCheckpointError("checkpoint-file-read-failed") from None
    if len(raw) > _MAX_CHECKPOINT_BYTES:
        raise ProviderCheckpointError("checkpoint-storage-invalid")
    return raw


def _checkpoint_path_stage(path: Path, raw: bytes, generation: str) -> bool:
    target = _checkpoint_file(path, generation)
    target.parent.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        with target.open("xb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        created = True
    except FileExistsError:
        pass
    except OSError:
        raise ProviderCheckpointError("checkpoint-file-stage-failed") from None
    if _checkpoint_path_read(path, generation) != raw:
        raise ProviderCheckpointError("checkpoint-file-readback-failed")
    return created


def _checkpoint_path_delete(path: Path, generation: str) -> None:
    target = _checkpoint_file(path, generation)
    with suppress(FileNotFoundError):
        target.unlink()


def _checkpoint_filesystem_read(generation: str) -> bytes | None:
    return _checkpoint_path_read(_CHECKPOINT_FILES_PATH, generation)


def _checkpoint_filesystem_stage(raw: bytes, generation: str, _digest: str) -> bool:
    return _checkpoint_path_stage(_CHECKPOINT_FILES_PATH, raw, generation)


def _checkpoint_filesystem_delete(generation: str) -> None:
    _checkpoint_path_delete(_CHECKPOINT_FILES_PATH, generation)


def _checkpoint_clock_read(generation: str) -> bytes | None:
    return _checkpoint_path_read(_CHECKPOINT_CLOCK_PATH, generation)


def _checkpoint_clock_stage(raw: bytes, generation: str, _digest: str) -> bool:
    return _checkpoint_path_stage(_CHECKPOINT_CLOCK_PATH, raw, generation)


def _checkpoint_clock_delete(generation: str) -> None:
    _checkpoint_path_delete(_CHECKPOINT_CLOCK_PATH, generation)


_CHECKPOINT_READERS: Final = {
    "postgres": _checkpoint_pg_read,
    "redis": _checkpoint_redis_read,
    "rabbitmq": _checkpoint_rabbit_read,
    "browser_session": _checkpoint_selenium_read,
    "filesystem": _checkpoint_filesystem_read,
    "clock": _checkpoint_clock_read,
}
_CHECKPOINT_STAGERS: Final = {
    "postgres": _checkpoint_pg_stage,
    "redis": _checkpoint_redis_stage,
    "rabbitmq": _checkpoint_rabbit_stage,
    "browser_session": _checkpoint_selenium_stage,
    "filesystem": _checkpoint_filesystem_stage,
    "clock": _checkpoint_clock_stage,
}
_CHECKPOINT_DELETERS: Final = {
    "postgres": _checkpoint_pg_delete,
    "redis": _checkpoint_redis_delete,
    "rabbitmq": _checkpoint_rabbit_delete,
    "browser_session": _checkpoint_selenium_delete,
    "filesystem": _checkpoint_filesystem_delete,
    "clock": _checkpoint_clock_delete,
}


class RealProviderLabStateStore:
    """Immutable six-provider shards with one transactional PostgreSQL pointer.

    PostgreSQL alone performs the visibility CAS.  Other providers never carry
    mutable active pointers, so partial staging cannot become visible.
    """

    def __init__(self) -> None:
        self._poisoned = False

    @property
    def poisoned(self) -> bool:
        return self._poisoned

    def _require_healthy(self) -> None:
        if self._poisoned:
            raise ProviderCheckpointPoisonedError("checkpoint-store-poisoned")

    def _poison(self) -> Never:
        self._poisoned = True
        raise ProviderCheckpointPoisonedError("checkpoint-store-poisoned")

    def stage(self, checkpoint: bytes) -> ProviderCheckpointCapture:
        self._require_healthy()
        raw, generation, digest = _validate_checkpoint_bytes(checkpoint)
        created: list[str] = []
        try:
            for provider in _CHECKPOINT_PROVIDERS:
                existed = _CHECKPOINT_READERS[provider](generation) is not None
                try:
                    was_created = _CHECKPOINT_STAGERS[provider](raw, generation, digest)
                except _ProviderCheckpointUnownedStageError:
                    raise
                except Exception:
                    # A stager can fail after its immutable shard was created
                    # (for example during exact read-back).  Since the
                    # pre-read proved the generation absent, cleanup remains
                    # safe and cannot delete a caller-owned shard.
                    if not existed:
                        created.append(provider)
                    raise
                if was_created:
                    created.append(provider)
            return self.capture(generation)
        except Exception:
            cleanup_valid = True
            for provider in reversed(created):
                try:
                    _CHECKPOINT_DELETERS[provider](generation)
                    if _CHECKPOINT_READERS[provider](generation) is not None:
                        cleanup_valid = False
                except Exception:
                    cleanup_valid = False
            del cleanup_valid  # failure is poisoned even when rollback verifies clean
            self._poison()
        raise AssertionError("unreachable")

    def capture(self, generation: str) -> ProviderCheckpointCapture:
        self._require_healthy()
        if _GENERATION_RE.fullmatch(generation) is None:
            raise ProviderCheckpointError("checkpoint-generation-invalid")
        expected: bytes | None = None
        checkpoint_digest: str | None = None
        observations: list[ProviderCheckpointObservation] = []
        for provider in _CHECKPOINT_PROVIDERS:
            try:
                observed = _CHECKPOINT_READERS[provider](generation)
                if observed is None:
                    self._poison()
                raw, observed_generation, observed_digest = _validate_checkpoint_bytes(observed)
            except ProviderCheckpointPoisonedError:
                raise
            except Exception:
                self._poison()
            if observed_generation != generation:
                self._poison()
            if expected is None:
                expected = raw
                checkpoint_digest = observed_digest
            elif raw != expected or observed_digest != checkpoint_digest:
                self._poison()
            observations.append(
                ProviderCheckpointObservation(
                    provider=provider,
                    generation=generation,
                    checkpoint_digest=observed_digest,
                    storage_digest=_checkpoint_hash(raw),
                )
            )
        assert expected is not None and checkpoint_digest is not None
        return ProviderCheckpointCapture(
            generation=generation,
            checkpoint_digest=checkpoint_digest,
            checkpoint_bytes=expected,
            observations=tuple(observations),
        )

    def load_active(self) -> ProviderCheckpointCapture:
        self._require_healthy()
        generation = _checkpoint_pg_active()
        if generation is None:
            raise ProviderCheckpointError("checkpoint-active-generation-absent")
        return self.capture(generation)

    def compare_and_swap(
        self, expected_generation: str | None, next_generation: str
    ) -> ProviderCheckpointCapture:
        self._require_healthy()
        if (
            expected_generation is not None
            and _GENERATION_RE.fullmatch(expected_generation) is None
        ):
            raise ProviderCheckpointError("checkpoint-generation-invalid")
        if _GENERATION_RE.fullmatch(next_generation) is None:
            raise ProviderCheckpointError("checkpoint-generation-invalid")
        self.capture(next_generation)
        _checkpoint_pg_cas(expected_generation, next_generation)
        try:
            active = self.load_active()
        except ProviderCheckpointConflictError:
            raise
        except Exception:
            self._poison()
        if active.generation != next_generation:
            self._poison()
        return active


class _PageHandler(BaseHTTPRequestHandler):
    server_version = "StateWeaverProvider/1"
    sys_version = ""

    def do_GET(self) -> None:
        if self.path != "/session":
            self.send_error(404)
            return
        content = b"<!doctype html><title>StateWeaver provider</title><main>session</main>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, _format: str, *args: object) -> None:
        del args


def _serve() -> int:
    server = ThreadingHTTPServer(("0.0.0.0", 8080), _PageHandler)
    server.daemon_threads = True

    def stop(_signum: int, _frame: object) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    server.serve_forever(poll_interval=0.2)
    server.server_close()
    return 0


def _health() -> int:
    database_version = _postgres_query("SHOW server_version;")
    redis_info = _redis_command("INFO", "server")
    rabbit_overview = _http_json(
        "GET",
        "http://rabbitmq:15672/api/overview",
        authorization=_RABBIT_AUTHORIZATION,
    )
    current = _session_export()
    _, browser_version = _browser_roundtrip(_session_marker(current))
    _filesystem_export()
    _clock_export()
    _queue_export()
    _cache_export()
    if (
        len(database_version) != 1
        or len(database_version[0]) != 1
        or database_version[0][0] is None
        or not isinstance(redis_info, str)
        or "redis_version:" not in redis_info
        or not isinstance(rabbit_overview, dict)
        or not isinstance(rabbit_overview.get("rabbitmq_version"), str)
    ):
        raise ProviderBridgeError("real provider version discovery failed")
    redis_version = next(
        line.removeprefix("redis_version:").strip()
        for line in redis_info.splitlines()
        if line.startswith("redis_version:")
    )
    sys.stdout.write(
        _canonical(
            {
                "healthy": True,
                "providers": {
                    "browser": browser_version,
                    "postgres": database_version[0][0],
                    "rabbitmq": rabbit_overview["rabbitmq_version"],
                    "redis": redis_version,
                },
            }
        ).decode("utf-8")
        + "\n"
    )
    return 0


def _export() -> int:
    sys.stdout.buffer.write(_canonical(_archive()) + b"\n")
    return 0


def _import() -> int:
    validated = _validate_archive(_parse(sys.stdin.buffer.read(_MAX_DOCUMENT_BYTES + 1)))
    _restore(validated)
    if _archive() != validated:
        raise ProviderBridgeError("real-provider restore identity verification failed")
    sys.stdout.write('{"accepted":true,"schema_version":"2.0"}\n')
    return 0


def _mutate() -> int:
    value = _parse(sys.stdin.buffer.read(_MAX_DOCUMENT_BYTES + 1))
    if not isinstance(value, dict) or set(value) != {"marker", "tick"}:
        raise ValueError("mutation request shape is invalid")
    expected = _mutated_archive(_require_marker(value["marker"]), cast(int, value["tick"]))
    _restore(expected)
    if _archive() != expected:
        raise ProviderBridgeError("real-provider mutation identity verification failed")
    sys.stdout.write('{"accepted":true,"schema_version":"2.0"}\n')
    return 0


def _m5_action(
    value: object,
    *,
    expected: tuple[str, str, str],
    expected_artifact: str,
    sequence: int,
) -> dict[str, object]:
    """Validate one canonical envelope projection before any provider state change."""

    if not isinstance(value, dict) or set(value) != {
        "envelope",
        "action_digest",
    }:
        raise ValueError("M5 action shape is invalid")
    envelope = value["envelope"]
    if not isinstance(envelope, dict):
        raise ValueError("M5 envelope is invalid")
    encoded = _canonical(envelope)
    digest = "sha256:" + hashlib.sha256(encoded).hexdigest()
    action = envelope.get("action")
    requested_by = envelope.get("requested_by")
    method, path, identity = expected
    if (
        value["action_digest"] != digest
        or not isinstance(action, dict)
        or action.get("type") != "http.request"
        or action.get("method") != method
        or action.get("target") != {"scheme": "http", "host": "localhost", "port": 80, "path": path}
        or action.get("identity_handle") != identity
        or action.get("body_artifact") != expected_artifact
        or action.get("query") != []
        or action.get("headers") != []
        or action.get("template_ref") is not None
        or not isinstance(envelope.get("action_id"), str)
        or not re.fullmatch(r"[a-z][a-z0-9]*(?:[._:-][a-z0-9][a-z0-9_-]*)+", envelope["action_id"])
        or not isinstance(envelope.get("idempotency_key"), str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", envelope["idempotency_key"])
        or not isinstance(envelope.get("policy_decision_ref"), str)
        or envelope.get("sequence") != sequence
        or not isinstance(requested_by, dict)
        or set(requested_by) != {"type", "role", "actor_id"}
        or requested_by["type"] != "workflow"
        or not isinstance(requested_by["role"], str)
        or requested_by["actor_id"] is not None
    ):
        raise ValueError("M5 action is outside the fixed provider scenario")
    return {"action_id": envelope["action_id"], "action_digest": digest}


def _m5_marker(action: dict[str, object], *, sequence: int) -> str:
    # This is a state witness, not user-provided payload execution.  It is derived only from
    # canonical action binding data that passed the closed scenario table above.
    digest = cast(str, action["action_digest"]).removeprefix("sha256:")
    return f"m5-{sequence}-{digest[:48]}"


def _m5_replay() -> int:
    value = _parse(sys.stdin.buffer.read(_MAX_DOCUMENT_BYTES + 1))
    if not isinstance(value, dict) or set(value) != {"scenario", "mode", "actions"}:
        raise ValueError("M5 replay request shape is invalid")
    scenario = value["scenario"]
    mode = value["mode"]
    actions = value["actions"]
    if (
        not isinstance(scenario, str)
        or scenario not in _M5_ROUTES
        or mode not in {"vulnerable", "patched"}
        or (scenario == "primary_patched") != (mode == "patched")
        or not isinstance(actions, list)
        or len(actions) != len(_M5_ROUTES[scenario])
    ):
        raise ValueError("M5 replay scenario is invalid")
    steps: list[dict[str, object]] = []
    for sequence, (raw_action, expected, artifact) in enumerate(
        zip(actions, _M5_ROUTES[scenario], _M5_ARTIFACTS[scenario], strict=True), start=1
    ):
        action = _m5_action(
            raw_action,
            expected=expected,
            expected_artifact=artifact,
            sequence=sequence,
        )
        before = _archive()
        marker = _m5_marker(action, sequence=sequence)
        # Every admitted action deterministically traverses all six real providers.  The state is
        # derived from its canonical envelope digest, never from arbitrary request content.
        _restore(_mutated_archive(marker, sequence))
        after = _archive()
        if before == after:
            raise ProviderBridgeError("M5 provider state did not change")
        outcome, status = _M5_BOUNDARIES[scenario]
        steps.append(
            {
                "step_id": f"step.{sequence:02d}",
                "action_id": action["action_id"],
                "action_digest": action["action_digest"],
                "response_status": status if sequence == len(actions) else 200,
                "oracle_outcome": outcome if sequence == len(actions) else "INCONCLUSIVE",
                "before": before,
                "after": after,
            }
        )
    sys.stdout.write(
        _canonical({"accepted": True, "schema_version": "m5.1", "steps": steps}).decode("utf-8")
        + "\n"
    )
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
    if argv == ["mutate"]:
        return _mutate()
    if argv == ["m5-replay"]:
        return _m5_replay()
    return 64


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except ProviderBridgeError as error:
        # Public stderr is deliberately generic: provider payloads and browser state are untrusted.
        code = str(error)
        suffix = f":{code}" if code in _PUBLIC_FAILURE_CODES else ""
        sys.stderr.write(f"fixed real-provider operation failed{suffix}\n")
        raise SystemExit(65) from None
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        sys.stderr.write("fixed real-provider operation failed\n")
        raise SystemExit(65) from None
