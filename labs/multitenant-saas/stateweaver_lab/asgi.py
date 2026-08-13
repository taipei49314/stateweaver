"""Closed HTTP bindings and socket-free ASGI execution for typed lab actions."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Annotated, ClassVar, Final
from weakref import WeakKeyDictionary, WeakSet

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.types import ASGIApp, Message, Scope

from .fixtures import FixtureBearer
from .models import (
    ActionReceipt,
    AdvanceClockLabAction,
    ClaimReferenceLabAction,
    ClockResponse,
    DeferQueueLabAction,
    DocumentResponse,
    DowngradeRoleLabAction,
    MaskedDocumentResponse,
    MaskedReadLabAction,
    MockPolicyLabAction,
    MockPolicyResponse,
    PrimeAuthorizationCacheLabAction,
    PublishReferenceLabAction,
    ReadDocumentLabAction,
    ReferenceResponse,
    RetainSessionLabAction,
    RoleDowngradeResponse,
    TypedLabAction,
)
from .state import LabState

MAX_ASGI_RESPONSE_BYTES: Final = 65_536


class LabAsgiExecutionError(RuntimeError):
    """The app, route, or ASGI lifecycle did not match the sealed lab contract."""


class LabHttpMethod(StrEnum):
    GET = "GET"
    POST = "POST"


class _StrictModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


class LabHttpActionSpec(_StrictModel):
    """The complete server-owned HTTP binding for one concrete lab action."""

    method: LabHttpMethod
    path: Annotated[str, Field(pattern=r"^/v1/lab/[A-Za-z0-9_./-]+$")]
    route_template: Annotated[str, Field(pattern=r"^/v1/lab/[A-Za-z0-9_./{}-]+$")]
    identity_handle: Annotated[str, Field(pattern=r"^identity:test_[a-z_]+$")]
    body_artifact: Annotated[
        str,
        Field(pattern=r"^artifact:lab-action/[0-9a-f]{64}$"),
    ]
    expected_statuses: tuple[Annotated[int, Field(ge=100, le=599)], ...]

    @field_validator("expected_statuses")
    @classmethod
    def statuses_are_nonempty_and_unique(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if not value or len(value) != len(set(value)):
            raise ValueError("expected_statuses must be nonempty and unique")
        return value


class LabAsgiExecution(_StrictModel):
    """Bounded bytes returned by exactly one completed HTTP ASGI lifecycle."""

    method: LabHttpMethod
    path: Annotated[str, Field(pattern=r"^/v1/lab/[A-Za-z0-9_./-]+$")]
    route: Annotated[str, Field(pattern=r"^/v1/lab/[A-Za-z0-9_./{}-]+$")]
    status: Annotated[int, Field(ge=100, le=599)]
    body: Annotated[bytes, Field(max_length=MAX_ASGI_RESPONSE_BYTES)]


class _ErrorDetail(_StrictModel):
    code: Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[a-z0-9_]+$")]


class _ErrorResponse(_StrictModel):
    detail: _ErrorDetail


type _ConcreteLabAction = (
    RetainSessionLabAction
    | PrimeAuthorizationCacheLabAction
    | DowngradeRoleLabAction
    | DeferQueueLabAction
    | PublishReferenceLabAction
    | ClaimReferenceLabAction
    | AdvanceClockLabAction
    | ReadDocumentLabAction
    | MaskedReadLabAction
    | MockPolicyLabAction
)

_FIXED_ACTION_SPECS: Final = {
    RetainSessionLabAction: (LabHttpMethod.POST, "/v1/lab/session/retain", (200,)),
    PrimeAuthorizationCacheLabAction: (
        LabHttpMethod.POST,
        "/v1/lab/authorization-cache/prime",
        (200,),
    ),
    DowngradeRoleLabAction: (
        LabHttpMethod.POST,
        "/v1/lab/admin/role-downgrade",
        (200,),
    ),
    DeferQueueLabAction: (LabHttpMethod.POST, "/v1/lab/admin/queue/defer", (200,)),
    PublishReferenceLabAction: (
        LabHttpMethod.POST,
        "/v1/lab/references/publish",
        (200,),
    ),
    ClaimReferenceLabAction: (
        LabHttpMethod.POST,
        "/v1/lab/references/claim",
        (200,),
    ),
    AdvanceClockLabAction: (
        LabHttpMethod.POST,
        "/v1/lab/admin/clock/advance",
        (200,),
    ),
}

_SEALED_APPS: WeakKeyDictionary[FastAPI, tuple[tuple[object, ...], ASGIApp]] = WeakKeyDictionary()
_FACTORY_APPS: WeakKeyDictionary[FastAPI, tuple[object, ...]] = WeakKeyDictionary()
_ACTIVE_APPS: WeakSet[FastAPI] = WeakSet()


def lab_action_artifact(action: TypedLabAction) -> str:
    """Return the canonical content handle for exact typed action parameters."""

    concrete = _require_concrete_action(action)
    encoded = json.dumps(
        concrete.model_dump(mode="json", by_alias=True, exclude_none=False),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"artifact:lab-action/{hashlib.sha256(encoded).hexdigest()}"


def resolve_lab_http_action(action: TypedLabAction) -> LabHttpActionSpec:
    """Resolve a typed action through the lab's sole closed HTTP mapping."""

    concrete = _require_concrete_action(action)
    statuses: tuple[int, ...]
    fixed = _FIXED_ACTION_SPECS.get(type(concrete))
    if fixed is not None:
        method, path, statuses = fixed
        route_template = path
    elif type(concrete) is ReadDocumentLabAction:
        method = LabHttpMethod.GET
        path = f"/v1/lab/documents/{concrete.payload.document_id.value}"
        route_template = "/v1/lab/documents/{document_id}"
        statuses = (200, 403)
    elif type(concrete) is MaskedReadLabAction:
        method = LabHttpMethod.GET
        path = f"/v1/lab/decoys/masked/{concrete.payload.document_id.value}"
        route_template = "/v1/lab/decoys/masked/{document_id}"
        statuses = (200,)
    elif type(concrete) is MockPolicyLabAction:
        method = LabHttpMethod.GET
        path = f"/v1/lab/decoys/mock-policy/{concrete.payload.document_id.value}"
        route_template = "/v1/lab/decoys/mock-policy/{document_id}"
        statuses = (200,)
    else:  # pragma: no cover - guarded by _require_concrete_action
        raise LabAsgiExecutionError("typed lab action is unsupported")
    return LabHttpActionSpec(
        method=method,
        path=path,
        route_template=route_template,
        identity_handle=_identity_for_actor(concrete.actor),
        body_artifact=lab_action_artifact(concrete),
        expected_statuses=statuses,
    )


def validate_lab_asgi_execution(
    action: TypedLabAction, execution: LabAsgiExecution
) -> LabAsgiExecution:
    """Revalidate retained ASGI result bytes against the exact typed action."""

    concrete = _require_concrete_action(action)
    spec = resolve_lab_http_action(concrete)
    if (
        execution.method is not spec.method
        or execution.path != spec.path
        or execution.route != spec.route_template
        or execution.status not in spec.expected_statuses
    ):
        raise LabAsgiExecutionError("retained ASGI result is outside the typed action contract")
    _validate_response(concrete, execution)
    return execution


def seal_lab_asgi_app(app: FastAPI) -> None:
    """Seal a freshly created repository app outside attacker-controlled app state."""

    factory_signature = _FACTORY_APPS.get(app)
    if (
        type(app) is not FastAPI
        or factory_signature is None
        or _app_signature(app) != factory_signature
        or type(getattr(app.state, "lab", None)) is not LabState
    ):
        raise LabAsgiExecutionError("lab ASGI app cannot be sealed")
    if app in _SEALED_APPS:
        raise LabAsgiExecutionError("lab ASGI app is already sealed")
    middleware_stack = app.build_middleware_stack()
    app.middleware_stack = middleware_stack
    _SEALED_APPS[app] = (_app_signature(app), middleware_stack)


def _register_trusted_lab_app(app: FastAPI) -> None:
    """Register the exact app factory result before it crosses a trust boundary."""

    if type(app) is not FastAPI or type(getattr(app.state, "lab", None)) is not LabState:
        raise LabAsgiExecutionError("repository app factory returned an invalid app")
    if app in _FACTORY_APPS:
        raise LabAsgiExecutionError("repository app was registered more than once")
    _FACTORY_APPS[app] = _app_signature(app)


async def execute_lab_action_asgi(
    app: FastAPI,
    action: TypedLabAction,
) -> LabAsgiExecution:
    """Execute a typed action through one sealed, socket-free FastAPI lifecycle."""

    concrete = _require_concrete_action(action)
    spec = resolve_lab_http_action(concrete)
    sealed = _SEALED_APPS.get(app)
    if (
        type(app) is not FastAPI
        or sealed is None
        or type(getattr(app.state, "lab", None)) is not LabState
        or app.debug
        or app.dependency_overrides
        or _app_signature(app) != sealed[0]
        or app.middleware_stack is not sealed[1]
    ):
        raise LabAsgiExecutionError("lab ASGI app binding changed")
    if app in _ACTIVE_APPS:
        raise LabAsgiExecutionError("lab ASGI app already has an active lifecycle")

    body = _request_body(concrete, spec.method)
    scope = _request_scope(spec, concrete, body)
    request_sent = False
    response_started = False
    response_complete = False
    status: int | None = None
    response_body = bytearray()

    async def receive() -> Message:
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        nonlocal response_complete, response_started, status
        message_type = message.get("type")
        if message_type == "http.response.start":
            candidate = message.get("status")
            headers = message.get("headers", [])
            if (
                response_started
                or isinstance(candidate, bool)
                or not isinstance(candidate, int)
                or not 100 <= candidate <= 599
                or not isinstance(headers, list)
                or any(
                    not isinstance(pair, tuple)
                    or len(pair) != 2
                    or not all(isinstance(item, bytes) for item in pair)
                    for pair in headers
                )
            ):
                raise LabAsgiExecutionError("ASGI response start is invalid")
            response_started = True
            status = candidate
            return
        if message_type == "http.response.body":
            chunk = message.get("body", b"")
            more_body = message.get("more_body", False)
            if (
                not response_started
                or response_complete
                or not isinstance(chunk, bytes)
                or type(more_body) is not bool
            ):
                raise LabAsgiExecutionError("ASGI response body order is invalid")
            response_body.extend(chunk)
            if len(response_body) > MAX_ASGI_RESPONSE_BYTES:
                raise LabAsgiExecutionError("ASGI response exceeded the byte limit")
            response_complete = not more_body
            return
        raise LabAsgiExecutionError("ASGI response message type is invalid")

    _ACTIVE_APPS.add(app)
    try:
        try:
            await FastAPI.__call__(app, scope, receive, send)
        except LabAsgiExecutionError:
            raise
        except Exception:
            raise LabAsgiExecutionError("lab ASGI application failed") from None
    finally:
        _ACTIVE_APPS.discard(app)
    if (
        _SEALED_APPS.get(app) != sealed
        or _app_signature(app) != sealed[0]
        or app.middleware_stack is not sealed[1]
    ):
        raise LabAsgiExecutionError("lab ASGI app binding changed")
    route = getattr(scope.get("route"), "path", None)
    if status is None or not response_complete or not isinstance(route, str):
        raise LabAsgiExecutionError("ASGI response lifecycle was incomplete")
    if route != spec.route_template or status not in spec.expected_statuses:
        raise LabAsgiExecutionError("ASGI outcome is outside the typed action contract")
    result = LabAsgiExecution(
        method=spec.method,
        path=spec.path,
        route=route,
        status=status,
        body=bytes(response_body),
    )
    _validate_response(concrete, result)
    return result


def _require_concrete_action(action: TypedLabAction) -> _ConcreteLabAction:
    allowed = (
        RetainSessionLabAction,
        PrimeAuthorizationCacheLabAction,
        DowngradeRoleLabAction,
        DeferQueueLabAction,
        PublishReferenceLabAction,
        ClaimReferenceLabAction,
        AdvanceClockLabAction,
        ReadDocumentLabAction,
        MaskedReadLabAction,
        MockPolicyLabAction,
    )
    if type(action) not in allowed:
        raise LabAsgiExecutionError("typed lab action is unsupported")
    return action


def _identity_for_actor(actor: FixtureBearer) -> str:
    if actor in {FixtureBearer.TENANT_A_OLD_EDITOR, FixtureBearer.TENANT_A_FRESH_VIEWER}:
        return "identity:test_user_a"
    if actor is FixtureBearer.TENANT_B_VIEWER:
        return "identity:test_user_b"
    if actor is FixtureBearer.LAB_ADMIN:
        return "identity:test_admin"
    raise LabAsgiExecutionError("typed lab actor is unsupported")


def _request_body(action: _ConcreteLabAction, method: LabHttpMethod) -> bytes:
    if method is LabHttpMethod.GET:
        return b""
    return json.dumps(
        action.payload.model_dump(mode="json", by_alias=True, exclude_none=False),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _request_scope(
    spec: LabHttpActionSpec,
    action: _ConcreteLabAction,
    body: bytes,
) -> Scope:
    headers = [(b"host", b"lab"), (b"authorization", f"Bearer {action.actor.value}".encode())]
    if body:
        headers.extend(
            [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
        )
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.5"},
        "http_version": "1.1",
        "method": spec.method.value,
        "scheme": "http",
        "path": spec.path,
        "raw_path": spec.path.encode("ascii"),
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": ("127.0.0.1", 1),
        "server": ("lab", 80),
        "state": {},
        "extensions": {},
    }


def _validate_response(action: _ConcreteLabAction, response: LabAsgiExecution) -> None:
    if response.status >= 400:
        model: type[BaseModel] = _ErrorResponse
    elif type(action) in {
        RetainSessionLabAction,
        PrimeAuthorizationCacheLabAction,
        DeferQueueLabAction,
    }:
        model = ActionReceipt
    elif type(action) is DowngradeRoleLabAction:
        model = RoleDowngradeResponse
    elif type(action) in {PublishReferenceLabAction, ClaimReferenceLabAction}:
        model = ReferenceResponse
    elif type(action) is AdvanceClockLabAction:
        model = ClockResponse
    elif type(action) is ReadDocumentLabAction:
        model = DocumentResponse
    elif type(action) is MaskedReadLabAction:
        model = MaskedDocumentResponse
    elif type(action) is MockPolicyLabAction:
        model = MockPolicyResponse
    else:  # pragma: no cover - guarded by _require_concrete_action
        raise LabAsgiExecutionError("typed lab action has no response model")
    try:
        model.model_validate_json(response.body)
    except (ValueError, TypeError):
        raise LabAsgiExecutionError("ASGI response body is malformed") from None


def _app_signature(app: FastAPI) -> tuple[object, ...]:
    routes: list[tuple[object, ...]] = []
    for route in app.routes:
        methods = getattr(route, "methods", None)
        routes.append(
            (
                getattr(route, "path", None),
                getattr(getattr(route, "path_regex", None), "pattern", None),
                tuple(sorted(methods)) if isinstance(methods, set) else (),
                id(getattr(route, "endpoint", None)),
                id(getattr(getattr(route, "dependant", None), "call", None)),
            )
        )
    middleware: list[tuple[object, ...]] = []
    for item in app.user_middleware:
        values = tuple(
            sorted(
                (key, f"callable:{id(value)}" if callable(value) else repr(value))
                for key, value in item.kwargs.items()
            )
        )
        middleware.append((item.cls, values))
    exception_handlers = tuple(
        sorted(
            (
                f"{getattr(key, '__module__', '')}.{getattr(key, '__qualname__', repr(key))}",
                id(value),
            )
            for key, value in app.exception_handlers.items()
        )
    )
    configuration = (
        app.debug,
        app.openapi_url,
        app.docs_url,
        app.redoc_url,
        app.root_path,
        app.root_path_in_servers,
        app.router.redirect_slashes,
        id(app.router),
        id(app.router.lifespan_context),
    )
    return (configuration, tuple(routes), tuple(middleware), exception_handlers)


__all__ = [
    "MAX_ASGI_RESPONSE_BYTES",
    "LabAsgiExecution",
    "LabAsgiExecutionError",
    "LabHttpActionSpec",
    "LabHttpMethod",
    "execute_lab_action_asgi",
    "lab_action_artifact",
    "resolve_lab_http_action",
    "seal_lab_asgi_app",
    "validate_lab_asgi_execution",
]
