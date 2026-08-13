from __future__ import annotations

import asyncio

import pytest
from fastapi import FastAPI
from starlette.types import Receive, Scope, Send
from stateweaver_lab import (
    LabAsgiExecutionError,
    LabHttpMethod,
    LabMode,
    create_app,
    execute_lab_action_asgi,
    lab_action_artifact,
    resolve_lab_http_action,
    seal_lab_asgi_app,
)
from stateweaver_lab.fixtures import FixtureBearer
from stateweaver_lab.models import (
    AdvanceClockLabAction,
    AdvanceClockRequest,
    ClaimReferenceLabAction,
    ClaimReferenceRequest,
    DeferQueueLabAction,
    DelayQueueRequest,
    DocumentId,
    DowngradeRoleLabAction,
    MaskedReadLabAction,
    MockPolicyLabAction,
    PrimeAuthorizationCacheLabAction,
    PrimeAuthorizationCacheRequest,
    PrincipalId,
    PublishReferenceLabAction,
    PublishReferenceRequest,
    QueueJobId,
    ReadDocumentLabAction,
    ReadDocumentRequest,
    ReferenceId,
    RetainSessionLabAction,
    Role,
    RoleDowngradeRequest,
    TypedLabAction,
)
from stateweaver_lab.state import AuthContext, LabState


def _actions() -> tuple[TypedLabAction, ...]:
    return (
        RetainSessionLabAction(),
        PrimeAuthorizationCacheLabAction(
            payload=PrimeAuthorizationCacheRequest(document_id=DocumentId.TENANT_A_OWNED)
        ),
        DowngradeRoleLabAction(
            payload=RoleDowngradeRequest(
                principal_id=PrincipalId.A_EDITOR,
                new_role=Role.VIEWER,
                propagation="queued",
            )
        ),
        DeferQueueLabAction(
            payload=DelayQueueRequest(job_id=QueueJobId.ROLE_SYNC_A, delay_seconds=240)
        ),
        PublishReferenceLabAction(
            payload=PublishReferenceRequest(
                document_id=DocumentId.TENANT_B_PROTECTED,
                recipient_id=PrincipalId.A_EDITOR,
            )
        ),
        ClaimReferenceLabAction(payload=ClaimReferenceRequest(reference_id=ReferenceId.B_TO_A)),
        AdvanceClockLabAction(payload=AdvanceClockRequest(seconds=90)),
        ReadDocumentLabAction(
            actor=FixtureBearer.TENANT_A_OLD_EDITOR,
            payload=ReadDocumentRequest(document_id=DocumentId.TENANT_B_PROTECTED),
        ),
        MaskedReadLabAction(
            actor=FixtureBearer.TENANT_A_OLD_EDITOR,
            payload=ReadDocumentRequest(document_id=DocumentId.TENANT_B_PROTECTED),
        ),
        MockPolicyLabAction(
            actor=FixtureBearer.TENANT_A_OLD_EDITOR,
            payload=ReadDocumentRequest(document_id=DocumentId.TENANT_B_PROTECTED),
        ),
    )


def test_lab_owned_http_specs_are_closed_and_canonical() -> None:
    actions = _actions()
    specs = tuple(resolve_lab_http_action(action) for action in actions)

    assert [spec.method for spec in specs] == [LabHttpMethod.POST] * 7 + [
        LabHttpMethod.GET,
        LabHttpMethod.GET,
        LabHttpMethod.GET,
    ]
    assert specs[7].route_template == "/v1/lab/documents/{document_id}"
    assert specs[7].expected_statuses == (200, 403)
    assert all(
        spec.body_artifact == lab_action_artifact(action)
        for spec, action in zip(specs, actions, strict=True)
    )
    assert len({spec.body_artifact for spec in specs}) == len(specs)


def test_actual_socket_free_asgi_lifecycle_returns_route_status_and_exact_body() -> None:
    app = create_app("vulnerable")
    seal_lab_asgi_app(app)

    execution = asyncio.run(execute_lab_action_asgi(app, RetainSessionLabAction()))

    assert execution.method is LabHttpMethod.POST
    assert execution.path == "/v1/lab/session/retain"
    assert execution.route == "/v1/lab/session/retain"
    assert execution.status == 200
    assert execution.body.startswith(b'{"action_id":')
    assert app.state.lab.evidence().records


def test_retained_exact_state_can_be_bound_before_sealing() -> None:
    app = create_app("vulnerable")
    retained = LabState.canonical(LabMode.VULNERABLE)
    app.state.lab = retained
    seal_lab_asgi_app(app)

    asyncio.run(execute_lab_action_asgi(app, RetainSessionLabAction()))

    assert app.state.lab is retained
    assert retained.evidence().records


def test_arbitrary_or_route_tampered_apps_cannot_be_sealed() -> None:
    arbitrary = FastAPI()
    arbitrary.state.lab = LabState.canonical(LabMode.VULNERABLE)
    with pytest.raises(LabAsgiExecutionError, match="cannot be sealed"):
        seal_lab_asgi_app(arbitrary)

    tampered = create_app("vulnerable")
    tampered.routes.pop()
    with pytest.raises(LabAsgiExecutionError, match="cannot be sealed"):
        seal_lab_asgi_app(tampered)


def test_middleware_or_dependency_tampering_fails_closed() -> None:
    app = create_app("vulnerable")
    seal_lab_asgi_app(app)
    app.middleware_stack = None
    with pytest.raises(LabAsgiExecutionError, match="binding changed"):
        asyncio.run(execute_lab_action_asgi(app, RetainSessionLabAction()))

    app = create_app("vulnerable")
    seal_lab_asgi_app(app)

    def original_dependency() -> None:
        return None

    def replacement_dependency() -> None:
        return None

    app.dependency_overrides[original_dependency] = replacement_dependency
    with pytest.raises(LabAsgiExecutionError, match="binding changed"):
        asyncio.run(execute_lab_action_asgi(app, RetainSessionLabAction()))


def test_malformed_response_body_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    app = create_app("vulnerable")
    state = app.state.lab
    monkeypatch.setattr(state, "retain_old_session", lambda context: {"unexpected": True})
    seal_lab_asgi_app(app)

    with pytest.raises(LabAsgiExecutionError, match=r"failed|malformed"):
        asyncio.run(execute_lab_action_asgi(app, RetainSessionLabAction()))


def test_oversize_response_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    app = create_app("vulnerable")
    state = app.state.lab
    original = state.retain_old_session

    def oversized(context: AuthContext) -> object:
        receipt = original(context)
        return receipt.model_copy(update={"action_id": "x" * 70_000})

    monkeypatch.setattr(state, "retain_old_session", oversized)
    seal_lab_asgi_app(app)

    with pytest.raises(LabAsgiExecutionError, match="byte limit"):
        asyncio.run(execute_lab_action_asgi(app, RetainSessionLabAction()))


def test_response_order_is_validated(monkeypatch: pytest.MonkeyPatch) -> None:
    import stateweaver_lab.asgi as asgi_module

    app = create_app("vulnerable")
    seal_lab_asgi_app(app)

    async def body_before_start(scope: Scope, receive: Receive, send: Send) -> None:
        del scope, receive
        await send({"type": "http.response.body", "body": b"{}", "more_body": False})

    signature, _ = asgi_module._SEALED_APPS[app]
    app.middleware_stack = body_before_start
    asgi_module._SEALED_APPS[app] = (signature, body_before_start)

    with pytest.raises(LabAsgiExecutionError, match="body order"):
        asyncio.run(execute_lab_action_asgi(app, RetainSessionLabAction()))
