from __future__ import annotations

import socket
from typing import Any, Never, cast

import pytest
from fastapi.testclient import TestClient
from pydantic import TypeAdapter, ValidationError
from stateweaver_lab import DeterministicLabService, TypedLabAction, create_app
from stateweaver_lab.fixtures import (
    SYNTHETIC_MOCK_PLACEHOLDER,
    SYNTHETIC_TENANT_B_MARKER,
    FixtureBearer,
)
from stateweaver_lab.models import (
    AdvanceClockLabAction,
    AdvanceClockRequest,
    ClaimReferenceLabAction,
    ClaimReferenceRequest,
    DeferQueueLabAction,
    DelayQueueRequest,
    DocumentId,
    DowngradeRoleLabAction,
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
)


def bearer_headers(bearer: FixtureBearer) -> dict[str, str]:
    """Build headers from the closed synthetic fixture enum."""

    return {"Authorization": f"Bearer {bearer.value}"}


OLD_A = bearer_headers(FixtureBearer.TENANT_A_OLD_EDITOR)
FRESH_A = bearer_headers(FixtureBearer.TENANT_A_FRESH_VIEWER)
VIEWER_B = bearer_headers(FixtureBearer.TENANT_B_VIEWER)
ADMIN = bearer_headers(FixtureBearer.LAB_ADMIN)


def run_chain_setup(
    client: TestClient,
    *,
    omit: str | None = None,
    advance_seconds: int = 90,
) -> dict[str, Any]:
    responses: dict[str, Any] = {}
    if omit != "old_session_retained":
        responses["retain"] = client.post(
            "/v1/lab/session/retain",
            headers=OLD_A,
            json={"purpose": "clean-replay"},
        )
    if omit != "stale_authorization_cache":
        responses["prime"] = client.post(
            "/v1/lab/authorization-cache/prime",
            headers=OLD_A,
            json={"document_id": "doc-a-owned"},
        )
    if omit != "role_downgraded":
        responses["downgrade"] = client.post(
            "/v1/lab/admin/role-downgrade",
            headers=ADMIN,
            json={
                "principal_id": "principal-a",
                "new_role": "viewer",
                "propagation": "queued",
            },
        )
    if omit != "queue_sync_delayed":
        responses["defer"] = client.post(
            "/v1/lab/admin/queue/defer",
            headers=ADMIN,
            json={"job_id": "job-role-sync-a", "delay_seconds": 240},
        )
    if omit != "foreign_reference_obtained":
        responses["publish"] = client.post(
            "/v1/lab/references/publish",
            headers=VIEWER_B,
            json={
                "document_id": "doc-b-protected",
                "recipient_id": "principal-a",
            },
        )
        responses["claim"] = client.post(
            "/v1/lab/references/claim",
            headers=OLD_A,
            json={"reference_id": "ref-b-to-a"},
        )
    if omit != "replay_window_open":
        responses["advance"] = client.post(
            "/v1/lab/admin/clock/advance",
            headers=ADMIN,
            json={"seconds": advance_seconds},
        )
    return responses


def assert_setup_succeeded(responses: dict[str, Any]) -> None:
    assert responses
    statuses = {name: response.status_code for name, response in responses.items()}
    assert statuses == dict.fromkeys(responses, 200)


def oracle(client: TestClient) -> dict[str, Any]:
    response = client.get("/v1/lab/oracle", headers=ADMIN)
    assert response.status_code == 200
    return cast(dict[str, Any], response.json())


def test_complete_chain_violates_oracle_only_in_vulnerable_mode(
    vulnerable_client: TestClient,
) -> None:
    responses = run_chain_setup(vulnerable_client)
    assert_setup_succeeded(responses)

    chain_state = vulnerable_client.get("/v1/lab/chain-state", headers=ADMIN).json()
    assert chain_state
    assert all(chain_state.values())

    disclosure = vulnerable_client.get("/v1/lab/documents/doc-b-protected", headers=OLD_A)
    assert disclosure.status_code == 200
    assert disclosure.json()["owner_tenant"] == "tenant-b"
    assert disclosure.json()["body"] == SYNTHETIC_TENANT_B_MARKER

    result = oracle(vulnerable_client)
    assert result["violated"] is True
    assert result["verdict"] == "VIOLATED"
    assert result["evidence_ids"] == [disclosure.json()["evidence_id"]]
    assert all(check["passed"] for check in result["checks"])


def test_same_chain_is_blocked_by_patched_mode(
    patched_client: TestClient,
) -> None:
    responses = run_chain_setup(patched_client)
    assert_setup_succeeded(responses)

    chain_state = patched_client.get("/v1/lab/chain-state", headers=ADMIN).json()
    assert chain_state["stale_authorization_cache"] is False

    blocked = patched_client.get("/v1/lab/documents/doc-b-protected", headers=OLD_A)
    assert blocked.status_code == 403
    assert blocked.json()["detail"]["code"] == "tenant_boundary_enforced"
    assert oracle(patched_client)["violated"] is False


@pytest.mark.parametrize(
    "missing_prerequisite",
    [
        "old_session_retained",
        "stale_authorization_cache",
        "role_downgraded",
        "queue_sync_delayed",
        "foreign_reference_obtained",
        "replay_window_open",
    ],
)
def test_each_missing_prerequisite_blocks_disclosure(
    missing_prerequisite: str,
) -> None:
    with TestClient(create_app("vulnerable")) as client:
        run_chain_setup(client, omit=missing_prerequisite)
        blocked = client.get("/v1/lab/documents/doc-b-protected", headers=OLD_A)
        assert blocked.status_code == 403
        assert oracle(client)["violated"] is False


def test_replay_after_controlled_window_is_blocked(
    vulnerable_client: TestClient,
) -> None:
    responses = run_chain_setup(vulnerable_client, advance_seconds=181)
    assert_setup_succeeded(responses)
    blocked = vulnerable_client.get("/v1/lab/documents/doc-b-protected", headers=OLD_A)
    assert blocked.status_code == 403
    assert oracle(vulnerable_client)["violated"] is False


def test_masked_200_is_a_negative_control(
    vulnerable_client: TestClient,
) -> None:
    response = vulnerable_client.get("/v1/lab/decoys/masked/doc-b-protected", headers=OLD_A)
    assert response.status_code == 200
    assert response.json()["masked"] is True
    assert response.json()["body"] == "[MASKED]"
    assert oracle(vulnerable_client)["violated"] is False


def test_mock_only_allow_is_a_negative_control(
    vulnerable_client: TestClient,
) -> None:
    response = vulnerable_client.get("/v1/lab/decoys/mock-policy/doc-b-protected", headers=OLD_A)
    assert response.status_code == 200
    assert response.json()["simulated_decision"] == "allow"
    assert response.json()["body"] == SYNTHETIC_MOCK_PLACEHOLDER
    assert response.json()["provenance"] == "MOCKED"
    assert oracle(vulnerable_client)["violated"] is False


def test_fresh_token_is_a_negative_control(
    vulnerable_client: TestClient,
) -> None:
    assert_setup_succeeded(run_chain_setup(vulnerable_client))
    blocked = vulnerable_client.get("/v1/lab/documents/doc-b-protected", headers=FRESH_A)
    assert blocked.status_code == 403
    assert oracle(vulnerable_client)["violated"] is False


def test_clean_seed_and_reset_are_deterministic() -> None:
    with (
        TestClient(create_app("vulnerable")) as first,
        TestClient(create_app("vulnerable")) as second,
    ):
        first_initial = first.get("/v1/lab/state", headers=ADMIN).json()
        second_initial = second.get("/v1/lab/state", headers=ADMIN).json()
        assert first_initial == second_initial

        assert_setup_succeeded(run_chain_setup(first))
        assert first.get("/v1/lab/state", headers=ADMIN).json() != first_initial
        reset = first.post(
            "/v1/lab/reset",
            headers=ADMIN,
            json={"seed": "m0-canonical-v1"},
        )
        assert reset.status_code == 200
        assert reset.json() == first_initial
        assert first.get("/v1/lab/evidence", headers=ADMIN).json() == {"records": []}


def test_vulnerable_and_patched_apps_have_no_process_global_mode_state() -> None:
    with (
        TestClient(create_app("vulnerable")) as vulnerable,
        TestClient(create_app("patched")) as patched,
    ):
        patched_initial = patched.get("/v1/lab/state", headers=ADMIN).json()

        assert_setup_succeeded(run_chain_setup(vulnerable))
        disclosure = vulnerable.get(
            "/v1/lab/documents/doc-b-protected",
            headers=OLD_A,
        )
        assert disclosure.status_code == 200
        assert oracle(vulnerable)["violated"] is True
        assert patched.get("/v1/lab/state", headers=ADMIN).json() == patched_initial

        assert_setup_succeeded(run_chain_setup(patched))
        blocked = patched.get(
            "/v1/lab/documents/doc-b-protected",
            headers=OLD_A,
        )
        assert blocked.status_code == 403
        assert oracle(patched)["violated"] is False
        assert oracle(vulnerable)["violated"] is True


def test_same_plan_has_same_fingerprint() -> None:
    with (
        TestClient(create_app("vulnerable")) as first,
        TestClient(create_app("vulnerable")) as second,
    ):
        assert_setup_succeeded(run_chain_setup(first))
        assert_setup_succeeded(run_chain_setup(second))
        first.get("/v1/lab/documents/doc-b-protected", headers=OLD_A)
        second.get("/v1/lab/documents/doc-b-protected", headers=OLD_A)
        assert (
            first.get("/v1/lab/state", headers=ADMIN).json()
            == second.get("/v1/lab/state", headers=ADMIN).json()
        )


def test_evidence_and_layered_capture_never_record_bearer_values(
    vulnerable_client: TestClient,
) -> None:
    assert_setup_succeeded(run_chain_setup(vulnerable_client))
    vulnerable_client.get("/v1/lab/documents/doc-b-protected", headers=OLD_A)
    evidence = vulnerable_client.get("/v1/lab/evidence", headers=ADMIN)
    layers = vulnerable_client.get("/v1/lab/state/layers", headers=ADMIN)
    assert evidence.status_code == 200
    assert layers.status_code == 200
    layer_payload = layers.json()
    assert set(layer_payload) == {
        "schema_version",
        "fingerprint",
        "application",
        "database",
        "cache",
        "queue",
        "browser",
        "configuration",
        "clock",
    }
    assert layer_payload["clock"]["mode"] == "controlled"
    assert layer_payload["configuration"]["external_egress_enabled"] is False
    browser_sessions = layer_payload["browser"]["sessions"]
    assert browser_sessions
    assert all(
        set(session)
        == {
            "session_handle",
            "principal_id",
            "issued_role",
            "session_generation",
            "issued_at",
            "expires_at",
            "identity_hash",
        }
        for session in browser_sessions
    )
    assert all(session["session_handle"].startswith("session-") for session in browser_sessions)
    assert all(session["identity_hash"].startswith("sha256:") for session in browser_sessions)
    serialized = evidence.text + layers.text
    for bearer in FixtureBearer:
        assert bearer.value not in serialized
    assert SYNTHETIC_TENANT_B_MARKER not in serialized


def test_unknown_bearer_is_rejected_without_echo(
    vulnerable_client: TestClient,
) -> None:
    response = vulnerable_client.get(
        "/v1/lab/state",
        headers={"Authorization": "Bearer do-not-echo-this"},
    )
    assert response.status_code == 401
    assert "do-not-echo-this" not in response.text


def test_write_models_reject_extra_fields_and_scalar_coercion(
    vulnerable_client: TestClient,
) -> None:
    extra = vulnerable_client.post(
        "/v1/lab/session/retain",
        headers=OLD_A,
        json={"purpose": "clean-replay", "role": "admin"},
    )
    coerced = vulnerable_client.post(
        "/v1/lab/admin/clock/advance",
        headers=ADMIN,
        json={"seconds": "90"},
    )
    assert extra.status_code == 422
    assert coerced.status_code == 422


def test_host_header_is_fail_closed(vulnerable_client: TestClient) -> None:
    response = vulnerable_client.get("/healthz", headers={"Host": "outside.example"})
    assert response.status_code == 400


def test_local_lab_flow_uses_no_socket_connect_dns_or_wildcard_bind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    forbidden_calls: list[str] = []

    def reject(operation: str) -> Never:
        forbidden_calls.append(operation)
        raise AssertionError(f"local in-process lab attempted {operation}")

    def reject_connect(*_args: object, **_kwargs: object) -> None:
        reject("socket connect")

    def reject_connect_ex(*_args: object, **_kwargs: object) -> int:
        reject("socket connect_ex")

    def reject_dns(*_args: object, **_kwargs: object) -> object:
        reject("DNS resolution")

    original_bind = socket.socket.bind

    def reject_wildcard_bind(sock: socket.socket, address: object) -> None:
        host = address[0] if isinstance(address, tuple) and address else None
        if host in {"", "0.0.0.0", "::", None}:
            reject("wildcard bind")
        original_bind(sock, address)  # type: ignore[arg-type]

    def install_guards(patcher: pytest.MonkeyPatch) -> None:
        patcher.setattr(socket.socket, "connect", reject_connect)
        patcher.setattr(socket.socket, "connect_ex", reject_connect_ex)
        patcher.setattr(socket, "create_connection", reject_connect)
        patcher.setattr(socket, "getaddrinfo", reject_dns)
        patcher.setattr(socket, "gethostbyname", reject_dns)
        patcher.setattr(socket, "gethostbyname_ex", reject_dns)
        patcher.setattr(socket.socket, "bind", reject_wildcard_bind)

    with monkeypatch.context() as construction_guard:
        install_guards(construction_guard)
        app = create_app("vulnerable")

    # Windows TestClient bootstrap needs an internal socketpair for its event loop. Exclude that
    # harness-only channel, then guard calls made while the app handles the representative flow.
    with TestClient(app) as client, monkeypatch.context() as flow_guard:
        install_guards(flow_guard)
        assert client.get("/healthz").status_code == 200
        assert_setup_succeeded(run_chain_setup(client))
        assert (
            client.get(
                "/v1/lab/documents/doc-b-protected",
                headers=OLD_A,
            ).status_code
            == 200
        )
        assert oracle(client)["violated"] is True

    assert forbidden_calls == []


def test_invalid_mode_is_rejected() -> None:
    with pytest.raises(TypeError, match="mode"):
        create_app()  # type: ignore[call-arg]
    with pytest.raises(ValueError, match=r"vulnerable.*patched"):
        create_app("unknown")


def test_programmatic_service_executes_the_same_typed_chain() -> None:
    service = DeterministicLabService.seed("vulnerable")
    initial = service.capture()
    actions = (
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
            payload=DelayQueueRequest(
                job_id=QueueJobId.ROLE_SYNC_A,
                delay_seconds=240,
            )
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
    )
    for action in actions:
        service.execute(action)
    assert service.oracle().violated is True
    assert service.capture_layers().clock.now.isoformat().endswith("+00:00")
    assert service.reset() == initial


def test_typed_action_union_rejects_unknown_actions_and_extras() -> None:
    adapter: TypeAdapter[TypedLabAction] = TypeAdapter(TypedLabAction)
    parsed = adapter.validate_python(
        {
            "action_type": "clock.advance",
            "actor": FixtureBearer.LAB_ADMIN,
            "payload": {"seconds": 90},
        }
    )
    assert isinstance(parsed, AdvanceClockLabAction)
    with pytest.raises(ValidationError):
        adapter.validate_python(
            {
                "action_type": "shell.execute",
                "actor": FixtureBearer.LAB_ADMIN,
                "payload": {},
            }
        )
    with pytest.raises(ValidationError):
        adapter.validate_python(
            {
                "action_type": "time.sleep",
                "actor": FixtureBearer.LAB_ADMIN,
                "payload": {"seconds": 90},
            }
        )
    with pytest.raises(ValidationError):
        adapter.validate_python(
            {
                "action_type": "clock.advance",
                "actor": FixtureBearer.LAB_ADMIN,
                "payload": {"seconds": 90, "command": "whoami"},
            }
        )
