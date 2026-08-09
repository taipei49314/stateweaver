"""Authorized process-local observation over the repository-owned synthetic lab."""

from __future__ import annotations

import asyncio
import copy
import inspect
import traceback
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
import stateweaver.adapters.telemetry.opentelemetry.runtime as runtime_module
from pydantic import ValidationError
from stateweaver.adapters.in_process_lab import (
    CANONICAL_RANDOM_SEED,
    FixedLabActionRegistry,
    InProcessLabEnvironment,
    PolicyAuthorization,
    lab_action_artifact,
    lab_http_action_spec,
)
from stateweaver.adapters.telemetry.opentelemetry import (
    ObservedStatePath,
    RuntimeObservationController,
    RuntimeObservationError,
    RuntimeObservationRequest,
    RuntimeObservationResult,
    SpanKind,
)
from stateweaver.contracts import (
    ActionEnvelope,
    ActionTarget,
    EnvironmentMode,
    HttpRequestAction,
    RequestedBy,
    RequesterType,
    RiskClass,
    ScopeAction,
    ScopeActions,
    ScopeIdentities,
    ScopeLimits,
    ScopeManifest,
    ScopeMetadata,
    ScopeSpec,
    ScopeTargets,
    ScopeValidity,
    TargetSelector,
)
from stateweaver.policy import BudgetSnapshot, PolicyRequest, evaluate_policy
from stateweaver.replay import canonical_sha256
from stateweaver_lab import LabMode
from stateweaver_lab.fixtures import FixtureBearer
from stateweaver_lab.models import RetainSessionLabAction

EVALUATED_AT = datetime(2026, 7, 29, tzinfo=UTC)
LAB_ACTION = RetainSessionLabAction()


def _envelope(
    *,
    action_id: str = "action.runtime.retain",
    idempotency_key: str | None = None,
    timeout_ms: int = 1_000,
) -> ActionEnvelope:
    spec = lab_http_action_spec(LAB_ACTION)
    return ActionEnvelope(
        action_id=action_id,
        experiment_id="experiment.runtime.observation",
        world_id="world.runtime.001",
        scope_action=ScopeAction.HTTP_REQUEST,
        action=HttpRequestAction(
            method=spec.method,
            target=ActionTarget(
                scheme="http",
                host="localhost",
                port=80,
                path=spec.path,
            ),
            body_artifact=lab_action_artifact(LAB_ACTION),
            identity_handle=spec.identity_handle,
            expected_statuses=spec.expected_statuses,
        ),
        risk_class=RiskClass.REVERSIBLE_STATE_CHANGE,
        idempotency_key=idempotency_key
        or canonical_sha256({"action": action_id, "purpose": "runtime-observation"}),
        requested_by=RequestedBy(type=RequesterType.WORKFLOW, role="runtime_observation"),
        policy_decision_ref=f"decision.{action_id.removeprefix('action.')}",
        timeout_ms=timeout_ms,
    )


def _policy_request(
    envelope: ActionEnvelope,
    *,
    allow: bool = True,
    max_write_requests: int = 4,
) -> PolicyRequest:
    actions = (
        ScopeActions(allow=(ScopeAction.HTTP_REQUEST,))
        if allow
        else ScopeActions(
            allow=(ScopeAction.PASSIVE_OBSERVATION,),
            deny=(ScopeAction.HTTP_REQUEST,),
        )
    )
    manifest = ScopeManifest(
        metadata=ScopeMetadata(name="runtime-observation-tests"),
        spec=ScopeSpec(
            environmentMode=EnvironmentMode.SOURCE_BACKED,
            targets=ScopeTargets(
                include=(
                    TargetSelector(
                        host="localhost",
                        ports=(80,),
                        paths=("/v1/lab/**",),
                    ),
                )
            ),
            identities=ScopeIdentities(allowed=("test_user_a",)),
            actions=actions,
            limits=ScopeLimits(
                requestsPerSecond=10.0,
                concurrentMaterializedWorlds=1,
                maxWriteRequests=max_write_requests,
            ),
            validity=ScopeValidity(
                notBefore=datetime(2026, 1, 1, tzinfo=UTC),
                expiresAt=datetime(2027, 1, 1, tzinfo=UTC),
            ),
        ),
    )
    return PolicyRequest(
        scope_manifest=manifest,
        action_envelope=envelope,
        budget=BudgetSnapshot(
            requests_in_window=0,
            request_window_seconds=1.0,
            write_requests_used=0,
        ),
        evaluated_at=EVALUATED_AT,
    )


async def _runtime(
    *,
    envelope: ActionEnvelope | None = None,
    allow: bool = True,
    max_write_requests: int = 4,
) -> tuple[RuntimeObservationController, RuntimeObservationRequest, InProcessLabEnvironment]:
    authorized = envelope or _envelope()
    policy_request = _policy_request(
        authorized,
        allow=allow,
        max_write_requests=max_write_requests,
    )
    authorization = PolicyAuthorization.bind(
        authorized,
        policy_request,
        evaluate_policy(policy_request),
    )
    registry = FixedLabActionRegistry(
        by_action_id={authorized.action_id: LAB_ACTION},
        by_body_artifact={lab_action_artifact(LAB_ACTION): LAB_ACTION},
        policy_authorizations={authorized.policy_decision_ref: authorization},
    )
    environment = InProcessLabEnvironment(mode=LabMode.VULNERABLE, registry=registry)
    await environment.create_root_seed(
        root_seed_id="root.runtime.observation",
        random_seed=CANONICAL_RANDOM_SEED,
    )
    controller = RuntimeObservationController(environment)
    return controller, _request(authorized), environment


def _request(
    envelope: ActionEnvelope,
    *,
    world_id: str | None = None,
    name: str = "retain synthetic old session",
) -> RuntimeObservationRequest:
    return RuntimeObservationRequest(
        world_id=world_id or envelope.world_id,
        transition_id="transition.runtime.retain",
        name=name,
        action_envelope=envelope,
        expected_route="/v1/lab/session/retain",
        observed_paths=(
            ObservedStatePath(
                delta_id="delta.runtime.evidence-count",
                subject="resource.lab.application",
                capture_path="application.evidence_count",
                state_path="session.evidence_count",
            ),
        ),
    )


def test_controller_issues_trace_and_derives_state_delta_from_authorized_lab_action() -> None:
    async def exercise() -> None:
        controller, request, environment = await _runtime()

        result = await controller.observe(request)
        receipt = controller.verify(result.receipt)
        assert controller.verify(receipt.model_dump(mode="json")) == receipt

        assert result.flow.action == request.action_envelope.action
        assert result.flow.deltas == receipt.deltas
        assert receipt.action_envelope == request.action_envelope
        assert (
            receipt.authorization.policy_decision_ref == request.action_envelope.policy_decision_ref
        )
        assert receipt.authorization.idempotency_key == request.action_envelope.idempotency_key
        assert receipt.before_capture.payload_digest != receipt.after_capture.payload_digest
        assert receipt.before_capture.sequence + 1 == receipt.after_capture.sequence
        assert receipt.deltas[0].precondition.value == 0
        assert receipt.deltas[0].effect.value == 1
        assert receipt.deltas[0].observable.value == 1
        assert len(environment.evidence_records) == 1
        assert receipt.issued_trace.span.attribute_map()["http.route"] == request.expected_route
        assert receipt.trace_evidence.sha256 == receipt.issued_trace.span_digest
        assert receipt.source_digest.startswith("sha256:")
        assert receipt.receipt_digest.startswith("sha256:")

    asyncio.run(exercise())


def test_observation_request_cannot_accept_claimed_runtime_or_authorization_material() -> None:
    payload = _request(_envelope()).model_dump(mode="python")

    for forbidden in (
        "action",
        "policy_decision",
        "scope_manifest",
        "trace",
        "trace_evidence",
        "state_deltas",
        "taint",
        "before_capture",
    ):
        with pytest.raises(ValidationError):
            RuntimeObservationRequest.model_validate({**payload, forbidden: "caller-claimed"})


def test_observation_request_rejects_nonlocal_or_ambiguous_capture_contracts() -> None:
    base: dict[str, Any] = _request(_envelope()).model_dump(mode="python")
    rejected_payloads: list[dict[str, Any]] = []

    wrong_world = copy.deepcopy(base)
    wrong_world["world_id"] = "world.runtime.other"
    rejected_payloads.append(wrong_world)

    remote_target = copy.deepcopy(base)
    remote_target["action_envelope"]["action"]["target"]["host"] = "example.invalid"
    rejected_payloads.append(remote_target)

    no_paths = copy.deepcopy(base)
    no_paths["observed_paths"] = ()
    rejected_payloads.append(no_paths)

    duplicate_delta = copy.deepcopy(base)
    duplicate_delta["observed_paths"] = (
        base["observed_paths"][0],
        {
            **base["observed_paths"][0],
            "capture_path": "application.reference_published",
        },
    )
    rejected_payloads.append(duplicate_delta)

    duplicate_capture = copy.deepcopy(base)
    duplicate_capture["observed_paths"] = (
        base["observed_paths"][0],
        {
            **base["observed_paths"][0],
            "delta_id": "delta.runtime.other",
        },
    )
    rejected_payloads.append(duplicate_capture)

    for payload in rejected_payloads:
        with pytest.raises(ValidationError):
            RuntimeObservationRequest.model_validate(payload)


def test_controller_constructor_accepts_only_the_exact_environment_without_forge_tokens() -> None:
    assert not hasattr(runtime_module, "_FACTORY_TOKEN")
    assert not hasattr(runtime_module, "_InProcessLabBinding")
    assert tuple(inspect.signature(RuntimeObservationController).parameters) == ("environment",)
    slots = set(RuntimeObservationController.__slots__)
    assert not slots.intersection({"_app", "_binding", "_capture", "_source_schema", "_token"})

    secret = FixtureBearer.TENANT_A_OLD_EDITOR.value
    with pytest.raises(RuntimeObservationError, match="exact") as captured:
        RuntimeObservationController(object())
    assert captured.value.__cause__ is None
    assert secret not in "".join(
        traceback.format_exception(
            type(captured.value), captured.value, captured.value.__traceback__
        )
    )


def test_bound_environment_capture_method_cannot_be_substituted_after_factory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        controller, request, environment = await _runtime()
        forged_calls = 0

        async def forged_capture() -> object:
            nonlocal forged_calls
            forged_calls += 1
            return {"application": {"evidence_count": forged_calls}}

        monkeypatch.setattr(environment, "capture", forged_capture)
        result = await controller.observe(request)

        assert forged_calls == 0
        assert result.receipt.deltas[0].effect.value == 1

    asyncio.run(exercise())


def test_bound_environment_execution_and_route_cannot_be_substituted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        controller, request, environment = await _runtime()
        forged_calls = 0

        def forged_execute(*_args: object, **_kwargs: object) -> tuple[object, ...]:
            nonlocal forged_calls
            forged_calls += 1
            return ()

        monkeypatch.setattr(environment, "_execute_uncached", forged_execute)
        with pytest.raises(RuntimeObservationError) as captured:
            await controller.observe(request)

        assert forged_calls == 0
        assert not environment.evidence_records
        assert captured.value.__cause__ is None

        clean_controller, clean_request, clean_environment = await _runtime()
        unrelated_route = clean_request.model_copy(
            update={"expected_route": "/v1/lab/references/publish"}
        )
        with pytest.raises(RuntimeObservationError, match="route") as route_error:
            await clean_controller.observe(unrelated_route)

        assert not clean_environment.evidence_records
        assert route_error.value.__cause__ is None

    asyncio.run(exercise())


def test_bound_environment_internal_capture_cannot_be_substituted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        controller, request, environment = await _runtime()
        forged_calls = 0

        def forged_capture() -> object:
            nonlocal forged_calls
            forged_calls += 1
            return object()

        monkeypatch.setattr(environment, "_capture_unlocked", forged_capture)
        with pytest.raises(RuntimeObservationError) as captured:
            await controller.observe(request)

        assert forged_calls == 0
        assert not environment.evidence_records
        assert captured.value.__cause__ is None

    asyncio.run(exercise())


def test_bound_asgi_middleware_stack_cannot_be_substituted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        controller, request, environment = await _runtime()
        forged_calls = 0

        async def forged_app(
            _scope: object,
            _receive: object,
            _send: object,
        ) -> None:
            nonlocal forged_calls
            forged_calls += 1

        app = environment.__dict__["_app"]
        monkeypatch.setattr(app, "middleware_stack", forged_app)
        with pytest.raises(RuntimeObservationError) as captured:
            await controller.observe(request)

        assert forged_calls == 0
        assert not environment.evidence_records
        assert captured.value.__cause__ is None

    asyncio.run(exercise())


def test_policy_denial_and_budget_exhaustion_fail_before_app_state_changes() -> None:
    async def exercise() -> None:
        for options in ({"allow": False}, {"max_write_requests": 0}):
            controller, request, environment = await _runtime(**options)
            before = await type(environment).capture(environment)

            with pytest.raises(RuntimeObservationError, match="authorization") as captured:
                await controller.observe(request)

            after = await type(environment).capture(environment)
            assert after == before
            assert captured.value.__cause__ is None

    asyncio.run(exercise())


def test_idempotency_reuses_exact_result_and_rejects_semantic_conflicts() -> None:
    async def exercise() -> None:
        controller, request, environment = await _runtime()

        first = await controller.observe(request)
        after_first = await type(environment).capture(environment)
        second = await controller.observe(request)
        after_second = await type(environment).capture(environment)

        assert second == first
        assert after_second == after_first
        assert len(environment.evidence_records) == 1
        conflicting = request.model_copy(update={"name": "different observation semantics"})
        with pytest.raises(RuntimeObservationError, match="idempotency"):
            await controller.observe(conflicting)

    asyncio.run(exercise())


def test_second_controller_cannot_issue_a_fresh_trace_for_cached_execution() -> None:
    async def exercise() -> None:
        first_controller, request, environment = await _runtime()
        second_controller = RuntimeObservationController(environment)

        first = await first_controller.observe(request)
        with pytest.raises(RuntimeObservationError):
            await second_controller.observe(request)

        first_exporter = object.__getattribute__(first_controller, "_exporter")
        second_exporter = object.__getattribute__(second_controller, "_exporter")
        assert first_exporter._sequence == 1
        assert second_exporter._sequence == 0
        assert len(environment.evidence_records) == 1
        assert first.receipt.execution_id.startswith("execution.")
        assert first.receipt.execution_digest.startswith("sha256:")

    asyncio.run(exercise())


def test_concurrent_controllers_share_one_environment_issuance_claim() -> None:
    async def exercise() -> None:
        first_controller, request, environment = await _runtime()
        second_controller = RuntimeObservationController(environment)

        outcomes = await asyncio.gather(
            first_controller.observe(request),
            second_controller.observe(request),
            return_exceptions=True,
        )
        results = [item for item in outcomes if isinstance(item, RuntimeObservationResult)]
        failures = [item for item in outcomes if isinstance(item, RuntimeObservationError)]
        exporters = (
            object.__getattribute__(first_controller, "_exporter"),
            object.__getattribute__(second_controller, "_exporter"),
        )

        assert len(results) == 1
        assert len(failures) == 1
        assert sum(exporter._sequence for exporter in exporters) == 1
        assert len(environment.evidence_records) == 1

    asyncio.run(exercise())


def test_authorized_timeout_is_enforced_with_no_retained_exception_cause() -> None:
    async def exercise() -> None:
        envelope = _envelope(timeout_ms=10)
        controller, request, environment = await _runtime(envelope=envelope)
        environment_lock = environment.__dict__["_lock"]
        await environment_lock.acquire()
        try:
            with pytest.raises(RuntimeObservationError, match="deadline") as captured:
                await controller.observe(request)
        finally:
            environment_lock.release()

        assert captured.value.__cause__ is None
        with pytest.raises(RuntimeObservationError, match="poisoned"):
            await controller.observe(request)

    asyncio.run(exercise())


def test_actual_asgi_exception_cannot_retain_a_secret_cause_or_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        controller, request, environment = await _runtime()
        secret = FixtureBearer.TENANT_A_OLD_EDITOR.value
        state = environment.__dict__["_service"].__dict__["_state"]

        def forged_failure(_context: object) -> object:
            raise RuntimeError(f"forged app failure contained {secret}")

        monkeypatch.setattr(state, "retain_old_session", forged_failure)
        with pytest.raises(RuntimeObservationError, match="ASGI execution") as captured:
            await controller.observe(request)

        rendered = "".join(
            traceback.format_exception(
                type(captured.value),
                captured.value,
                captured.value.__traceback__,
            )
        )
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None
        assert secret not in rendered
        await environment.cleanup()
        assert not environment.evidence_records

    asyncio.run(exercise())


def test_controller_fails_closed_on_trace_capture_authorization_swap_and_order() -> None:
    async def exercise() -> None:
        first_controller, first_request, _first_environment = await _runtime()
        second_envelope = _envelope(action_id="action.runtime.second")
        second_controller, second_request, _second_environment = await _runtime(
            envelope=second_envelope
        )
        first = await first_controller.observe(first_request)
        second = await second_controller.observe(second_request)

        trace_tamper = first.receipt.model_dump(mode="python")
        trace_tamper["issued_trace"]["span_digest"] = "sha256:" + "0" * 64
        with pytest.raises(RuntimeObservationError):
            first_controller.verify(trace_tamper)

        trace_swap = first.receipt.model_dump(mode="python")
        trace_swap["issued_trace"] = second.receipt.issued_trace.model_dump(mode="python")
        with pytest.raises(RuntimeObservationError):
            first_controller.verify(trace_swap)

        authorization_swap = first.receipt.model_dump(mode="python")
        authorization_swap["authorization"] = second.receipt.authorization.model_dump(mode="python")
        with pytest.raises(RuntimeObservationError):
            first_controller.verify(authorization_swap)

        capture_tamper = first.receipt.model_dump(mode="python")
        capture_tamper["after_capture"]["payload_json"] = capture_tamper["before_capture"][
            "payload_json"
        ]
        with pytest.raises(RuntimeObservationError):
            first_controller.verify(capture_tamper)

        capture_swap = first.receipt.model_dump(mode="python")
        capture_swap["after_capture"] = second.receipt.after_capture.model_dump(mode="python")
        with pytest.raises(RuntimeObservationError):
            first_controller.verify(capture_swap)

        order_swap = first.receipt.model_dump(mode="python")
        order_swap["before_capture"], order_swap["after_capture"] = (
            order_swap["after_capture"],
            order_swap["before_capture"],
        )
        with pytest.raises(RuntimeObservationError):
            first_controller.verify(order_swap)

    asyncio.run(exercise())


def test_public_create_app_monkeypatch_cannot_replace_actual_asgi_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        import stateweaver_lab
        import stateweaver_lab.app as lab_app_module

        forged_calls = 0

        def forged_create_app(_mode: object) -> object:
            nonlocal forged_calls
            forged_calls += 1
            raise RuntimeError("forged public app factory must never run")

        monkeypatch.setattr(lab_app_module, "create_app", forged_create_app)
        monkeypatch.setattr(stateweaver_lab, "create_app", forged_create_app)
        controller, request, environment = await _runtime()
        result = await controller.observe(request)

        assert forged_calls == 0
        assert result.receipt.issued_trace.span.kind is SpanKind.SERVER
        assert result.receipt.issued_trace.span.attribute_map()["http.route"] == (
            request.expected_route
        )
        assert len(environment.evidence_records) == 1

    asyncio.run(exercise())


def test_runtime_trust_boundary_helpers_reject_malformed_or_secret_material() -> None:
    with pytest.raises(RuntimeObservationError, match="artifact set"):
        runtime_module._environment_capture_document(object())

    layer = SimpleNamespace(value="application")
    artifact = SimpleNamespace(layer=layer, payload={})
    with pytest.raises(RuntimeObservationError, match="layer names"):
        runtime_module._environment_capture_document(
            SimpleNamespace(artifacts=(artifact, artifact))
        )
    with pytest.raises(RuntimeObservationError, match="required layers"):
        runtime_module._environment_capture_document(SimpleNamespace(artifacts=()))

    malformed_documents: tuple[object, ...] = (
        [],
        {1: "non-string key"},
        {"value": object()},
    )
    for document in malformed_documents:
        with pytest.raises(RuntimeObservationError):
            runtime_module._json_document(document, label="adversarial document")
    with pytest.raises(RuntimeObservationError, match="nesting"):
        runtime_module._normalize_json(None, depth=33)

    for payload in ('{"authorization":"Bearer synthetic-secret"}', "not-json"):
        with pytest.raises(ValueError, match="capture payload") as capture_error:
            runtime_module._decode_capture(payload)
        assert capture_error.value.__cause__ is None
    with pytest.raises(RuntimeObservationError, match="secret-like key"):
        runtime_module._reject_secret_like_json({"password": "synthetic-secret"})
    with pytest.raises(RuntimeObservationError, match="secret-like text"):
        runtime_module._reject_secret_like_json(["authorization: synthetic-secret"])
    with pytest.raises(RuntimeObservationError, match="nesting"):
        runtime_module._reject_secret_like_json({}, depth=33)

    with pytest.raises(RuntimeObservationError, match="absent"):
        runtime_module._path_scalar({}, "application.evidence_count")
    with pytest.raises(RuntimeObservationError, match="scalar") as scalar_error:
        runtime_module._path_scalar({"application": {"value": []}}, "application.value")
    assert scalar_error.value.__cause__ is None
    with pytest.raises(TypeError, match="JSON scalar"):
        runtime_module._json_scalar(object())
