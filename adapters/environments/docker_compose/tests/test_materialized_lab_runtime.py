from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from typing import Literal

import pytest
from stateweaver.adapters.docker_compose import (
    ComposeAdapterError,
    MaterializedLabDockerRuntime,
    MaterializedLabRunRequest,
    ProcessResult,
)
from stateweaver.adapters.docker_compose import materialized_lab_runtime as runtime
from stateweaver.adapters.docker_compose import runner as runner_module
from stateweaver.adapters.docker_compose.real_provider_bridge import (
    ProviderCheckpointCapture,
    ProviderCheckpointObservation,
)
from stateweaver.adapters.docker_compose.runner import ProcessBoundaryError
from stateweaver.contracts import (
    ActionEnvelope,
    ActionTarget,
    EnvironmentMode,
    HttpMethod,
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
    canonical_json_bytes,
    sha256_digest,
)
from stateweaver.policy import BudgetSnapshot, PolicyAuthorization, PolicyRequest, evaluate_policy
from stateweaver_lab import LabStateCheckpoint
from stateweaver_lab.asgi import lab_action_artifact
from stateweaver_lab.fixtures import FixtureBearer
from stateweaver_lab.models import DocumentId, ReadDocumentLabAction, ReadDocumentRequest

_APP_IMAGE = f"sha256:{'a' * 64}"
_BRIDGE_IMAGE = f"sha256:{'b' * 64}"
_APP_CONTAINER = "c" * 64
_BRIDGE_CONTAINER = "d" * 64
_EVALUATED_AT = datetime(2026, 7, 29, tzinfo=UTC)


def _inputs() -> tuple[ActionEnvelope, ReadDocumentLabAction, PolicyRequest, PolicyAuthorization]:
    lab_action = ReadDocumentLabAction(
        actor=FixtureBearer.TENANT_A_OLD_EDITOR,
        payload=ReadDocumentRequest(document_id=DocumentId.TENANT_A_OWNED),
    )
    envelope = ActionEnvelope(
        action_id="action.m5-runtime-01",
        experiment_id="experiment.m5.clean-root",
        world_id="world.m5.clean-root",
        scope_action=ScopeAction.HTTP_REQUEST,
        action=HttpRequestAction(
            method=HttpMethod.GET,
            target=ActionTarget(
                scheme="http", host="localhost", port=80, path="/v1/lab/documents/doc-a-owned"
            ),
            identity_handle="identity:test_user_a",
            body_artifact=lab_action_artifact(lab_action),
            expected_statuses=(200, 403),
        ),
        risk_class=RiskClass.PASSIVE,
        idempotency_key=sha256_digest("m5-runtime-idempotency"),
        requested_by=RequestedBy(type=RequesterType.WORKFLOW, role="m5_clean_root"),
        policy_decision_ref="policy.m5-runtime-01",
        sequence=1,
        timeout_ms=10_000,
    )
    scope = ScopeManifest(
        metadata=ScopeMetadata(name="m5-runtime"),
        spec=ScopeSpec(
            environmentMode=EnvironmentMode.SOURCE_BACKED,
            targets=ScopeTargets(
                include=(TargetSelector(host="localhost", ports=(80,), paths=("/v1/lab/**",)),)
            ),
            identities=ScopeIdentities(allowed=("test_user_a",)),
            actions=ScopeActions(allow=(ScopeAction.HTTP_REQUEST,)),
            limits=ScopeLimits(
                requestsPerSecond=10.0,
                concurrentMaterializedWorlds=1,
                maxWriteRequests=8,
            ),
            validity=ScopeValidity(
                notBefore=datetime(2026, 1, 1, tzinfo=UTC),
                expiresAt=datetime(2027, 1, 1, tzinfo=UTC),
            ),
        ),
    )
    request = PolicyRequest(
        scope_manifest=scope,
        action_envelope=envelope,
        budget=BudgetSnapshot(
            requests_in_window=0, request_window_seconds=1.0, write_requests_used=0
        ),
        evaluated_at=_EVALUATED_AT,
    )
    return (
        envelope,
        lab_action,
        request,
        PolicyAuthorization.bind(envelope, request, evaluate_policy(request)),
    )


def _request() -> MaterializedLabRunRequest:
    action, lab_action, policy_request, authorization = _inputs()
    return MaterializedLabRunRequest(
        repository_marker="0" * 40,
        mode="vulnerable",
        scenario="same_tenant_document",
        run_id="run.m5.runtime",
        plan_id="plan.m5.runtime",
        root_seed_id="root.m5.runtime",
        root_digest=sha256_digest("root"),
        plan_digest=sha256_digest("plan"),
        m4_state_binding_digest=sha256_digest("m4-binding"),
        m4_source_snapshot_digest=sha256_digest("m4-snapshot"),
        m4_after_archive_digest=sha256_digest("m4-archive"),
        m4_provider_state_digest=sha256_digest("m4-providers"),
        actions=(action,),
        action_bytes=(canonical_json_bytes(action),),
        lab_actions=(lab_action,),
        lab_action_bytes=(canonical_json_bytes(lab_action),),
        policy_authorizations=(authorization,),
        policy_authorization_bytes=(authorization.canonical_bytes(),),
        policy_requests=(policy_request,),
        policy_request_bytes=(policy_request.canonical_bytes(),),
    )


def _primary_request(mode: Literal["vulnerable", "patched"]) -> MaterializedLabRunRequest:
    from stateweaver.cli.runtime_qualification import (
        OBSERVED_LAB_ACTIONS,
        _action_envelope,
        _policy_request,
    )

    actions = tuple(
        _action_envelope(index).model_copy(update={"sequence": index}) for index in range(1, 9)
    )
    policy_requests = tuple(
        _policy_request(action, index) for index, action in enumerate(actions, start=1)
    )
    authorizations = tuple(
        PolicyAuthorization.bind(action, request, evaluate_policy(request))
        for action, request in zip(actions, policy_requests, strict=True)
    )
    return MaterializedLabRunRequest(
        repository_marker="0" * 40,
        mode=mode,
        scenario="primary_patched" if mode == "patched" else "primary_vulnerable",
        run_id=f"run.m5.runtime-primary-{mode}",
        plan_id="plan.m5.runtime-primary",
        root_seed_id="root.m5.runtime-primary",
        root_digest=sha256_digest("primary-root"),
        plan_digest=sha256_digest("primary-plan"),
        m4_state_binding_digest=sha256_digest("m4-binding"),
        m4_source_snapshot_digest=sha256_digest("m4-snapshot"),
        m4_after_archive_digest=sha256_digest("m4-archive"),
        m4_provider_state_digest=sha256_digest("m4-providers"),
        actions=actions,
        action_bytes=tuple(canonical_json_bytes(item) for item in actions),
        lab_actions=OBSERVED_LAB_ACTIONS,
        lab_action_bytes=tuple(canonical_json_bytes(item) for item in OBSERVED_LAB_ACTIONS),
        policy_authorizations=authorizations,
        policy_authorization_bytes=tuple(item.canonical_bytes() for item in authorizations),
        policy_requests=policy_requests,
        policy_request_bytes=tuple(item.canonical_bytes() for item in policy_requests),
    )


@dataclass
class _Runner:
    output: dict[str, object]
    calls: list[tuple[tuple[str, ...], bytes | None]] = field(default_factory=list)

    async def run(self, argv: tuple[str, ...], *, stdin: bytes | None = None) -> ProcessResult:
        self.calls.append((argv, stdin))
        if argv[-3:] == ("ps", "--quiet", "materialized-lab"):
            return ProcessResult(returncode=0, stdout=_APP_CONTAINER)
        if argv[-3:] == ("ps", "--quiet", "provider-bridge"):
            return ProcessResult(returncode=0, stdout=_BRIDGE_CONTAINER)
        if argv[:4] == ("docker", "inspect", "--format", "{{.Image}}"):
            return ProcessResult(
                returncode=0,
                stdout=_APP_IMAGE if argv[-1] == _APP_CONTAINER else _BRIDGE_IMAGE,
            )
        if argv[:4] == (
            "docker",
            "inspect",
            "--format",
            runtime._SOURCE_REVISION_FORMAT,
        ):
            return ProcessResult(returncode=0, stdout="0" * 40)
        if argv[-1] == "execute":
            return ProcessResult(
                returncode=0, stdout=json.dumps(runtime._json_compatible(self.output))
            )
        return ProcessResult(returncode=0)


def _capture(checkpoint: LabStateCheckpoint) -> ProviderCheckpointCapture:
    raw = checkpoint.canonical_bytes()
    observations = tuple(
        ProviderCheckpointObservation(
            provider=provider,
            generation=checkpoint.generation,
            checkpoint_digest=checkpoint.checkpoint_digest,
            storage_digest="sha256:" + sha256(raw).hexdigest(),
        )
        for provider in runtime._PROVIDERS
    )
    return ProviderCheckpointCapture(
        generation=checkpoint.generation,
        checkpoint_digest=checkpoint.checkpoint_digest,
        checkpoint_bytes=raw,
        observations=observations,
    )


class _ProviderStore:
    def __init__(self) -> None:
        self.staged: dict[str, ProviderCheckpointCapture] = {}
        self.active: str | None = None

    def stage(self, raw: bytes) -> ProviderCheckpointCapture:
        capture = _capture(LabStateCheckpoint.from_canonical_bytes(raw))
        self.staged[capture.generation] = capture
        return capture

    def load_active(self) -> ProviderCheckpointCapture:
        assert self.active is not None
        return self.staged[self.active]

    def compare_and_swap(
        self, expected: str | None, next_generation: str
    ) -> ProviderCheckpointCapture:
        assert self.active == expected
        self.active = next_generation
        return self.load_active()


@pytest.mark.asyncio
async def test_container_executes_actual_asgi_and_commits_each_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _ProviderStore()
    monkeypatch.setattr(runtime, "RealProviderLabStateStore", lambda: store)

    output = await runtime._execute_in_container(_request())

    assert output["execution_backend"] == "fastapi-asgi"
    assert output["checkpoint_visibility"] == "SIX_IMMUTABLE_SHARDS_POSTGRES_CAS"
    steps = output["steps"]
    assert isinstance(steps, list) and len(steps) == 1
    trace = steps[0]["trace"]
    assert trace["route"] == "/v1/lab/documents/{document_id}"
    assert trace["response_status"] == 200
    final_checkpoint = output["final_checkpoint"]
    assert isinstance(final_checkpoint, dict)
    assert store.active == final_checkpoint["generation"]
    observations = final_checkpoint["observations"]
    assert isinstance(observations, list) and len(observations) == 6


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "expected_status", "expected_verdict"),
    (("vulnerable", 200, "VIOLATED"), ("patched", 403, "NOT_VIOLATED")),
)
async def test_full_primary_chain_uses_eight_actual_asgi_checkpoint_transitions(
    monkeypatch: pytest.MonkeyPatch,
    mode: Literal["vulnerable", "patched"],
    expected_status: int,
    expected_verdict: str,
) -> None:
    store = _ProviderStore()
    monkeypatch.setattr(runtime, "RealProviderLabStateStore", lambda: store)

    output = await runtime._execute_in_container(_primary_request(mode))

    steps = output["steps"]
    assert isinstance(steps, list) and len(steps) == 8
    assert steps[-1]["trace"]["response_status"] == expected_status
    assert steps[-1]["oracle"]["verdict"] == expected_verdict
    assert all(len(step["after"]["observations"]) == 6 for step in steps)


def test_checkpoint_witness_rejects_exact_bytes_substitution() -> None:
    from stateweaver_lab import create_app

    witness = runtime._checkpoint_witness(
        _capture(create_app("vulnerable").state.lab.export_checkpoint())
    )
    tampered = dict(witness)
    observations = tampered["observations"]
    assert isinstance(observations, list)
    tampered["observations"] = tuple(observations)
    raw = witness["checkpoint_bytes"]
    assert isinstance(raw, bytes)
    tampered["checkpoint_bytes"] = raw + b" "
    tampered["checkpoint_bytes_digest"] = "sha256:" + sha256(raw + b" ").hexdigest()
    with pytest.raises(ValueError, match="checkpoint witness bytes"):
        runtime.CheckpointWitness.model_validate(tampered)


@pytest.mark.asyncio
async def test_forged_oracle_or_evidence_is_rejected_even_when_outer_digests_are_rehashed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _ProviderStore()
    monkeypatch.setattr(runtime, "RealProviderLabStateStore", lambda: store)
    request = _request()
    output = await runtime._execute_in_container(request)
    binding_values: dict[str, object] = {
        "application_image_id": _APP_IMAGE,
        "bridge_image_id": _BRIDGE_IMAGE,
        "application_container_id": _APP_CONTAINER,
        "bridge_container_id": _BRIDGE_CONTAINER,
        "application_source_revision": "0" * 40,
        "image_identity_provenance": "EXECUTED_COMPOSE_CONTAINERS",
        "provider_image_refs": runtime._PROVIDER_IMAGE_REFS,
        "provider_image_set_digest": sha256_digest(runtime._PROVIDER_IMAGE_REFS),
        "provider_image_provenance": "PINNED_MANIFEST_REFS_NOT_RUNTIME_IMAGE_IDS",
    }
    binding = runtime.ApplicationImageBinding.model_validate(
        {**binding_values, "binding_digest": runtime._digest(binding_values)}
    )
    for receipt_field in ("oracle", "appended_evidence"):
        forged = json.loads(json.dumps(runtime._json_compatible(output)))
        step = forged["steps"][0]
        if receipt_field == "oracle":
            step[receipt_field]["verdict"] = "VIOLATED"
            step[receipt_field]["violated"] = True
            step["oracle_digest"] = runtime._digest(step[receipt_field])
        else:
            step[receipt_field]["outcome"] = "forged"
        step_values = {key: value for key, value in step.items() if key != "step_digest"}
        step["step_digest"] = runtime._digest(step_values)
        with pytest.raises(ValueError, match="step is not content bound"):
            runtime._parse_runtime_result(
                ProcessResult(returncode=0, stdout=json.dumps(forged)), request, binding
            )


@pytest.mark.asyncio
async def test_forged_trace_is_rejected_even_when_every_outer_digest_is_rehashed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _ProviderStore()
    monkeypatch.setattr(runtime, "RealProviderLabStateStore", lambda: store)
    request = _request()
    output = await runtime._execute_in_container(request)
    binding_values: dict[str, object] = {
        "application_image_id": _APP_IMAGE,
        "bridge_image_id": _BRIDGE_IMAGE,
        "application_container_id": _APP_CONTAINER,
        "bridge_container_id": _BRIDGE_CONTAINER,
        "application_source_revision": "0" * 40,
        "image_identity_provenance": "EXECUTED_COMPOSE_CONTAINERS",
        "provider_image_refs": runtime._PROVIDER_IMAGE_REFS,
        "provider_image_set_digest": sha256_digest(runtime._PROVIDER_IMAGE_REFS),
        "provider_image_provenance": "PINNED_MANIFEST_REFS_NOT_RUNTIME_IMAGE_IDS",
    }
    binding = runtime.ApplicationImageBinding.model_validate(
        {**binding_values, "binding_digest": runtime._digest(binding_values)}
    )
    substitutions: tuple[tuple[str, object], ...] = (
        ("method", "POST"),
        ("path", "/v1/lab/forged"),
        ("route", "/v1/lab/forged"),
        ("response_status", 599),
        ("lab_action_digest", sha256_digest("forged-lab-action")),
        ("policy_authorization_digest", sha256_digest("forged-authorization")),
        ("policy_request_digest", sha256_digest("forged-request")),
        ("response_body", b'{"evidence_id":"ev-999"}'),
        ("response_evidence_id", None),
    )
    for trace_field, value in substitutions:
        forged = json.loads(json.dumps(runtime._json_compatible(output)))
        trace = forged["steps"][0]["trace"]
        trace[trace_field] = runtime._json_compatible(value)
        if trace_field == "response_body":
            assert isinstance(value, bytes)
            trace["response_body_digest"] = runtime._raw_digest(value)
        trace_values = {key: item for key, item in trace.items() if key != "observation_digest"}
        trace["observation_digest"] = runtime._digest(trace_values)
        step = forged["steps"][0]
        step_values = {key: item for key, item in step.items() if key != "step_digest"}
        step["step_digest"] = runtime._digest(step_values)
        with pytest.raises(ValueError):
            runtime._parse_runtime_result(
                ProcessResult(returncode=0, stdout=json.dumps(forged)), request, binding
            )


def test_control_plan_and_root_identifiers_accept_compiler_grammar() -> None:
    request = _request().model_dump(mode="python")
    request["plan_id"] = "plan.m5.control-masked_response"
    request["root_seed_id"] = "root.m5.control-masked_response"
    closed = MaterializedLabRunRequest.model_validate(request)
    assert closed.plan_id.endswith("masked_response")


@pytest.mark.asyncio
async def test_timeout_occurs_before_checkpoint_visibility_cas(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _ProviderStore()
    monkeypatch.setattr(runtime, "RealProviderLabStateStore", lambda: store)

    async def timeout(*_args: object, **_kwargs: object) -> object:
        raise TimeoutError

    monkeypatch.setattr(runtime, "execute_lab_action_asgi", timeout)
    with pytest.raises(ValueError, match="timeout"):
        await runtime._execute_in_container(_request())
    assert store.active is not None
    assert len(store.staged) == 1


def test_container_execute_serializes_exact_checkpoint_bytes(
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    request = _request()
    binding_values: dict[str, object] = {
        "application_image_id": _APP_IMAGE,
        "bridge_image_id": _BRIDGE_IMAGE,
        "application_container_id": _APP_CONTAINER,
        "bridge_container_id": _BRIDGE_CONTAINER,
        "application_source_revision": "0" * 40,
        "image_identity_provenance": "EXECUTED_COMPOSE_CONTAINERS",
        "provider_image_refs": runtime._PROVIDER_IMAGE_REFS,
        "provider_image_set_digest": sha256_digest(runtime._PROVIDER_IMAGE_REFS),
        "provider_image_provenance": "PINNED_MANIFEST_REFS_NOT_RUNTIME_IMAGE_IDS",
    }
    binding = runtime.ApplicationImageBinding.model_validate(
        {**binding_values, "binding_digest": runtime._digest(binding_values)}
    )
    payload = runtime._runtime_payload(request, binding)

    class _Input:
        buffer = __import__("io").BytesIO(payload)

    store = _ProviderStore()
    monkeypatch.setattr(runtime, "RealProviderLabStateStore", lambda: store)
    monkeypatch.setattr(sys, "stdin", _Input())
    assert runtime._container_main(("materialized_lab_runtime", "execute")) == 0
    output = json.loads(capsysbinary.readouterr().out)
    raw = output["initial_checkpoint"]["checkpoint_bytes"].encode("utf-8")
    LabStateCheckpoint.from_canonical_bytes(raw)


@pytest.mark.asyncio
async def test_runtime_uses_only_fixed_compose_argv_and_always_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request()
    store = _ProviderStore()
    monkeypatch.setattr(runtime, "RealProviderLabStateStore", lambda: store)
    output = await runtime._execute_in_container(request)
    runner = _Runner(output)

    receipt = await MaterializedLabDockerRuntime(runner=runner).run(request)

    assert receipt.status == "M5_MATERIALIZED_APPLICATION_SCENARIO_EXECUTED"
    assert receipt.execution_backend == "fastapi-asgi"
    assert receipt.destroyed is True
    assert receipt.image_binding.application_container_id == _APP_CONTAINER
    assert receipt.image_binding.bridge_container_id == _BRIDGE_CONTAINER
    assert receipt.image_binding.application_image_id == _APP_IMAGE
    assert receipt.image_binding.bridge_image_id == _BRIDGE_IMAGE
    assert receipt.image_binding.application_source_revision == request.repository_marker
    up_index = next(
        index
        for index, (argv, _stdin) in enumerate(runner.calls)
        if argv[-4:] == ("up", "--detach", "--wait", "--no-build")
    )
    identity_index = next(
        index
        for index, (argv, _stdin) in enumerate(runner.calls)
        if argv[-3:] == ("ps", "--quiet", "materialized-lab")
    )
    assert identity_index > up_index
    assert any(
        argv[-3:] == ("down", "--volumes", "--remove-orphans") for argv, _stdin in runner.calls
    )
    assert tuple(argv[1:3] for argv, _stdin in runner.calls[-3:]) == (
        ("ps", "--all"),
        ("network", "ls"),
        ("volume", "ls"),
    )
    execute_argv, execute_stdin = next(item for item in runner.calls if item[0][-1] == "execute")
    assert execute_argv[-7:] == (
        "exec",
        "--no-TTY",
        "materialized-lab",
        "python",
        "-m",
        "stateweaver.adapters.docker_compose.materialized_lab_runtime",
        "execute",
    )
    assert execute_stdin is not None and b"policy_request_bytes" in execute_stdin
    assert all("http://" not in " ".join(argv) for argv, _stdin in runner.calls)


@pytest.mark.asyncio
async def test_runtime_rejects_executed_app_with_another_source_revision() -> None:
    @dataclass
    class _WrongRevisionRunner(_Runner):
        async def run(self, argv: tuple[str, ...], *, stdin: bytes | None = None) -> ProcessResult:
            if argv[:4] == (
                "docker",
                "inspect",
                "--format",
                runtime._SOURCE_REVISION_FORMAT,
            ):
                self.calls.append((argv, stdin))
                return ProcessResult(returncode=0, stdout="f" * 40)
            return await super().run(argv, stdin=stdin)

    runner = _WrongRevisionRunner({})
    with pytest.raises(ComposeAdapterError, match="source revision"):
        await MaterializedLabDockerRuntime(runner=runner).run(_request())
    assert any(
        argv[-3:] == ("down", "--volumes", "--remove-orphans") for argv, _stdin in runner.calls
    )


@pytest.mark.asyncio
async def test_receipt_independently_rejects_another_source_revision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _ProviderStore()
    monkeypatch.setattr(runtime, "RealProviderLabStateStore", lambda: store)
    request = _request()
    output = await runtime._execute_in_container(request)
    binding_values: dict[str, object] = {
        "application_container_id": _APP_CONTAINER,
        "application_image_id": _APP_IMAGE,
        "application_source_revision": "f" * 40,
        "bridge_container_id": _BRIDGE_CONTAINER,
        "bridge_image_id": _BRIDGE_IMAGE,
        "image_identity_provenance": "EXECUTED_COMPOSE_CONTAINERS",
        "provider_image_refs": runtime._PROVIDER_IMAGE_REFS,
        "provider_image_set_digest": sha256_digest(runtime._PROVIDER_IMAGE_REFS),
        "provider_image_provenance": "PINNED_MANIFEST_REFS_NOT_RUNTIME_IMAGE_IDS",
    }
    binding = runtime.ApplicationImageBinding.model_validate(
        {**binding_values, "binding_digest": runtime._digest(binding_values)}
    )
    with pytest.raises(ValueError, match="receipt is not content bound"):
        runtime._parse_runtime_result(
            ProcessResult(returncode=0, stdout=json.dumps(runtime._json_compatible(output))),
            request,
            binding,
        )


@pytest.mark.asyncio
async def test_static_or_provider_only_output_is_rejected_and_cleaned_up() -> None:
    runner = _Runner({"execution_backend": "provider-bridge", "steps": []})
    with pytest.raises(ComposeAdapterError, match="failed closed"):
        await MaterializedLabDockerRuntime(runner=runner).run(_request())
    assert any(
        argv[-3:] == ("down", "--volumes", "--remove-orphans") for argv, _stdin in runner.calls
    )


@pytest.mark.asyncio
async def test_timeout_forces_compose_cleanup() -> None:
    @dataclass
    class _TimeoutRunner(_Runner):
        async def run(self, argv: tuple[str, ...], *, stdin: bytes | None = None) -> ProcessResult:
            if argv[-1] == "execute":
                self.calls.append((argv, stdin))
                raise ProcessBoundaryError("process-deadline-exceeded")
            return await super().run(argv, stdin=stdin)

    runner = _TimeoutRunner({})
    with pytest.raises(ComposeAdapterError, match="failed closed"):
        await MaterializedLabDockerRuntime(runner=runner).run(_request())
    assert any(
        argv[-3:] == ("down", "--volumes", "--remove-orphans") for argv, _stdin in runner.calls
    )


@pytest.mark.asyncio
async def test_receipt_is_not_minted_when_cleanup_inventory_has_residue() -> None:
    @dataclass
    class _ResidualRunner(_Runner):
        async def run(self, argv: tuple[str, ...], *, stdin: bytes | None = None) -> ProcessResult:
            result = await super().run(argv, stdin=stdin)
            if argv[1:3] == ("volume", "ls"):
                return ProcessResult(returncode=0, stdout="retained-volume")
            return result

    runner = _ResidualRunner({"execution_backend": "provider-bridge", "steps": []})
    with pytest.raises(ComposeAdapterError, match="cleanup failed"):
        await MaterializedLabDockerRuntime(runner=runner).run(_request())


@pytest.mark.asyncio
async def test_cleanup_failure_takes_precedence_over_execution_failure() -> None:
    @dataclass
    class _DoubleFailureRunner(_Runner):
        async def run(self, argv: tuple[str, ...], *, stdin: bytes | None = None) -> ProcessResult:
            if argv[-1] == "execute":
                self.calls.append((argv, stdin))
                raise ProcessBoundaryError("process-deadline-exceeded")
            if argv[-3:] == ("down", "--volumes", "--remove-orphans"):
                self.calls.append((argv, stdin))
                return ProcessResult(returncode=1)
            return await super().run(argv, stdin=stdin)

    with pytest.raises(ComposeAdapterError, match="cleanup failed"):
        await MaterializedLabDockerRuntime(runner=_DoubleFailureRunner({})).run(_request())


def test_request_rejects_policy_or_typed_action_substitution() -> None:
    request = _request()
    with pytest.raises(ValueError, match="retained bytes"):
        MaterializedLabRunRequest.model_validate(
            request.model_dump(mode="python") | {"policy_request_bytes": (b"{}",)}
        )


def test_request_accepts_compiled_m4_primary_root_seed() -> None:
    request = _request()
    rebound = request.model_copy(update={"root_seed_id": "root.m4.real-provider.a1b2c3"})

    assert (
        MaterializedLabRunRequest.model_validate(rebound.model_dump(mode="python")).root_seed_id
        == "root.m4.real-provider.a1b2c3"
    )
    with pytest.raises(ValueError, match="closed lab registry"):
        MaterializedLabRunRequest.model_validate(
            request.model_dump(mode="python")
            | {
                "actions": (
                    request.actions[0].model_copy(
                        update={
                            "action": request.actions[0].action.model_copy(
                                update={"identity_handle": "identity:test_user_b"}
                            )
                        }
                    ),
                ),
                "action_bytes": (
                    canonical_json_bytes(
                        request.actions[0].model_copy(
                            update={
                                "action": request.actions[0].action.model_copy(
                                    update={"identity_handle": "identity:test_user_b"}
                                )
                            }
                        )
                    ),
                ),
            }
        )


def test_runner_admits_application_execute_only_with_fixed_argv() -> None:
    project = "swm2" + "1" * 32
    expected = (
        "docker",
        "compose",
        "--project-name",
        project,
        "--file",
        str(runner_module._REAL_COMPOSE_FILE),
        "exec",
        "--no-TTY",
        "materialized-lab",
        "python",
        "-m",
        "stateweaver.adapters.docker_compose.materialized_lab_runtime",
        "execute",
    )
    assert runner_module.require_exact_argv(expected) == expected
    with pytest.raises(ValueError):
        runner_module.require_exact_argv((*expected, "--caller-command"))


def test_runner_admits_only_fixed_executed_container_identity_argv() -> None:
    project = "swm2" + "1" * 32
    compose_prefix = (
        "docker",
        "compose",
        "--project-name",
        project,
        "--file",
        str(runner_module._REAL_COMPOSE_FILE),
    )
    for service in ("materialized-lab", "provider-bridge"):
        argv = (*compose_prefix, "ps", "--quiet", service)
        assert runner_module.require_exact_argv(argv) == argv
    for container in (_APP_CONTAINER, _BRIDGE_CONTAINER):
        image_argv = ("docker", "inspect", "--format", "{{.Image}}", container)
        assert runner_module.require_exact_argv(image_argv) == image_argv
    revision_argv = (
        "docker",
        "inspect",
        "--format",
        runtime._SOURCE_REVISION_FORMAT,
        _APP_CONTAINER,
    )
    assert runner_module.require_exact_argv(revision_argv) == revision_argv
    with pytest.raises(ValueError):
        runner_module.require_exact_argv(
            (*compose_prefix, "ps", "--quiet", "caller-controlled-service")
        )
    with pytest.raises(ValueError):
        runner_module.require_exact_argv(
            ("docker", "inspect", "--format", "{{json .Config.Labels}}", _APP_CONTAINER)
        )
