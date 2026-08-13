from __future__ import annotations

import json
from dataclasses import dataclass, field

import pytest
from stateweaver.adapters.docker_compose import (
    ComposeAdapterError,
    MaterializedLabDockerRuntime,
    MaterializedLabRunRequest,
    ProcessResult,
)
from stateweaver.adapters.docker_compose import runner as runner_module
from stateweaver.adapters.docker_compose.runner import ProcessBoundaryError
from stateweaver.contracts import (
    ActionEnvelope,
    ActionTarget,
    HttpMethod,
    HttpRequestAction,
    RequestedBy,
    RequesterType,
    RiskClass,
    ScopeAction,
    canonical_json_bytes,
    sha256_digest,
)

_APP_IMAGE = f"sha256:{'a' * 64}"
_BRIDGE_IMAGE = f"sha256:{'b' * 64}"


def _action() -> ActionEnvelope:
    return ActionEnvelope(
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
            body_artifact="artifact:lab-action/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            expected_statuses=(200,),
        ),
        risk_class=RiskClass.PASSIVE,
        idempotency_key=sha256_digest("m5-runtime-idempotency"),
        requested_by=RequestedBy(type=RequesterType.WORKFLOW, role="m5_clean_root"),
        policy_decision_ref="policy.m5-runtime-01",
        sequence=1,
        timeout_ms=10_000,
    )


def _request() -> MaterializedLabRunRequest:
    action = _action()
    policy = canonical_json_bytes({"action_id": action.action_id, "allowed": True})
    return MaterializedLabRunRequest(
        repository_marker="0" * 40,
        mode="vulnerable",
        plan_id="plan.m5.runtime",
        root_seed_id="root.m5.runtime",
        root_digest=sha256_digest("root"),
        plan_digest=sha256_digest("plan"),
        actions=(action,),
        action_bytes=(canonical_json_bytes(action),),
        policy_authorization_bytes=(policy,),
    )


@dataclass
class _Runner:
    output: dict[str, object]
    calls: list[tuple[tuple[str, ...], bytes | None]] = field(default_factory=list)

    async def run(self, argv: tuple[str, ...], *, stdin: bytes | None = None) -> ProcessResult:
        self.calls.append((argv, stdin))
        if argv[:4] == ("docker", "image", "inspect", "--format"):
            return ProcessResult(
                returncode=0,
                stdout=_APP_IMAGE
                if argv[-1].startswith("stateweaver-materialized")
                else _BRIDGE_IMAGE,
            )
        if argv[-1] == "execute":
            return ProcessResult(returncode=0, stdout=json.dumps(self.output))
        return ProcessResult(returncode=0)


def _runtime_output(request: MaterializedLabRunRequest) -> dict[str, object]:
    action = request.actions[0]
    typed = action.action
    assert isinstance(typed, HttpRequestAction)
    assert typed.method is not None and typed.target is not None
    return {
        "execution_backend": "fastapi-asgi",
        "provider_checkpoint_status": "PARTIAL",
        "route_traces": [
            {
                "action_id": action.action_id,
                "action_digest": sha256_digest(action),
                "method": typed.method.value,
                "path": typed.target.path,
                "response_status": 200,
                "trace_id": "trace-m5-runtime-0001",
            }
        ],
    }


@pytest.mark.asyncio
async def test_runtime_uses_only_fixed_compose_argv_and_always_cleans_up() -> None:
    request = _request()
    runner = _Runner(_runtime_output(request))

    receipt = await MaterializedLabDockerRuntime(runner=runner).run(request)

    assert receipt.status == "M5_MATERIALIZED_APPLICATION_UNQUALIFIED"
    assert receipt.execution_backend == "fastapi-asgi"
    assert receipt.destroyed is True
    assert runner.calls[-1][0][-3:] == ("down", "--volumes", "--remove-orphans")
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
    assert execute_stdin is not None and b"action_bytes" in execute_stdin
    assert all("http://" not in " ".join(argv) for argv, _stdin in runner.calls)


@pytest.mark.asyncio
async def test_provider_only_or_static_boundary_is_rejected_and_cleaned_up() -> None:
    request = _request()
    runner = _Runner(
        {
            "execution_backend": "provider-bridge",
            "provider_checkpoint_status": "UNAVAILABLE",
            "route_traces": [],
        }
    )

    with pytest.raises(ComposeAdapterError, match="failed closed"):
        await MaterializedLabDockerRuntime(runner=runner).run(request)

    assert runner.calls[-1][0][-3:] == ("down", "--volumes", "--remove-orphans")


@pytest.mark.asyncio
async def test_timeout_or_partial_execution_forces_compose_cleanup() -> None:
    request = _request()

    @dataclass
    class _TimeoutRunner(_Runner):
        async def run(self, argv: tuple[str, ...], *, stdin: bytes | None = None) -> ProcessResult:
            self.calls.append((argv, stdin))
            if argv[:4] == ("docker", "image", "inspect", "--format"):
                return ProcessResult(
                    returncode=0,
                    stdout=(
                        _APP_IMAGE
                        if argv[-1].startswith("stateweaver-materialized")
                        else _BRIDGE_IMAGE
                    ),
                )
            if argv[-1] == "execute":
                raise ProcessBoundaryError("process-deadline-exceeded")
            return ProcessResult(returncode=0)

    runner = _TimeoutRunner({})
    with pytest.raises(ComposeAdapterError, match="failed closed"):
        await MaterializedLabDockerRuntime(runner=runner).run(request)
    assert runner.calls[-1][0][-3:] == ("down", "--volumes", "--remove-orphans")


def test_request_rejects_noncanonical_policy_bytes_and_caller_paths() -> None:
    request = _request()
    with pytest.raises(ValueError, match="policy bytes"):
        MaterializedLabRunRequest.model_validate(
            request.model_dump(mode="python") | {"policy_authorization_bytes": (b'{"b":1, "a":2}',)}
        )
    with pytest.raises(ValueError, match="HTTP envelope"):
        MaterializedLabRunRequest.model_validate(
            request.model_dump(mode="python")
            | {
                "actions": (
                    _action().model_copy(
                        update={
                            "action": _action().action.model_copy(
                                update={
                                    "target": ActionTarget(
                                        scheme="http", host="example.test", port=80, path="/x"
                                    )
                                }
                            )
                        }
                    ),
                )
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
