from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from stateweaver.adapters.docker_compose import (
    ComposeAdapterError,
    M5MaterializedProviderRunRequest,
    MaterializedCandidateRequest,
    ProcessResult,
    RealDockerComposeEnvironmentAdapter,
)
from stateweaver.adapters.docker_compose import runner as runner_module
from stateweaver.adapters.docker_compose.runner import require_exact_argv
from stateweaver.contracts import (
    ActionEnvelope,
    ActionTarget,
    HttpMethod,
    HttpRequestAction,
    RequestedBy,
    RequesterType,
    RiskClass,
    ScopeAction,
    WorldTier,
    sha256_digest,
)
from stateweaver.worlds import CapabilityLevel, EnvironmentHandle, TargetSpec

_IMAGE_ID = f"sha256:{'4' * 64}"
_IMAGE = "stateweaver-real-provider-bridge:local"
_BRIDGE = (
    "exec",
    "--no-TTY",
    "provider-bridge",
    "python",
    "/opt/stateweaver/real_provider_bridge.py",
)


def _components(marker: str = "baseline", *, tick: int = 0) -> dict[str, object]:
    timestamp = (
        (datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=tick))
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )
    return {
        "filesystem": {"files": {"marker.txt": marker, "tenant.txt": "alpha"}},
        "database": {"rows": [{"id": 1, "tenant": "alpha", "value": marker}]},
        "cache": {"entries": {"sw:marker": marker}},
        "queue": {"messages": [marker]},
        "session": {
            "cookies": [{"name": "sw_marker", "path": "/", "value": marker}],
            "local_storage": {"sw.marker": marker},
        },
        "clock": {"iso8601": timestamp, "tick": tick},
    }


def _archive(components: dict[str, object]) -> str:
    return json.dumps(
        {
            "schema_version": "2.0",
            "target": {"target_id": "real-provider-demo", "target_version": "1.0.0"},
            "components": components,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


@dataclass
class _RealRunner:
    states: dict[str, dict[str, object]] = field(default_factory=dict)
    running: dict[str, str] = field(default_factory=dict)
    calls: list[tuple[tuple[str, ...], bytes | None]] = field(default_factory=list)
    image_id: str = _IMAGE_ID
    cleanup_residue: bool = False
    unchanged_provider: str | None = None

    async def run(
        self,
        argv: tuple[str, ...],
        *,
        stdin: bytes | None = None,
    ) -> ProcessResult:
        self.calls.append((argv, stdin))
        if argv == ("docker", "version", "--format", "{{.Server.Version}}"):
            return ProcessResult(returncode=0, stdout="29.0.0")
        if argv[:3] == ("docker", "image", "inspect"):
            assert argv[-1] == _IMAGE
            return ProcessResult(returncode=0, stdout=self.image_id + "\n")
        if argv[:4] == ("docker", "inspect", "--format", "{{.Image}}"):
            project = "swm2" + argv[4]
            return ProcessResult(returncode=0, stdout=self.running[project] + "\n")
        if argv[:3] in {
            ("docker", "ps", "--all"),
            ("docker", "network", "ls"),
            ("docker", "volume", "ls"),
        }:
            return ProcessResult(returncode=0, stdout="residue\n" if self.cleanup_residue else "")

        project = argv[3]
        operation = argv[6:]
        if operation == ("up", "--detach", "--wait", "--no-build"):
            self.states.setdefault(project, _components())
            self.running[project] = self.image_id
            return ProcessResult(returncode=0)
        if operation == ("down", "--volumes", "--remove-orphans"):
            self.states.pop(project, None)
            self.running.pop(project, None)
            return ProcessResult(returncode=0)
        if operation == ("ps", "--format", "json", "provider-bridge"):
            return ProcessResult(
                returncode=0,
                stdout=json.dumps(
                    [
                        {
                            "Service": "provider-bridge",
                            "Image": _IMAGE,
                            "ID": project.removeprefix("swm2"),
                            "Project": project,
                            "State": "running",
                            "Health": "healthy",
                        }
                    ]
                ),
            )
        if operation == (*_BRIDGE, "export"):
            return ProcessResult(returncode=0, stdout=_archive(self.states[project]))
        if operation == (*_BRIDGE, "import"):
            assert stdin is not None
            value = json.loads(stdin)
            self.states[project] = deepcopy(value["components"])
            return ProcessResult(
                returncode=0,
                stdout='{"accepted":true,"schema_version":"2.0"}',
            )
        if operation == (*_BRIDGE, "mutate"):
            assert stdin is not None
            request = json.loads(stdin)
            before = deepcopy(self.states[project])
            changed = _components(request["marker"], tick=request["tick"])
            if self.unchanged_provider is not None:
                changed[self.unchanged_provider] = before[self.unchanged_provider]
            self.states[project] = changed
            return ProcessResult(
                returncode=0,
                stdout='{"accepted":true,"schema_version":"2.0"}',
            )
        if operation == (*_BRIDGE, "m5-replay"):
            assert stdin is not None
            request = json.loads(stdin)
            steps: list[dict[str, object]] = []
            for sequence, item in enumerate(request["actions"], start=1):
                before_archive = _archive(deepcopy(self.states[project]))
                envelope = item["envelope"]
                marker = f"m5-{sequence}-{item['action_digest'].removeprefix('sha256:')[:48]}"
                self.states[project] = _components(marker, tick=sequence)
                after_archive = _archive(deepcopy(self.states[project]))
                boundary = request["scenario"]
                terminal = sequence == len(request["actions"])
                outcome = {
                    "primary_vulnerable": "VIOLATED",
                    "primary_patched": "SATISFIED",
                    "masked_response": "SATISFIED",
                    "mock_only_response": "INCONCLUSIVE",
                    "fresh_session": "SATISFIED",
                    "same_tenant_document": "SATISFIED",
                }[boundary]
                status = 403 if boundary in {"primary_patched", "fresh_session"} else 200
                steps.append(
                    {
                        "step_id": f"step.{sequence:02d}",
                        "action_id": envelope["action_id"],
                        "action_digest": item["action_digest"],
                        "response_status": status if terminal else 200,
                        "oracle_outcome": outcome if terminal else "INCONCLUSIVE",
                        "before": json.loads(before_archive),
                        "after": json.loads(after_archive),
                    }
                )
            return ProcessResult(
                returncode=0,
                stdout=json.dumps({"accepted": True, "schema_version": "m5.1", "steps": steps}),
            )
        raise AssertionError(f"unexpected operation: {operation!r}")

    @staticmethod
    def project(environment: EnvironmentHandle) -> str:
        return environment.opaque_ref.removeprefix("compose:")


def _target() -> TargetSpec:
    return TargetSpec(target_id="real-provider-demo", target_version="1.0.0")


def _m5_actions() -> tuple[ActionEnvelope, ...]:
    routes = (
        ("POST", "/v1/lab/session/retain", "identity:test_user_a"),
        ("POST", "/v1/lab/authorization-cache/prime", "identity:test_user_a"),
        ("POST", "/v1/lab/admin/role-downgrade", "identity:test_admin"),
        ("POST", "/v1/lab/admin/queue/defer", "identity:test_admin"),
        ("POST", "/v1/lab/references/publish", "identity:test_user_b"),
        ("POST", "/v1/lab/references/claim", "identity:test_user_a"),
        ("POST", "/v1/lab/admin/clock/advance", "identity:test_admin"),
        ("GET", "/v1/lab/documents/doc-b-protected", "identity:test_user_a"),
    )
    artifacts = (
        "artifact:lab-action/7eb1f0de12757921da8a4c72e6205da5c9eee1e91734f4366654944f63bbdb1c",
        "artifact:lab-action/b0ce666d62a32abda4c7d728015ad28c3ab8921076d6e809de07430b379f3529",
        "artifact:lab-action/eb306cd87f03c6effeefe57f28108524403b1a5b29879c2f6dcd2bdb1031f4ac",
        "artifact:lab-action/717cf353f0d600b8219233ff9d8c3b550d7d7732be451ba927ea69980377a23d",
        "artifact:lab-action/4239662eb56eacaf0f99ad44fbd07114e7a11dd7a8a22b0a2807187c96bddb6a",
        "artifact:lab-action/5561a3981cf6bd0787214e8df26bcdc920f94682a0cbf368f6551f6ba2caa1b9",
        "artifact:lab-action/c695724e7257cda434bc3af760f2c95c6076a62f19f0427bb1dbac412b828882",
        "artifact:lab-action/bfa39df7d04dfdb24507fff3bbe7a9737f9704aecbe91a0c0d7103dffc0db8a9",
    )
    return tuple(
        ActionEnvelope(
            action_id=f"action.m5.test-{index:02d}",
            experiment_id="experiment.m5.test",
            world_id="world.m5.test",
            scope_action=ScopeAction.HTTP_REQUEST,
            action=HttpRequestAction(
                method=HttpMethod(method),
                target=ActionTarget(scheme="http", host="localhost", port=80, path=path),
                body_artifact=artifacts[index - 1],
                identity_handle=identity,
                expected_statuses=(200, 403) if index == 8 else (200,),
            ),
            risk_class=(
                RiskClass.PASSIVE if method == "GET" else RiskClass.REVERSIBLE_STATE_CHANGE
            ),
            idempotency_key=sha256_digest({"m5": index}),
            requested_by=RequestedBy(type=RequesterType.WORKFLOW, role="m5_test"),
            policy_decision_ref=f"policy.m5.test-{index:02d}",
            sequence=index,
        )
        for index, (method, path, identity) in enumerate(routes, start=1)
    )


def _real_compose_argv(*operation: str) -> tuple[str, ...]:
    compose_file = Path(runner_module.__file__).with_name("real_compose.yaml")
    return require_exact_argv(
        (
            "docker",
            "compose",
            "--project-name",
            f"swm2{'a' * 32}",
            "--file",
            str(compose_file),
            *operation,
        )
    )


def test_real_runner_has_bounded_start_deadline_and_typed_import() -> None:
    start = _real_compose_argv("up", "--detach", "--wait", "--no-build")
    export = _real_compose_argv(*_BRIDGE, "export")
    state_import = _real_compose_argv(*_BRIDGE, "import")
    mutate = _real_compose_argv(*_BRIDGE, "mutate")

    assert runner_module.PROCESS_DEADLINE_SECONDS < runner_module._deadline_seconds(start) <= 180
    assert runner_module._deadline_seconds(export) == runner_module.PROCESS_DEADLINE_SECONDS
    assert runner_module._accepts_state_stdin(state_import) is True
    assert runner_module._accepts_state_stdin(mutate) is True
    assert runner_module._accepts_state_stdin(export) is False


def test_real_compose_fixture_is_digest_pinned_internal_and_unpublished() -> None:
    package = Path(runner_module.__file__).parent
    compose = (package / "real_compose.yaml").read_text(encoding="utf-8")
    dockerfile = (package / "RealDockerfile").read_text(encoding="utf-8")
    postgres_init = (package / "real_postgres_init.sql").read_text(encoding="utf-8")

    assert compose.count("@sha256:") == 4
    assert "internal: true" in compose
    assert "ports:" not in compose
    assert "docker.sock" not in compose
    assert "pull_policy: never" in compose
    assert "read_only: true" in compose
    assert "cap_drop: [ALL]" in compose
    assert "no-new-privileges:true" in compose
    assert '["CMD", "su-exec", "rabbitmq", "rabbitmq-diagnostics"' in compose
    assert "@sha256:" in dockerfile
    assert "USER 65532:65532" in dockerfile
    assert "CREATE TABLE IF NOT EXISTS sw_state" in postgres_init
    assert "CHECK (tenant ~" in postgres_init


@pytest.mark.asyncio
async def test_real_destroy_retains_ownership_until_inventory_is_empty() -> None:
    runner = _RealRunner()
    adapter = RealDockerComposeEnvironmentAdapter(runner=runner)
    environment = await adapter.prepare(_target())

    runner.cleanup_residue = True
    with pytest.raises(ComposeAdapterError, match="cleanup inventory"):
        await adapter.destroy(environment)

    runner.cleanup_residue = False
    await adapter.destroy(environment)
    await adapter.destroy(environment)


@pytest.mark.asyncio
async def test_real_profile_advertises_supported_six_provider_capabilities() -> None:
    adapter = RealDockerComposeEnvironmentAdapter(runner=_RealRunner())
    capabilities = adapter.capabilities()
    assert capabilities.pin.adapter == "docker-compose-real-providers"
    assert set(capabilities.capabilities) == {
        "filesystem_fork",
        "postgres_snapshot",
        "redis_snapshot",
        "queue_snapshot",
        "browser_session_fork",
        "controlled_clock",
    }
    assert set(capabilities.capabilities.values()) == {CapabilityLevel.SUPPORTED}


@pytest.mark.asyncio
async def test_real_profile_snapshots_forks_restores_and_destroys_all_components() -> None:
    runner = _RealRunner()
    adapter = RealDockerComposeEnvironmentAdapter(runner=runner)
    root = await adapter.prepare(_target())
    clean = await adapter.snapshot(root)
    assert set(clean.content_hashes) == {
        "filesystem",
        "database",
        "cache",
        "queue",
        "session",
        "clock",
    }

    root_project = runner.project(root)
    runner.states[root_project] = _components("root-mutated", tick=1)
    mutated = await adapter.snapshot(root)
    assert all(
        mutated.content_hashes[name] != clean.content_hashes[name] for name in clean.content_hashes
    )

    child = await adapter.fork(clean)
    child_snapshot = await adapter.snapshot(child)
    assert child_snapshot.content_hashes == clean.content_hashes

    await adapter.restore(root, clean)
    assert (await adapter.snapshot(root)).content_hashes == clean.content_hashes

    await adapter.destroy(child)
    await adapter.destroy(root)
    assert runner.states == {}
    assert runner.running == {}


@pytest.mark.asyncio
async def test_real_profile_materializes_one_closed_observed_candidate() -> None:
    runner = _RealRunner()
    adapter = RealDockerComposeEnvironmentAdapter(runner=runner)
    root = await adapter.prepare(_target())
    root_snapshot = await adapter.snapshot(root)
    child = await adapter.fork(root_snapshot)
    request = MaterializedCandidateRequest(
        allocation_id="allocation.m4.replay.aaaaaaaaaaaaaaaa.23",
        candidate_id="candidate.m4.aaaaaaaaaaaaaaaa.23",
        source_tier=WorldTier.GHOST,
        target_tier=WorldTier.REPLAY,
        candidate_fingerprint=sha256_digest({"candidate": 23}),
        observed_transition_digest=sha256_digest({"transition": "observed"}),
        evidence_ref="evidence.m3.observed",
        oracle_ref="oracle.m4.provider-delta.aaaaaaaaaaaaaaaa.23",
        ordinal=23,
    )

    receipt = await adapter.materialize_observed_candidate(child, request)

    assert receipt.environment_id == child.environment_id
    assert receipt.request_digest == sha256_digest(request)
    assert receipt.oracle_passed is True
    assert receipt.changed_provider_count == 6
    assert {item.provider for item in receipt.providers} == {
        "filesystem",
        "database",
        "cache",
        "queue",
        "session",
        "clock",
    }
    assert all(item.before_sha256 != item.after_sha256 for item in receipt.providers)
    assert receipt.provider_state_digest == sha256_digest(
        {item.provider: item.after_sha256 for item in receipt.providers}
    )
    assert receipt.state_binding.adapter_pin == adapter.capabilities().pin
    assert receipt.state_binding.bridge_image_id == _IMAGE_ID
    assert receipt.state_binding.source_snapshot_id == root_snapshot.snapshot_id
    assert (
        receipt.state_binding.source_snapshot_state_fingerprint == root_snapshot.state_fingerprint
    )
    assert receipt.state_binding.provider_state_digest == receipt.provider_state_digest
    assert receipt.state_binding.application_image_binding == "UNOBSERVED"

    await adapter.destroy(child)
    await adapter.destroy(root)


@pytest.mark.asyncio
async def test_m5_provider_replay_rebuilds_winner_and_restores_providers() -> None:
    runner = _RealRunner()
    adapter = RealDockerComposeEnvironmentAdapter(runner=runner)
    root = await adapter.prepare(_target())
    snapshot = await adapter.snapshot(root)
    winner = await adapter.fork(snapshot)
    m4 = await adapter.materialize_observed_candidate(
        winner,
        MaterializedCandidateRequest(
            allocation_id="allocation.m4.replay.aaaaaaaaaaaaaaaa.07",
            candidate_id="candidate.m4.aaaaaaaaaaaaaaaa.07",
            source_tier=WorldTier.GHOST,
            target_tier=WorldTier.REPLAY,
            candidate_fingerprint=sha256_digest({"candidate": 7}),
            observed_transition_digest=sha256_digest({"transition": "observed"}),
            evidence_ref="evidence.m3.observed",
            oracle_ref="oracle.m4.provider-delta.aaaaaaaaaaaaaaaa.07",
            ordinal=7,
        ),
    )
    request = M5MaterializedProviderRunRequest(
        repository_marker="4" * 40,
        m4_provider_receipt=m4,
        m4_receipt_sha256=sha256_digest({"m4": "bytes"}),
        m4_receipt_digest=sha256_digest({"m4": "receipt"}),
        process_receipt_sha256=sha256_digest({"m5": "process-bytes"}),
        process_receipt_digest=sha256_digest({"m5": "process-receipt"}),
        plan_id="plan.m5.clean-root",
        root_seed_id="root.m5.clean-root",
        root_digest=sha256_digest({"root": 1}),
        plan_digest=sha256_digest({"plan": 1}),
        run_id="run.m5.provider-clean-root-01",
        scenario="primary_vulnerable",
        mode="vulnerable",
        actions=_m5_actions(),
        expected_oracle_outcome="VIOLATED",
        expected_response_status=200,
    )

    receipt = await adapter.run_m5_materialized_provider(request)

    assert len(receipt.steps) == 8
    assert receipt.steps[-1].oracle_outcome == "VIOLATED"
    assert receipt.steps[-1].response_status == 200
    assert {item.provider: item.sha256 for item in receipt.restored_provider_state} == {
        item.provider: item.after_sha256 for item in m4.providers
    }
    await adapter.destroy(winner)
    await adapter.destroy(root)
    assert runner.states == {}
    assert runner.running == {}


@pytest.mark.asyncio
async def test_materialization_fails_closed_when_any_provider_did_not_change() -> None:
    runner = _RealRunner(unchanged_provider="queue")
    adapter = RealDockerComposeEnvironmentAdapter(runner=runner)
    root = await adapter.prepare(_target())
    root_snapshot = await adapter.snapshot(root)
    child = await adapter.fork(root_snapshot)
    request = MaterializedCandidateRequest(
        allocation_id="allocation.m4.replay.aaaaaaaaaaaaaaaa.22",
        candidate_id="candidate.m4.aaaaaaaaaaaaaaaa.22",
        source_tier=WorldTier.GHOST,
        target_tier=WorldTier.REPLAY,
        candidate_fingerprint=sha256_digest({"candidate": 22}),
        observed_transition_digest=sha256_digest({"transition": "observed"}),
        evidence_ref="evidence.m3.observed",
        oracle_ref="oracle.m4.provider-delta.aaaaaaaaaaaaaaaa.22",
        ordinal=22,
    )

    with pytest.raises(ComposeAdapterError, match="provider oracle"):
        await adapter.materialize_observed_candidate(child, request)

    await adapter.destroy(child)
    await adapter.destroy(root)


@pytest.mark.asyncio
async def test_real_profile_rejects_arbitrary_target_and_image_swap() -> None:
    runner = _RealRunner()
    adapter = RealDockerComposeEnvironmentAdapter(runner=runner)
    with pytest.raises(ComposeAdapterError, match="fixed real-provider"):
        await adapter.prepare(TargetSpec(target_id="other", target_version="1.0.0"))

    root = await adapter.prepare(_target())
    snapshot = await adapter.snapshot(root)
    runner.image_id = f"sha256:{'5' * 64}"
    with pytest.raises(ComposeAdapterError, match="image identity changed"):
        await adapter.fork(snapshot)
    await adapter.destroy(root)
