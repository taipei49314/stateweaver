from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import pytest
from stateweaver.adapters.docker_compose import (
    ComposeAdapterError,
    ComposeUnavailableError,
    DockerComposeEnvironmentAdapter,
    ProcessResult,
)
from stateweaver.adapters.docker_compose.runner import require_exact_argv
from stateweaver.worlds import CapabilityLevel, TargetSpec


@dataclass
class FakeRunner:
    calls: list[tuple[str, ...]] = field(default_factory=list)
    missing_docker: bool = False
    unhealthy: bool = False
    malicious_result: bool = False
    malformed_fields: bool = False
    failures: set[tuple[str, ...]] = field(default_factory=set)

    async def run(self, argv: tuple[str, ...]) -> ProcessResult:
        self.calls.append(argv)
        if self.missing_docker:
            raise FileNotFoundError("docker")
        if argv in self.failures:
            return ProcessResult(returncode=1)
        if self.malicious_result:
            return object()  # type: ignore[return-value]
        if self.malformed_fields:
            return ProcessResult(returncode=0, stdout=None)  # type: ignore[arg-type]
        if argv[-3:] == ("ps", "--format", "json"):
            stdout = "[]" if self.unhealthy else '[{"State":"running"}]'
            return ProcessResult(returncode=0, stdout=stdout)
        return ProcessResult(returncode=0, stdout="local")


def _target() -> TargetSpec:
    return TargetSpec(target_id="synthetic-demo", target_version="1.0.0")


def test_capabilities_remain_partial_until_real_state_capture_is_proven() -> None:
    manifest = DockerComposeEnvironmentAdapter(runner=FakeRunner()).capabilities()

    assert manifest.capabilities
    assert set(manifest.capabilities.values()) == {CapabilityLevel.PARTIAL}


@pytest.mark.parametrize(
    "argv",
    [
        ("docker", "run", "untrusted"),
        ("docker", "compose", "--project-name", "caller", "down"),
        ("powershell", "-Command", "Write-Output unexpected"),
    ],
)
def test_runner_grammar_rejects_every_non_adapter_command(argv: tuple[str, ...]) -> None:
    with pytest.raises(ValueError, match="fixed synthetic"):
        require_exact_argv(argv)


@pytest.mark.asyncio
async def test_fixed_argv_snapshot_restore_and_idempotent_destroy() -> None:
    runner = FakeRunner()
    adapter = DockerComposeEnvironmentAdapter(runner=runner)
    env = await adapter.prepare(_target())
    snapshot = await adapter.snapshot(env)
    child = await adapter.fork(snapshot)
    await adapter.restore(child, snapshot)
    await adapter.destroy(env)
    await adapter.destroy(env)

    assert snapshot.source_environment_id == env.environment_id
    assert child.environment_id != env.environment_id
    assert all(call[0] == "docker" for call in runner.calls)
    assert all("--file" in call for call in runner.calls if call[1:2] == ("compose",))
    assert any(call[-3:] == ("down", "--volumes", "--remove-orphans") for call in runner.calls)


@pytest.mark.asyncio
async def test_four_siblings_have_disjoint_project_and_volume_namespaces() -> None:
    adapter = DockerComposeEnvironmentAdapter(runner=FakeRunner())
    siblings = await asyncio.gather(*(adapter.prepare(_target()) for _ in range(4)))

    assert len({item.opaque_ref for item in siblings}) == 4
    assert len({item.namespace.network for item in siblings}) == 4
    assert len({item.namespace.database for item in siblings}) == 4
    await asyncio.gather(*(adapter.destroy(item) for item in siblings))


@pytest.mark.asyncio
async def test_rejects_targets_handles_and_malicious_process_results() -> None:
    adapter = DockerComposeEnvironmentAdapter(runner=FakeRunner())
    unsupported = TargetSpec(target_id="other-demo", target_version="1.0.0")
    with pytest.raises(ComposeAdapterError, match="fixed synthetic"):
        await adapter.prepare(unsupported)
    secret_target = TargetSpec(
        target_id="synthetic-demo", target_version="1.0.0", secret_handles=("secret:one",)
    )
    with pytest.raises(ComposeAdapterError, match="fixed synthetic"):
        await adapter.prepare(secret_target)

    malicious = DockerComposeEnvironmentAdapter(runner=FakeRunner(malicious_result=True))
    with pytest.raises(ComposeAdapterError, match="invalid result"):
        await malicious.prepare(_target())
    malformed = DockerComposeEnvironmentAdapter(runner=FakeRunner(malformed_fields=True))
    with pytest.raises(ComposeAdapterError, match="invalid result"):
        await malformed.prepare(_target())


@pytest.mark.asyncio
async def test_missing_docker_and_unhealthy_compose_fail_closed() -> None:
    missing = DockerComposeEnvironmentAdapter(runner=FakeRunner(missing_docker=True))
    with pytest.raises(ComposeUnavailableError, match="unavailable"):
        await missing.prepare(_target())

    unhealthy = DockerComposeEnvironmentAdapter(runner=FakeRunner(unhealthy=True))
    with pytest.raises(ComposeAdapterError, match="health check"):
        await unhealthy.prepare(_target())
