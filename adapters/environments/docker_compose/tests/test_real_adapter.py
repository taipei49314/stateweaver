from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from stateweaver.adapters.docker_compose import (
    ComposeAdapterError,
    ProcessResult,
    RealDockerComposeEnvironmentAdapter,
)
from stateweaver.adapters.docker_compose import runner as runner_module
from stateweaver.adapters.docker_compose.runner import require_exact_argv
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
    return {
        "filesystem": {"files": {"marker.txt": marker, "tenant.txt": "alpha"}},
        "database": {"rows": [{"id": 1, "tenant": "alpha", "value": marker}]},
        "cache": {"entries": {"sw:marker": marker}},
        "queue": {"messages": [marker]},
        "session": {
            "cookies": [{"name": "sw_marker", "path": "/", "value": marker}],
            "local_storage": {"sw.marker": marker},
        },
        "clock": {"iso8601": f"2026-01-01T00:00:{tick:02d}Z", "tick": tick},
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
        raise AssertionError(f"unexpected operation: {operation!r}")

    @staticmethod
    def project(environment: EnvironmentHandle) -> str:
        return environment.opaque_ref.removeprefix("compose:")


def _target() -> TargetSpec:
    return TargetSpec(target_id="real-provider-demo", target_version="1.0.0")


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
