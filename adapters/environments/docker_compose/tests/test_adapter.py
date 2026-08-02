from __future__ import annotations

import asyncio
import json
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from stateweaver.adapters.docker_compose import (
    ComposeAdapterError,
    ComposeUnavailableError,
    DockerComposeEnvironmentAdapter,
    ProcessResult,
)
from stateweaver.adapters.docker_compose.runner import SubprocessRunner, require_exact_argv
from stateweaver.worlds import CapabilityLevel, EnvironmentHandle, TargetSpec, WorldManager

_IMAGE_ID = f"sha256:{'1' * 64}"
_IMAGE = "stateweaver-synthetic-demo:local"
_BRIDGE_SUFFIX = (
    "exec",
    "--no-TTY",
    "synthetic-demo",
    "python",
    "/opt/stateweaver/state_bridge.py",
)


def _seed_components() -> dict[str, dict[str, object]]:
    return {
        "filesystem": {"files": [{"path": "/fixture/version", "value": "1.0.0"}]},
        "database": {"rows": [{"id": "root-row", "value": "clean"}]},
        "cache": {"entries": []},
        "queue": {"jobs": []},
        "session": {"sessions": []},
        "clock": {"mode": "controlled", "now": "2026-07-29T12:00:00Z"},
    }


def _archive(components: dict[str, dict[str, object]]) -> str:
    return json.dumps(
        {
            "schema_version": "1.0",
            "target": {
                "target_id": "synthetic-demo",
                "target_version": "1.0.0",
            },
            "components": components,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


@dataclass
class FakeRunner:
    calls: list[tuple[tuple[str, ...], bytes | None]] = field(default_factory=list)
    states: dict[str, dict[str, dict[str, object]]] = field(default_factory=dict)
    running_image_ids: dict[str, str] = field(default_factory=dict)
    missing_docker: bool = False
    unhealthy: bool = False
    malicious_result: bool = False
    malformed_fields: bool = False
    image_id: str = _IMAGE_ID
    retag_on_up: bool = False
    export_override: str | None = None
    ps_override: str | None = None
    import_ack_override: str | None = None
    failure_operations: set[tuple[str, ...]] = field(default_factory=set)
    block_down: bool = False
    down_started: asyncio.Event = field(default_factory=asyncio.Event)
    release_down: asyncio.Event = field(default_factory=asyncio.Event)

    async def run(
        self,
        argv: tuple[str, ...],
        *,
        stdin: bytes | None = None,
    ) -> ProcessResult:
        self.calls.append((argv, stdin))
        if self.missing_docker:
            raise FileNotFoundError("docker")
        if self.malicious_result:
            return object()  # type: ignore[return-value]
        if self.malformed_fields:
            return ProcessResult(returncode=0, stdout=None)  # type: ignore[arg-type]
        if argv == ("docker", "version", "--format", "{{.Server.Version}}"):
            return ProcessResult(returncode=0, stdout="27.0.0")
        if argv[:3] == ("docker", "image", "inspect"):
            return ProcessResult(returncode=0, stdout=f"{self.image_id}\n")
        if argv[:4] == ("docker", "inspect", "--format", "{{.Image}}"):
            project = f"swm2{argv[4]}"
            return ProcessResult(returncode=0, stdout=f"{self.running_image_ids[project]}\n")

        project = argv[3]
        operation = argv[6:]
        if operation in self.failure_operations:
            return ProcessResult(returncode=1, stderr="fixed failure")
        if operation == ("up", "--detach", "--wait", "--no-build"):
            if self.retag_on_up:
                self.image_id = f"sha256:{'2' * 64}"
                self.retag_on_up = False
            self.states.setdefault(project, _seed_components())
            self.running_image_ids[project] = self.image_id
            return ProcessResult(returncode=0)
        if operation == ("down", "--volumes", "--remove-orphans"):
            if self.block_down:
                self.down_started.set()
                await self.release_down.wait()
            self.states.pop(project, None)
            self.running_image_ids.pop(project, None)
            return ProcessResult(returncode=0)
        if operation == ("ps", "--format", "json"):
            if self.ps_override is not None:
                return ProcessResult(returncode=0, stdout=self.ps_override)
            health = "unhealthy" if self.unhealthy else "healthy"
            return ProcessResult(
                returncode=0,
                stdout=json.dumps(
                    [
                        {
                            "Service": "synthetic-demo",
                            "Image": _IMAGE,
                            "ID": project.removeprefix("swm2"),
                            "Project": project,
                            "State": "running",
                            "Health": health,
                        }
                    ]
                ),
            )
        if operation == (*_BRIDGE_SUFFIX, "export"):
            stdout = self.export_override or _archive(self.states[project])
            return ProcessResult(returncode=0, stdout=stdout)
        if operation == (*_BRIDGE_SUFFIX, "import"):
            assert stdin is not None
            payload = json.loads(stdin)
            self.states[project] = deepcopy(payload["components"])
            return ProcessResult(
                returncode=0,
                stdout=(self.import_ack_override or '{"accepted":true,"schema_version":"1.0"}'),
            )
        raise AssertionError(f"unexpected fixed runner operation: {operation!r}")

    @staticmethod
    def project(env: EnvironmentHandle) -> str:
        return env.opaque_ref.removeprefix("compose:")

    def mutate(self, env: EnvironmentHandle, component: str, value: dict[str, object]) -> None:
        self.states[self.project(env)][component] = deepcopy(value)


def _target() -> TargetSpec:
    return TargetSpec(target_id="synthetic-demo", target_version="1.0.0")


def test_capabilities_remain_partial_and_world_manager_rejects_promotion() -> None:
    adapter = DockerComposeEnvironmentAdapter(runner=FakeRunner())
    manifest = adapter.capabilities()

    assert manifest.capabilities
    assert set(manifest.capabilities.values()) == {CapabilityLevel.PARTIAL}
    with pytest.raises(Exception, match="lacks required M2 isolation capabilities"):
        WorldManager(adapter)


@pytest.mark.parametrize(
    "argv",
    [
        ("docker", "run", "untrusted"),
        ("docker", "compose", "--project-name", "caller", "down"),
        ("powershell", "-Command", "Write-Output unexpected"),
        (
            "docker",
            "compose",
            "--project-name",
            f"swm2{'a' * 32}",
            "--file",
            "caller.yaml",
            *_BRIDGE_SUFFIX,
            "export",
        ),
        ("docker", "inspect", "--format", "{{.Image}}", "../../caller"),
    ],
)
def test_runner_grammar_rejects_every_non_adapter_command(argv: tuple[str, ...]) -> None:
    with pytest.raises(ValueError, match="fixed synthetic"):
        require_exact_argv(argv)


@pytest.mark.asyncio
async def test_snapshot_fork_and_restore_are_bound_to_real_component_content() -> None:
    runner = FakeRunner()
    adapter = DockerComposeEnvironmentAdapter(runner=runner)
    root = await adapter.prepare(_target())
    clean = await adapter.snapshot(root)

    runner.mutate(root, "database", {"rows": [{"id": "root-row", "value": "mutated"}]})
    mutated = await adapter.snapshot(root)
    assert mutated.content_hashes["database"] != clean.content_hashes["database"]
    assert {
        component
        for component in clean.content_hashes
        if clean.content_hashes[component] != mutated.content_hashes[component]
    } == {"database"}

    child = await adapter.fork(clean)
    child_snapshot = await adapter.snapshot(child)
    assert child_snapshot.content_hashes == clean.content_hashes
    runner.mutate(child, "queue", {"jobs": [{"id": "child-only"}]})
    assert (await adapter.snapshot(child)).state_fingerprint != clean.state_fingerprint
    assert (await adapter.snapshot(root)).content_hashes == mutated.content_hashes

    await adapter.restore(child, clean)
    assert (await adapter.snapshot(child)).content_hashes == clean.content_hashes
    await adapter.destroy(root)
    descendant = await adapter.fork(clean)
    assert (await adapter.snapshot(descendant)).content_hashes == clean.content_hashes
    await adapter.destroy(child)
    await adapter.destroy(descendant)


@pytest.mark.asyncio
async def test_four_siblings_share_one_snapshot_and_isolate_component_mutations() -> None:
    runner = FakeRunner()
    adapter = DockerComposeEnvironmentAdapter(runner=runner)
    root = await adapter.prepare(_target())
    clean = await adapter.snapshot(root)
    siblings = await asyncio.gather(*(adapter.fork(clean) for _ in range(4)))

    for index, sibling in enumerate(siblings):
        runner.mutate(sibling, "session", {"sessions": [{"sibling": index}]})
    sibling_snapshots = await asyncio.gather(*(adapter.snapshot(item) for item in siblings))

    assert len({item.opaque_ref for item in siblings}) == 4
    assert len({item.namespace.network for item in siblings}) == 4
    assert len({item.namespace.database for item in siblings}) == 4
    assert len({item.state_fingerprint for item in sibling_snapshots}) == 4
    assert (await adapter.snapshot(root)).content_hashes == clean.content_hashes
    await asyncio.gather(*(adapter.destroy(item) for item in siblings))
    await adapter.destroy(root)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        ("root_snapshot_id", "root:forged"),
        ("source_environment_id", "environment:forged"),
        ("state_fingerprint", f"sha256:{'f' * 64}"),
    ],
)
async def test_same_id_snapshot_substitution_is_rejected_before_process_call(
    field_name: str,
    replacement: str,
) -> None:
    runner = FakeRunner()
    adapter = DockerComposeEnvironmentAdapter(runner=runner)
    env = await adapter.prepare(_target())
    snapshot = await adapter.snapshot(env)
    forged = snapshot.model_copy(update={field_name: replacement})
    calls_before = len(runner.calls)

    with pytest.raises(ComposeAdapterError, match="snapshot"):
        await adapter.fork(forged)
    with pytest.raises(ComposeAdapterError, match="snapshot"):
        await adapter.restore(env, forged)
    assert len(runner.calls) == calls_before


@pytest.mark.asyncio
async def test_restore_rejects_a_snapshot_from_another_root_before_process_call() -> None:
    runner = FakeRunner()
    adapter = DockerComposeEnvironmentAdapter(runner=runner)
    first = await adapter.prepare(_target())
    second = await adapter.prepare(_target())
    first_snapshot = await adapter.snapshot(first)
    calls_before = len(runner.calls)

    with pytest.raises(ComposeAdapterError, match="root lineage"):
        await adapter.restore(second, first_snapshot)
    assert len(runner.calls) == calls_before


@pytest.mark.asyncio
async def test_destroy_rejects_same_id_forged_handle_and_cancelled_destroy_is_retryable() -> None:
    runner = FakeRunner()
    adapter = DockerComposeEnvironmentAdapter(runner=runner)
    env = await adapter.prepare(_target())
    forged = env.model_copy(update={"opaque_ref": "compose:forged"})
    calls_before = len(runner.calls)
    with pytest.raises(ComposeAdapterError, match="not owned"):
        await adapter.destroy(forged)
    assert len(runner.calls) == calls_before

    runner.block_down = True
    first_destroy = asyncio.create_task(adapter.destroy(env))
    await runner.down_started.wait()
    first_destroy.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first_destroy
    runner.block_down = False
    runner.release_down.set()
    await adapter.destroy(env)
    await adapter.destroy(env)


@pytest.mark.asyncio
async def test_failed_up_attempts_compensating_down_and_image_changes_fail_closed() -> None:
    runner = FakeRunner(failure_operations={("up", "--detach", "--wait", "--no-build")})
    adapter = DockerComposeEnvironmentAdapter(runner=runner)
    with pytest.raises(ComposeUnavailableError, match="command failed"):
        await adapter.prepare(_target())
    assert any(call[0][-3:] == ("down", "--volumes", "--remove-orphans") for call in runner.calls)

    healthy_runner = FakeRunner()
    healthy = DockerComposeEnvironmentAdapter(runner=healthy_runner)
    env = await healthy.prepare(_target())
    snapshot = await healthy.snapshot(env)
    healthy_runner.image_id = f"sha256:{'2' * 64}"
    with pytest.raises(ComposeAdapterError, match="image identity changed"):
        await healthy.fork(snapshot)

    race_runner = FakeRunner(retag_on_up=True)
    with pytest.raises(ComposeAdapterError, match="running container image identity"):
        await DockerComposeEnvironmentAdapter(runner=race_runner).prepare(_target())
    assert not race_runner.states


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad_archive",
    [
        pytest.param("{}", id="empty-object"),
        pytest.param(
            _archive({**_seed_components(), "unexpected": {}}),
            id="extra-component",
        ),
        pytest.param(
            '{"schema_version":"1.0","schema_version":"1.0"}',
            id="duplicate-key",
        ),
        pytest.param("x" * 1_048_577, id="oversized"),
    ],
)
async def test_invalid_or_oversized_state_archives_fail_closed(bad_archive: str) -> None:
    runner = FakeRunner(export_override=bad_archive)
    adapter = DockerComposeEnvironmentAdapter(runner=runner)
    env = await adapter.prepare(_target())
    with pytest.raises(ComposeAdapterError, match="archive"):
        await adapter.snapshot(env)


@pytest.mark.asyncio
async def test_targets_process_results_and_health_are_strict() -> None:
    adapter = DockerComposeEnvironmentAdapter(runner=FakeRunner())
    with pytest.raises(ComposeAdapterError, match="fixed synthetic"):
        await adapter.prepare(TargetSpec(target_id="other-demo", target_version="1.0.0"))
    with pytest.raises(ComposeAdapterError, match="fixed synthetic"):
        await adapter.prepare(
            TargetSpec(
                target_id="synthetic-demo",
                target_version="1.0.0",
                secret_handles=("secret:one",),
            )
        )
    with pytest.raises(ComposeAdapterError, match="invalid result"):
        await DockerComposeEnvironmentAdapter(runner=FakeRunner(malicious_result=True)).prepare(
            _target()
        )
    with pytest.raises(ComposeAdapterError, match="invalid result"):
        await DockerComposeEnvironmentAdapter(runner=FakeRunner(malformed_fields=True)).prepare(
            _target()
        )
    with pytest.raises(ComposeUnavailableError, match="unavailable"):
        await DockerComposeEnvironmentAdapter(runner=FakeRunner(missing_docker=True)).prepare(
            _target()
        )
    with pytest.raises(ComposeAdapterError, match="health check"):
        await DockerComposeEnvironmentAdapter(runner=FakeRunner(unhealthy=True)).prepare(_target())

    duplicate_health = '[{"Service":"synthetic-demo","Service":"synthetic-demo"}]'
    with pytest.raises(ComposeAdapterError, match="health response"):
        await DockerComposeEnvironmentAdapter(
            runner=FakeRunner(ps_override=duplicate_health)
        ).prepare(_target())


@pytest.mark.asyncio
async def test_import_acknowledgement_rejects_duplicate_keys_and_cleans_child() -> None:
    runner = FakeRunner(
        import_ack_override=('{"accepted":true,"accepted":true,"schema_version":"1.0"}')
    )
    adapter = DockerComposeEnvironmentAdapter(runner=runner)
    root = await adapter.prepare(_target())
    snapshot = await adapter.snapshot(root)
    with pytest.raises(ComposeAdapterError, match="import response"):
        await adapter.fork(snapshot)
    assert set(runner.states) == {runner.project(root)}


@pytest.mark.asyncio
@pytest.mark.parametrize("lookup_race", [False, True], ids=["normal", "already-exited"])
async def test_cancelled_subprocess_is_terminated_and_reaped(
    monkeypatch: pytest.MonkeyPatch,
    lookup_race: bool,
) -> None:
    class WaitingProcess:
        def __init__(self) -> None:
            self.returncode: int | None = None
            self.communicating = asyncio.Event()
            self.terminated = False
            self.killed = False

        async def communicate(self, input: bytes | None = None) -> tuple[bytes, bytes]:
            del input
            self.communicating.set()
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

        def terminate(self) -> None:
            self.terminated = True
            self.returncode = 0 if lookup_race else 143
            if lookup_race:
                raise ProcessLookupError

        def kill(self) -> None:
            self.killed = True
            self.returncode = 137

        async def wait(self) -> int:
            assert self.returncode is not None
            return self.returncode

    process = WaitingProcess()

    async def create(*args: object, **kwargs: object) -> WaitingProcess:
        del args, kwargs
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)
    task = asyncio.create_task(
        SubprocessRunner().run(("docker", "version", "--format", "{{.Server.Version}}"))
    )
    await process.communicating.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert process.terminated is True
    assert process.killed is False


def test_compose_fixture_is_repository_owned_and_sandboxed() -> None:
    package = Path(__file__).parents[1] / "src/stateweaver/adapters/docker_compose"
    compose = (package / "compose.yaml").read_text(encoding="utf-8")
    dockerfile = (package / "Dockerfile").read_text(encoding="utf-8")

    assert "internal: true" in compose
    assert "pull_policy: never" in compose
    assert "read_only: true" in compose
    assert "cap_drop: [ALL]" in compose
    assert "no-new-privileges:true" in compose
    assert "ports:" not in compose
    assert "docker.sock" not in compose
    assert "@sha256:" in dockerfile
    assert "USER 65532:65532" in dockerfile
