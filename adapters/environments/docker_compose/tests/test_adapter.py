from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

import pytest
from stateweaver.adapters.docker_compose import (
    ComposeAdapterError,
    ComposeUnavailableError,
    DockerComposeEnvironmentAdapter,
    ProcessResult,
)
from stateweaver.adapters.docker_compose import runner as runner_module
from stateweaver.adapters.docker_compose.runner import (
    MAX_PROCESS_STREAM_BYTES,
    ProcessBoundaryError,
    SubprocessRunner,
    require_exact_argv,
)
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
_UP = ("up", "--detach", "--wait", "--no-build")
_DOWN = ("down", "--volumes", "--remove-orphans")
_EXPORT = (*_BRIDGE_SUFFIX, "export")
_IMPORT = (*_BRIDGE_SUFFIX, "import")


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
class OperationBarrier:
    parties: int
    auto_release: bool = True
    active: int = 0
    max_active: int = 0
    projects: set[str] = field(default_factory=set)
    reached: asyncio.Event = field(default_factory=asyncio.Event)
    release: asyncio.Event = field(default_factory=asyncio.Event)

    async def wait(self, project: str) -> None:
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        self.projects.add(project)
        if len(self.projects) >= self.parties:
            self.reached.set()
            if self.auto_release:
                self.release.set()
        try:
            await self.release.wait()
        finally:
            self.active -= 1


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
    single_object_ps: bool = False
    import_ack_override: str | None = None
    failure_operations: set[tuple[str, ...]] = field(default_factory=set)
    barriers: dict[tuple[str, ...], OperationBarrier] = field(default_factory=dict)
    block_down: bool = False
    block_down_after_commit: bool = False
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
        barrier = self.barriers.get(operation)
        if barrier is not None:
            await barrier.wait(project)
        if operation == _UP:
            if self.retag_on_up:
                self.image_id = f"sha256:{'2' * 64}"
                self.retag_on_up = False
            self.states.setdefault(project, _seed_components())
            self.running_image_ids[project] = self.image_id
            return ProcessResult(returncode=0)
        if operation == _DOWN:
            if self.block_down:
                self.down_started.set()
                await self.release_down.wait()
            self.states.pop(project, None)
            self.running_image_ids.pop(project, None)
            if self.block_down_after_commit:
                self.down_started.set()
                await self.release_down.wait()
            return ProcessResult(returncode=0)
        if operation == ("ps", "--format", "json"):
            if self.ps_override is not None:
                return ProcessResult(returncode=0, stdout=self.ps_override)
            health = "unhealthy" if self.unhealthy else "healthy"
            row = {
                "Service": "synthetic-demo",
                "Image": _IMAGE,
                "ID": project.removeprefix("swm2"),
                "Project": project,
                "State": "running",
                "Health": health,
            }
            return ProcessResult(
                returncode=0,
                stdout=json.dumps(row if self.single_object_ps else [row]),
            )
        if operation == _EXPORT:
            stdout = self.export_override or _archive(self.states[project])
            return ProcessResult(returncode=0, stdout=stdout)
        if operation == _IMPORT:
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


class _StaticReader:
    def __init__(self, content: bytes) -> None:
        self._content = content

    async def read(self, size: int) -> bytes:
        result = self._content[:size]
        self._content = self._content[size:]
        return result


class _ExplodingReader:
    def __init__(self, error: Exception) -> None:
        self._error = error

    async def read(self, _size: int) -> bytes:
        raise self._error


class _ExplodingWriter:
    def __init__(self, error: Exception) -> None:
        self._error = error

    def write(self, _content: bytes) -> None:
        pass

    async def drain(self) -> None:
        raise self._error

    def close(self) -> None:
        pass

    async def wait_closed(self) -> None:
        pass


_NONEXISTENT_TEST_PROCESS_GROUP = 2_000_000_000


class _CompletedProcess:
    stdin = None
    pid = _NONEXISTENT_TEST_PROCESS_GROUP

    def __init__(self, stdout: bytes, stderr: bytes = b"") -> None:
        self.returncode: int | None = None
        self.stdout = _StaticReader(stdout)
        self.stderr = _StaticReader(stderr)

    async def wait(self) -> int:
        self.returncode = 0
        return self.returncode

    def send_signal(self, _signal: int) -> None:
        self.returncode = 143

    def terminate(self) -> None:
        self.returncode = 143

    def kill(self) -> None:
        self.returncode = 137


class _BlockingReader:
    def __init__(self, process: _WaitingProcess) -> None:
        self._process = process

    async def read(self, _size: int) -> bytes:
        self._process.reading.set()
        await self._process.finished.wait()
        return b""


class _WaitingProcess:
    stdin: _ExplodingWriter | None = None
    pid = _NONEXISTENT_TEST_PROCESS_GROUP

    def __init__(self, *, lookup_race: bool = False) -> None:
        self.returncode: int | None = None
        self.reading = asyncio.Event()
        self.finished = asyncio.Event()
        self.terminated = False
        self.killed = False
        self.lookup_race = lookup_race
        self.stdout: _BlockingReader | _StaticReader | _ExplodingReader = _BlockingReader(self)
        self.stderr: _BlockingReader | _StaticReader | _ExplodingReader = _BlockingReader(self)

    def _finish(self, returncode: int) -> None:
        self.returncode = returncode
        self.finished.set()

    def send_signal(self, _signal: int) -> None:
        self.terminated = True
        self._finish(0 if self.lookup_race else 143)
        if self.lookup_race:
            raise ProcessLookupError

    def terminate(self) -> None:
        self.terminated = True
        self._finish(0 if self.lookup_race else 143)
        if self.lookup_race:
            raise ProcessLookupError

    def kill(self) -> None:
        self.killed = True
        self._finish(137)

    async def wait(self) -> int:
        await self.finished.wait()
        assert self.returncode is not None
        return self.returncode


class _ExitedLeaderWithOpenPipes(_WaitingProcess):
    def __init__(self) -> None:
        super().__init__()
        self.returncode = 0

    async def wait(self) -> int:
        return 0


class _ExplodingWaitProcess(_WaitingProcess):
    def __init__(self, error: Exception) -> None:
        super().__init__()
        self.stdout = _StaticReader(b"")
        self.stderr = _StaticReader(b"")
        self._error = error

    async def wait(self) -> int:
        raise self._error


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

    await adapter.restore(child, child_snapshot)
    assert (await adapter.snapshot(child)).content_hashes == child_snapshot.content_hashes
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
    fork_barrier = OperationBarrier(parties=4)
    runner.barriers[_UP] = fork_barrier
    siblings = await asyncio.wait_for(
        asyncio.gather(*(adapter.fork(clean) for _ in range(4))),
        timeout=2.0,
    )
    runner.barriers.pop(_UP)

    for index, sibling in enumerate(siblings):
        runner.mutate(sibling, "session", {"sessions": [{"sibling": index}]})
    snapshot_barrier = OperationBarrier(parties=4)
    runner.barriers[_EXPORT] = snapshot_barrier
    sibling_snapshots = await asyncio.wait_for(
        asyncio.gather(*(adapter.snapshot(item) for item in siblings)),
        timeout=2.0,
    )
    runner.barriers.pop(_EXPORT)

    assert fork_barrier.max_active == 4
    assert len(fork_barrier.projects) == 4
    assert snapshot_barrier.max_active == 4
    assert len({item.opaque_ref for item in siblings}) == 4
    assert len({item.namespace.network for item in siblings}) == 4
    assert len({item.namespace.database for item in siblings}) == 4
    assert len({item.state_fingerprint for item in sibling_snapshots}) == 4
    assert (await adapter.snapshot(root)).content_hashes == clean.content_hashes
    await asyncio.gather(*(adapter.destroy(item) for item in siblings))
    await adapter.destroy(root)


@pytest.mark.asyncio
async def test_same_world_snapshots_serialize_while_waiting_for_the_lifecycle_gate() -> None:
    runner = FakeRunner()
    adapter = DockerComposeEnvironmentAdapter(runner=runner)
    env = await adapter.prepare(_target())
    barrier = OperationBarrier(parties=1, auto_release=False)
    runner.barriers[_EXPORT] = barrier

    first = asyncio.create_task(adapter.snapshot(env))
    await asyncio.wait_for(barrier.reached.wait(), timeout=1.0)
    second = asyncio.create_task(adapter.snapshot(env))
    await asyncio.sleep(0)
    export_calls = [call for call, _stdin in runner.calls if call[6:] == _EXPORT]
    assert len(export_calls) == 1

    barrier.release.set()
    await asyncio.wait_for(asyncio.gather(first, second), timeout=2.0)
    assert barrier.max_active == 1
    await adapter.destroy(env)


@pytest.mark.asyncio
async def test_destroy_wins_before_a_waiting_snapshot_revalidates_ownership() -> None:
    runner = FakeRunner(block_down=True)
    adapter = DockerComposeEnvironmentAdapter(runner=runner)
    env = await adapter.prepare(_target())

    destroy = asyncio.create_task(adapter.destroy(env))
    await asyncio.wait_for(runner.down_started.wait(), timeout=1.0)
    waiting_snapshot = asyncio.create_task(adapter.snapshot(env))
    await asyncio.sleep(0)
    calls_before_release = len(runner.calls)
    runner.release_down.set()
    await asyncio.wait_for(destroy, timeout=1.0)
    with pytest.raises(ComposeAdapterError, match="not owned"):
        await asyncio.wait_for(waiting_snapshot, timeout=1.0)
    assert len(runner.calls) == calls_before_release
    await adapter.destroy(env)


@pytest.mark.asyncio
async def test_concurrent_prepare_reserves_unique_project_identities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = FakeRunner()
    barrier = OperationBarrier(parties=2)
    runner.barriers[_UP] = barrier
    adapter = DockerComposeEnvironmentAdapter(runner=runner)
    first_token = "a" * 32
    second_token = "b" * 32
    tokens = iter((first_token, first_token, second_token))
    monkeypatch.setattr(
        "stateweaver.adapters.docker_compose.adapter.uuid.uuid4",
        lambda: SimpleNamespace(hex=next(tokens)),
    )

    environments = await asyncio.wait_for(
        asyncio.gather(adapter.prepare(_target()), adapter.prepare(_target())),
        timeout=2.0,
    )
    assert {item.environment_id for item in environments} == {
        f"environment:{first_token}",
        f"environment:{second_token}",
    }
    assert barrier.max_active == 2
    await asyncio.gather(*(adapter.destroy(item) for item in environments))


@pytest.mark.asyncio
async def test_snapshot_retention_capacity_fails_before_another_process_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "stateweaver.adapters.docker_compose.adapter._MAX_ISSUED_SNAPSHOTS",
        1,
    )
    runner = FakeRunner()
    adapter = DockerComposeEnvironmentAdapter(runner=runner)
    env = await adapter.prepare(_target())
    await adapter.snapshot(env)
    calls_before = len(runner.calls)

    with pytest.raises(ComposeAdapterError, match="retention capacity"):
        await adapter.snapshot(env)
    assert len(runner.calls) == calls_before
    await adapter.destroy(env)


@pytest.mark.asyncio
async def test_cancelled_fork_removes_unpublished_child_and_preserves_root() -> None:
    runner = FakeRunner()
    adapter = DockerComposeEnvironmentAdapter(runner=runner)
    root = await adapter.prepare(_target())
    clean = await adapter.snapshot(root)
    barrier = OperationBarrier(parties=1, auto_release=False)
    runner.barriers[_IMPORT] = barrier

    fork = asyncio.create_task(adapter.fork(clean))
    await asyncio.wait_for(barrier.reached.wait(), timeout=1.0)
    child_project = next(iter(barrier.projects))
    fork.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(fork, timeout=1.0)
    runner.barriers.pop(_IMPORT)

    assert child_project not in runner.states
    assert (await adapter.snapshot(root)).content_hashes == clean.content_hashes
    await adapter.destroy(root)


@pytest.mark.asyncio
async def test_cancelled_destructive_restore_compensates_and_remains_retryable() -> None:
    runner = FakeRunner(block_down_after_commit=True)
    adapter = DockerComposeEnvironmentAdapter(runner=runner)
    env = await adapter.prepare(_target())
    clean = await adapter.snapshot(env)
    runner.mutate(env, "database", {"rows": [{"value": "dirty"}]})

    restore = asyncio.create_task(adapter.restore(env, clean))
    await asyncio.wait_for(runner.down_started.wait(), timeout=1.0)
    restore.cancel()
    runner.release_down.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(restore, timeout=1.0)

    runner.block_down_after_commit = False
    await adapter.restore(env, clean)
    assert (await adapter.snapshot(env)).content_hashes == clean.content_hashes
    await adapter.destroy(env)


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
async def test_restore_rejects_a_same_root_snapshot_from_another_source_world() -> None:
    runner = FakeRunner()
    adapter = DockerComposeEnvironmentAdapter(runner=runner)
    root = await adapter.prepare(_target())
    root_snapshot = await adapter.snapshot(root)
    child = await adapter.fork(root_snapshot)
    child_snapshot = await adapter.snapshot(child)
    calls_before = len(runner.calls)

    with pytest.raises(ComposeAdapterError, match="source environment"):
        await adapter.restore(root, child_snapshot)
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
async def test_health_accepts_compose_single_object_json() -> None:
    runner = FakeRunner(single_object_ps=True)

    environment = await DockerComposeEnvironmentAdapter(runner=runner).prepare(_target())

    assert FakeRunner.project(environment) in runner.states


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
    process = _WaitingProcess(lookup_race=lookup_race)

    async def create(*args: object, **kwargs: object) -> _WaitingProcess:
        del args, kwargs
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)
    monkeypatch.setattr(runner_module, "_PROCESS_TERMINATION_SECONDS", 0.0)
    task = asyncio.create_task(
        SubprocessRunner().run(("docker", "version", "--format", "{{.Server.Version}}"))
    )
    await process.reading.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert process.terminated is True
    assert process.killed is True


@pytest.mark.asyncio
async def test_subprocess_runner_enforces_deadline_and_reaps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _WaitingProcess()

    async def create(*args: object, **kwargs: object) -> _WaitingProcess:
        del args, kwargs
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)
    monkeypatch.setattr(
        "stateweaver.adapters.docker_compose.runner.PROCESS_DEADLINE_SECONDS",
        0.01,
    )
    monkeypatch.setattr(runner_module, "_PROCESS_TERMINATION_SECONDS", 0.0)

    with pytest.raises(ProcessBoundaryError, match="process-deadline-exceeded"):
        await SubprocessRunner().run(("docker", "version", "--format", "{{.Server.Version}}"))
    assert process.terminated is True
    assert process.killed is True


@pytest.mark.asyncio
async def test_deadline_signals_group_after_leader_exits_with_open_pipes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _ExitedLeaderWithOpenPipes()

    async def create(*args: object, **kwargs: object) -> _ExitedLeaderWithOpenPipes:
        del args, kwargs
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)
    monkeypatch.setattr(
        "stateweaver.adapters.docker_compose.runner.PROCESS_DEADLINE_SECONDS",
        0.01,
    )
    monkeypatch.setattr(runner_module, "_PROCESS_TERMINATION_SECONDS", 0.0)

    with pytest.raises(ProcessBoundaryError, match="process-deadline-exceeded"):
        await SubprocessRunner().run(("docker", "version", "--format", "{{.Server.Version}}"))
    assert process.terminated is True
    assert process.killed is True


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_source", ["read", "write", "wait"])
async def test_unexpected_process_io_failure_aborts_tree_and_preserves_exception(
    monkeypatch: pytest.MonkeyPatch,
    failure_source: str,
) -> None:
    error = ConnectionAbortedError(f"simulated-{failure_source}-failure")
    process: _WaitingProcess
    if failure_source == "wait":
        process = _ExplodingWaitProcess(error)
    else:
        process = _WaitingProcess()
        if failure_source == "read":
            process.stdout = _ExplodingReader(error)
        else:
            process.stdin = _ExplodingWriter(error)

    async def create(*args: object, **kwargs: object) -> _WaitingProcess:
        del args, kwargs
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)
    monkeypatch.setattr(
        "stateweaver.adapters.docker_compose.runner._PROCESS_TERMINATION_SECONDS",
        0.0,
    )
    if failure_source == "write":
        package = Path(__file__).parents[1] / "src/stateweaver/adapters/docker_compose"
        argv: tuple[str, ...] = (
            "docker",
            "compose",
            "--project-name",
            f"swm2{'1' * 32}",
            "--file",
            str(package / "compose.yaml"),
            "exec",
            "--no-TTY",
            "synthetic-demo",
            "python",
            "/opt/stateweaver/state_bridge.py",
            "import",
        )
        stdin = b"{}"
    else:
        argv = ("docker", "version", "--format", "{{.Server.Version}}")
        stdin = None

    with pytest.raises(ConnectionAbortedError, match=f"simulated-{failure_source}-failure"):
        await SubprocessRunner().run(argv, stdin=stdin)
    assert process.terminated is True
    assert process.killed is True


def test_windows_taskkill_uses_closed_resolved_system32_argv(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    windows_root = tmp_path / "Windows"
    taskkill = windows_root / "System32" / "taskkill.exe"
    taskkill.parent.mkdir(parents=True)
    taskkill.touch()
    monkeypatch.setenv("SYSTEMROOT", str(windows_root))
    monkeypatch.delenv("WINDIR", raising=False)
    captured: dict[str, object] = {}

    def run(argv: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        captured["argv"] = argv
        captured.update(kwargs)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(subprocess, "run", run)

    resolved = runner_module._resolve_windows_system_binary("taskkill.exe")
    assert resolved == taskkill.resolve()
    runner_module._run_windows_taskkill(resolved, 4242)

    assert captured["argv"] == (str(taskkill), "/PID", "4242", "/T", "/F")
    assert captured["shell"] is False
    assert captured["cwd"] == str(taskkill.parent)
    assert captured["stdin"] is subprocess.DEVNULL
    assert captured["stdout"] is subprocess.DEVNULL
    assert captured["stderr"] is subprocess.DEVNULL
    environment = captured["env"]
    assert isinstance(environment, dict)
    assert set(environment) == {"PATH", "SYSTEMROOT"}
    assert environment["PATH"] == str(taskkill.parent)


@pytest.mark.asyncio
@pytest.mark.parametrize("stream", ["stdout", "stderr"])
async def test_subprocess_runner_caps_each_output_stream_before_return(
    monkeypatch: pytest.MonkeyPatch,
    stream: str,
) -> None:
    oversized = b"x" * (MAX_PROCESS_STREAM_BYTES + 1)
    process = _CompletedProcess(
        oversized if stream == "stdout" else b"",
        oversized if stream == "stderr" else b"",
    )

    async def create(*args: object, **kwargs: object) -> _CompletedProcess:
        del args, kwargs
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)
    monkeypatch.setattr(runner_module, "_PROCESS_TERMINATION_SECONDS", 0.0)

    with pytest.raises(ProcessBoundaryError, match="process-output-limit-exceeded"):
        await SubprocessRunner().run(("docker", "version", "--format", "{{.Server.Version}}"))


@pytest.mark.asyncio
async def test_subprocess_runner_uses_fixed_linux_engine_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    async def create(*args: object, **kwargs: object) -> _CompletedProcess:
        del args
        captured.update(kwargs)
        return _CompletedProcess(b"29.0.0\n")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)

    result = await SubprocessRunner().run(("docker", "version", "--format", "{{.Server.Version}}"))

    environment = captured["env"]
    assert isinstance(environment, dict)
    expected_host = (
        "npipe:////./pipe/dockerDesktopLinuxEngine"
        if os.name == "nt"
        else "unix:///var/run/docker.sock"
    )
    assert result.stdout == "29.0.0\n"
    assert environment["DOCKER_HOST"] == expected_host
    assert set(environment) <= {"PATH", "DOCKER_HOST", "SYSTEMROOT", "WINDIR"}


@pytest.mark.asyncio
async def test_subprocess_runner_uses_standalone_compose_without_user_config_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    async def create(*args: object, **kwargs: object) -> _CompletedProcess:
        captured["argv"] = args
        captured["env"] = kwargs["env"]
        captured["cwd"] = kwargs["cwd"]
        return _CompletedProcess(b"[]\n")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)
    package = Path(__file__).parents[1] / "src/stateweaver/adapters/docker_compose"
    original = (
        "docker",
        "compose",
        "--project-name",
        f"swm2{'1' * 32}",
        "--file",
        str(package / "compose.yaml"),
        "ps",
        "--format",
        "json",
    )

    await SubprocessRunner().run(original)

    executed = captured["argv"]
    assert isinstance(executed, tuple)
    assert Path(executed[0]).is_absolute()
    if os.name == "nt":
        assert Path(executed[0]).name.lower() == "docker-compose.exe"
        assert executed[1:] == original[2:]
    else:
        assert Path(executed[0]).name == "docker"
        assert executed[1:] == original[1:]
    environment = captured["env"]
    assert isinstance(environment, dict)
    assert "USERPROFILE" not in environment
    assert "APPDATA" not in environment
    assert captured.get("cwd") == str(package)


@pytest.mark.asyncio
async def test_subprocess_runner_rejects_relative_executable_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: "relative-tool")
    runner = SubprocessRunner()

    with pytest.raises(FileNotFoundError, match="trusted docker executable"):
        await runner.run(("docker", "version", "--format", "{{.Server.Version}}"))


@pytest.mark.asyncio
async def test_subprocess_runner_binds_executable_before_path_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    trusted = tmp_path / ("docker.exe" if os.name == "nt" else "docker")
    trusted.touch()
    trusted.chmod(0o755)
    monkeypatch.setattr(
        shutil,
        "which",
        lambda name: str(trusted) if name == "docker" else None,
    )
    runner = SubprocessRunner()
    monkeypatch.setenv("PATH", str(tmp_path / "untrusted-later"))
    captured: dict[str, object] = {}

    async def create(*args: object, **kwargs: object) -> _CompletedProcess:
        captured["argv"] = args
        captured.update(kwargs)
        return _CompletedProcess(b"29.0.0\n")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)

    await runner.run(("docker", "version", "--format", "{{.Server.Version}}"))

    argv = captured["argv"]
    assert isinstance(argv, tuple)
    assert argv[0] == str(trusted.resolve())
    environment = captured["env"]
    assert isinstance(environment, dict)
    assert str(tmp_path / "untrusted-later") not in environment["PATH"]


def test_compose_fixture_is_repository_owned_and_sandboxed() -> None:
    package = Path(__file__).parents[1] / "src/stateweaver/adapters/docker_compose"
    compose = (package / "compose.yaml").read_text(encoding="utf-8")
    dockerfile = (package / "Dockerfile").read_text(encoding="utf-8")

    assert "internal: true" in compose
    assert "pull_policy: never" in compose
    assert "read_only: true" in compose
    assert "cap_drop: [ALL]" in compose
    assert "no-new-privileges:true" in compose
    assert "timeout: 10s" in compose
    assert "ports:" not in compose
    assert "docker.sock" not in compose
    assert "@sha256:" in dockerfile
    assert "USER 65532:65532" in dockerfile
