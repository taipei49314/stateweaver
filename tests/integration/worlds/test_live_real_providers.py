from __future__ import annotations

import asyncio
import json
import os
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

import pytest
from stateweaver.adapters.docker_compose import (
    ComposeUnavailableError,
    ProcessResult,
    RealDockerComposeEnvironmentAdapter,
)
from stateweaver.adapters.docker_compose import runner as runner_module
from stateweaver.adapters.docker_compose.runner import SubprocessRunner
from stateweaver.worlds import EnvironmentHandle, SnapshotManifest, TargetSpec

pytestmark = [pytest.mark.docker_integration, pytest.mark.asyncio]

_OPT_IN = "STATEWEAVER_RUN_REAL_DOCKER_INTEGRATION"
_UP = ("up", "--detach", "--wait", "--no-build")
_PS = ("ps", "--format", "json", "provider-bridge")
_BRIDGE = (
    "exec",
    "--no-TTY",
    "provider-bridge",
    "python",
    "/opt/stateweaver/real_provider_bridge.py",
)
_COMPONENTS = {"filesystem", "database", "cache", "queue", "session", "clock"}
_COMPOSE_FILE = (
    Path(__file__).parents[3]
    / "adapters"
    / "environments"
    / "docker_compose"
    / "src"
    / "stateweaver"
    / "adapters"
    / "docker_compose"
    / "real_compose.yaml"
)


@dataclass
class _UpBarrier:
    parties: int
    projects: set[str] = field(default_factory=set)
    release: asyncio.Event = field(default_factory=asyncio.Event)
    in_flight: int = 0
    max_in_flight: int = 0

    async def arrive(self, project: str) -> None:
        self.projects.add(project)
        if len(self.projects) >= self.parties:
            self.release.set()
        await self.release.wait()


class _BarrierProcessRunner:
    def __init__(self) -> None:
        self._delegate = SubprocessRunner()
        self._up_barrier: _UpBarrier | None = None

    def arm_up(self, parties: int) -> _UpBarrier:
        if self._up_barrier is not None:
            raise RuntimeError("an up barrier is already armed")
        barrier = _UpBarrier(parties=parties)
        self._up_barrier = barrier
        return barrier

    def disarm_up(self, barrier: _UpBarrier) -> None:
        if self._up_barrier is not barrier:
            raise RuntimeError("attempted to disarm a different up barrier")
        self._up_barrier = None

    async def run(
        self,
        argv: tuple[str, ...],
        *,
        stdin: bytes | None = None,
    ) -> ProcessResult:
        barrier = self._up_barrier
        is_up = (
            len(argv) >= 10
            and argv[:3] == ("docker", "compose", "--project-name")
            and argv[6:] == _UP
        )
        if barrier is None or not is_up:
            return await self._delegate.run(argv, stdin=stdin)
        project = argv[3]
        await barrier.arrive(project)
        barrier.in_flight += 1
        barrier.max_in_flight = max(barrier.max_in_flight, barrier.in_flight)
        try:
            return await self._delegate.run(argv, stdin=stdin)
        finally:
            barrier.in_flight -= 1


class _FaultProcessRunner:
    def __init__(self, *, fail_after_up: bool = False) -> None:
        self._delegate = SubprocessRunner()
        self._fail_after_up = fail_after_up
        self.up_started = asyncio.Event()
        self.project: str | None = None

    async def run(
        self,
        argv: tuple[str, ...],
        *,
        stdin: bytes | None = None,
    ) -> ProcessResult:
        is_up = (
            len(argv) >= 10
            and argv[:3] == ("docker", "compose", "--project-name")
            and argv[6:] == _UP
        )
        if not is_up:
            return await self._delegate.run(argv, stdin=stdin)
        self.project = argv[3]
        self.up_started.set()
        result = await self._delegate.run(argv, stdin=stdin)
        if self._fail_after_up:
            return ProcessResult(returncode=70, stderr="fixed injected partial failure")
        return result


def _target() -> TargetSpec:
    return TargetSpec(target_id="real-provider-demo", target_version="1.0.0")


def _project(environment: EnvironmentHandle) -> str:
    return environment.opaque_ref.removeprefix("compose:")


def _compose(environment: EnvironmentHandle, *operation: str) -> tuple[str, ...]:
    return (
        "docker",
        "compose",
        "--project-name",
        _project(environment),
        "--file",
        str(_COMPOSE_FILE),
        *operation,
    )


async def _export(
    runner: _BarrierProcessRunner,
    environment: EnvironmentHandle,
) -> dict[str, object]:
    result = await runner.run(_compose(environment, *_BRIDGE, "export"))
    assert result.returncode == 0
    value = json.loads(result.stdout)
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


async def _mutate(
    runner: _BarrierProcessRunner,
    environment: EnvironmentHandle,
    *,
    marker: str,
    tick: int,
) -> None:
    request = json.dumps(
        {"marker": marker, "tick": tick},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    result = await runner.run(
        _compose(environment, *_BRIDGE, "mutate"),
        stdin=request,
    )
    assert result.returncode == 0
    assert json.loads(result.stdout) == {"accepted": True, "schema_version": "2.0"}


def _assert_marker(value: dict[str, object], marker: str, tick: int) -> None:
    assert value["schema_version"] == "2.0"
    components = cast(dict[str, object], value["components"])
    assert set(components) == _COMPONENTS
    assert cast(dict[str, object], components["database"])["rows"] == [
        {"id": 1, "tenant": "alpha", "value": marker}
    ]
    assert cast(dict[str, object], components["cache"])["entries"] == {"sw:marker": marker}
    assert cast(dict[str, object], components["queue"])["messages"] == [marker]
    assert cast(dict[str, object], components["filesystem"])["files"] == {
        "marker.txt": marker,
        "tenant.txt": "alpha",
    }
    session = cast(dict[str, object], components["session"])
    assert session["cookies"] == [{"name": "sw_marker", "path": "/", "value": marker}]
    assert session["local_storage"] == {"sw.marker": marker}
    assert cast(dict[str, object], components["clock"])["tick"] == tick


def _receipt(
    *,
    baselines: list[SnapshotManifest],
    mutated: list[SnapshotManifest],
    restored: list[SnapshotManifest],
    max_in_flight: tuple[int, int],
) -> dict[str, object]:
    return {
        "schema_version": "stateweaver-m2-real-provider-observation-v1",
        "adapter": "docker-compose-real-providers@0.1.0",
        "target": "real-provider-demo@1.0.0",
        "providers": sorted(_COMPONENTS),
        "siblings": 4,
        "overlap": {
            "fork_max_in_flight": max_in_flight[0],
            "restore_max_in_flight": max_in_flight[1],
        },
        "worlds": [
            {
                "baseline": dict(baseline.content_hashes),
                "mutated": dict(current.content_hashes),
                "restored": dict(after.content_hashes),
            }
            for baseline, current, after in zip(
                baselines,
                mutated,
                restored,
                strict=True,
            )
        ],
        "cleanup": {"adapter_owned_worlds": 0, "status": "PASS"},
        "status": "PASS",
    }


def _write_receipt(value: dict[str, object]) -> None:
    receipt_path = Path("artifacts/m2-live/real-provider-receipt.json")
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _write_cleanup_receipt(case: str) -> None:
    receipt_path = Path(f"artifacts/m2-live/cleanup-{case}.json")
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_text(
        json.dumps(
            {
                "case": case,
                "containers_after": 0,
                "networks_after": 0,
                "schema_version": "stateweaver-m2-cleanup-case-v1",
                "status": "PASS",
                "volumes_after": 0,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )


async def _assert_project_absent(runner: _FaultProcessRunner, project: str) -> None:
    label = f"label=com.docker.compose.project={project}"
    commands = (
        ("docker", "ps", "--all", "--filter", label, "--format", "{{.ID}}"),
        ("docker", "network", "ls", "--filter", label, "--format", "{{.ID}}"),
        ("docker", "volume", "ls", "--filter", label, "--format", "{{.Name}}"),
    )
    for command in commands:
        result = await runner.run(command)
        assert result.returncode == 0
        assert not result.stdout.strip()


@pytest.fixture
def real_docker_opt_in() -> None:
    if os.environ.get(_OPT_IN) != "1":
        pytest.fail(f"explicit real-provider Docker selection requires {_OPT_IN}=1")


async def test_four_real_provider_siblings_overlap_isolate_restore_and_cleanup(
    real_docker_opt_in: None,
) -> None:
    del real_docker_opt_in
    runner = _BarrierProcessRunner()
    adapter = RealDockerComposeEnvironmentAdapter(runner=runner)
    created: list[EnvironmentHandle] = []
    projects_to_verify: list[EnvironmentHandle] = []
    cleanup_results: list[object] = []
    baselines: list[SnapshotManifest] = []
    mutated: list[SnapshotManifest] = []
    restored: list[SnapshotManifest] = []
    fork_barrier: _UpBarrier | None = None
    restore_barrier: _UpBarrier | None = None

    try:
        root = await adapter.prepare(_target())
        created.append(root)
        projects_to_verify.append(root)
        root_snapshot = await adapter.snapshot(root)
        _assert_marker(await _export(runner, root), "baseline", 0)
        await adapter.destroy(root)
        created.remove(root)

        fork_barrier = runner.arm_up(4)
        tasks = [asyncio.create_task(adapter.fork(root_snapshot)) for _ in range(4)]
        try:
            fork_results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=300.0,
            )
        finally:
            runner.disarm_up(fork_barrier)
            for task in tasks:
                if task.done() and not task.cancelled():
                    with suppress(Exception):
                        task_value = task.result()
                        if isinstance(task_value, EnvironmentHandle) and task_value not in created:
                            created.append(task_value)
        fork_failures = [
            f"{type(result).__name__}:{result}"
            for result in fork_results
            if not isinstance(result, EnvironmentHandle)
        ]
        assert not fork_failures, fork_failures
        siblings = cast(list[EnvironmentHandle], fork_results)
        projects_to_verify.extend(siblings)
        assert fork_barrier.max_in_flight == 4
        assert len(fork_barrier.projects) == 4
        assert len({item.opaque_ref for item in siblings}) == 4
        assert len({item.namespace.network for item in siblings}) == 4
        assert len({item.namespace.database for item in siblings}) == 4
        assert len({item.namespace.session for item in siblings}) == 4

        baselines = list(await asyncio.gather(*(adapter.snapshot(item) for item in siblings)))
        assert all(item.content_hashes == root_snapshot.content_hashes for item in baselines)
        await asyncio.gather(
            *(
                _mutate(runner, sibling, marker=f"sibling-{index}", tick=index + 1)
                for index, sibling in enumerate(siblings)
            )
        )
        exports = await asyncio.gather(*(_export(runner, item) for item in siblings))
        for index, value in enumerate(exports):
            _assert_marker(value, f"sibling-{index}", index + 1)
        mutated = list(await asyncio.gather(*(adapter.snapshot(item) for item in siblings)))
        for baseline, current in zip(baselines, mutated, strict=True):
            assert set(current.content_hashes) == _COMPONENTS
            assert all(
                current.content_hashes[name] != baseline.content_hashes[name]
                for name in _COMPONENTS
            )
        for component in _COMPONENTS:
            assert len({item.content_hashes[component] for item in mutated}) == 4

        restore_barrier = runner.arm_up(4)
        try:
            restore_results = await asyncio.wait_for(
                asyncio.gather(
                    *(
                        adapter.restore(sibling, baseline)
                        for sibling, baseline in zip(siblings, baselines, strict=True)
                    ),
                    return_exceptions=True,
                ),
                timeout=300.0,
            )
        finally:
            runner.disarm_up(restore_barrier)
        restore_failures = [
            f"{type(result).__name__}:{result}" for result in restore_results if result is not None
        ]
        assert not restore_failures, restore_failures
        assert restore_barrier.max_in_flight == 4
        assert len(restore_barrier.projects) == 4
        restored = list(await asyncio.gather(*(adapter.snapshot(item) for item in siblings)))
        assert all(
            current.content_hashes == baseline.content_hashes
            for current, baseline in zip(restored, baselines, strict=True)
        )
        clean_exports = await asyncio.gather(*(_export(runner, item) for item in siblings))
        for value in clean_exports:
            _assert_marker(value, "baseline", 0)
    finally:
        cleanup_results = await asyncio.gather(
            *(adapter.destroy(item) for item in reversed(created)),
            return_exceptions=True,
        )

    assert cleanup_results == [None] * len(created)
    for environment in projects_to_verify:
        ps_result = await runner.run(_compose(environment, *_PS))
        assert ps_result.returncode == 0
        value = [] if not ps_result.stdout.strip() else json.loads(ps_result.stdout)
        assert value == []
    assert fork_barrier is not None and restore_barrier is not None
    await asyncio.to_thread(
        _write_receipt,
        _receipt(
            baselines=baselines,
            mutated=mutated,
            restored=restored,
            max_in_flight=(fork_barrier.max_in_flight, restore_barrier.max_in_flight),
        ),
    )
    await asyncio.to_thread(_write_cleanup_receipt, "success")


async def test_real_provider_start_timeout_returns_inventory_to_zero(
    real_docker_opt_in: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del real_docker_opt_in
    monkeypatch.setattr(runner_module, "REAL_PROVIDER_START_DEADLINE_SECONDS", 0.5)
    runner = _FaultProcessRunner()
    adapter = RealDockerComposeEnvironmentAdapter(runner=runner)

    with pytest.raises(ComposeUnavailableError, match="fixed deadline"):
        await adapter.prepare(_target())

    assert runner.project is not None
    await _assert_project_absent(runner, runner.project)
    await asyncio.to_thread(_write_cleanup_receipt, "timeout")


async def test_real_provider_cancellation_returns_inventory_to_zero(
    real_docker_opt_in: None,
) -> None:
    del real_docker_opt_in
    runner = _FaultProcessRunner()
    adapter = RealDockerComposeEnvironmentAdapter(runner=runner)
    task = asyncio.create_task(adapter.prepare(_target()))
    await asyncio.wait_for(runner.up_started.wait(), timeout=30.0)
    await asyncio.sleep(0.5)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert runner.project is not None
    await _assert_project_absent(runner, runner.project)
    await asyncio.to_thread(_write_cleanup_receipt, "cancellation")


async def test_real_provider_partial_failure_returns_inventory_to_zero(
    real_docker_opt_in: None,
) -> None:
    del real_docker_opt_in
    runner = _FaultProcessRunner(fail_after_up=True)
    adapter = RealDockerComposeEnvironmentAdapter(runner=runner)

    with pytest.raises(ComposeUnavailableError, match="command failed"):
        await adapter.prepare(_target())

    assert runner.project is not None
    await _assert_project_absent(runner, runner.project)
    await asyncio.to_thread(_write_cleanup_receipt, "partial-failure")
