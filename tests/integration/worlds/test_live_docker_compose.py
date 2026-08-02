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
    DockerComposeEnvironmentAdapter,
    ProcessResult,
)
from stateweaver.adapters.docker_compose import adapter as adapter_module
from stateweaver.adapters.docker_compose.runner import SubprocessRunner
from stateweaver.worlds import EnvironmentHandle, SnapshotManifest, TargetSpec

pytestmark = [pytest.mark.docker_integration, pytest.mark.asyncio]

_OPT_IN = "STATEWEAVER_RUN_DOCKER_INTEGRATION"
_UP = ("up", "--detach", "--wait", "--no-build")
_PS = ("ps", "--format", "json")
_BRIDGE = (
    "exec",
    "--no-TTY",
    "synthetic-demo",
    "python",
    "/opt/stateweaver/state_bridge.py",
)
assert adapter_module.__file__ is not None
_COMPOSE_FILE = Path(adapter_module.__file__).with_name("compose.yaml")


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
            and argv[:3]
            == (
                "docker",
                "compose",
                "--project-name",
            )
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


def _target() -> TargetSpec:
    return TargetSpec(target_id="synthetic-demo", target_version="1.0.0")


def _project(env: EnvironmentHandle) -> str:
    return env.opaque_ref.removeprefix("compose:")


def _compose(env: EnvironmentHandle, *operation: str) -> tuple[str, ...]:
    return (
        "docker",
        "compose",
        "--project-name",
        _project(env),
        "--file",
        str(_COMPOSE_FILE),
        *operation,
    )


async def _export(runner: _BarrierProcessRunner, env: EnvironmentHandle) -> dict[str, object]:
    result = await runner.run(_compose(env, *_BRIDGE, "export"))
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert isinstance(payload, dict)
    return cast(dict[str, object], payload)


async def _set_session_marker(
    runner: _BarrierProcessRunner,
    env: EnvironmentHandle,
    marker: str,
) -> None:
    payload = await _export(runner, env)
    components = cast(dict[str, object], payload["components"])
    components["session"] = {"sessions": [{"world": marker}]}
    archive = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    result = await runner.run(_compose(env, *_BRIDGE, "import"), stdin=archive)
    assert result.returncode == 0
    assert json.loads(result.stdout) == {"accepted": True, "schema_version": "1.0"}


def _without_session(snapshot: SnapshotManifest) -> dict[str, str]:
    return {
        component: digest
        for component, digest in snapshot.content_hashes.items()
        if component != "session"
    }


@pytest.fixture
def docker_opt_in() -> None:
    if os.environ.get(_OPT_IN) != "1":
        pytest.fail(f"explicit live Docker selection requires {_OPT_IN}=1")


async def test_four_live_siblings_overlap_isolate_and_restore(
    docker_opt_in: None,
) -> None:
    del docker_opt_in
    runner = _BarrierProcessRunner()
    adapter = DockerComposeEnvironmentAdapter(runner=runner)
    created: list[EnvironmentHandle] = []
    projects_to_verify: list[EnvironmentHandle] = []
    cleanup_results: list[object] = []

    try:
        root = await adapter.prepare(_target())
        created.append(root)
        root_snapshot = await adapter.snapshot(root)

        fork_barrier = runner.arm_up(4)
        fork_tasks = [asyncio.create_task(adapter.fork(root_snapshot)) for _ in range(4)]
        try:
            fork_results = await asyncio.wait_for(
                asyncio.gather(
                    *fork_tasks,
                    return_exceptions=True,
                ),
                timeout=120.0,
            )
        finally:
            runner.disarm_up(fork_barrier)
            for task in fork_tasks:
                if task.done() and not task.cancelled():
                    with suppress(Exception):
                        task_result = task.result()
                        if (
                            isinstance(task_result, EnvironmentHandle)
                            and task_result not in created
                        ):
                            created.append(task_result)
        assert all(isinstance(result, EnvironmentHandle) for result in fork_results)
        siblings = cast(list[EnvironmentHandle], fork_results)
        projects_to_verify.extend(created)
        assert len(fork_barrier.projects) == 4
        assert fork_barrier.max_in_flight == 4
        assert len({item.opaque_ref for item in siblings}) == 4
        assert len({item.namespace.network for item in siblings}) == 4
        assert len({item.namespace.database for item in siblings}) == 4

        baselines = await asyncio.gather(*(adapter.snapshot(item) for item in siblings))
        await asyncio.gather(
            *(
                _set_session_marker(runner, sibling, f"sibling-{index}")
                for index, sibling in enumerate(siblings)
            )
        )
        exported = await asyncio.gather(*(_export(runner, item) for item in siblings))
        for index, payload in enumerate(exported):
            components = cast(dict[str, object], payload["components"])
            assert components["session"] == {"sessions": [{"world": f"sibling-{index}"}]}
        mutated = await asyncio.gather(*(adapter.snapshot(item) for item in siblings))
        assert len({item.content_hashes["session"] for item in mutated}) == 4
        assert all(
            _without_session(current) == _without_session(baseline)
            for current, baseline in zip(mutated, baselines, strict=True)
        )
        assert (await adapter.snapshot(root)).content_hashes == root_snapshot.content_hashes

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
                timeout=120.0,
            )
        finally:
            runner.disarm_up(restore_barrier)
        assert restore_results == [None, None, None, None]
        assert len(restore_barrier.projects) == 4
        assert restore_barrier.max_in_flight == 4
        restored = await asyncio.gather(*(adapter.snapshot(item) for item in siblings))
        assert all(
            current.content_hashes == baseline.content_hashes
            for current, baseline in zip(restored, baselines, strict=True)
        )
    finally:
        cleanup_results = await asyncio.gather(
            *(adapter.destroy(item) for item in reversed(created)),
            return_exceptions=True,
        )

    assert cleanup_results == [None] * len(created)
    for env in projects_to_verify:
        ps_result = await runner.run(_compose(env, *_PS))
        assert ps_result.returncode == 0
        payload = [] if not ps_result.stdout.strip() else json.loads(ps_result.stdout)
        assert payload == []
