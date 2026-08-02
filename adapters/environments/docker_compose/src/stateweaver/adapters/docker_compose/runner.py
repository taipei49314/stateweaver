"""A narrow shell-free process boundary for the adapter's fixed Docker argv."""

from __future__ import annotations

import asyncio
import os
import re
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

_COMPOSE_FILE = Path(__file__).with_name("compose.yaml")
_PROJECT_PATTERN = re.compile(r"^swm2[0-9a-f]{32}$")
_CONTAINER_ID_PATTERN = re.compile(r"^[0-9a-f]{12,64}$")
MAX_STATE_ARCHIVE_BYTES = 1_048_576
_STATE_BRIDGE_PREFIX = (
    "exec",
    "--no-TTY",
    "synthetic-demo",
    "python",
    "/opt/stateweaver/state_bridge.py",
)
_COMPOSE_OPERATIONS = frozenset(
    {
        ("up", "--detach", "--wait", "--no-build"),
        ("down", "--volumes", "--remove-orphans"),
        ("ps", "--format", "json"),
        (*_STATE_BRIDGE_PREFIX, "export"),
        (*_STATE_BRIDGE_PREFIX, "import"),
    }
)


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class ProcessRunner(Protocol):
    async def run(self, argv: tuple[str, ...], *, stdin: bytes | None = None) -> ProcessResult: ...


class SubprocessRunner:
    """Runs a pre-built argv with shell=False and no caller-provided environment."""

    async def run(self, argv: tuple[str, ...], *, stdin: bytes | None = None) -> ProcessResult:
        exact_argv = require_exact_argv(argv)
        is_import = exact_argv[-len(_STATE_BRIDGE_PREFIX) - 1 :] == (
            *_STATE_BRIDGE_PREFIX,
            "import",
        )
        if is_import != (stdin is not None):
            raise ValueError("only the fixed state import operation accepts stdin")
        if stdin is not None and (not stdin or len(stdin) > MAX_STATE_ARCHIVE_BYTES):
            raise ValueError("state import payload exceeds the fixed archive boundary")
        environment = {
            "PATH": os.environ.get("PATH", os.defpath),
            "DOCKER_HOST": (
                "npipe:////./pipe/docker_engine"
                if os.name == "nt"
                else "unix:///var/run/docker.sock"
            ),
        }
        for required_name in ("SYSTEMROOT", "WINDIR"):
            if required_name in os.environ:
                environment[required_name] = os.environ[required_name]
        try:
            process = await asyncio.create_subprocess_exec(
                *exact_argv,
                stdin=(
                    asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL
                ),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=environment,
            )
        except FileNotFoundError:
            raise
        try:
            stdout, stderr = await process.communicate(input=stdin)
        except asyncio.CancelledError:
            if process.returncode is None:
                with suppress(ProcessLookupError):
                    process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=2.0)
                except TimeoutError:
                    with suppress(ProcessLookupError):
                        process.kill()
                    await process.wait()
            raise
        if process.returncode is None:
            raise RuntimeError("docker process did not terminate")
        return ProcessResult(
            returncode=process.returncode,
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=stderr.decode("utf-8", errors="replace"),
        )


def require_exact_argv(argv: Sequence[str]) -> tuple[str, ...]:
    """Admit only the adapter's fixed local Docker and Compose command grammar."""

    if not argv or any(not isinstance(item, str) for item in argv):
        raise ValueError("argv must be a non-empty string tuple")
    exact = tuple(argv)
    if exact == ("docker", "version", "--format", "{{.Server.Version}}"):
        return exact
    if exact == (
        "docker",
        "image",
        "inspect",
        "--format",
        "{{.Id}}",
        "stateweaver-synthetic-demo:local",
    ):
        return exact
    if (
        len(exact) == 5
        and exact[:4] == ("docker", "inspect", "--format", "{{.Image}}")
        and _CONTAINER_ID_PATTERN.fullmatch(exact[4])
    ):
        return exact
    prefix = ("docker", "compose", "--project-name")
    if (
        len(exact) < 7
        or exact[:3] != prefix
        or not _PROJECT_PATTERN.fullmatch(exact[3])
        or exact[4:6] != ("--file", str(_COMPOSE_FILE))
        or exact[6:] not in _COMPOSE_OPERATIONS
    ):
        raise ValueError("runner accepts only the fixed synthetic Compose argv")
    return exact
