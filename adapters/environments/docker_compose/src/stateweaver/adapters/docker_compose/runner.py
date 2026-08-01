"""A narrow shell-free process boundary for the adapter's fixed Docker argv."""

from __future__ import annotations

import asyncio
import os
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

_COMPOSE_FILE = Path(__file__).with_name("compose.yaml")
_PROJECT_PATTERN = re.compile(r"^swm2[0-9a-f]{32}$")
_COMPOSE_OPERATIONS = frozenset(
    {
        ("up", "--detach", "--wait", "--no-build"),
        ("down", "--volumes", "--remove-orphans"),
        ("ps", "--format", "json"),
    }
)


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class ProcessRunner(Protocol):
    async def run(self, argv: tuple[str, ...]) -> ProcessResult: ...


class SubprocessRunner:
    """Runs a pre-built argv with shell=False and no caller-provided environment."""

    async def run(self, argv: tuple[str, ...]) -> ProcessResult:
        exact_argv = require_exact_argv(argv)
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
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=environment,
            )
        except FileNotFoundError:
            raise
        stdout, stderr = await process.communicate()
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
