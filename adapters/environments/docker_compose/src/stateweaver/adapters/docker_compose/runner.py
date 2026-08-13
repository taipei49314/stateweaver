"""A narrow shell-free process boundary for the adapter's fixed Docker argv."""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import signal
import subprocess
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol

_COMPOSE_FILE = Path(__file__).with_name("compose.yaml")
_REAL_COMPOSE_FILE = Path(__file__).with_name("real_compose.yaml")
_PROJECT_PATTERN = re.compile(r"^swm2[0-9a-f]{32}$")
_CONTAINER_ID_PATTERN = re.compile(r"^[0-9a-f]{12,64}$")
_PROJECT_LABEL_PREFIX = "label=com.docker.compose.project="
MAX_STATE_ARCHIVE_BYTES = 1_048_576
MAX_PROCESS_STREAM_BYTES: Final = MAX_STATE_ARCHIVE_BYTES
PROCESS_DEADLINE_SECONDS: Final = 60.0
# A five-service real-provider world has a materially slower bounded health
# transition than the single-container diagnostic fixture.  Keep the wider
# boundary tied only to the exact, admitted real-provider `compose up` argv.
REAL_PROVIDER_START_DEADLINE_SECONDS: Final = 180.0
MATERIALIZED_APPLICATION_DEADLINE_SECONDS: Final = 180.0
_PROCESS_TERMINATION_SECONDS: Final = 2.0
_PROCESS_READ_CHUNK_BYTES: Final = 64 * 1024
_STATE_BRIDGE_PREFIX = (
    "exec",
    "--no-TTY",
    "synthetic-demo",
    "python",
    "/opt/stateweaver/state_bridge.py",
)
_REAL_STATE_BRIDGE_PREFIX = (
    "exec",
    "--no-TTY",
    "provider-bridge",
    "python",
    "/opt/stateweaver/real_provider_bridge.py",
)
_MATERIALIZED_LAB_RUNTIME_PREFIX = (
    "exec",
    "--no-TTY",
    "materialized-lab",
    "python",
    "-m",
    "stateweaver.adapters.docker_compose.materialized_lab_runtime",
    "execute",
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
_REAL_COMPOSE_OPERATIONS = frozenset(
    {
        ("up", "--detach", "--wait", "--no-build"),
        ("down", "--volumes", "--remove-orphans"),
        ("ps", "--format", "json", "provider-bridge"),
        (*_REAL_STATE_BRIDGE_PREFIX, "export"),
        (*_REAL_STATE_BRIDGE_PREFIX, "import"),
        (*_REAL_STATE_BRIDGE_PREFIX, "mutate"),
        (*_REAL_STATE_BRIDGE_PREFIX, "m5-replay"),
        _MATERIALIZED_LAB_RUNTIME_PREFIX,
    }
)


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class ProcessBoundaryError(RuntimeError):
    """Stable subprocess-boundary failure without retaining child output."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ProcessRunner(Protocol):
    async def run(self, argv: tuple[str, ...], *, stdin: bytes | None = None) -> ProcessResult: ...


class SubprocessRunner:
    """Runs a pre-built argv with shell=False and no caller-provided environment."""

    def __init__(self) -> None:
        # Resolve executable identity once. Later caller mutations of PATH or cwd
        # cannot redirect an admitted argv to a different program.
        self._docker_executable = _resolve_executable("docker")
        self._compose_executable = (
            _resolve_executable("docker-compose") if os.name == "nt" else None
        )
        self._child_path = _closed_child_path(
            self._docker_executable,
            self._compose_executable,
        )

    async def run(self, argv: tuple[str, ...], *, stdin: bytes | None = None) -> ProcessResult:
        exact_argv = require_exact_argv(argv)
        if os.name == "nt" and exact_argv[:2] == ("docker", "compose"):
            if self._compose_executable is None:
                raise FileNotFoundError("trusted docker-compose executable is unavailable")
            process_argv = (str(self._compose_executable), *exact_argv[2:])
        else:
            if self._docker_executable is None:
                raise FileNotFoundError("trusted docker executable is unavailable")
            process_argv = (str(self._docker_executable), *exact_argv[1:])
        accepts_stdin = _accepts_state_stdin(exact_argv)
        if accepts_stdin != (stdin is not None):
            raise ValueError("only fixed state write operations accept stdin")
        if stdin is not None and (not stdin or len(stdin) > MAX_STATE_ARCHIVE_BYTES):
            raise ValueError("state import payload exceeds the fixed archive boundary")
        environment = {
            "PATH": self._child_path,
            "DOCKER_HOST": (
                # The fixed fixture is a Linux image. Modern Docker Desktop exposes
                # its Linux engine on this named pipe; docker_engine may point at a
                # stopped Windows engine and ignores the selected desktop-linux context.
                "npipe:////./pipe/dockerDesktopLinuxEngine"
                if os.name == "nt"
                else "unix:///var/run/docker.sock"
            ),
        }
        for required_name in ("SYSTEMROOT", "WINDIR"):
            if required_name in os.environ:
                environment[required_name] = os.environ[required_name]
        stdin_target = asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL
        try:
            if os.name == "nt":
                creation_flag = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", None)
                if not isinstance(creation_flag, int):
                    raise RuntimeError("Windows process-group isolation is unavailable")
                process = await asyncio.create_subprocess_exec(
                    *process_argv,
                    stdin=stdin_target,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=environment,
                    cwd=str(_COMPOSE_FILE.parent),
                    limit=_PROCESS_READ_CHUNK_BYTES,
                    creationflags=creation_flag,
                )
            else:
                process = await asyncio.create_subprocess_exec(
                    *process_argv,
                    stdin=stdin_target,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=environment,
                    cwd=str(_COMPOSE_FILE.parent),
                    limit=_PROCESS_READ_CHUNK_BYTES,
                    start_new_session=True,
                )
        except FileNotFoundError:
            raise
        tasks = (
            asyncio.create_task(_read_bounded(process.stdout)),
            asyncio.create_task(_read_bounded(process.stderr)),
            asyncio.create_task(_write_stdin(process.stdin, stdin)),
            asyncio.create_task(process.wait()),
        )
        try:
            stdout, stderr, _written, returncode = await asyncio.wait_for(
                asyncio.gather(*tasks),
                timeout=_deadline_seconds(exact_argv),
            )
        except TimeoutError:
            with suppress(BaseException):
                await _abort_and_reap(process, tasks)
            raise ProcessBoundaryError("process-deadline-exceeded") from None
        except ProcessBoundaryError:
            with suppress(BaseException):
                await _abort_and_reap(process, tasks)
            raise
        except asyncio.CancelledError:
            with suppress(BaseException):
                await _abort_and_reap(process, tasks)
            raise
        except BaseException:
            # Pipe and wait implementations may surface platform-specific OSError
            # subclasses. Preserve the authoritative exception after containing
            # the entire admitted process tree.
            with suppress(BaseException):
                await _abort_and_reap(process, tasks)
            raise
        if process.returncode is None or process.returncode != returncode:
            raise RuntimeError("docker process did not terminate")
        return ProcessResult(
            returncode=returncode,
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=stderr.decode("utf-8", errors="replace"),
        )


def _deadline_seconds(exact_argv: tuple[str, ...]) -> float:
    if exact_argv[4:6] == ("--file", str(_REAL_COMPOSE_FILE)) and exact_argv[6:] == (
        "up",
        "--detach",
        "--wait",
        "--no-build",
    ):
        return REAL_PROVIDER_START_DEADLINE_SECONDS
    if (
        exact_argv[4:6] == ("--file", str(_REAL_COMPOSE_FILE))
        and exact_argv[6:] == _MATERIALIZED_LAB_RUNTIME_PREFIX
    ):
        return MATERIALIZED_APPLICATION_DEADLINE_SECONDS
    return PROCESS_DEADLINE_SECONDS


def _accepts_state_stdin(exact_argv: tuple[str, ...]) -> bool:
    operations = (
        (*_STATE_BRIDGE_PREFIX, "import"),
        (*_REAL_STATE_BRIDGE_PREFIX, "import"),
        (*_REAL_STATE_BRIDGE_PREFIX, "mutate"),
        (*_REAL_STATE_BRIDGE_PREFIX, "m5-replay"),
        _MATERIALIZED_LAB_RUNTIME_PREFIX,
    )
    return any(exact_argv[-len(operation) :] == operation for operation in operations)


async def _read_bounded(stream: asyncio.StreamReader | None) -> bytes:
    if stream is None:
        raise ProcessBoundaryError("process-pipe-missing")
    content = bytearray()
    while True:
        remaining = MAX_PROCESS_STREAM_BYTES + 1 - len(content)
        chunk = await stream.read(min(_PROCESS_READ_CHUNK_BYTES, max(1, remaining)))
        if not chunk:
            return bytes(content)
        content.extend(chunk)
        if len(content) > MAX_PROCESS_STREAM_BYTES:
            raise ProcessBoundaryError("process-output-limit-exceeded")


async def _write_stdin(
    stream: asyncio.StreamWriter | None,
    content: bytes | None,
) -> None:
    if content is None:
        if stream is not None:
            stream.close()
        return
    if stream is None:
        raise ProcessBoundaryError("process-pipe-missing")
    try:
        stream.write(content)
        await stream.drain()
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        stream.close()
        with suppress(BrokenPipeError, ConnectionResetError):
            await stream.wait_closed()


async def _abort_and_reap(
    process: asyncio.subprocess.Process,
    tasks: Sequence[asyncio.Task[object]],
) -> None:
    runtime_process: object = process
    if os.name == "nt" and isinstance(runtime_process, asyncio.subprocess.Process):
        # taskkill must see the live group leader to enumerate its descendants,
        # so Windows uses an immediate closed-argv tree termination.
        await _force_process_tree(process)
    else:
        # POSIX groups retain their pgid after the leader exits. Give every member
        # the same fixed grace interval, then always escalate the group, independent
        # of the direct child's returncode.
        _signal_process_tree(process, force=False)
        if _PROCESS_TERMINATION_SECONDS > 0:
            await asyncio.sleep(_PROCESS_TERMINATION_SECONDS)
        await _force_process_tree(process)
    if process.returncode is None:
        try:
            await asyncio.wait_for(process.wait(), timeout=_PROCESS_TERMINATION_SECONDS)
        except BaseException:
            with suppress(ProcessLookupError):
                process.kill()
            with suppress(BaseException):
                await asyncio.wait_for(
                    process.wait(),
                    timeout=_PROCESS_TERMINATION_SECONDS,
                )
    for task in tasks:
        if not task.done():
            task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


async def _force_process_tree(process: asyncio.subprocess.Process) -> None:
    runtime_process: object = process
    if os.name == "nt" and isinstance(runtime_process, asyncio.subprocess.Process):
        taskkill = _resolve_windows_system_binary("taskkill.exe")
        if taskkill is not None:
            with suppress(Exception):
                await asyncio.to_thread(_run_windows_taskkill, taskkill, process.pid)
        # Reap/terminate the direct leader even if taskkill raced with normal exit.
        with suppress(ProcessLookupError):
            process.kill()
        return
    _signal_process_tree(process, force=True)


def _run_windows_taskkill(taskkill: Path, pid: int) -> None:
    """Force one Windows process tree through a closed absolute System32 argv."""

    subprocess.run(
        (str(taskkill), "/PID", str(pid), "/T", "/F"),
        shell=False,
        check=False,
        timeout=_PROCESS_TERMINATION_SECONDS,
        cwd=str(taskkill.parent),
        env=_windows_system_environment(taskkill.parent),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _resolve_windows_system_binary(name: str) -> Path | None:
    for variable in ("SYSTEMROOT", "WINDIR"):
        root = os.environ.get(variable)
        if not root:
            continue
        system32 = Path(root) / "System32"
        candidate = system32 / name
        try:
            resolved_system32 = system32.resolve(strict=True)
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if resolved.parent == resolved_system32 and resolved.is_file():
            return resolved
    return None


def _windows_system_environment(system32: Path) -> dict[str, str]:
    environment = {"PATH": str(system32)}
    for required_name in ("SYSTEMROOT", "WINDIR"):
        if required_name in os.environ:
            environment[required_name] = os.environ[required_name]
    return environment


def _resolve_executable(name: str) -> Path | None:
    discovered = shutil.which(name)
    if discovered is None:
        return None
    candidate = Path(discovered)
    if not candidate.is_absolute():
        return None
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    return resolved if resolved.is_file() and os.access(resolved, os.X_OK) else None


def _closed_child_path(*executables: Path | None) -> str:
    directories: list[str] = []
    for executable in executables:
        if executable is not None and str(executable.parent) not in directories:
            directories.append(str(executable.parent))
    for raw_directory in os.defpath.split(os.pathsep):
        directory = Path(raw_directory)
        if directory.is_absolute() and str(directory) not in directories:
            directories.append(str(directory))
    return os.pathsep.join(directories)


def _signal_process_tree(process: asyncio.subprocess.Process, *, force: bool) -> None:
    """Signal the isolated process group, with a direct-process fallback."""

    try:
        if os.name == "nt":
            if not force:
                ctrl_break_event = getattr(signal, "CTRL_BREAK_EVENT", None)
                if not isinstance(ctrl_break_event, int):
                    raise AttributeError("Windows process-group signalling is unavailable")
                runtime_process: object = process
                if isinstance(runtime_process, asyncio.subprocess.Process):
                    os.kill(process.pid, ctrl_break_event)
                else:
                    signal_method = getattr(runtime_process, "send_" + "signal")
                    signal_method(ctrl_break_event)
            else:
                process.kill()
            return
        # start_new_session=True makes the direct child's pid the stable process
        # group id even after that group leader exits.
        process_group = process.pid
        kill_signal = getattr(signal, "SIGKILL" if force else "SIGTERM", None)
        kill_process_group = getattr(os, "killpg", None)
        if not isinstance(kill_signal, int) or not callable(kill_process_group):
            raise AttributeError("POSIX process-group signalling is unavailable")
        kill_process_group(process_group, kill_signal)
    except (AttributeError, OSError, ProcessLookupError):
        method_name = "kill" if force else "terminate"
        direct_method = getattr(process, method_name, None)
        if callable(direct_method):
            with suppress(ProcessLookupError):
                direct_method()


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
    if exact == (
        "docker",
        "image",
        "inspect",
        "--format",
        "{{.Id}}",
        "stateweaver-real-provider-bridge:local",
    ):
        return exact
    if exact == (
        "docker",
        "image",
        "inspect",
        "--format",
        "{{.Id}}",
        "stateweaver-materialized-lab:local",
    ):
        return exact
    if (
        len(exact) == 5
        and exact[:4] == ("docker", "inspect", "--format", "{{.Image}}")
        and _CONTAINER_ID_PATTERN.fullmatch(exact[4])
    ):
        return exact
    if len(exact) == 7 and exact[3] == "--filter" and exact[5] == "--format":
        label = exact[4]
        project = label.removeprefix(_PROJECT_LABEL_PREFIX)
        inventory_prefix = exact[:3]
        inventory_format = exact[6]
        if (
            label == f"{_PROJECT_LABEL_PREFIX}{project}"
            and _PROJECT_PATTERN.fullmatch(project) is not None
            and (
                (inventory_prefix == ("docker", "ps", "--all") and inventory_format == "{{.ID}}")
                or (
                    inventory_prefix == ("docker", "network", "ls")
                    and inventory_format == "{{.ID}}"
                )
                or (
                    inventory_prefix == ("docker", "volume", "ls")
                    and inventory_format == "{{.Name}}"
                )
            )
        ):
            return exact
    prefix = ("docker", "compose", "--project-name")
    fixed_compose = (
        exact[4:6] == ("--file", str(_COMPOSE_FILE)) and exact[6:] in _COMPOSE_OPERATIONS
    ) or (
        exact[4:6] == ("--file", str(_REAL_COMPOSE_FILE)) and exact[6:] in _REAL_COMPOSE_OPERATIONS
    )
    if (
        len(exact) < 7
        or exact[:3] != prefix
        or not _PROJECT_PATTERN.fullmatch(exact[3])
        or not fixed_compose
    ):
        raise ValueError("runner accepts only the fixed synthetic Compose argv")
    return exact
