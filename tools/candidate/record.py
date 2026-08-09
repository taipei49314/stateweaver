"""Run one argv without a shell and append a canonical typed command record."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from .common import CandidateError, canonical_json_bytes
from .receipt import load_command_records, validate_command_record


def _now() -> str:
    return datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _append(path: Path, record: dict[str, object]) -> None:
    existing = path.read_bytes() if path.exists() else b""
    if existing:
        load_command_records(existing)
    content = existing + canonical_json_bytes(validate_command_record(record))
    load_command_records(content)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        written = os.write(descriptor, content[len(existing) :])
        if written != len(content) - len(existing):
            raise CandidateError("command-record-write-failed")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--stage", required=True)
    parser.add_argument("--cwd", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args(argv)
    command = list(arguments.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("a command argv is required after --")
    executable = shutil.which(command[0], path=os.environ.get("PATH"))
    if executable is None:
        candidate = Path(command[0])
        if not candidate.is_absolute():
            candidate = arguments.cwd / candidate
        if not candidate.is_file():
            return 127
        executable = str(candidate)
    command[0] = Path(executable).resolve(strict=True).as_posix()
    started_at = _now()
    try:
        completed = subprocess.run(command, cwd=arguments.cwd, check=False)
        exit_code = completed.returncode
    except OSError:
        exit_code = 127
    completed_at = _now()
    record = {
        "argv": command,
        "completed_at": completed_at,
        "cwd": arguments.cwd.resolve().as_posix(),
        "exit_code": exit_code,
        "stage": arguments.stage,
        "started_at": started_at,
        "status": "PASS" if exit_code == 0 else "FAIL",
    }
    if exit_code == 0:
        _append(arguments.output, record)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
