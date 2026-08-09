"""Measure Git checkout cleanliness with closed argv and explicit generated-root exclusions."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from .common import CandidateError, canonical_json_bytes

_MAX_UNTRACKED_OUTPUT_BYTES = 4 * 1024 * 1024


def _run_git(
    root: Path, arguments: list[str], *, capture: bool = False
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=False,
            capture_output=capture,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise CandidateError("git-clean-check-failed") from None


def check_git_clean(root: Path, *, allowed_untracked: tuple[Path, ...] = ()) -> bool:
    if root.is_symlink():
        raise CandidateError("git-clean-root-invalid")
    repository_root = root.resolve(strict=True)
    if not repository_root.is_dir():
        raise CandidateError("git-clean-root-invalid")
    allowed: tuple[Path, ...] = tuple(path.resolve(strict=False) for path in allowed_untracked)
    for path in allowed:
        try:
            path.relative_to(repository_root)
        except ValueError:
            raise CandidateError("git-clean-allowlist-invalid") from None
    if _run_git(repository_root, ["diff", "--quiet", "HEAD", "--"]).returncode != 0:
        return False
    if _run_git(repository_root, ["diff", "--cached", "--quiet"]).returncode != 0:
        return False
    untracked = _run_git(
        repository_root,
        ["ls-files", "--others", "--exclude-standard", "-z"],
        capture=True,
    )
    if untracked.returncode != 0 or len(untracked.stdout) > _MAX_UNTRACKED_OUTPUT_BYTES:
        raise CandidateError("git-clean-check-failed")
    for raw_path in untracked.stdout.split(b"\0"):
        if not raw_path:
            continue
        try:
            relative = raw_path.decode("utf-8")
        except UnicodeDecodeError:
            raise CandidateError("git-clean-path-invalid") from None
        candidate = (repository_root / relative).resolve(strict=False)
        try:
            candidate.relative_to(repository_root)
        except ValueError:
            raise CandidateError("git-clean-path-invalid") from None
        if not any(candidate == path or path in candidate.parents for path in allowed):
            return False
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--allow-untracked", type=Path, action="append", default=[])
    arguments = parser.parse_args(argv)
    try:
        clean = check_git_clean(
            arguments.repository_root,
            allowed_untracked=tuple(arguments.allow_untracked),
        )
    except (CandidateError, OSError) as error:
        code = error.code if isinstance(error, CandidateError) else "git-clean-check-failed"
        print(canonical_json_bytes({"clean": False, "error": code}).decode(), end="")
        return 2
    print(canonical_json_bytes({"clean": clean, "error": None}).decode(), end="")
    return 0 if clean else 1


if __name__ == "__main__":
    sys.exit(main())
