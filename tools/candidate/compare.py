"""Byte-compare two reproducibility roots after safe, single-read snapshots."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .common import CandidateError, canonical_json_bytes, sha256_bytes, snapshot_tree


def compare_roots(left: Path, right: Path) -> tuple[bool, str | None]:
    """Return equality and the first stable difference code."""

    try:
        left_snapshot = snapshot_tree(left)
        right_snapshot = snapshot_tree(right)
    except CandidateError as error:
        return False, error.code
    if not left_snapshot or not right_snapshot:
        return False, "reproducibility-root-empty"
    if set(left_snapshot) != set(right_snapshot):
        return False, "reproducibility-file-set-mismatch"
    for path in sorted(left_snapshot):
        if sha256_bytes(left_snapshot[path]) != sha256_bytes(right_snapshot[path]):
            return False, f"reproducibility-content-mismatch:{path}"
    return True, None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("left", type=Path)
    parser.add_argument("right", type=Path)
    arguments = parser.parse_args(argv)
    equal, error = compare_roots(arguments.left, arguments.right)
    print(canonical_json_bytes({"equal": equal, "error": error}).decode(), end="")
    return 0 if equal else 1


if __name__ == "__main__":
    sys.exit(main())
