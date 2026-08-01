"""Compatibility entry point; verifies an isolated acceptance run."""

from __future__ import annotations

import sys

from stateweaver.evidence.cli import main

if __name__ == "__main__":
    raise SystemExit(main(["verify", *sys.argv[1:]]))
