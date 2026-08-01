"""Compatibility entry point; calls the isolated evidence package CLI."""

from __future__ import annotations

import sys

from stateweaver.evidence.cli import main

if __name__ == "__main__":
    raise SystemExit(main(["collect", *sys.argv[1:]]))
