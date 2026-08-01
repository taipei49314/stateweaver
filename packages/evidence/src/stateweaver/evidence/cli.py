"""Offline CLI for collecting and checking acceptance evidence."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

from ._io import EvidenceInputError, json_mapping
from .collector import collect_from_json_file
from .verify import verify_acceptance_evidence


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="stateweaver-acceptance-evidence")
    commands = parser.add_subparsers(dest="command", required=True)
    collect = commands.add_parser("collect")
    collect.add_argument("--foundation-json", type=Path, required=True)
    collect.add_argument("--inputs-json", type=Path, required=True)
    collect.add_argument("--output-root", type=Path, required=True)
    collect.add_argument("--run-id", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("run_directory", type=Path)
    arguments = parser.parse_args(argv)
    if arguments.command == "verify":
        verification = verify_acceptance_evidence(arguments.run_directory)
        response = {"valid": verification.valid, "errors": list(verification.errors)}
        print(json.dumps(response, sort_keys=True))
        return 0 if verification.valid else 1
    try:
        support = json_mapping(arguments.inputs_json)
        junit = support.get("junit_sources")
        metadata = support.get("run_metadata")
        if not isinstance(junit, dict) or not isinstance(metadata, dict):
            raise EvidenceInputError("supporting evidence inputs are incomplete")
        if not all(isinstance(value, str) for value in junit.values()):
            raise EvidenceInputError("supporting evidence inputs are incomplete")
        junit_paths = cast(dict[str, str], junit)
        metadata_evidence = cast(dict[str, Any], metadata)
        collection = collect_from_json_file(
            foundation_json=arguments.foundation_json,
            output_root=arguments.output_root,
            run_id=arguments.run_id,
            junit_sources={name: Path(value) for name, value in junit_paths.items()},
            run_metadata=metadata_evidence,
        )
    except EvidenceInputError as error:
        print(json.dumps({"collected": False, "error": str(error)}, sort_keys=True))
        return 1
    response = {"collected": True, "run_directory": str(collection.run_directory)}
    print(json.dumps(response, sort_keys=True))
    return 0
