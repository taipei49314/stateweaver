"""Console entry point for StateWeaver's deterministic foundation verification."""

from __future__ import annotations

import argparse
import importlib.util
import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from stateweaver.evidence import AcceptanceEvidenceError

from .evidence import collect_foundation_evidence, verify_foundation_evidence
from .foundation import verify_foundation

_VERSION: Final = "0.1.0"
_COMPONENTS: Final = (
    ("contracts", "stateweaver.contracts"),
    ("evidence", "stateweaver.evidence"),
    ("policy", "stateweaver.policy"),
    ("replay", "stateweaver.replay"),
    ("in_process_lab", "stateweaver.adapters.in_process_lab"),
    ("synthetic_lab", "stateweaver_lab"),
)


def _absolute_datetime(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected an ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise argparse.ArgumentTypeError("timestamp must include a UTC offset")
    return parsed.astimezone(UTC)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stateweaver",
        description="Offline, in-process verification for the StateWeaver synthetic foundation.",
    )
    parser.add_argument("--json", action="store_true", help="write a machine-readable JSON result")
    foundation = parser.add_subparsers(dest="command", required=True)
    foundation_parser = foundation.add_parser("foundation", help="verify the replay differential")
    foundation_commands = foundation_parser.add_subparsers(dest="foundation_command", required=True)
    foundation_commands.add_parser(
        "verify", help="run five vulnerable replays, patched replay, and controls"
    )
    collect = foundation_commands.add_parser(
        "collect-evidence", help="collect and self-verify one immutable foundation proof"
    )
    collect.add_argument("--output-root", type=Path, required=True)
    collect.add_argument("--run-id", required=True)
    collect.add_argument("--repository-marker", default="local-working-tree")
    collect.add_argument(
        "--started-at",
        type=_absolute_datetime,
        required=True,
        help="UTC timestamp captured immediately before the normative JUnit commands",
    )
    collect.add_argument("--junit-contracts", type=Path, required=True)
    collect.add_argument("--junit-policy", type=Path, required=True)
    collect.add_argument("--junit-lab", type=Path, required=True)
    collect.add_argument("--junit-replay", type=Path, required=True)
    check = foundation_commands.add_parser(
        "verify-evidence", help="verify hashes and causal bindings in a proof bundle"
    )
    check.add_argument("run_directory", type=Path)
    check.add_argument("--repository-marker")
    foundation.add_parser("doctor", help="report offline component availability")
    return parser


def _doctor_result() -> dict[str, object]:
    return {
        "auth_required": False,
        "components": {
            name: {"available": importlib.util.find_spec(module) is not None}
            for name, module in _COMPONENTS
        },
        "mode": "offline-in-process",
        "version": _VERSION,
    }


def main(argv: Sequence[str] | None = None) -> int:
    """Run a selected safe, local verification command and return its exit status."""

    arguments = _parser().parse_args(argv)
    if arguments.command == "doctor":
        print(json.dumps(_doctor_result(), sort_keys=True, separators=(",", ":")))
        return 0
    if arguments.command != "foundation":
        return 2

    if arguments.foundation_command == "verify-evidence":
        verification = verify_foundation_evidence(
            arguments.run_directory, repository_marker=arguments.repository_marker
        )
        print(
            json.dumps(
                {"errors": list(verification.errors), "valid": verification.valid},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0 if verification.valid else 1

    if arguments.foundation_command == "collect-evidence":
        try:
            result = collect_foundation_evidence(
                output_root=arguments.output_root,
                run_id=arguments.run_id,
                repository_marker=arguments.repository_marker,
                junit_contracts=arguments.junit_contracts,
                junit_policy=arguments.junit_policy,
                junit_lab=arguments.junit_lab,
                junit_replay=arguments.junit_replay,
                started_at=arguments.started_at,
            )
        except (AcceptanceEvidenceError, OSError):
            result = {"collected": False, "error": {"code": "evidence_collection_error"}}
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            return 1
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0

    if arguments.foundation_command != "verify":
        return 2

    try:
        report = verify_foundation()
    except Exception:
        print(
            json.dumps(
                {"accepted": False, "error": {"code": "verification_error"}},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1
    print(json.dumps(report.to_json(), sort_keys=True, separators=(",", ":")))
    return 0 if report.accepted else 1


if __name__ == "__main__":  # pragma: no cover - exercised through the script entry point
    raise SystemExit(main())
