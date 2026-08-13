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
from stateweaver.evidence.hosted_qualification import HostedQualificationError
from stateweaver.evidence.package_install import (
    PackageInstallQualificationError,
    write_package_install_receipt,
)
from stateweaver.evidence.runtime_observation import (
    RuntimeObservationQualificationError,
    write_runtime_observation_qualification,
)

from .evidence import collect_foundation_evidence, verify_foundation_evidence
from .foundation import verify_foundation
from .hosted_qualification import (
    admit_hosted_qualification,
    build_hosted_docker_qualification,
    write_hosted_receipt,
)
from .materialized_chain_qualification import (
    MaterializedChainQualificationError,
    qualify_actual_materialized_chain,
    write_materialized_chain_qualification,
)
from .materialized_search_qualification import (
    qualify_materialized_search,
    write_materialized_search_qualification,
)
from .observed_chain_qualification import (
    ObservedChainQualificationError,
    qualify_observed_chain,
    write_observed_chain_qualification,
)
from .runtime_qualification import qualify_runtime_observation

_VERSION: Final = "0.1.0"
_COMPONENTS: Final = (
    ("compiler", "stateweaver.compiler"),
    ("contracts", "stateweaver.contracts"),
    ("docker_compose", "stateweaver.adapters.docker_compose"),
    ("evidence", "stateweaver.evidence"),
    ("policy", "stateweaver.policy"),
    ("replay", "stateweaver.replay"),
    ("search", "stateweaver.search"),
    ("in_process_lab", "stateweaver.adapters.in_process_lab"),
    ("opentelemetry", "stateweaver.adapters.telemetry.opentelemetry"),
    ("synthetic_lab", "stateweaver_lab"),
    ("twin", "stateweaver.twin"),
    ("world_workflow", "stateweaver.workflows.world"),
    ("worlds", "stateweaver.worlds"),
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
    collect.add_argument("--package-install-receipt", type=Path)
    collect.add_argument("--runtime-observation-receipt", type=Path)
    collect.add_argument("--hosted-qualification-admission", type=Path)
    package_install = foundation_commands.add_parser(
        "qualify-package-install",
        help="retain a clean-wheel public-contract import receipt",
    )
    package_install.add_argument("--output", type=Path, required=True)
    package_install.add_argument("--repository-marker", required=True)
    package_install.add_argument("--source-root", type=Path, required=True)
    runtime_observation = foundation_commands.add_parser(
        "qualify-runtime-observation",
        help="execute and retain one application-emitted runtime observation",
    )
    runtime_observation.add_argument("--output", type=Path, required=True)
    runtime_observation.add_argument("--repository-marker", required=True)
    materialized_search = foundation_commands.add_parser(
        "qualify-materialized-search",
        help="execute and retain the M3-derived 24-to-4-to-2-to-1 real-world search",
    )
    materialized_search.add_argument("--output", type=Path, required=True)
    materialized_search.add_argument("--repository-marker", required=True)
    hosted_docker = foundation_commands.add_parser(
        "qualify-hosted-docker",
        help="validate and retain exact hosted M2-M5 Docker artifacts",
    )
    hosted_docker.add_argument("--m2-root", type=Path, required=True)
    hosted_docker.add_argument("--m4-root", type=Path, required=True)
    hosted_docker.add_argument("--m5-root", type=Path, required=True)
    hosted_docker.add_argument("--repository-marker", required=True)
    hosted_docker.add_argument("--tree-sha", required=True)
    hosted_docker.add_argument("--workflow-run-id", type=int, required=True)
    hosted_docker.add_argument("--workflow-run-attempt", type=int, required=True)
    hosted_docker.add_argument("--workflow-run-url", required=True)
    hosted_docker.add_argument("--runner-os", choices=("Linux",), required=True)
    hosted_docker.add_argument("--runner-arch", choices=("X64",), required=True)
    hosted_docker.add_argument("--output", type=Path, required=True)
    hosted_admission = foundation_commands.add_parser(
        "admit-hosted-docker",
        help="verify hosted receipt attestation and retain its acceptance admission",
    )
    hosted_admission.add_argument("--qualification-receipt", type=Path, required=True)
    hosted_admission.add_argument("--attestation-bundle", type=Path, required=True)
    hosted_admission.add_argument("--repository-marker", required=True)
    hosted_admission.add_argument("--output", type=Path, required=True)
    observed_chain = foundation_commands.add_parser(
        "qualify-observed-chain",
        help="compile exact retained M4 bytes and replay five clean roots",
    )
    observed_chain.add_argument("--m4-receipt", type=Path, required=True)
    observed_chain.add_argument("--repository-marker", required=True)
    observed_chain.add_argument("--output", type=Path, required=True)
    materialized_chain = foundation_commands.add_parser(
        "qualify-materialized-chain",
        help="qualify ten actual-ASGI Docker scenarios over retained provider state",
    )
    materialized_chain.add_argument("--m4-receipt", type=Path, required=True)
    materialized_chain.add_argument("--process-receipt", type=Path, required=True)
    materialized_chain.add_argument("--repository-marker", required=True)
    materialized_chain.add_argument("--output", type=Path, required=True)
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
                {
                    "errors": list(verification.errors),
                    "snapshot_sha256": verification.snapshot_sha256,
                    "valid": verification.valid,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0 if verification.valid else 1

    if arguments.foundation_command == "qualify-package-install":
        try:
            receipt = write_package_install_receipt(
                output=arguments.output,
                repository_marker=arguments.repository_marker,
                source_root=arguments.source_root,
            )
        except (OSError, PackageInstallQualificationError):
            print(
                json.dumps(
                    {"qualified": False, "error": {"code": "package_install_not_qualified"}},
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 1
        print(
            json.dumps(
                {
                    "qualified": True,
                    "requirement_id": receipt["requirement_id"],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0

    if arguments.foundation_command == "qualify-runtime-observation":
        try:
            runtime_receipt = qualify_runtime_observation(arguments.repository_marker)
            write_runtime_observation_qualification(arguments.output, runtime_receipt)
        except (OSError, RuntimeObservationQualificationError):
            print(
                json.dumps(
                    {
                        "qualified": False,
                        "error": {"code": "runtime_observation_not_qualified"},
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 1
        print(
            json.dumps(
                {
                    "qualified": True,
                    "semantic_digest": runtime_receipt.semantic_digest,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0

    if arguments.foundation_command == "qualify-materialized-search":
        try:
            materialized_receipt = qualify_materialized_search(arguments.repository_marker)
            write_materialized_search_qualification(arguments.output, materialized_receipt)
        except (OSError, RuntimeError, ValueError):
            print(
                json.dumps(
                    {
                        "qualified": False,
                        "error": {"code": "materialized_search_not_qualified"},
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 1
        print(
            json.dumps(
                {
                    "qualified": True,
                    "receipt_digest": materialized_receipt.receipt_digest,
                    "winner": materialized_receipt.winner.candidate_id,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0

    if arguments.foundation_command == "qualify-hosted-docker":
        try:
            hosted_receipt = build_hosted_docker_qualification(
                m2_root=arguments.m2_root,
                m4_root=arguments.m4_root,
                m5_root=arguments.m5_root,
                repository_marker=arguments.repository_marker,
                tree_sha=arguments.tree_sha,
                workflow_run_id=arguments.workflow_run_id,
                workflow_run_attempt=arguments.workflow_run_attempt,
                workflow_run_url=arguments.workflow_run_url,
                runner_os=arguments.runner_os,
                runner_arch=arguments.runner_arch,
            )
            write_hosted_receipt(arguments.output, hosted_receipt)
        except (OSError, HostedQualificationError, ValueError):
            print(
                json.dumps(
                    {"qualified": False, "error": {"code": "hosted_docker_not_qualified"}},
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 1
        print(
            json.dumps(
                {
                    "qualified": True,
                    "receipt_digest": hosted_receipt.receipt_digest,
                    "workflow_run_id": hosted_receipt.workflow_run_id,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0

    if arguments.foundation_command == "admit-hosted-docker":
        try:
            admission = admit_hosted_qualification(
                qualification_receipt_path=arguments.qualification_receipt,
                attestation_bundle_path=arguments.attestation_bundle,
                expected_repository_marker=arguments.repository_marker,
            )
            write_hosted_receipt(arguments.output, admission)
        except (OSError, HostedQualificationError, ValueError):
            print(
                json.dumps(
                    {"admitted": False, "error": {"code": "hosted_docker_not_admitted"}},
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 1
        print(
            json.dumps(
                {"admission_digest": admission.admission_digest, "admitted": True},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0

    if arguments.foundation_command == "qualify-observed-chain":
        try:
            chain_receipt = qualify_observed_chain(
                m4_receipt_path=arguments.m4_receipt,
                repository_marker=arguments.repository_marker,
            )
            write_observed_chain_qualification(arguments.output, chain_receipt)
        except (OSError, ObservedChainQualificationError, ValueError):
            print(
                json.dumps(
                    {"qualified": False, "error": {"code": "observed_chain_not_qualified"}},
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 1
        print(
            json.dumps(
                {
                    "clean_root_replays": len(chain_receipt.runs),
                    "qualified": True,
                    "receipt_digest": chain_receipt.receipt_digest,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0

    if arguments.foundation_command == "qualify-materialized-chain":
        try:
            witness = qualify_actual_materialized_chain(
                m4_receipt_path=arguments.m4_receipt,
                process_receipt_path=arguments.process_receipt,
                repository_marker=arguments.repository_marker,
            )
            write_materialized_chain_qualification(arguments.output, witness)
        except (OSError, MaterializedChainQualificationError, RuntimeError, ValueError):
            print(
                json.dumps(
                    {
                        "qualified": False,
                        "error": {"code": "materialized_chain_not_qualified"},
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 1
        print(
            json.dumps(
                {
                    "actual_asgi_qualified": True,
                    "receipt_digest": witness.receipt_digest,
                    "sw_m5_chain_admitted": True,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0

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
                package_install_receipt=arguments.package_install_receipt,
                runtime_observation_receipt=arguments.runtime_observation_receipt,
                hosted_qualification_admission=arguments.hosted_qualification_admission,
            )
        except (
            AcceptanceEvidenceError,
            OSError,
            PackageInstallQualificationError,
            RuntimeObservationQualificationError,
            HostedQualificationError,
        ):
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
