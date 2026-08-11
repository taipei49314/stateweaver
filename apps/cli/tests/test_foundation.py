from __future__ import annotations

import json
import socket
from pathlib import Path, PurePosixPath
from typing import Any, cast

import pytest
from stateweaver.evidence import RuntimeObservationQualificationReceipt
from stateweaver.evidence.collector import _JUNIT_REQUIRED_IDENTITIES
from stateweaver.replay import ReplayPlan, ReplayRunResult, RootSeed, canonical_sha256

from stateweaver.cli import evidence as cli_evidence
from stateweaver.cli.__main__ import main
from stateweaver.cli.foundation import verify_foundation
from stateweaver.cli.network_guard import (
    NETWORK_GUARD_VERSION,
    NetworkEgressDenied,
    deny_network_egress,
)
from stateweaver.cli.runtime_qualification import qualify_runtime_observation


def test_foundation_verification_meets_all_acceptance_conditions() -> None:
    report = verify_foundation()

    assert report.accepted is True
    assert report.vulnerable_deterministic is True
    assert report.vulnerable_all_runs_succeeded is True
    assert report.patched_uses_identical_plan is True
    assert len(report.vulnerable) == 5
    assert {item.oracle_outcome for item in report.vulnerable} == {"VIOLATED"}
    assert report.patched.oracle_outcome == "SATISFIED"
    assert report.patched.final_response_status == 403
    assert report.patched.status == "failed"
    assert report.patched.failed_step_id == "step.07"
    assert report.patched.failure_code == "ORACLE_EXPECTATION_MISMATCH"
    assert report.patched.evidence_count == 1
    assert len(report.patched.action_log) == 8
    assert len(report.negative_controls) == 10
    expected_controls = {
        **{f"missing_prerequisite_{index}": ("SATISFIED", 403) for index in (0, 1, 3, 5, 6)},
        "expired_replay_window": ("SATISFIED", 403),
        "masked_response": ("SATISFIED", 200),
        "mock_only_response": ("INCONCLUSIVE", 200),
        "fresh_session": ("SATISFIED", 403),
        "same_tenant_document": ("SATISFIED", 200),
    }
    assert {
        item.name: (item.oracle_outcome, item.final_response_status)
        for item in report.negative_controls
    } == expected_controls


def test_console_command_prints_compact_machine_readable_json(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["foundation", "verify"]) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert payload["accepted"] is True
    assert payload["network_guard"] == NETWORK_GUARD_VERSION
    assert payload["vulnerable"]["deterministic"] is True
    assert payload["vulnerable"]["all_runs_succeeded"] is True
    assert payload["vulnerable"]["action_log_count"] == 8
    assert len(payload["vulnerable"]["attempts"]) == 5
    assert len({item["signature"] for item in payload["vulnerable"]["attempts"]}) == 1
    assert len(payload["canonical_action_log"]) == 8
    assert payload["canonical_action_log"][-1]["evidence_ids"]
    assert len(payload["canonical_action_log"][-1]["trace_id"]) == 32
    assert payload["patched_uses_identical_plan"] is True
    plan = ReplayPlan.model_validate_json(json.dumps(payload["canonical_plan"]))
    root = RootSeed.model_validate_json(json.dumps(payload["root_state"]))
    first_run = ReplayRunResult.model_validate_json(
        json.dumps(payload["vulnerable"]["attempts"][0]["replay_result"])
    )
    assert canonical_sha256(plan) == payload["plan_hash"]
    assert plan.root_seed_id == root.root_seed_id
    assert first_run.root_fingerprint == root.capture.fingerprint
    assert payload["vulnerable"]["attempts"][0]["oracle_results"][0]["observed"]
    assert payload["vulnerable"]["attempts"][0]["evidence_records"]
    assert set(payload["policy_decisions"]) == {
        entry["policy_decision_ref"] for entry in payload["canonical_action_log"]
    } | {
        decision_ref
        for control in payload["negative_controls"]
        for decision_ref in (
            step["action"]["policy_decision_ref"] for step in control["plan"]["steps"]
        )
    }


def test_doctor_reports_offline_component_availability(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--json", "doctor"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["version"] == "0.1.0"
    assert payload["mode"] == "offline-in-process"
    assert payload["auth_required"] is False
    assert all(component["available"] for component in payload["components"].values())


def test_runtime_fingerprint_ignores_uv_cache_but_binds_package_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    metadata_path = tmp_path / "demo-1.0.dist-info" / "METADATA"
    uv_cache_path = metadata_path.parent / "uv_cache.json"
    runtime_path = tmp_path / "demo_runtime" / "__init__.py"
    metadata_path.parent.mkdir(parents=True)
    runtime_path.parent.mkdir(parents=True)
    metadata_path.write_text("Metadata-Version: 2.4\nName: demo\nVersion: 1.0\n", encoding="utf-8")
    uv_cache_path.write_text('{"timestamp":1}\n', encoding="utf-8")
    runtime_path.write_text('VALUE = "bound"\n', encoding="utf-8")

    class FakeDistribution:
        version = "1.0"
        files = (
            PurePosixPath("demo-1.0.dist-info/METADATA"),
            PurePosixPath("demo-1.0.dist-info/uv_cache.json"),
            PurePosixPath("demo_runtime/__init__.py"),
        )

        @staticmethod
        def read_text(filename: str) -> str | None:
            return metadata_path.read_text(encoding="utf-8") if filename == "METADATA" else None

        @staticmethod
        def locate_file(path: PurePosixPath) -> Path:
            return tmp_path / path.as_posix()

    monkeypatch.setattr(cli_evidence, "_RUNTIME_DISTRIBUTIONS", ("demo",))
    monkeypatch.setattr(cli_evidence, "distribution", lambda _name: FakeDistribution())

    baseline = cli_evidence._runtime_dependency_fingerprint()
    uv_cache_path.write_text('{"timestamp":2}\n', encoding="utf-8")
    assert cli_evidence._runtime_dependency_fingerprint() == baseline

    runtime_path.write_text('VALUE = "changed"\n', encoding="utf-8")
    assert cli_evidence._runtime_dependency_fingerprint() != baseline


def test_help_lists_doctor_and_foundation_verify(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_result:
        main(["--help"])

    assert exit_result.value.code == 0
    help_text = capsys.readouterr().out
    assert "doctor" in help_text
    assert "foundation" in help_text


def test_package_install_qualification_rejects_workspace_source_environment(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "package-install.json"
    source_root = Path(__file__).resolve().parents[3]

    assert (
        main(
            [
                "foundation",
                "qualify-package-install",
                "--output",
                str(output),
                "--repository-marker",
                "synthetic-test-tree",
                "--source-root",
                str(source_root),
            ]
        )
        == 1
    )
    result = json.loads(capsys.readouterr().out)
    assert result == {
        "error": {"code": "package_install_not_qualified"},
        "qualified": False,
    }
    assert not output.exists()


def _required_junit_paths(tmp_path: Path) -> dict[str, Path]:
    required_identities = {
        name: tuple(sorted(identities)) for name, identities in _JUNIT_REQUIRED_IDENTITIES.items()
    }
    junit_paths: dict[str, Path] = {}
    for name in ("contracts", "policy", "lab", "replay"):
        path = tmp_path / f"{name}.xml"
        testcases = "".join(
            f'<testcase classname="{identity.split("::", 1)[0]}" '
            f'name="{identity.split("::", 1)[1]}" />'
            for identity in required_identities[name]
        )
        path.write_text(
            f'<testsuite name="{name}" tests="{len(required_identities[name])}" '
            f'failures="0" errors="0" skipped="0">{testcases}</testsuite>',
            encoding="utf-8",
        )
        junit_paths[name] = path
    return junit_paths


def test_console_collects_and_rechecks_causally_bound_evidence(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    junit_paths = _required_junit_paths(tmp_path)

    run_id = "cli-proof.1"
    output_root = tmp_path / "evidence"
    assert (
        main(
            [
                "foundation",
                "collect-evidence",
                "--output-root",
                str(output_root),
                "--run-id",
                run_id,
                "--repository-marker",
                "synthetic-test-tree",
                "--started-at",
                "2026-01-01T00:00:00Z",
                "--junit-contracts",
                str(junit_paths["contracts"]),
                "--junit-policy",
                str(junit_paths["policy"]),
                "--junit-lab",
                str(junit_paths["lab"]),
                "--junit-replay",
                str(junit_paths["replay"]),
            ]
        )
        == 0
    )
    collection = json.loads(capsys.readouterr().out)
    assert collection["collected"] is True
    assert collection["verified"] is True

    run_directory = output_root / run_id
    assert main(["foundation", "verify-evidence", str(run_directory)]) == 0
    verification = json.loads(capsys.readouterr().out)
    assert verification["errors"] == []
    assert verification["valid"] is True
    assert verification["snapshot_sha256"].startswith("sha256:")


def test_console_collects_and_independently_reexecutes_runtime_observation(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "d" * 40
    runtime_receipt = tmp_path / "runtime-observation.json"
    assert (
        main(
            [
                "foundation",
                "qualify-runtime-observation",
                "--repository-marker",
                marker,
                "--output",
                str(runtime_receipt),
            ]
        )
        == 0
    )
    capsys.readouterr()
    junit_paths = _required_junit_paths(tmp_path)
    run_id = "cli-runtime-proof.1"
    output_root = tmp_path / "evidence"

    assert (
        main(
            [
                "foundation",
                "collect-evidence",
                "--output-root",
                str(output_root),
                "--run-id",
                run_id,
                "--repository-marker",
                marker,
                "--started-at",
                "2026-01-01T00:00:00Z",
                "--junit-contracts",
                str(junit_paths["contracts"]),
                "--junit-policy",
                str(junit_paths["policy"]),
                "--junit-lab",
                str(junit_paths["lab"]),
                "--junit-replay",
                str(junit_paths["replay"]),
                "--runtime-observation-receipt",
                str(runtime_receipt),
            ]
        )
        == 0
    )
    collection = json.loads(capsys.readouterr().out)
    assert collection["collected"] is True

    run_directory = output_root / run_id
    assert (
        main(
            [
                "foundation",
                "verify-evidence",
                str(run_directory),
                "--repository-marker",
                marker,
            ]
        )
        == 0
    )
    verification = json.loads(capsys.readouterr().out)
    results = json.loads(
        (run_directory / "qualification" / "registry" / "results.json").read_text(encoding="utf-8")
    )

    assert verification["valid"] is True
    assert results["summary"] == {
        "blocked": 34,
        "failed": 0,
        "not_run": 15,
        "passed": 43,
        "required": 92,
    }

    original_qualifier = qualify_runtime_observation

    def mutate_during_reexecution(
        repository_marker: str,
    ) -> RuntimeObservationQualificationReceipt:
        reproduced = original_qualifier(repository_marker)
        replay_junit = run_directory / "junit" / "replay.xml"
        replay_junit.write_bytes(replay_junit.read_bytes() + b" ")
        return reproduced

    monkeypatch.setattr(
        cli_evidence,
        "qualify_runtime_observation",
        mutate_during_reexecution,
    )
    assert (
        main(
            [
                "foundation",
                "verify-evidence",
                str(run_directory),
                "--repository-marker",
                marker,
            ]
        )
        == 1
    )
    raced = json.loads(capsys.readouterr().out)
    assert raced == {
        "errors": ["evidence bundle changed during independent runtime verification"],
        "snapshot_sha256": None,
        "valid": False,
    }


def test_network_guard_denies_connect_bind_and_restores_socket_class() -> None:
    original_socket = socket.socket
    with deny_network_egress() as guard:
        with pytest.raises(NetworkEgressDenied):
            socket.create_connection(("127.0.0.1", 9))
        guarded_socket = socket.socket()
        try:
            with pytest.raises(NetworkEgressDenied):
                guarded_socket.bind(("0.0.0.0", 0))
        finally:
            guarded_socket.close()
    assert guard.denied_attempts == 2
    assert socket.socket is original_socket


def test_network_guard_restores_after_an_unrelated_exception() -> None:
    original_socket = socket.socket
    with pytest.raises(RuntimeError, match="synthetic failure"), deny_network_egress():
        raise RuntimeError("synthetic failure")
    assert socket.socket is original_socket


@pytest.mark.parametrize(
    "operation",
    (
        "getaddrinfo",
        "gethostbyname",
        "gethostbyname_ex",
        "gethostbyaddr",
        "getnameinfo",
        "getfqdn",
        "create_server",
        "connect_ex",
        "listen",
        "sendto",
        "sendmsg",
    ),
)
def test_network_guard_denies_each_supported_socket_surface(operation: str) -> None:
    with deny_network_egress() as guard:
        guarded_socket = socket.socket()
        try:
            with pytest.raises(NetworkEgressDenied):
                if operation == "getaddrinfo":
                    socket.getaddrinfo("localhost", 80)
                elif operation == "gethostbyname":
                    socket.gethostbyname("localhost")
                elif operation == "gethostbyname_ex":
                    socket.gethostbyname_ex("localhost")
                elif operation == "gethostbyaddr":
                    socket.gethostbyaddr("127.0.0.1")
                elif operation == "getnameinfo":
                    socket.getnameinfo(("127.0.0.1", 80), 0)
                elif operation == "getfqdn":
                    socket.getfqdn("localhost")
                elif operation == "create_server":
                    socket.create_server(("127.0.0.1", 0))
                elif operation == "connect_ex":
                    guarded_socket.connect_ex(("127.0.0.1", 9))
                elif operation == "listen":
                    guarded_socket.listen()
                elif operation == "sendto":
                    guarded_socket.sendto(b"synthetic", ("127.0.0.1", 9))
                else:
                    cast(Any, guarded_socket).sendmsg([b"synthetic"])
        finally:
            guarded_socket.close()
    assert guard.denied_attempts == 1
