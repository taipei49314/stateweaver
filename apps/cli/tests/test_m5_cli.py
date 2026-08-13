from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from pydantic import BaseModel
from stateweaver.evidence.hosted_qualification import HostedQualificationError

from stateweaver.cli import __main__ as cli_main
from stateweaver.cli import hosted_qualification as hosted


def _payload(capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(capsys.readouterr().out))


class _CanonicalFixture(BaseModel):
    alpha: int
    beta: int


def test_hosted_reader_rejects_non_regular_empty_and_changed_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(HostedQualificationError, match="not a regular file"):
        hosted._read_regular(tmp_path / "missing.json")

    empty = tmp_path / "empty.json"
    empty.write_bytes(b"")
    with pytest.raises(HostedQualificationError, match="size is invalid"):
        hosted._read_regular(empty)

    changed = tmp_path / "changed.json"
    changed.write_bytes(b"x")
    original_read_bytes = Path.read_bytes

    def changed_read(path: Path) -> bytes:
        return b"xx" if path == changed else original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", changed_read)
    with pytest.raises(HostedQualificationError, match="changed while reading"):
        hosted._read_regular(changed)


def test_hosted_reader_translates_filesystem_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = tmp_path / "artifact.json"
    artifact.write_bytes(b"{}\n")

    def unreadable(_path: Path) -> bool:
        raise OSError("synthetic stat race")

    monkeypatch.setattr(Path, "is_symlink", unreadable)
    with pytest.raises(HostedQualificationError, match="artifact is unreadable"):
        hosted._read_regular(artifact)


def test_hosted_exact_tree_rejects_invalid_and_unreadable_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(HostedQualificationError, match="root is invalid"):
        hosted._require_exact_tree(tmp_path / "missing", ("receipt.json",))

    (tmp_path / "unexpected.json").write_bytes(b"{}\n")
    with pytest.raises(HostedQualificationError, match="artifact set is not exact"):
        hosted._require_exact_tree(tmp_path, ("receipt.json",))

    def unreadable(_path: Path) -> Any:
        raise OSError("synthetic directory race")

    monkeypatch.setattr(Path, "iterdir", unreadable)
    with pytest.raises(HostedQualificationError, match="root is unreadable"):
        hosted._require_exact_tree(tmp_path, ("receipt.json",))


def test_hosted_json_loader_rejects_noncanonical_bytes() -> None:
    with pytest.raises(HostedQualificationError, match="JSON is invalid"):
        hosted._json_model(b'{"beta":2, "alpha":1}\n', _CanonicalFixture)


@pytest.mark.parametrize(
    ("content", "error"),
    (
        (b"<", "JUnit is invalid"),
        (b"<root />", "JUnit is invalid"),
        (
            b'<testsuite tests="1" failures="0" errors="0" skipped="0">'
            b'<testcase name="case" /></testsuite>',
            "identity is invalid",
        ),
        (
            b'<testsuite tests="not-an-int" failures="0" errors="0" skipped="0">'
            b'<testcase classname="suite" name="case" /></testsuite>',
            "counters are invalid",
        ),
        (
            b'<testsuite tests="2" failures="0" errors="0" skipped="0">'
            b'<testcase classname="suite" name="case" /></testsuite>',
            "counters are inconsistent",
        ),
        (
            b'<testsuite tests="1" failures="1" errors="0" skipped="0">'
            b'<testcase classname="suite" name="case"><failure /></testcase></testsuite>',
            "JUnit did not pass",
        ),
    ),
)
def test_hosted_junit_parser_fails_closed(content: bytes, error: str) -> None:
    with pytest.raises(HostedQualificationError, match=error):
        hosted._junit(content, artifact_path="qualification/m5/junit.xml")


@pytest.mark.parametrize("content", (b"\xff\n", b"wrong\n"))
def test_hosted_sha_text_requires_exact_ascii_wire_bytes(content: bytes) -> None:
    with pytest.raises(HostedQualificationError, match="Git identity"):
        hosted._exact_sha_text(content, "a" * 40)


def test_hosted_admission_rejects_receipt_changed_after_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        hosted,
        "load_hosted_docker_qualification",
        lambda *_args, **_kwargs: _CanonicalFixture(alpha=1, beta=2),
    )
    monkeypatch.setattr(hosted, "_read_regular", lambda *_args, **_kwargs: b"changed\n")

    with pytest.raises(HostedQualificationError, match="receipt changed"):
        hosted.admit_hosted_qualification(
            qualification_receipt_path=tmp_path / "qualification.json",
            attestation_bundle_path=tmp_path / "attestation.json",
            expected_repository_marker="a" * 40,
        )


def test_qualify_hosted_docker_wires_typed_arguments_and_writes_receipt(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = SimpleNamespace(receipt_digest="sha256:hosted", workflow_run_id=42)
    build_calls: list[dict[str, object]] = []
    write_calls: list[tuple[Path, object]] = []

    def build(**kwargs: object) -> object:
        build_calls.append(kwargs)
        return receipt

    monkeypatch.setattr(cli_main, "build_hosted_docker_qualification", build)
    monkeypatch.setattr(
        cli_main,
        "write_hosted_receipt",
        lambda output, value: write_calls.append((output, value)),
    )
    output = tmp_path / "hosted.json"

    status = cli_main.main(
        [
            "foundation",
            "qualify-hosted-docker",
            "--m2-root",
            str(tmp_path / "m2"),
            "--m4-root",
            str(tmp_path / "m4"),
            "--m5-root",
            str(tmp_path / "m5"),
            "--repository-marker",
            "a" * 40,
            "--tree-sha",
            "b" * 40,
            "--workflow-run-id",
            "42",
            "--workflow-run-attempt",
            "3",
            "--workflow-run-url",
            "https://github.example/actions/runs/42",
            "--runner-os",
            "Linux",
            "--runner-arch",
            "X64",
            "--output",
            str(output),
        ]
    )

    assert status == 0
    assert build_calls == [
        {
            "m2_root": tmp_path / "m2",
            "m4_root": tmp_path / "m4",
            "m5_root": tmp_path / "m5",
            "repository_marker": "a" * 40,
            "tree_sha": "b" * 40,
            "workflow_run_id": 42,
            "workflow_run_attempt": 3,
            "workflow_run_url": "https://github.example/actions/runs/42",
            "runner_os": "Linux",
            "runner_arch": "X64",
        }
    ]
    assert write_calls == [(output, receipt)]
    assert _payload(capsys) == {
        "qualified": True,
        "receipt_digest": "sha256:hosted",
        "workflow_run_id": 42,
    }


@pytest.mark.parametrize("failure", (OSError("disk"), ValueError("invalid")))
def test_qualify_hosted_docker_fails_closed_without_writing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
) -> None:
    writes: list[object] = []

    def fail(**_kwargs: object) -> object:
        raise failure

    monkeypatch.setattr(cli_main, "build_hosted_docker_qualification", fail)
    monkeypatch.setattr(cli_main, "write_hosted_receipt", lambda *_args: writes.append(_args))

    status = cli_main.main(
        [
            "foundation",
            "qualify-hosted-docker",
            "--m2-root",
            str(tmp_path / "m2"),
            "--m4-root",
            str(tmp_path / "m4"),
            "--m5-root",
            str(tmp_path / "m5"),
            "--repository-marker",
            "marker",
            "--tree-sha",
            "tree",
            "--workflow-run-id",
            "1",
            "--workflow-run-attempt",
            "1",
            "--workflow-run-url",
            "https://github.example/actions/runs/1",
            "--runner-os",
            "Linux",
            "--runner-arch",
            "X64",
            "--output",
            str(tmp_path / "hosted.json"),
        ]
    )

    assert status == 1
    assert writes == []
    assert _payload(capsys) == {
        "error": {"code": "hosted_docker_not_qualified"},
        "qualified": False,
    }


def test_hosted_parser_rejects_unapproved_runner_before_qualification(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[object] = []
    monkeypatch.setattr(
        cli_main,
        "build_hosted_docker_qualification",
        lambda **kwargs: calls.append(kwargs),
    )

    with pytest.raises(SystemExit) as raised:
        cli_main.main(
            [
                "foundation",
                "qualify-hosted-docker",
                "--m2-root",
                str(tmp_path / "m2"),
                "--m4-root",
                str(tmp_path / "m4"),
                "--m5-root",
                str(tmp_path / "m5"),
                "--repository-marker",
                "marker",
                "--tree-sha",
                "tree",
                "--workflow-run-id",
                "1",
                "--workflow-run-attempt",
                "1",
                "--workflow-run-url",
                "https://github.example/actions/runs/1",
                "--runner-os",
                "Windows",
                "--runner-arch",
                "X64",
                "--output",
                str(tmp_path / "hosted.json"),
            ]
        )

    assert raised.value.code == 2
    assert calls == []
    assert "invalid choice" in capsys.readouterr().err


def test_admit_hosted_docker_wires_paths_and_writes_admission(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admission = SimpleNamespace(admission_digest="sha256:admission")
    admit_calls: list[dict[str, object]] = []
    write_calls: list[tuple[Path, object]] = []

    def admit(**kwargs: object) -> object:
        admit_calls.append(kwargs)
        return admission

    monkeypatch.setattr(cli_main, "admit_hosted_qualification", admit)
    monkeypatch.setattr(
        cli_main,
        "write_hosted_receipt",
        lambda output, value: write_calls.append((output, value)),
    )
    qualification = tmp_path / "qualification.json"
    attestation = tmp_path / "attestation.json"
    output = tmp_path / "admission.json"

    status = cli_main.main(
        [
            "foundation",
            "admit-hosted-docker",
            "--qualification-receipt",
            str(qualification),
            "--attestation-bundle",
            str(attestation),
            "--repository-marker",
            "c" * 40,
            "--output",
            str(output),
        ]
    )

    assert status == 0
    assert admit_calls == [
        {
            "qualification_receipt_path": qualification,
            "attestation_bundle_path": attestation,
            "expected_repository_marker": "c" * 40,
        }
    ]
    assert write_calls == [(output, admission)]
    assert _payload(capsys) == {
        "admission_digest": "sha256:admission",
        "admitted": True,
    }


def test_admit_hosted_docker_fails_closed_without_writing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writes: list[object] = []

    def fail(**_kwargs: object) -> object:
        raise ValueError("not admitted")

    monkeypatch.setattr(cli_main, "admit_hosted_qualification", fail)
    monkeypatch.setattr(cli_main, "write_hosted_receipt", lambda *_args: writes.append(_args))

    status = cli_main.main(
        [
            "foundation",
            "admit-hosted-docker",
            "--qualification-receipt",
            str(tmp_path / "qualification.json"),
            "--attestation-bundle",
            str(tmp_path / "attestation.json"),
            "--repository-marker",
            "marker",
            "--output",
            str(tmp_path / "admission.json"),
        ]
    )

    assert status == 1
    assert writes == []
    assert _payload(capsys) == {
        "admitted": False,
        "error": {"code": "hosted_docker_not_admitted"},
    }


def test_qualify_observed_chain_wires_input_and_writes_receipt(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = SimpleNamespace(runs=(object(),) * 5, receipt_digest="sha256:observed")
    qualify_calls: list[dict[str, object]] = []
    write_calls: list[tuple[Path, object]] = []

    def qualify(**kwargs: object) -> object:
        qualify_calls.append(kwargs)
        return receipt

    monkeypatch.setattr(cli_main, "qualify_observed_chain", qualify)
    monkeypatch.setattr(
        cli_main,
        "write_observed_chain_qualification",
        lambda output, value: write_calls.append((output, value)),
    )
    m4_receipt = tmp_path / "m4.json"
    output = tmp_path / "observed.json"

    status = cli_main.main(
        [
            "foundation",
            "qualify-observed-chain",
            "--m4-receipt",
            str(m4_receipt),
            "--repository-marker",
            "d" * 40,
            "--output",
            str(output),
        ]
    )

    assert status == 0
    assert qualify_calls == [{"m4_receipt_path": m4_receipt, "repository_marker": "d" * 40}]
    assert write_calls == [(output, receipt)]
    assert _payload(capsys) == {
        "clean_root_replays": 5,
        "qualified": True,
        "receipt_digest": "sha256:observed",
    }


def test_qualify_observed_chain_fails_closed_without_writing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writes: list[object] = []

    def fail(**_kwargs: object) -> object:
        raise ValueError("invalid chain")

    monkeypatch.setattr(cli_main, "qualify_observed_chain", fail)
    monkeypatch.setattr(
        cli_main,
        "write_observed_chain_qualification",
        lambda *_args: writes.append(_args),
    )

    status = cli_main.main(
        [
            "foundation",
            "qualify-observed-chain",
            "--m4-receipt",
            str(tmp_path / "m4.json"),
            "--repository-marker",
            "marker",
            "--output",
            str(tmp_path / "observed.json"),
        ]
    )

    assert status == 1
    assert writes == []
    assert _payload(capsys) == {
        "error": {"code": "observed_chain_not_qualified"},
        "qualified": False,
    }


def test_qualify_materialized_chain_wires_both_receipts_and_writes_witness(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    witness = SimpleNamespace(receipt_digest="sha256:materialized")
    qualify_calls: list[dict[str, object]] = []
    write_calls: list[tuple[Path, object]] = []

    def qualify(**kwargs: object) -> object:
        qualify_calls.append(kwargs)
        return witness

    monkeypatch.setattr(cli_main, "qualify_actual_materialized_chain", qualify)
    monkeypatch.setattr(
        cli_main,
        "write_materialized_chain_qualification",
        lambda output, value: write_calls.append((output, value)),
    )
    m4_receipt = tmp_path / "m4.json"
    process_receipt = tmp_path / "process.json"
    output = tmp_path / "materialized.json"

    status = cli_main.main(
        [
            "foundation",
            "qualify-materialized-chain",
            "--m4-receipt",
            str(m4_receipt),
            "--process-receipt",
            str(process_receipt),
            "--repository-marker",
            "e" * 40,
            "--output",
            str(output),
        ]
    )

    assert status == 0
    assert qualify_calls == [
        {
            "m4_receipt_path": m4_receipt,
            "process_receipt_path": process_receipt,
            "repository_marker": "e" * 40,
        }
    ]
    assert write_calls == [(output, witness)]
    assert _payload(capsys) == {
        "actual_asgi_qualified": True,
        "receipt_digest": "sha256:materialized",
        "sw_m5_chain_admitted": True,
    }


@pytest.mark.parametrize("failure", (OSError("disk"), RuntimeError("runtime"), ValueError("bad")))
def test_qualify_materialized_chain_fails_closed_without_writing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
) -> None:
    writes: list[object] = []

    def fail(**_kwargs: object) -> object:
        raise failure

    monkeypatch.setattr(cli_main, "qualify_actual_materialized_chain", fail)
    monkeypatch.setattr(
        cli_main,
        "write_materialized_chain_qualification",
        lambda *_args: writes.append(_args),
    )

    status = cli_main.main(
        [
            "foundation",
            "qualify-materialized-chain",
            "--m4-receipt",
            str(tmp_path / "m4.json"),
            "--process-receipt",
            str(tmp_path / "process.json"),
            "--repository-marker",
            "marker",
            "--output",
            str(tmp_path / "materialized.json"),
        ]
    )

    assert status == 1
    assert writes == []
    assert _payload(capsys) == {
        "error": {"code": "materialized_chain_not_qualified"},
        "qualified": False,
    }
