"""Focused hosted ingestion checks for the Phase-D actual-ASGI composite."""

from __future__ import annotations

import importlib
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest
from stateweaver.contracts import canonical_json_bytes
from stateweaver.evidence.hosted_qualification import HostedQualificationError

import stateweaver.cli.hosted_qualification as hosted_qualification
from stateweaver.cli.hosted_qualification import (
    _LEGACY_M5_FILES,
    _M5_FILES,
    _MAX_FILE_BYTES,
    _MAX_PRODUCER_BYTES,
    _actual_materialized_m5,
    _hosted_artifact_role,
    _require_exact_tree,
    build_hosted_docker_qualification,
)
from stateweaver.cli.materialized_chain_qualification import (
    ActualMaterializedChainQualificationReceipt,
    write_materialized_chain_qualification,
)
from stateweaver.cli.materialized_search_qualification import (
    MaterializedSearchQualificationReceipt,
)
from stateweaver.cli.observed_chain_qualification import ObservedChainQualificationReceipt

pytest_plugins = ("test_actual_materialized_chain_qualification",)

_DIGEST_A = "sha256:" + "a" * 64
_DIGEST_B = "sha256:" + "b" * 64
_MARKER = "4" * 40


def _stub_inputs() -> tuple[
    dict[str, bytes],
    bytes,
    ObservedChainQualificationReceipt,
    ActualMaterializedChainQualificationReceipt,
]:
    process = ObservedChainQualificationReceipt.model_construct(
        m4_receipt_digest=_DIGEST_A,
        receipt_digest=_DIGEST_B,
    )
    process_bytes = canonical_json_bytes(process) + b"\n"
    m4_bytes = b'{"receipt_digest":"' + _DIGEST_A.encode("ascii") + b'"}\n'
    actual = ActualMaterializedChainQualificationReceipt.model_construct(
        repository_marker=_MARKER,
        m4_receipt_json=m4_bytes.decode("utf-8"),
        m4_receipt_digest=_DIGEST_A,
        process_receipt_json=process_bytes.decode("utf-8"),
        process_receipt_digest=_DIGEST_B,
        cleanup_count=10,
        all_cleanups_passed=True,
        all_projects_destroyed=True,
    )
    return (
        {
            "materialized-chain-replay.json": b"{}\n",
            "observed-chain-receipt.json": process_bytes,
        },
        m4_bytes,
        process,
        actual,
    )


def test_actual_m5_hosted_parser_accepts_only_exact_cross_bound_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files, m4_bytes, process, actual = _stub_inputs()

    def parse(content: bytes, model: type[object]) -> object:
        assert content == b"{}\n"
        assert model is ActualMaterializedChainQualificationReceipt
        return actual

    monkeypatch.setattr(hosted_qualification, "_json_model", parse)

    parsed = _actual_materialized_m5(
        files,
        m4_bytes=m4_bytes,
        process_receipt=process,
        repository_marker=_MARKER,
    )

    assert parsed == actual
    assert _M5_FILES == (
        "materialized-chain-replay.json",
        "observed-chain-receipt.json",
    )
    assert _LEGACY_M5_FILES != _M5_FILES


def test_actual_m5_hosted_parser_rejects_path_and_cross_receipt_substitution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files, m4_bytes, process, actual = _stub_inputs()
    monkeypatch.setattr(hosted_qualification, "_json_model", lambda *_: actual)
    with pytest.raises(HostedQualificationError, match="artifact set"):
        _actual_materialized_m5(
            {**files, "materialized-provider-receipt.json": b"{}\n"},
            m4_bytes=m4_bytes,
            process_receipt=process,
            repository_marker=_MARKER,
        )
    with pytest.raises(HostedQualificationError, match="cross-bound"):
        _actual_materialized_m5(
            files,
            m4_bytes=m4_bytes + b" ",
            process_receipt=process,
            repository_marker=_MARKER,
        )
    with pytest.raises(HostedQualificationError, match="cross-bound"):
        _actual_materialized_m5(
            files,
            m4_bytes=m4_bytes,
            process_receipt=process,
            repository_marker="f" * 40,
        )


def test_actual_m5_exact_tree_caps_and_artifact_role(tmp_path: Path) -> None:
    root = tmp_path / "m5"
    root.mkdir()
    for name in _M5_FILES:
        (root / name).write_bytes(b"{}\n")
    assert tuple(sorted(_require_exact_tree(root, _M5_FILES))) == tuple(sorted(_M5_FILES))
    (root / "materialized-provider-receipt.json").write_bytes(b"{}\n")
    with pytest.raises(HostedQualificationError, match="artifact set"):
        _require_exact_tree(root, _M5_FILES)

    legacy = tmp_path / "legacy-m5"
    legacy.mkdir()
    (legacy / "materialized-provider-receipt.json").write_bytes(b"{}\n")
    (legacy / "observed-chain-receipt.json").write_bytes(b"{}\n")
    with pytest.raises(HostedQualificationError, match="artifact set"):
        _require_exact_tree(legacy, _M5_FILES)

    assert 4 * 1_048_576 < _MAX_FILE_BYTES <= 64 * 1_048_576
    assert _MAX_FILE_BYTES <= _MAX_PRODUCER_BYTES <= 64 * 1_048_576
    assert _hosted_artifact_role("materialized-chain-replay.json") == ("qualification-receipt")
    assert _hosted_artifact_role("observed-chain-receipt.json") == "qualification-receipt"


def test_full_hosted_builder_retains_process_and_actual_m5_bytes(
    actual_receipt: ActualMaterializedChainQualificationReceipt,
    tmp_path: Path,
) -> None:
    fixtures = importlib.import_module("test_materialized_search_qualification")
    roots = cast(
        Callable[..., tuple[Path, Path, Path]],
        fixtures._hosted_roots,
    )
    m4 = MaterializedSearchQualificationReceipt.model_validate_json(actual_receipt.m4_receipt_json)
    tree_sha = "a" * 40
    m2_root, m4_root, m5_root = roots(
        tmp_path,
        m4=m4,
        marker=actual_receipt.repository_marker,
        tree_sha=tree_sha,
    )
    (m5_root / "observed-chain-receipt.json").write_bytes(
        actual_receipt.process_receipt_json.encode("utf-8")
    )
    write_materialized_chain_qualification(
        m5_root / "materialized-chain-replay.json",
        actual_receipt,
    )

    producer = build_hosted_docker_qualification(
        m2_root=m2_root,
        m4_root=m4_root,
        m5_root=m5_root,
        repository_marker=actual_receipt.repository_marker,
        tree_sha=tree_sha,
        workflow_run_id=123456,
        workflow_run_attempt=1,
        workflow_run_url=("https://github.com/taipei49314/stateweaver/actions/runs/123456"),
        runner_os="Linux",
        runner_arch="X64",
    )

    assert producer.schema_version == "stateweaver-hosted-docker-qualification-v3"
    assert producer.status == "HOSTED_M2_M5_QUALIFIED"
    assert producer.m5_receipt_json == actual_receipt.process_receipt_json
    assert producer.m5_actual_receipt_json == (
        m5_root / "materialized-chain-replay.json"
    ).read_text(encoding="utf-8")
    assert producer.m5.actual_receipt_digest == actual_receipt.receipt_digest
