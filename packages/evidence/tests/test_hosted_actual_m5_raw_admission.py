"""Independent raw-JSON checks for the actual-ASGI hosted M5 boundary."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
from stateweaver.cli.materialized_chain_qualification import (
    ActualMaterializedChainQualificationReceipt,
)
from stateweaver.contracts import canonical_json_bytes
from stateweaver.evidence.hosted_qualification import (
    M5HostedProjection,
    _actual_signature,
    _raw_digest,
    _semantic_digest,
    _validate_actual_m5_composite,
)

sys.path.insert(0, str(Path(__file__).parents[3] / "apps" / "cli" / "tests"))
pytest_plugins = ("test_actual_materialized_chain_qualification",)


def _raw(actual_receipt: ActualMaterializedChainQualificationReceipt) -> dict[str, Any]:
    return actual_receipt.model_dump(mode="json")


def _process(actual: dict[str, Any]) -> dict[str, Any]:
    value = __import__("json").loads(actual["process_receipt_json"])
    assert isinstance(value, dict)
    return value


def _m4(actual: dict[str, Any]) -> dict[str, Any]:
    value = __import__("json").loads(actual["m4_receipt_json"])
    assert isinstance(value, dict)
    return value


def _projection(actual: dict[str, Any]) -> M5HostedProjection:
    runs = actual["clean_root_runs"]
    patched = actual["patched_run"]
    controls = actual["negative_controls"]
    return M5HostedProjection(
        m4_receipt_sha256=actual["m4_receipt_sha256"],
        m4_receipt_digest=actual["m4_receipt_digest"],
        process_receipt_sha256=actual["process_receipt_sha256"],
        process_receipt_digest=actual["process_receipt_digest"],
        actual_receipt_digest=actual["receipt_digest"],
        runtime=actual["runtime"],
        m4_winner_state_binding_digest=actual["m4_winner_state_binding_digest"],
        m4_source_snapshot_digest=actual["m4_source_snapshot_digest"],
        m4_after_archive_digest=actual["m4_after_archive_digest"],
        m4_provider_state_digest=actual["m4_provider_state_digest"],
        execution_plan_digest=actual["execution_plan_digest"],
        primary_plan_digest=actual["primary_plan_digest"],
        application_image_binding_digest=actual["application_image_binding"]["binding_digest"],
        clean_root_run_ids=tuple(item["run_id"] for item in runs),
        clean_root_materialized_receipt_digests=tuple(
            item["materialized_run_receipt_digest"] for item in runs
        ),
        vulnerable_deterministic_signatures=tuple(actual["vulnerable_deterministic_signatures"]),
        initial_checkpoint_bytes_digest=actual["initial_checkpoint_bytes_digest"],
        patched_run_id=patched["run_id"],
        patched_materialized_receipt_digest=patched["materialized_run_receipt_digest"],
        negative_control_names=tuple(item["name"] for item in controls),
        negative_control_materialized_receipt_digests=tuple(
            item["materialized_run_receipt_digest"] for item in controls
        ),
        cleanup_count=10,
        receipt_digest=actual["receipt_digest"],
    )


def _validate(actual: dict[str, Any]) -> None:
    _validate_actual_m5_composite(
        actual,
        raw_m4=_m4(actual),
        raw_process=_process(actual),
        m4_receipt_json=actual["m4_receipt_json"],
        process_receipt_json=actual["process_receipt_json"],
        projection=_projection(actual),
        repository_marker=actual["repository_marker"],
    )


def _rehash_receipt(receipt: dict[str, Any]) -> None:
    receipt["receipt_digest"] = _semantic_digest(receipt, "receipt_digest")


def _rehash_actual(actual: dict[str, Any]) -> None:
    actual["receipt_digest"] = _semantic_digest(actual, "receipt_digest")


def test_independent_raw_actual_m5_validation_accepts_all_ten_runs(
    actual_receipt: ActualMaterializedChainQualificationReceipt,
) -> None:
    actual = _raw(actual_receipt)

    _validate(actual)

    assert len(actual["clean_root_runs"]) == 5
    assert len(actual["negative_controls"]) == 4


@pytest.mark.parametrize(
    "mutation",
    ("provider", "checkpoint", "trace", "image", "cleanup", "container"),
)
def test_independent_raw_actual_m5_validation_rejects_rehashed_tampering(
    actual_receipt: ActualMaterializedChainQualificationReceipt,
    mutation: str,
) -> None:
    actual = _raw(actual_receipt)
    witness = actual["clean_root_runs"][0]
    receipt = witness["materialized_run_receipt"]
    if mutation == "provider":
        receipt["initial_checkpoint"]["observations"][0]["provider"] = "redis"
    elif mutation == "checkpoint":
        receipt["initial_checkpoint"]["checkpoint_bytes"] = "{}"
        receipt["initial_checkpoint"]["checkpoint_bytes_digest"] = _raw_digest("{}")
    elif mutation == "trace":
        trace = receipt["steps"][0]["trace"]
        trace["response_status"] = 599
        trace["observation_digest"] = _semantic_digest(trace, "observation_digest")
        receipt["steps"][0]["step_digest"] = _semantic_digest(receipt["steps"][0], "step_digest")
    elif mutation == "image":
        receipt["image_binding"]["application_source_revision"] = "f" * 40
        receipt["image_binding"]["binding_digest"] = _semantic_digest(
            receipt["image_binding"], "binding_digest"
        )
    elif mutation == "cleanup":
        receipt["cleanup_status"] = "FAIL"
    else:
        witness["materialized_run_receipt"]["image_binding"]["application_container_id"] = actual[
            "clean_root_runs"
        ][1]["materialized_run_receipt"]["image_binding"]["application_container_id"]
        receipt["image_binding"]["binding_digest"] = _semantic_digest(
            receipt["image_binding"], "binding_digest"
        )
    _rehash_receipt(receipt)
    witness["materialized_run_receipt_digest"] = receipt["receipt_digest"]
    actual["vulnerable_deterministic_signatures"] = [
        _actual_signature(item) for item in actual["clean_root_runs"]
    ]
    _rehash_actual(actual)

    with pytest.raises(ValueError):
        _validate(actual)


def test_exact_byte_digest_distinguishes_trailing_newline(
    actual_receipt: ActualMaterializedChainQualificationReceipt,
) -> None:
    actual = _raw(actual_receipt)
    retained = actual["process_receipt_json"]

    assert _raw_digest(retained) != _raw_digest(canonical_json_bytes(_process(actual))[:-1])
    assert _raw_digest(retained) == actual["process_receipt_sha256"]
