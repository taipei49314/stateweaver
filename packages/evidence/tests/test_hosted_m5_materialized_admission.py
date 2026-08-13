"""M5 admission requires the actual-ASGI ten-run qualification composite."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
import stateweaver.evidence.hosted_qualification as hosted_qualification
from pydantic import ValidationError
from stateweaver.evidence.hosted_qualification import (
    _MAX_HOSTED_ADMISSION_BYTES,
    _MAX_HOSTED_ARTIFACT_TOTAL_BYTES,
    _MAX_HOSTED_PRODUCER_BYTES,
    M5_MATERIALIZED_CHAIN_QUALIFICATION_PATH,
    M5_OBSERVED_CHAIN_QUALIFICATION_PATH,
    M5HostedProjection,
    hosted_qualification_admissions,
)

_DIGEST = "sha256:" + "a" * 64


def _projection() -> dict[str, object]:
    return {
        "m4_receipt_sha256": _DIGEST,
        "m4_receipt_digest": _DIGEST,
        "process_receipt_sha256": _DIGEST,
        "process_receipt_digest": _DIGEST,
        "actual_receipt_digest": _DIGEST,
        "runtime": "docker-compose-fastapi-asgi-six-provider@0.1.0",
        "m4_winner_state_binding_digest": _DIGEST,
        "m4_source_snapshot_digest": _DIGEST,
        "m4_after_archive_digest": _DIGEST,
        "m4_provider_state_digest": _DIGEST,
        "execution_plan_digest": _DIGEST,
        "primary_plan_digest": _DIGEST,
        "application_image_binding_digest": _DIGEST,
        "clean_root_run_ids": tuple(f"run.m5.clean-root-{index:02d}" for index in range(1, 6)),
        "clean_root_materialized_receipt_digests": (_DIGEST,) * 5,
        "vulnerable_deterministic_signatures": (_DIGEST,) * 5,
        "initial_checkpoint_bytes_digest": _DIGEST,
        "patched_run_id": "run.m5.patched-01",
        "patched_materialized_receipt_digest": _DIGEST,
        "negative_control_names": (
            "masked_response",
            "mock_only_response",
            "fresh_session",
            "same_tenant_document",
        ),
        "negative_control_materialized_receipt_digests": (_DIGEST,) * 4,
        "cleanup_count": 10,
        "receipt_digest": _DIGEST,
    }


def test_m5_process_and_actual_paths_remain_distinct() -> None:
    assert M5_OBSERVED_CHAIN_QUALIFICATION_PATH == ("qualification/m5/observed-chain-receipt.json")
    assert M5_MATERIALIZED_CHAIN_QUALIFICATION_PATH == (
        "qualification/m5/materialized-chain-replay.json"
    )


def test_actual_projection_rejects_incomplete_ten_run_boundary() -> None:
    values = _projection()
    values["clean_root_run_ids"] = ("run.m5.clean-root-01",)

    with pytest.raises(ValidationError, match="projection is incomplete"):
        M5HostedProjection.model_validate(values)


def test_actual_admission_is_the_only_boundary_that_admits_m5(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(hosted_qualification, "runtime_observation_admissions", lambda _: {})
    admission = SimpleNamespace(
        admission_digest=_DIGEST,
        qualification=SimpleNamespace(m4=SimpleNamespace(m3_qualification=object())),
    )

    admitted = hosted_qualification_admissions(admission)  # type: ignore[arg-type]

    assert admitted["M5-X01"] == _DIGEST
    assert admitted["SW-M5-CHAIN"] == _DIGEST


def test_hosted_size_caps_do_not_exceed_candidate_boundaries() -> None:
    assert _MAX_HOSTED_PRODUCER_BYTES <= 64 * 1_048_576
    assert _MAX_HOSTED_ADMISSION_BYTES <= 64 * 1_048_576
    assert _MAX_HOSTED_ARTIFACT_TOTAL_BYTES <= 256 * 1_048_576


def test_legacy_provider_projection_is_rejected() -> None:
    values = _projection()
    values["materialized_receipt_digest"] = values.pop("actual_receipt_digest")
    values["provider_runtime"] = "docker-compose-real-providers@0.1.0"

    with pytest.raises(ValidationError):
        M5HostedProjection.model_validate(values)
