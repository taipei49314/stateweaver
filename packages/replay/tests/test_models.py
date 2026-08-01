from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import pytest
from pydantic import JsonValue, ValidationError
from stateweaver.replay import (
    CaptureLayer,
    DeterminismClassification,
    DeterminismReport,
    ReplayObservation,
    ReplayRunResult,
    ReplayRunStatus,
    RootSeed,
    StateArtifact,
    StateCapture,
    canonical_sha256,
)


def test_state_artifact_rejects_tampered_content_hash() -> None:
    with pytest.raises(ValidationError, match="content_hash does not match"):
        StateArtifact(
            layer=CaptureLayer.CACHE,
            payload={"generation": 7},
            content_hash=f"sha256:{'0' * 64}",
        )


def test_capture_rejects_duplicate_state_layers() -> None:
    artifact = StateArtifact.from_payload(
        layer=CaptureLayer.DATABASE,
        payload={"role": "viewer"},
    )
    with pytest.raises(ValidationError, match="duplicate layers"):
        StateCapture.from_artifacts(
            capture_id="capture.001",
            controlled_at=datetime(2026, 7, 29, tzinfo=UTC),
            artifacts=(artifact, artifact),
        )


def test_capture_requires_absolute_controlled_time() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        StateCapture.from_artifacts(
            capture_id="capture.001",
            controlled_at=datetime(2026, 7, 29),  # noqa: DTZ001 - deliberately invalid input
            artifacts=(),
        )


def test_artifact_observation_and_adapter_versions_are_deeply_immutable() -> None:
    source: dict[str, JsonValue] = {"tick": 1, "nested": {"values": [1, 2]}}
    artifact = StateArtifact.from_payload(layer=CaptureLayer.APPLICATION, payload=source)
    observation = ReplayObservation(
        observation_id="observation.001",
        kind="synthetic",
        payload=source,
    )
    capture = StateCapture.from_artifacts(
        capture_id="capture.immutable",
        controlled_at=datetime(2026, 7, 29, tzinfo=UTC),
        artifacts=(artifact,),
    )
    root = RootSeed(
        root_seed_id="root.immutable",
        target_version="lab-vulnerable",
        random_seed=1,
        clock_epoch=capture.controlled_at,
        capture=capture,
        adapter_versions={"lab": "0.1.0"},
    )
    original_hash = artifact.content_hash
    source["tick"] = 2

    assert artifact.payload["tick"] == 1
    assert observation.payload["tick"] == 1
    assert artifact.content_hash == original_hash
    with pytest.raises(TypeError):
        cast(Any, artifact.payload)["tick"] = 3
    with pytest.raises(TypeError):
        cast(Any, artifact.payload["nested"])["values"] = ()
    with pytest.raises(TypeError):
        cast(Any, observation.payload)["tick"] = 3
    with pytest.raises(TypeError):
        cast(Any, root.adapter_versions)["lab"] = "9.9.9"


@pytest.mark.parametrize(
    "value, message",
    [
        ({1: "ambiguous", "1": "visible"}, "string keys"),
        (datetime(2026, 7, 29), "timezone-aware"),  # noqa: DTZ001 - invalid fixture
        ({"measurement": float("nan")}, "Out of range float values"),
    ],
)
def test_public_canonical_hash_rejects_ambiguous_json(value: object, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        canonical_sha256(value)


def test_success_result_cannot_omit_steps_or_fingerprints() -> None:
    with pytest.raises(ValidationError, match="successful replay"):
        ReplayRunResult(
            run_id="run.invalid",
            plan_id="plan.invalid",
            status=ReplayRunStatus.SUCCEEDED,
            steps=(),
            action_log=(),
            trace_hash=f"sha256:{'0' * 64}",
        )


def test_determinism_report_cannot_make_a_vacuous_claim() -> None:
    with pytest.raises(ValidationError, match="at least 2 items"):
        DeterminismReport(
            plan_id="plan.invalid",
            run_ids=(),
            run_statuses=(),
            signatures=(),
            deterministic=True,
            all_runs_succeeded=True,
            classification=DeterminismClassification.DETERMINISTIC,
        )
