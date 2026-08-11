"""Runtime-observation qualification and clean-wheel CLI regressions."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from stateweaver.contracts import sha256_digest
from stateweaver.evidence import (
    RuntimeObservationQualificationError,
    build_runtime_observation_qualification,
    load_runtime_observation_qualification,
)

from stateweaver.cli.__main__ import main
from stateweaver.cli.runtime_qualification import (
    qualify_runtime_observation,
    validate_runtime_qualification_against_adapter,
)

MARKER = "d" * 40


def test_runtime_qualification_reexecutes_with_stable_semantics() -> None:
    first = qualify_runtime_observation(MARKER)
    second = qualify_runtime_observation(MARKER)

    assert first.semantic_digest == second.semantic_digest
    assert first.receipt_digest != second.receipt_digest
    assert first.projection.source_digest == second.projection.source_digest
    assert first.projection.before_capture.payload_digest == (
        second.projection.before_capture.payload_digest
    )
    assert first.projection.after_capture.payload_digest == (
        second.projection.after_capture.payload_digest
    )
    assert first.projection.state_changes[0].precondition.value == 0
    assert first.projection.state_changes[0].effect.value == 1
    assert first.projection.transition_fragment.source == "observed"
    assert first.projection.trace.route == "/v1/lab/session/retain"
    assert first.exit_criterion_satisfied is True
    assert first.release_eligible is False


def test_adapter_receipt_substitution_fails_closed() -> None:
    qualified = qualify_runtime_observation(MARKER)
    substituted = json.loads(qualified.adapter_receipt_json)
    substituted["name"] = "substituted but internally rehashed"
    substituted["receipt_digest"] = sha256_digest(
        {key: value for key, value in substituted.items() if key != "receipt_digest"}
    )
    with pytest.raises(
        RuntimeObservationQualificationError,
        match="receipt is invalid",
    ):
        build_runtime_observation_qualification(
            adapter_receipt=substituted,
            projection=qualified.projection,
        )


def test_cli_writes_canonical_runtime_qualification_bound_to_marker(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "runtime-observation.json"

    assert (
        main(
            [
                "foundation",
                "qualify-runtime-observation",
                "--repository-marker",
                MARKER,
                "--output",
                str(output),
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    retained = load_runtime_observation_qualification(
        output,
        expected_repository_marker=MARKER,
    )

    assert result == {
        "qualified": True,
        "semantic_digest": retained.semantic_digest,
    }
    assert validate_runtime_qualification_against_adapter(retained) == retained
    with pytest.raises(RuntimeObservationQualificationError, match="does not match"):
        load_runtime_observation_qualification(
            output,
            expected_repository_marker="e" * 40,
        )
