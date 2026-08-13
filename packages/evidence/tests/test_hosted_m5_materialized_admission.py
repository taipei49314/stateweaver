"""M5 hosted admission rejects a Docker runner without retained provider execution."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
import stateweaver.evidence.hosted_qualification as hosted_qualification
from stateweaver.contracts import sha256_digest
from stateweaver.evidence.hosted_qualification import (
    M5_MATERIALIZED_PROVIDER_QUALIFICATION_PATH,
    M5_OBSERVED_CHAIN_QUALIFICATION_PATH,
    _validate_materialized_m5_run,
    hosted_qualification_admissions,
)


def _plan() -> dict[str, Any]:
    action = {"action_id": "action:00000000000000000000000000000001"}
    return {
        "plan_id": "plan.m5.materialized",
        "steps": [{"step_id": "step.01", "action": action}],
    }


def test_m5_process_and_materialized_paths_remain_distinct() -> None:
    assert M5_OBSERVED_CHAIN_QUALIFICATION_PATH == "qualification/m5/observed-chain-receipt.json"
    assert (
        M5_MATERIALIZED_PROVIDER_QUALIFICATION_PATH
        == "qualification/m5/materialized-provider-receipt.json"
    )


def test_materialized_m5_run_rejects_missing_six_provider_captures() -> None:
    plan = _plan()
    action_log = [{"step_id": "step.01", "action": plan["steps"][0]["action"]}]
    result = {"status": "succeeded"}
    root = {"root_seed_id": "root.m5"}
    run = {
        "run_id": "run.m5.clean-root-01",
        "root": root,
        "root_digest": sha256_digest(root),
        "result": result,
        "result_digest": sha256_digest(result),
        "action_log": action_log,
        "action_log_digest": sha256_digest(action_log),
        "steps": [
            {
                "step_id": "step.01",
                "action": plan["steps"][0]["action"],
                "action_digest": sha256_digest(plan["steps"][0]["action"]),
                "response_status": 200,
                "oracle_outcome": "VIOLATED",
                "provider_captures": {},
            }
        ],
    }

    with pytest.raises(ValueError, match="provider capture"):
        _validate_materialized_m5_run(
            run,
            expected_plan=plan,
            expected_root=root,
            expected_run_id="run.m5.clean-root-01",
            expected_status="succeeded",
            expected_outcome="VIOLATED",
            expected_response_status=200,
        )


def test_retained_materialized_provider_witness_does_not_admit_sw_m5(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(hosted_qualification, "runtime_observation_admissions", lambda _: {})
    admission = SimpleNamespace(
        admission_digest="sha256:" + "a" * 64,
        qualification=SimpleNamespace(m4=SimpleNamespace(m3_qualification=object())),
    )

    assert "SW-M5-CHAIN" not in hosted_qualification_admissions(admission)  # type: ignore[arg-type]
