"""Deterministic and adversarial tests for V2 replay event semantics."""

from __future__ import annotations

from typing import cast

import pytest
from evidence_test_fixtures import plan as fixture_plan
from evidence_test_fixtures import root as fixture_root
from evidence_test_fixtures import scenario
from pydantic import ValidationError
from stateweaver.contracts import ActionEnvelope, OracleOutcome, canonical_json_bytes
from stateweaver.evidence.semantic_trace import (
    RealityTraceArtifactV2,
    RealityTraceEventKind,
    RealityTraceEventType,
    RealityTraceEventV2,
    RealityTraceFact,
    RealityTraceFactValue,
    RealityTraceLane,
    derive_reality_trace_v2,
)
from stateweaver.replay import (
    ReplayActionLogEntry,
    ReplayRunResult,
    ReplayRunStatus,
    ReplayStepResult,
    ReplayStepStatus,
    canonical_sha256,
)


def _scenario_result(*, run_id: str = "run.semantic.001", failed: bool = False) -> ReplayRunResult:
    replay_plan = fixture_plan()
    value = scenario(
        name="semantic_trace",
        run_id=run_id,
        replay_plan=replay_plan,
        root_seed=fixture_root(),
        oracle_outcome=OracleOutcome.VIOLATED,
        response_status=200,
        failed=failed,
    )["replay_result"]
    return ReplayRunResult.model_validate_json(canonical_json_bytes(value))


def _result_with_trace_hash(payload: dict[str, object]) -> ReplayRunResult:
    projection = {
        key: payload[key]
        for key in (
            "plan_id",
            "status",
            "root_fingerprint",
            "final_fingerprint",
            "steps",
            "action_log",
            "failed_step_id",
        )
    }
    return ReplayRunResult.model_validate({**payload, "trace_hash": canonical_sha256(projection)})


def _boundary_result(
    step_id: str, *, status: ReplayRunStatus, failure_code: str
) -> ReplayRunResult:
    baseline = _scenario_result()
    return _result_with_trace_hash(
        {
            "run_id": f"run.semantic.{step_id}",
            "plan_id": baseline.plan_id,
            "status": status,
            "root_fingerprint": baseline.root_fingerprint,
            "final_fingerprint": (
                baseline.final_fingerprint if status is ReplayRunStatus.CLEANUP_FAILED else None
            ),
            "steps": (
                ReplayStepResult(
                    step_id=step_id,
                    status=ReplayStepStatus.FAILED,
                    failure_code=failure_code,
                    failure_message=f"synthetic {step_id} failure detail",
                ),
            ),
            "action_log": (),
            "failed_step_id": step_id,
        }
    )


def _skipped_result() -> ReplayRunResult:
    failed = _scenario_result(run_id="run.semantic.skipped", failed=True)
    first_log = failed.action_log[0]
    action_payload = first_log.action.model_dump(mode="python")
    action = ActionEnvelope.model_validate(
        {
            **action_payload,
            "action_id": "action.semantic.skipped",
            "idempotency_key": canonical_sha256({"action": "semantic.skipped"}),
            "policy_decision_ref": "policy.semantic.skipped",
            "sequence": first_log.sequence + 1,
        }
    )
    skipped_step = ReplayStepResult(step_id="step.01", status=ReplayStepStatus.SKIPPED)
    envelope_hash = canonical_sha256(action)
    skipped_log = ReplayActionLogEntry(
        step_id=skipped_step.step_id,
        action=action,
        action_id=action.action_id,
        action_type=action.action_type,
        sequence=action.sequence,
        status=skipped_step.status,
        idempotency_key=action.idempotency_key,
        policy_decision_ref=action.policy_decision_ref,
        trace_id=canonical_sha256(
            {
                "plan_id": failed.plan_id,
                "step_id": skipped_step.step_id,
                "envelope_hash": envelope_hash,
            }
        ).removeprefix("sha256:")[:32],
        envelope_hash=envelope_hash,
        request_template_hash=canonical_sha256(action.action),
        observation_hash=canonical_sha256(()),
        oracle_results_hash=canonical_sha256(()),
    )
    return _result_with_trace_hash(
        {
            **failed.model_dump(mode="python", exclude={"trace_hash"}),
            "steps": (*failed.steps, skipped_step),
            "action_log": (*failed.action_log, skipped_log),
        }
    )


def _facts(event: RealityTraceEventV2) -> dict[str, RealityTraceFactValue]:
    return {fact.name: fact.value for fact in event.payload}


def _remint_event(event: RealityTraceEventV2, *, sequence: int) -> RealityTraceEventV2:
    return RealityTraceEventV2.create(
        event_type=event.event_type,
        run_id=event.run_id,
        plan_id=event.plan_id,
        sequence=sequence,
        trace_id=event.trace_id,
        step_id=event.step_id,
        payload=event.payload,
    )


def _remint_trace(
    original: RealityTraceArtifactV2, events: tuple[RealityTraceEventV2, ...]
) -> RealityTraceArtifactV2:
    return RealityTraceArtifactV2.create(
        lane=original.lane,
        run_id=original.run_id,
        plan_id=original.plan_id,
        replay_trace_hash=original.replay_trace_hash,
        events=events,
    )


def test_success_trace_projects_exact_action_semantics() -> None:
    result = _scenario_result()

    trace = derive_reality_trace_v2(result, lane=RealityTraceLane.PRIMARY)

    assert trace.schema_version == "2.0"
    assert trace.algorithm == "stateweaver.replay-step-events.v1"
    assert trace.run_id == result.run_id
    assert trace.plan_id == result.plan_id
    assert trace.replay_trace_hash == result.trace_hash
    assert len(trace.events) == len(result.steps) + 2
    assert trace.events[0].event_type is RealityTraceEventType.REPLAY_STARTED
    assert trace.events[-1].event_type is RealityTraceEventType.REPLAY_COMPLETED
    event = trace.events[1]
    log = result.action_log[0]
    facts = _facts(event)
    assert event.kind is RealityTraceEventKind.ACTION
    assert event.step_id == result.steps[0].step_id
    assert event.trace_id == log.trace_id
    assert facts["action_id"] == log.action_id
    assert facts["action_sequence"] == log.sequence
    assert facts["action_type"] == log.action_type
    assert facts["envelope_hash"] == log.envelope_hash
    assert facts["policy_decision_ref"] == log.policy_decision_ref
    assert facts["observation_hash"] == log.observation_hash
    assert facts["oracle_results_hash"] == log.oracle_results_hash
    assert facts["evidence_ids"] == log.evidence_ids
    trace.require_replay_result(result)


@pytest.mark.parametrize(
    ("result", "expected_code"),
    (
        (
            _boundary_result(
                "root",
                status=ReplayRunStatus.ROOT_DIVERGED,
                failure_code="ROOT_FINGERPRINT_MISMATCH",
            ),
            "ROOT_FINGERPRINT_MISMATCH",
        ),
        (
            _boundary_result(
                "preflight", status=ReplayRunStatus.FAILED, failure_code="PREFLIGHT_FAILURE"
            ),
            "PREFLIGHT_FAILURE",
        ),
        (
            _boundary_result(
                "cleanup",
                status=ReplayRunStatus.CLEANUP_FAILED,
                failure_code="CLEANUP_FAILURE",
            ),
            "CLEANUP_FAILURE",
        ),
    ),
)
def test_boundary_failures_are_hashed_without_leaking_messages(
    result: ReplayRunResult, expected_code: str
) -> None:
    trace = derive_reality_trace_v2(result, lane=RealityTraceLane.PRIMARY)

    event = trace.events[1]
    facts = _facts(event)
    assert event.kind is RealityTraceEventKind.BOUNDARY
    assert facts["failure_code"] == expected_code
    assert cast(str, facts["failure_message_sha256"]).startswith("sha256:")
    assert "synthetic" not in trace.model_dump_json()
    assert trace.matches_replay_result(result)


def test_failed_and_skipped_steps_each_have_one_exact_event() -> None:
    result = _skipped_result()

    trace = derive_reality_trace_v2(result, lane=RealityTraceLane.CONTROL)

    step_events = trace.events[1:-1]
    assert tuple(event.step_id for event in step_events) == tuple(
        step.step_id for step in result.steps
    )
    assert tuple(_facts(event)["status"] for event in step_events) == ("failed", "skipped")
    assert all(event.kind is RealityTraceEventKind.ACTION for event in step_events)


def test_event_payload_substitution_is_detected_after_full_remint() -> None:
    result = _scenario_result()
    trace = derive_reality_trace_v2(result, lane=RealityTraceLane.PRIMARY)
    started = trace.events[0]
    payload = tuple(
        RealityTraceFact(
            name=fact.name,
            value="sha256:" + "f" * 64 if fact.name == "root_fingerprint" else fact.value,
        )
        for fact in started.payload
    )
    forged_started = RealityTraceEventV2.create(
        event_type=started.event_type,
        run_id=started.run_id,
        plan_id=started.plan_id,
        sequence=started.sequence,
        trace_id=started.trace_id,
        step_id=started.step_id,
        payload=payload,
    )
    forged = _remint_trace(trace, (forged_started, *trace.events[1:]))

    assert forged.semantic_trace_hash != trace.semantic_trace_hash
    assert not forged.matches_replay_result(result)
    with pytest.raises(ValueError, match="semantics do not match"):
        forged.require_replay_result(result)


def test_event_omission_is_detected_after_sequences_and_hashes_are_reminted() -> None:
    result = _skipped_result()
    trace = derive_reality_trace_v2(result, lane=RealityTraceLane.PRIMARY)
    retained = (*trace.events[:2], *trace.events[3:])
    events = tuple(_remint_event(event, sequence=index) for index, event in enumerate(retained))
    forged = _remint_trace(trace, events)

    assert not forged.matches_replay_result(result)


def test_step_reordering_is_detected_after_sequences_and_hashes_are_reminted() -> None:
    result = _skipped_result()
    trace = derive_reality_trace_v2(result, lane=RealityTraceLane.PRIMARY)
    reordered = (trace.events[0], trace.events[2], trace.events[1], trace.events[-1])
    events = tuple(_remint_event(event, sequence=index) for index, event in enumerate(reordered))
    forged = _remint_trace(trace, events)

    assert not forged.matches_replay_result(result)


def test_semantic_hash_excludes_run_occurrence_but_artifact_binds_it() -> None:
    first = _scenario_result(run_id="run.semantic.001")
    second = ReplayRunResult.model_validate(
        {**first.model_dump(mode="python"), "run_id": "run.semantic.002"}
    )

    first_trace = derive_reality_trace_v2(first, lane=RealityTraceLane.PRIMARY)
    second_trace = derive_reality_trace_v2(second, lane=RealityTraceLane.PRIMARY)

    assert first_trace.semantic_trace_hash == second_trace.semantic_trace_hash
    assert first_trace.run_id != second_trace.run_id
    assert first_trace.events[0].event_id != second_trace.events[0].event_id
    assert first_trace.events[0].event_sha256 != second_trace.events[0].event_sha256
    assert all(event.run_id == first.run_id for event in first_trace.events)
    assert all(event.run_id == second.run_id for event in second_trace.events)


def test_patch_lane_has_distinct_semantics_and_completion_event() -> None:
    result = _scenario_result()
    primary = derive_reality_trace_v2(result, lane=RealityTraceLane.PRIMARY)
    patch = derive_reality_trace_v2(result, lane=RealityTraceLane.PATCH)

    assert patch.events[-1].event_type is RealityTraceEventType.PATCH_REPLAY_COMPLETED
    assert patch.semantic_trace_hash != primary.semantic_trace_hash


def test_declared_hash_schema_and_extra_fields_fail_closed() -> None:
    trace = derive_reality_trace_v2(_scenario_result(), lane=RealityTraceLane.PRIMARY)
    event_payload = trace.events[0].model_dump(mode="python")
    with pytest.raises(ValidationError, match="event hash"):
        RealityTraceEventV2.model_validate({**event_payload, "event_sha256": "sha256:" + "0" * 64})

    artifact_payload = trace.model_dump(mode="python")
    with pytest.raises(ValidationError):
        RealityTraceArtifactV2.model_validate({**artifact_payload, "algorithm": "unknown"})
    with pytest.raises(ValidationError, match="Extra inputs"):
        RealityTraceArtifactV2.model_validate({**artifact_payload, "verified": True})


def test_nested_constructed_event_is_revalidated() -> None:
    trace = derive_reality_trace_v2(_scenario_result(), lane=RealityTraceLane.PRIMARY)
    forged = RealityTraceEventV2.model_construct(
        **{**trace.events[0].model_dump(mode="python"), "event_sha256": "sha256:" + "0" * 64}
    )

    with pytest.raises(ValidationError, match="event hash"):
        RealityTraceArtifactV2.model_validate(
            {**trace.model_dump(mode="python"), "events": (forged, *trace.events[1:])}
        )
