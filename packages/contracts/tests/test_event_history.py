from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import JsonValue, ValidationError
from stateweaver.contracts import (
    EventEnvelope,
    EventHistory,
    EventType,
    RequestedBy,
    RequesterType,
    sha256_digest,
)

NOW = datetime(2026, 8, 1, 8, 0, tzinfo=UTC)
OTHER_DIGEST = "sha256:" + "f" * 64
ACTOR = RequestedBy(type=RequesterType.WORKFLOW, role="experiment_orchestrator")


def _event(
    *,
    event_type: EventType = EventType.ACTION_AUTHORIZED,
    experiment_id: str = "exp_01",
    run_id: str = "run_01",
    world_id: str | None = "world_23",
    actor: RequestedBy = ACTOR,
    trace_id: str = "a" * 32,
    timestamp: datetime = NOW,
    sequence: int = 1,
    prev_event_hash: str | None = None,
    payload: dict[str, JsonValue] | None = None,
) -> EventEnvelope:
    return EventEnvelope.create(
        event_type=event_type,
        experiment_id=experiment_id,
        run_id=run_id,
        world_id=world_id,
        actor=actor,
        trace_id=trace_id,
        timestamp=timestamp,
        sequence=sequence,
        prev_event_hash=prev_event_hash,
        payload=payload or {"action_id": "act_091", "authorized": True},
    )


def _events() -> tuple[EventEnvelope, ...]:
    first = _event(event_type=EventType.REPLAY_STARTED, payload={"plan_id": "plan_01"})
    second = _event(
        event_type=EventType.ACTION_EXECUTED,
        trace_id="b" * 32,
        timestamp=NOW + timedelta(seconds=1),
        sequence=2,
        prev_event_hash=first.semantic_hash,
        payload={"action_id": "act_091", "status": "succeeded"},
    )
    third = _event(
        event_type=EventType.REPLAY_COMPLETED,
        trace_id="c" * 32,
        timestamp=NOW + timedelta(seconds=2),
        sequence=3,
        prev_event_hash=second.semantic_hash,
        payload={"status": "succeeded"},
    )
    return first, second, third


def _history() -> EventHistory:
    return EventHistory.create(experiment_id="exp_01", run_id="run_01", events=_events())


def test_event_v2_round_trip_separates_payload_and_semantic_integrity() -> None:
    payload: dict[str, JsonValue] = {"action_id": "act_091", "authorized": True}
    authorized = _event(event_type=EventType.ACTION_AUTHORIZED, payload=payload)
    completed = _event(event_type=EventType.REPLAY_COMPLETED, payload=payload)

    assert authorized.schema_version == "2.0"
    assert authorized.payload_hash == sha256_digest(payload)
    assert authorized.payload_hash == completed.payload_hash
    assert authorized.semantic_hash != completed.semantic_hash
    assert authorized.event_id != completed.event_id
    assert EventEnvelope.model_validate_json(authorized.model_dump_json()) == authorized


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("event_type", EventType.REPLAY_COMPLETED),
        ("experiment_id", "exp_other"),
        ("run_id", "run_other"),
        ("world_id", "world_other"),
        (
            "actor",
            RequestedBy(type=RequesterType.ADAPTER, role="synthetic_adapter"),
        ),
        ("trace_id", "b" * 32),
        ("timestamp", NOW + timedelta(seconds=1)),
        ("sequence", 2),
        ("prev_event_hash", OTHER_DIGEST),
    ],
)
def test_event_metadata_substitution_rejects_stale_semantic_hash(
    field: str, replacement: object
) -> None:
    payload = _event().model_dump(mode="python")
    payload[field] = replacement

    with pytest.raises(ValidationError, match="semantic_hash"):
        EventEnvelope.model_validate(payload)


def test_event_payload_event_id_and_version_confusion_fail_closed() -> None:
    event = _event()

    changed_payload = event.model_dump(mode="python")
    changed_payload["payload"] = {"action_id": "act_091", "authorized": False}
    with pytest.raises(ValidationError, match="payload_hash"):
        EventEnvelope.model_validate(changed_payload)

    changed_event_id = event.model_dump(mode="python")
    changed_event_id["event_id"] = OTHER_DIGEST
    with pytest.raises(ValidationError, match="event_id"):
        EventEnvelope.model_validate(changed_event_id)

    legacy_version = event.model_dump(mode="python")
    legacy_version["schema_version"] = "1.0"
    with pytest.raises(ValidationError, match="literal_error"):
        EventEnvelope.model_validate(legacy_version)

    legacy_shape = event.model_dump(mode="python")
    legacy_shape["schema_version"] = "1.0"
    for field in ("event_id", "semantic_hash", "sequence", "prev_event_hash"):
        del legacy_shape[field]
    with pytest.raises(ValidationError):
        EventEnvelope.model_validate(legacy_shape)


def test_model_construct_and_model_copy_cannot_cross_revalidation_boundary() -> None:
    event = _event()
    forged_values = {**event.__dict__, "run_id": "run_other"}
    constructed = EventEnvelope.model_construct(**forged_values)
    copied = event.model_copy(update={"world_id": "world_other"})

    with pytest.raises(ValidationError, match="semantic_hash"):
        EventEnvelope.model_validate(constructed)
    with pytest.raises(ValidationError, match="semantic_hash"):
        EventEnvelope.model_validate_json(constructed.model_dump_json())
    with pytest.raises(ValidationError, match="semantic_hash"):
        EventEnvelope.model_validate(copied)


def test_nested_constructed_actor_and_event_are_revalidated() -> None:
    forged_actor = RequestedBy.model_construct(type=RequesterType.WORKFLOW, role="")
    with pytest.raises(ValidationError):
        _event(actor=forged_actor)

    history = _history()
    forged_event = EventEnvelope.model_construct(
        **{
            **history.events[1].model_dump(mode="python"),
            "event_type": EventType.FINDING_VERIFIED,
        }
    )
    forged_history = EventHistory.model_construct(
        **{
            **history.model_dump(mode="python", exclude={"events"}),
            "events": (history.events[0], forged_event, history.events[2]),
        }
    )
    with pytest.raises(ValidationError, match="semantic_hash"):
        EventHistory.model_validate(forged_history)


def test_event_history_round_trip_binds_exact_chain_and_head() -> None:
    history = _history()

    assert history.schema_version == "2.0"
    assert history.event_count == 3
    assert history.head_hash == history.events[-1].semantic_hash
    assert EventHistory.model_validate_json(history.model_dump_json()) == history


def test_event_history_rejects_reorder_and_resequence() -> None:
    history = _history()
    payload = history.model_dump(mode="python")
    serialized_events = tuple(payload["events"])
    payload["events"] = (serialized_events[1], serialized_events[0], serialized_events[2])
    with pytest.raises(ValidationError, match="sequence"):
        EventHistory.model_validate(payload)

    first = history.events[1].model_copy(update={"sequence": 1, "prev_event_hash": None})
    second = history.events[0].model_copy(
        update={"sequence": 2, "prev_event_hash": first.semantic_hash}
    )
    third = history.events[2].model_copy(
        update={"sequence": 3, "prev_event_hash": second.semantic_hash}
    )
    resequenced = history.model_copy(update={"events": (first, second, third)})
    with pytest.raises(ValidationError, match="semantic_hash"):
        EventHistory.model_validate(resequenced)


def test_event_history_rejects_drop_duplicate_and_cross_context_splice() -> None:
    history = _history()
    dropped = history.model_dump(mode="python")
    dropped["events"] = tuple(dropped["events"][:-1])
    with pytest.raises(ValidationError, match="event_count"):
        EventHistory.model_validate(dropped)

    with pytest.raises(ValidationError, match="event_id values must be unique"):
        EventHistory.create(
            experiment_id="exp_01",
            run_id="run_01",
            events=(history.events[0], history.events[0]),
        )

    foreign_run = _event(
        event_type=EventType.ACTION_EXECUTED,
        run_id="run_other",
        trace_id="b" * 32,
        timestamp=NOW + timedelta(seconds=1),
        sequence=2,
        prev_event_hash=history.events[0].semantic_hash,
        payload={"action_id": "act_091", "status": "succeeded"},
    )
    spliced = history.model_dump(mode="python")
    spliced_events = tuple(spliced["events"])
    spliced["events"] = (spliced_events[0], foreign_run, spliced_events[2])
    with pytest.raises(ValidationError, match="experiment_id and run_id"):
        EventHistory.model_validate(spliced)

    foreign_experiment = _event(
        event_type=EventType.ACTION_EXECUTED,
        experiment_id="exp_other",
        trace_id="b" * 32,
        timestamp=NOW + timedelta(seconds=1),
        sequence=2,
        prev_event_hash=history.events[0].semantic_hash,
        payload={"action_id": "act_091", "status": "succeeded"},
    )
    spliced["events"] = (spliced_events[0], foreign_experiment, spliced_events[2])
    with pytest.raises(ValidationError, match="experiment_id and run_id"):
        EventHistory.model_validate(spliced)


def test_event_history_rejects_broken_chain_and_nonmonotonic_timestamp() -> None:
    first = _events()[0]
    broken_link = _event(
        event_type=EventType.ACTION_EXECUTED,
        trace_id="b" * 32,
        timestamp=NOW + timedelta(seconds=1),
        sequence=2,
        prev_event_hash=OTHER_DIGEST,
        payload={"action_id": "act_091", "status": "succeeded"},
    )
    with pytest.raises(ValidationError, match="preceding event"):
        EventHistory.create(experiment_id="exp_01", run_id="run_01", events=(first, broken_link))

    backwards = _event(
        event_type=EventType.ACTION_EXECUTED,
        trace_id="b" * 32,
        timestamp=NOW - timedelta(seconds=1),
        sequence=2,
        prev_event_hash=first.semantic_hash,
        payload={"action_id": "act_091", "status": "succeeded"},
    )
    with pytest.raises(ValidationError, match="nondecreasing"):
        EventHistory.create(experiment_id="exp_01", run_id="run_01", events=(first, backwards))


@pytest.mark.parametrize(
    ("field", "replacement", "error"),
    [
        ("event_count", 2, "event_count"),
        ("head_hash", OTHER_DIGEST, "head_hash"),
        ("history_hash", OTHER_DIGEST, "history_hash"),
        ("experiment_id", "exp_other", "experiment_id and run_id"),
        ("run_id", "run_other", "experiment_id and run_id"),
    ],
)
def test_event_history_projection_substitution_fails_closed(
    field: str, replacement: object, error: str
) -> None:
    payload = _history().model_dump(mode="python")
    payload[field] = replacement

    with pytest.raises(ValidationError, match=error):
        EventHistory.model_validate(payload)


def test_history_version_confusion_and_constructed_stale_prefix_fail_closed() -> None:
    history = _history()
    legacy = history.model_dump(mode="python")
    legacy["schema_version"] = "1.0"
    with pytest.raises(ValidationError, match="literal_error"):
        EventHistory.model_validate(legacy)

    stale_prefix = EventHistory.model_construct(
        **{**history.__dict__, "events": history.events[:-1]}
    )
    with pytest.raises(ValidationError, match="event_count"):
        EventHistory.model_validate(stale_prefix)
    with pytest.raises(ValidationError, match="event_count"):
        EventHistory.model_validate_json(stale_prefix.model_dump_json())


def test_event_history_requires_at_least_one_event() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        EventHistory.create(experiment_id="exp_01", run_id="run_01", events=())
