from __future__ import annotations

import inspect

import pytest
from pydantic import ValidationError

from statechainbench import (
    BudgetEventKind,
    BudgetExceededError,
    BudgetLedger,
    BudgetLimits,
    CandidateSubmission,
    GeneratorConfig,
    HiddenOracle,
    LinearBaseline,
    OracleReason,
    StateWeaverTieredSystem,
    generate_dataset,
)


def test_hidden_oracle_surface_and_solver_boundary_do_not_expose_answers() -> None:
    dataset = generate_dataset(GeneratorConfig(seed=21, variants_per_family=1))
    public_names = {name for name in dir(dataset.oracle) if not name.startswith("_")}

    assert public_names == {"evaluate"}
    assert set(HiddenOracle.__dict__) >= {"evaluate"}
    assert "oracle" not in inspect.signature(LinearBaseline.solve).parameters
    assert "oracle" not in inspect.signature(StateWeaverTieredSystem.solve).parameters


def test_oracle_rejects_unknown_wrong_order_duplicate_and_modified_public_input() -> None:
    dataset = generate_dataset(GeneratorConfig(seed=31, variants_per_family=1))
    challenge = dataset.descriptors[0].public

    unknown = CandidateSubmission(
        challenge_id=challenge.challenge_id,
        action_tokens=("action.000000000000000000000000",),
    )
    assert dataset.oracle.evaluate(challenge, unknown).reason is OracleReason.UNKNOWN_ACTION

    inapplicable = next(
        action
        for action in challenge.actions
        if any(
            challenge.initial_mapping().get(cell.key) is not cell.value
            for cell in action.preconditions
        )
    )
    wrong_order = CandidateSubmission(
        challenge_id=challenge.challenge_id,
        action_tokens=(inapplicable.token,),
    )
    assert (
        dataset.oracle.evaluate(challenge, wrong_order).reason is OracleReason.PRECONDITION_FAILED
    )

    forged_duplicate = CandidateSubmission.model_construct(
        challenge_id=challenge.challenge_id,
        action_tokens=(challenge.actions[0].token, challenge.actions[0].token),
    )
    assert (
        dataset.oracle.evaluate(challenge, forged_duplicate).reason is OracleReason.DUPLICATE_ACTION
    )

    actions = list(challenge.actions)
    actions[0] = actions[0].model_copy(
        update={"action_cost": 1 if actions[0].action_cost != 1 else 2}
    )
    modified = challenge.model_copy(update={"actions": tuple(actions)})
    assert (
        dataset.oracle.evaluate(
            modified,
            CandidateSubmission(
                challenge_id=modified.challenge_id,
                action_tokens=(),
            ),
        ).reason
        is OracleReason.PUBLIC_CHALLENGE_MISMATCH
    )


def test_budget_ledger_is_immutable_content_bound_and_fail_closed() -> None:
    limits = BudgetLimits(max_action_cost=2, max_world_cost=1, max_latency_units=5)
    empty = BudgetLedger(limits=limits)
    charged = empty.reserve(
        kind=BudgetEventKind.ACTION,
        operation_key="execute.000000000000000000000001",
        action_token="action.000000000000000000000001",
        action_cost=2,
        latency_units=2,
    )

    assert not empty.events
    assert charged.usage.action_cost == 2
    with pytest.raises(BudgetExceededError):
        charged.reserve(
            kind=BudgetEventKind.WORLD,
            operation_key="world.000000000000000000000001",
            action_token="action.000000000000000000000001",
            world_cost=1,
            latency_units=4,
        )
    assert charged.usage.action_cost == 2
    assert charged.usage.world_cost == 0

    forged = charged.events[0].model_dump(mode="python")
    forged["action_cost"] = 1
    with pytest.raises(ValidationError, match="budget event ID"):
        type(charged.events[0]).model_validate(forged)
    with pytest.raises(ValidationError, match="frozen"):
        charged.limits = BudgetLimits(
            max_action_cost=999,
            max_world_cost=999,
            max_latency_units=999,
        )
