from __future__ import annotations

import re
from dataclasses import replace

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from statechainbench import (
    HOLDOUT_FAMILIES,
    TRAIN_FAMILIES,
    ChallengeFamily,
    DatasetSplit,
    GeneratorConfig,
    PublicChallenge,
    generate_dataset,
)


def test_generation_is_seeded_canonical_and_changes_across_seeds() -> None:
    first = generate_dataset(GeneratorConfig(seed=1729, variants_per_family=3))
    again = generate_dataset(GeneratorConfig(seed=1729, variants_per_family=3))
    other = generate_dataset(GeneratorConfig(seed=1730, variants_per_family=3))

    assert tuple(item.canonical_bytes() for item in first.descriptors) == tuple(
        item.canonical_bytes() for item in again.descriptors
    )
    assert {item.public.challenge_id for item in first.descriptors}.isdisjoint(
        item.public.challenge_id for item in other.descriptors
    )
    assert tuple(item.public.challenge_id for item in first.descriptors) == tuple(
        sorted(item.public.challenge_id for item in first.descriptors)
    )


def test_family_split_is_static_and_disjoint() -> None:
    assert TRAIN_FAMILIES.isdisjoint(HOLDOUT_FAMILIES)
    assert frozenset(ChallengeFamily) == TRAIN_FAMILIES | HOLDOUT_FAMILIES

    dataset = generate_dataset(GeneratorConfig(seed=9, variants_per_family=2))
    assert {item.family for item in dataset.for_split(DatasetSplit.TRAIN)} == TRAIN_FAMILIES
    assert {item.family for item in dataset.for_split(DatasetSplit.HOLDOUT)} == HOLDOUT_FAMILIES


def test_challenge_ids_are_independent_of_unrelated_families_and_dataset_size() -> None:
    selected = generate_dataset(
        GeneratorConfig(
            seed=444,
            variants_per_family=1,
            families=(ChallengeFamily.REQUEST_ORDERING,),
        )
    )
    expanded = generate_dataset(GeneratorConfig(seed=444, variants_per_family=3))

    selected_descriptor = selected.descriptors[0]
    matching = next(
        item
        for item in expanded.descriptors
        if item.family is ChallengeFamily.REQUEST_ORDERING and item.variant == 0
    )
    assert selected_descriptor.public.challenge_id == matching.public.challenge_id
    assert selected_descriptor.challenge_digest == matching.challenge_digest
    assert selected.config.config_digest != expanded.config.config_digest


def test_dataset_constructor_rejects_config_descriptor_and_oracle_substitution() -> None:
    first = generate_dataset(GeneratorConfig(seed=445, variants_per_family=1))
    other = generate_dataset(GeneratorConfig(seed=446, variants_per_family=1))

    with pytest.raises(ValueError, match="config and descriptors"):
        replace(first, config=other.config)
    with pytest.raises(ValueError, match="config and descriptors"):
        replace(first, descriptors=other.descriptors)
    with pytest.raises(ValueError, match="oracle"):
        replace(first, oracle=other.oracle)


@settings(max_examples=16, deadline=None)
@given(seed=st.integers(min_value=0, max_value=2**31 - 1))
def test_public_instances_are_opaque_nontrivial_and_answer_free(seed: int) -> None:
    dataset = generate_dataset(GeneratorConfig(seed=seed, variants_per_family=1))
    for descriptor in dataset.descriptors:
        public = descriptor.public
        encoded = public.model_dump_json().lower()
        assert re.fullmatch(r"challenge\.[0-9a-f]{24}", public.challenge_id)
        assert all(re.fullmatch(r"action\.[0-9a-f]{24}", action.token) for action in public.actions)
        assert set(type(public).model_fields) == {
            "challenge_id",
            "track",
            "initial_state",
            "goal",
            "actions",
            "max_chain_length",
        }
        assert not any(
            forbidden in encoded
            for forbidden in (
                "family",
                "holdout",
                "train",
                "solution",
                "terminal_state",
                "oracle",
            )
        )
        terminal = [action for action in public.actions if public.goal in action.effects]
        assert terminal
        assert max(len(action.preconditions) for action in terminal) >= 3
        assert len({action.token for action in public.actions}) == len(public.actions)


def test_closed_public_contract_rejects_direct_answer_encoding() -> None:
    public = generate_dataset(GeneratorConfig(seed=11, variants_per_family=1)).descriptors[0].public
    payload = public.model_dump(mode="python")
    payload["solution"] = [public.actions[0].token]

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        PublicChallenge.model_validate(payload)
