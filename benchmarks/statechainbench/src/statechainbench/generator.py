"""Seeded local challenge generation with family-level train/holdout isolation."""

from __future__ import annotations

from dataclasses import dataclass

from stateweaver.contracts import sha256_digest

from .models import (
    ChallengeDescriptor,
    ChallengeFamily,
    DatasetSplit,
    GeneratorConfig,
    PublicAction,
    PublicChallenge,
    StateCell,
)
from .oracle import HiddenOracle, evaluator_digest, make_hidden_oracle

TRAIN_FAMILIES = frozenset({ChallengeFamily.SESSION_CACHE, ChallengeFamily.QUEUE_ROLE_TRANSITION})
HOLDOUT_FAMILIES = frozenset({ChallengeFamily.REQUEST_ORDERING, ChallengeFamily.VERSION_FLAG_SKEW})
GENERATOR_VERSION = "statechainbench-generator-v2"


@dataclass(frozen=True, slots=True)
class GeneratedDataset:
    """Public descriptors plus an evaluation-only hidden oracle capability."""

    config: GeneratorConfig
    descriptors: tuple[ChallengeDescriptor, ...]
    oracle: HiddenOracle

    def __post_init__(self) -> None:
        validated = GeneratorConfig.model_validate(self.config.model_dump(mode="python"))
        expected_descriptors, registrations = _generate_material(validated)
        if self.config != validated or self.descriptors != expected_descriptors:
            raise ValueError("dataset config and descriptors do not match exact generation")
        expected_oracle = make_hidden_oracle(registrations)
        if evaluator_digest(self.oracle) != evaluator_digest(expected_oracle):
            raise ValueError("dataset oracle does not match its config and descriptors")

    @property
    def dataset_digest(self) -> str:
        return sha256_digest({"config": self.config, "descriptors": self.descriptors})

    @property
    def evaluator_digest(self) -> str:
        return evaluator_digest(self.oracle)

    def for_split(self, split: DatasetSplit) -> tuple[ChallengeDescriptor, ...]:
        return tuple(item for item in self.descriptors if item.split is split)


def generate_dataset(config: GeneratorConfig) -> GeneratedDataset:
    """Generate deterministic variants without embedding family or answers in public IDs."""

    config = GeneratorConfig.model_validate(config.model_dump(mode="python"))
    descriptors, registrations = _generate_material(config)
    return GeneratedDataset(
        config=config,
        descriptors=descriptors,
        oracle=make_hidden_oracle(registrations),
    )


def _generate_material(
    config: GeneratorConfig,
) -> tuple[
    tuple[ChallengeDescriptor, ...],
    tuple[tuple[str, str, tuple[StateCell, ...]], ...],
]:
    """Rebuild the exact public descriptors and hidden registrations for one config."""

    descriptors: list[ChallengeDescriptor] = []
    registrations: list[tuple[str, str, tuple[StateCell, ...]]] = []
    for family in config.families:
        split = family_split(family)
        for variant in range(config.variants_per_family):
            nonce = _suffix("nonce", GENERATOR_VERSION, config.seed, family.value, variant)
            challenge, terminal = _generate_challenge(
                variant=variant,
                family=family,
                nonce=nonce,
                challenge_id=_challenge_id(config, family, variant),
            )
            descriptors.append(
                ChallengeDescriptor(
                    family=family,
                    split=split,
                    variant=variant,
                    generator_version=config.generator_version,
                    public=challenge,
                )
            )
            registrations.append((challenge.challenge_id, challenge.fingerprint, terminal))
    ordered = tuple(sorted(descriptors, key=lambda item: item.public.challenge_id))
    return ordered, tuple(registrations)


def family_split(family: ChallengeFamily) -> DatasetSplit:
    if family in TRAIN_FAMILIES:
        return DatasetSplit.TRAIN
    if family in HOLDOUT_FAMILIES:
        return DatasetSplit.HOLDOUT
    raise ValueError("challenge family has no audited train/holdout assignment")


def _generate_challenge(
    *,
    variant: int,
    family: ChallengeFamily,
    nonce: str,
    challenge_id: str,
) -> tuple[PublicChallenge, tuple[StateCell, ...]]:
    stage_count = {
        ChallengeFamily.SESSION_CACHE: 3,
        ChallengeFamily.QUEUE_ROLE_TRANSITION: 4,
        ChallengeFamily.REQUEST_ORDERING: 3,
        ChallengeFamily.VERSION_FLAG_SKEW: 4,
    }[family]
    state_keys = tuple(_state_key(nonce, index) for index in range(stage_count + 3))
    stages = state_keys[:stage_count]
    guard, goal, noise = state_keys[stage_count:]
    initial_state = tuple(StateCell(key=key, value=key == guard) for key in state_keys)

    roles: list[tuple[tuple[StateCell, ...], tuple[StateCell, ...]]] = []
    for index, stage in enumerate(stages):
        preconditions = [StateCell(key=guard, value=True)]
        if index:
            preconditions.append(StateCell(key=stages[index - 1], value=True))
        roles.append(
            (
                tuple(preconditions),
                (StateCell(key=stage, value=True),),
            )
        )
    roles.append(
        (
            tuple(
                [StateCell(key=guard, value=True)]
                + [StateCell(key=stage, value=True) for stage in stages]
            ),
            (StateCell(key=goal, value=True),),
        )
    )
    terminal_role = len(roles) - 1
    noise_role = len(roles)
    roles.append(
        (
            (StateCell(key=guard, value=True),),
            (StateCell(key=noise, value=True),),
        )
    )
    trap_role = len(roles)
    roles.append(
        (
            (StateCell(key=guard, value=True),),
            (StateCell(key=guard, value=False),),
        )
    )

    actions = tuple(
        PublicAction(
            token=_action_token(nonce, index),
            preconditions=preconditions,
            effects=effects,
            action_cost=1 + _integer("cost", nonce, index, modulo=2),
        )
        for index, (preconditions, effects) in enumerate(roles)
    )
    solution_roles = tuple(range(terminal_role + 1))
    catalog_roles = {
        ChallengeFamily.SESSION_CACHE: (*solution_roles, noise_role, trap_role),
        ChallengeFamily.QUEUE_ROLE_TRANSITION: (*solution_roles, noise_role, trap_role),
        ChallengeFamily.REQUEST_ORDERING: (trap_role, noise_role, *solution_roles),
        ChallengeFamily.VERSION_FLAG_SKEW: (noise_role, *solution_roles, trap_role),
    }[family]
    if variant % 2 and family in TRAIN_FAMILIES:
        catalog_roles = (*solution_roles, trap_role, noise_role)

    goal_cell = StateCell(key=goal, value=True)
    catalog_actions = tuple(actions[index] for index in catalog_roles)
    max_chain_length = len(solution_roles) + 1
    # Bind the opaque ID only to fields the solver already receives. It therefore
    # cannot act as an extra family/split/answer side channel.
    challenge = PublicChallenge(
        challenge_id=challenge_id,
        initial_state=initial_state,
        goal=goal_cell,
        actions=catalog_actions,
        max_chain_length=max_chain_length,
    )
    terminal = tuple(
        sorted(
            (
                StateCell(key=guard, value=True),
                StateCell(key=goal, value=True),
                *(StateCell(key=stage, value=True) for stage in stages),
            ),
            key=lambda item: item.key,
        )
    )
    return challenge, terminal


def _challenge_id(config: GeneratorConfig, family: ChallengeFamily, variant: int) -> str:
    """Keep IDs stable when unrelated families, splits, or ordering change."""

    suffix = _suffix(
        "challenge",
        config.generator_version,
        config.seed,
        family.value,
        variant,
    )
    return f"challenge.{suffix[:24]}"


def _action_token(nonce: str, slot: int) -> str:
    return f"action.{_suffix('action', nonce, slot)[:24]}"


def _state_key(nonce: str, slot: int) -> str:
    return f"state.{_suffix('state', nonce, slot)[:16]}"


def _integer(*parts: object, modulo: int) -> int:
    return int(_suffix(*parts)[:8], 16) % modulo


def _suffix(*parts: object) -> str:
    return sha256_digest(parts).removeprefix("sha256:")
