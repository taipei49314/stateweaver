"""Search hypotheses remain proposals until evidence and replay validate them."""

from __future__ import annotations

from typing import Annotated

from pydantic import StringConstraints, field_validator, model_validator

from .base import ContractId, ContractModel, NonNegativeInt, Probability, VersionedContract
from .enums import HypothesisStatus, OracleType
from .state_ir import Predicate


class PredictedBoundary(ContractModel):
    type: OracleType


class EstimatedCost(ContractModel):
    llm_calls: NonNegativeInt
    target_requests: NonNegativeInt
    materialized_worlds: NonNegativeInt


class Hypothesis(VersionedContract):
    hypothesis_id: ContractId
    claim: Annotated[str, StringConstraints(strip_whitespace=True, min_length=12, max_length=1000)]
    required_facts: tuple[Predicate, ...]
    predicted_boundary: PredictedBoundary
    novelty_score: Probability
    information_gain: Probability
    estimated_cost: EstimatedCost
    suggested_mutations: tuple[
        Annotated[
            str,
            StringConstraints(
                strip_whitespace=True,
                min_length=3,
                max_length=128,
                pattern=r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$",
            ),
        ],
        ...,
    ]
    status: HypothesisStatus = HypothesisStatus.PROPOSED

    @field_validator("required_facts", "suggested_mutations")
    @classmethod
    def search_inputs_are_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("hypothesis inputs must not contain duplicates")
        return value

    @model_validator(mode="after")
    def proposed_hypothesis_has_a_search_path(self) -> Hypothesis:
        if not self.required_facts:
            raise ValueError("hypothesis requires at least one fact")
        if self.status is HypothesisStatus.PROPOSED and not self.suggested_mutations:
            raise ValueError("proposed hypothesis requires at least one suggested mutation")
        return self
