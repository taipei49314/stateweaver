"""Closed immutable models for deterministic tiered security-state search."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated

from pydantic import Field, StringConstraints, field_validator, model_validator
from stateweaver.contracts import (
    BrowserNavigateAction,
    CanonicalSecurityState,
    ContractId,
    HttpRequestAction,
    Hypothesis,
    Sha256Digest,
    StateCondition,
    TransitionFragment,
    WorldTier,
    canonical_json_bytes,
    sha256_digest,
)
from stateweaver.contracts.base import ContractModel, Name, NonNegativeInt, Probability

PositiveScore = Annotated[float, Field(ge=0.001, le=1.0)]
Priority = Annotated[float, Field(ge=0.0, le=1_000_000_000.0)]
DiversityKey = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=3,
        max_length=128,
        pattern=r"^[a-z][a-z0-9]*(?:[._:-][a-z0-9][a-z0-9_-]*)+$",
    ),
]


class ScoreSource(StrEnum):
    MODEL = "model"
    DETERMINISTIC = "deterministic"
    MEASURED = "measured"
    POLICY = "policy"


class PolicyGateOutcome(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class DecisionDisposition(StrEnum):
    PROMOTE = "PROMOTE"
    PRUNE = "PRUNE"


class ReasonCode(StrEnum):
    PROMOTED = "PROMOTED"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    POLICY_DENIED = "POLICY_DENIED"
    DUPLICATE_STATE = "DUPLICATE_STATE"
    DOMINATED_BY_CHEAPER_WORLD = "DOMINATED_BY_CHEAPER_WORLD"
    NO_NEW_FACTS = "NO_NEW_FACTS"
    LOW_FIDELITY_WITHOUT_CALIBRATION_PATH = "LOW_FIDELITY_WITHOUT_CALIBRATION_PATH"
    UNSUPPORTED_ADAPTER_CAPABILITY = "UNSUPPORTED_ADAPTER_CAPABILITY"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    NON_REVERSIBLE_ACTION_NOT_APPROVED = "NON_REVERSIBLE_ACTION_NOT_APPROVED"
    REPEATED_NONDETERMINISM = "REPEATED_NONDETERMINISM"
    MISSING_EVIDENCE = "MISSING_EVIDENCE"
    MISSING_ACTION_PLAN = "MISSING_ACTION_PLAN"
    MISSING_EXPECTED_OBSERVATION = "MISSING_EXPECTED_OBSERVATION"
    MISSING_MACHINE_ORACLE = "MISSING_MACHINE_ORACLE"
    MISSING_SNAPSHOT_CAPABILITY = "MISSING_SNAPSHOT_CAPABILITY"
    BEAM_CAPACITY = "BEAM_CAPACITY"
    ALREADY_PROMOTED = "ALREADY_PROMOTED"


class ScoreSignal(ContractModel):
    value: Probability
    source: ScoreSource


class PositiveScoreSignal(ContractModel):
    value: PositiveScore
    source: ScoreSource


class SearchScores(ContractModel):
    boundary_impact: ScoreSignal
    information_gain: ScoreSignal
    novelty: ScoreSignal
    composability: ScoreSignal
    fidelity: ScoreSignal
    reachability: ScoreSignal
    normalized_cost: PositiveScoreSignal
    operational_risk: PositiveScoreSignal

    @model_validator(mode="after")
    def score_sources_are_not_model_only(self) -> SearchScores:
        if any(
            signal.source is ScoreSource.MODEL
            for signal in (
                self.boundary_impact,
                self.composability,
                self.fidelity,
                self.reachability,
            )
        ):
            raise ValueError(
                "oracle, composition, fidelity, and reachability scores cannot be model-only"
            )
        if self.normalized_cost.source not in {
            ScoreSource.DETERMINISTIC,
            ScoreSource.MEASURED,
        }:
            raise ValueError("normalized cost requires deterministic or measured provenance")
        if self.operational_risk.source is not ScoreSource.POLICY:
            raise ValueError("operational risk must come from policy")
        return self

    def priority(self, uncertainty: float, uncertainty_bonus: float) -> float:
        numerator = (
            self.boundary_impact.value
            * self.information_gain.value
            * self.novelty.value
            * self.composability.value
            * self.fidelity.value
            * self.reachability.value
        )
        return (
            numerator
            * (1.0 + uncertainty * uncertainty_bonus)
            / (self.normalized_cost.value * self.operational_risk.value)
        )


class PromotionCost(ContractModel):
    llm_calls: NonNegativeInt = 0
    target_requests: NonNegativeInt = 0
    write_requests: NonNegativeInt = 0
    cpu_seconds: NonNegativeInt = 0


class PromotionGates(ContractModel):
    in_scope: bool
    policy_outcome: PolicyGateOutcome
    policy_decision_ref: ContractId
    approval_ref: ContractId | None = None
    reversible: bool
    action_plan_refs: tuple[ContractId, ...] = ()
    expected_observations: tuple[StateCondition, ...] = ()
    oracle_refs: tuple[ContractId, ...] = ()
    evidence_ids: tuple[ContractId, ...] = ()
    required_capabilities: tuple[Name, ...] = ()
    available_capabilities: tuple[Name, ...] = ()
    snapshot_capable: bool
    new_fact_count: NonNegativeInt
    calibration_path: bool
    repeated_nondeterminism: NonNegativeInt = 0

    @field_validator(
        "action_plan_refs",
        "oracle_refs",
        "evidence_ids",
        "required_capabilities",
        "available_capabilities",
    )
    @classmethod
    def references_are_sorted_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("promotion-gate references must be unique")
        return tuple(sorted(value))

    @field_validator("expected_observations")
    @classmethod
    def observations_are_canonical(
        cls, value: tuple[StateCondition, ...]
    ) -> tuple[StateCondition, ...]:
        encoded = [canonical_json_bytes(item) for item in value]
        if len(encoded) != len(set(encoded)):
            raise ValueError("expected observations must be unique")
        return tuple(
            item for _, item in sorted(zip(encoded, value, strict=True), key=lambda pair: pair[0])
        )

    @model_validator(mode="after")
    def approval_shape_is_coherent(self) -> PromotionGates:
        if self.policy_outcome is PolicyGateOutcome.ALLOW and self.approval_ref is not None:
            raise ValueError("an ALLOW policy gate cannot claim a separate approval")
        if self.policy_outcome is PolicyGateOutcome.DENY and self.approval_ref is not None:
            raise ValueError("a denied proposal cannot claim approval")
        return self


class SearchCandidate(ContractModel):
    candidate_id: ContractId
    hypothesis: Hypothesis
    tier: WorldTier
    state: CanonicalSecurityState
    state_fingerprint: Sha256Digest
    diversity_key: DiversityKey
    scores: SearchScores
    uncertainty: ScoreSignal
    transition_fragments: tuple[TransitionFragment, ...] = ()
    state_predicates: tuple[StateCondition, ...] = ()
    gates: PromotionGates
    promotion_cost: PromotionCost

    @field_validator("hypothesis")
    @classmethod
    def hypothesis_set_fields_are_canonical(cls, value: Hypothesis) -> Hypothesis:
        payload = value.model_dump(mode="python")
        payload["required_facts"] = tuple(sorted(value.required_facts))
        payload["suggested_mutations"] = tuple(sorted(value.suggested_mutations))
        return Hypothesis.model_validate(payload)

    @field_validator("transition_fragments")
    @classmethod
    def fragments_are_canonical(
        cls, value: tuple[TransitionFragment, ...]
    ) -> tuple[TransitionFragment, ...]:
        identifiers = [item.transition_id for item in value]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("candidate transition fragments must be unique")
        return tuple(sorted(value, key=lambda item: item.transition_id))

    @field_validator("state_predicates")
    @classmethod
    def predicates_are_canonical(
        cls, value: tuple[StateCondition, ...]
    ) -> tuple[StateCondition, ...]:
        encoded = [canonical_json_bytes(item) for item in value]
        if len(encoded) != len(set(encoded)):
            raise ValueError("candidate state predicates must be unique")
        return tuple(
            item for _, item in sorted(zip(encoded, value, strict=True), key=lambda pair: pair[0])
        )

    @model_validator(mode="after")
    def hypothesis_scores_are_bound(self) -> SearchCandidate:
        if self.scores.novelty.value != self.hypothesis.novelty_score:
            raise ValueError("candidate novelty must match its typed hypothesis")
        if self.scores.information_gain.value != self.hypothesis.information_gain:
            raise ValueError("candidate information gain must match its typed hypothesis")
        if self.state_fingerprint != self.state.fingerprint():
            raise ValueError(
                "candidate state fingerprint must derive from canonical security state"
            )
        if self.uncertainty.source is ScoreSource.MODEL:
            raise ValueError("twin uncertainty cannot be supplied only by a model")
        estimate = self.hypothesis.estimated_cost
        if (
            self.promotion_cost.llm_calls < estimate.llm_calls
            or self.promotion_cost.target_requests < estimate.target_requests
            or estimate.materialized_worlds > 1
        ):
            raise ValueError("promotion cost cannot understate the typed hypothesis estimate")
        for fragment in self.transition_fragments:
            action = fragment.action
            target = (
                action.target
                if isinstance(action, HttpRequestAction | BrowserNavigateAction)
                else None
            )
            if target is not None and target.host not in {"localhost", "127.0.0.1"}:
                raise ValueError("search fragments may only reference a local synthetic target")
        return self


class SearchBatch(ContractModel):
    candidates: tuple[SearchCandidate, ...]

    @field_validator("candidates")
    @classmethod
    def candidates_are_unique(
        cls, value: tuple[SearchCandidate, ...]
    ) -> tuple[SearchCandidate, ...]:
        if not value:
            raise ValueError("search batch cannot be empty")
        identifiers = [item.candidate_id for item in value]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("search candidate IDs must be unique")
        tiers = {item.tier for item in value}
        if len(tiers) != 1 or WorldTier.MATERIALIZED in tiers:
            raise ValueError("a search batch must contain one promotable source tier")
        return tuple(sorted(value, key=lambda item: item.candidate_id))


class BudgetLimits(ContractModel):
    max_llm_calls: NonNegativeInt
    max_target_requests: NonNegativeInt
    max_write_requests: NonNegativeInt
    max_cpu_seconds: NonNegativeInt
    max_ghost: NonNegativeInt = 64
    max_replay: NonNegativeInt = 16
    max_simulated: NonNegativeInt = 8
    max_materialized: NonNegativeInt = 4

    def tier_limit(self, tier: WorldTier) -> int:
        return {
            WorldTier.GHOST: self.max_ghost,
            WorldTier.REPLAY: self.max_replay,
            WorldTier.SIMULATED: self.max_simulated,
            WorldTier.MATERIALIZED: self.max_materialized,
        }[tier]


class BudgetReservation(ContractModel):
    reservation_id: ContractId
    candidate_id: ContractId
    target_tier: WorldTier
    sequence: Annotated[int, Field(ge=1)]
    cost: PromotionCost

    @model_validator(mode="after")
    def identifier_is_content_bound(self) -> BudgetReservation:
        expected = _reservation_id(self.candidate_id, self.target_tier, self.sequence, self.cost)
        if self.reservation_id != expected:
            raise ValueError("budget reservation ID must bind its immutable content")
        return self


class BudgetUsage(ContractModel):
    llm_calls: NonNegativeInt
    target_requests: NonNegativeInt
    write_requests: NonNegativeInt
    cpu_seconds: NonNegativeInt
    ghost_worlds: NonNegativeInt
    replay_worlds: NonNegativeInt
    simulated_worlds: NonNegativeInt
    materialized_worlds: NonNegativeInt

    def tier_count(self, tier: WorldTier) -> int:
        return {
            WorldTier.GHOST: self.ghost_worlds,
            WorldTier.REPLAY: self.replay_worlds,
            WorldTier.SIMULATED: self.simulated_worlds,
            WorldTier.MATERIALIZED: self.materialized_worlds,
        }[tier]


class BudgetLedger(ContractModel):
    limits: BudgetLimits
    reservations: tuple[BudgetReservation, ...] = ()

    @field_validator("reservations")
    @classmethod
    def reservations_are_append_only(
        cls, value: tuple[BudgetReservation, ...]
    ) -> tuple[BudgetReservation, ...]:
        if tuple(item.sequence for item in value) != tuple(range(1, len(value) + 1)):
            raise ValueError("budget reservation sequence must be contiguous")
        ids = [item.reservation_id for item in value]
        keys = [(item.candidate_id, item.target_tier) for item in value]
        if len(ids) != len(set(ids)) or len(keys) != len(set(keys)):
            raise ValueError("budget reservations must be unique")
        return value

    @model_validator(mode="after")
    def historical_usage_is_within_limits(self) -> BudgetLedger:
        if not self._fits(self.usage(), None):
            raise ValueError("budget ledger cannot contain overspent history")
        return self

    def usage(self) -> BudgetUsage:
        counts = dict.fromkeys(WorldTier, 0)
        for reservation in self.reservations:
            counts[reservation.target_tier] += 1
        return BudgetUsage(
            llm_calls=sum(item.cost.llm_calls for item in self.reservations),
            target_requests=sum(item.cost.target_requests for item in self.reservations),
            write_requests=sum(item.cost.write_requests for item in self.reservations),
            cpu_seconds=sum(item.cost.cpu_seconds for item in self.reservations),
            ghost_worlds=counts[WorldTier.GHOST],
            replay_worlds=counts[WorldTier.REPLAY],
            simulated_worlds=counts[WorldTier.SIMULATED],
            materialized_worlds=counts[WorldTier.MATERIALIZED],
        )

    def can_reserve(
        self, target_tier: WorldTier, cost: PromotionCost, candidate_id: str | None = None
    ) -> bool:
        if candidate_id is not None and any(
            item.candidate_id == candidate_id and item.target_tier is target_tier
            for item in self.reservations
        ):
            return False
        return self._fits(self.usage(), (target_tier, cost))

    def reserve(
        self, candidate_id: str, target_tier: WorldTier, cost: PromotionCost
    ) -> BudgetLedger:
        if not self.can_reserve(target_tier, cost, candidate_id):
            raise ValueError("budget reservation exceeds an immutable limit")
        sequence = len(self.reservations) + 1
        reservation_id = _reservation_id(candidate_id, target_tier, sequence, cost)
        reservation = BudgetReservation(
            reservation_id=reservation_id,
            candidate_id=candidate_id,
            target_tier=target_tier,
            sequence=sequence,
            cost=cost,
        )
        return BudgetLedger(limits=self.limits, reservations=(*self.reservations, reservation))

    def _fits(
        self,
        usage: BudgetUsage,
        addition: tuple[WorldTier, PromotionCost] | None,
    ) -> bool:
        tier = addition[0] if addition is not None else None
        cost = addition[1] if addition is not None else PromotionCost()
        numeric = (
            usage.llm_calls + cost.llm_calls <= self.limits.max_llm_calls,
            usage.target_requests + cost.target_requests <= self.limits.max_target_requests,
            usage.write_requests + cost.write_requests <= self.limits.max_write_requests,
            usage.cpu_seconds + cost.cpu_seconds <= self.limits.max_cpu_seconds,
        )
        tier_limits = all(
            usage.tier_count(item) + (1 if tier is item else 0) <= self.limits.tier_limit(item)
            for item in WorldTier
        )
        return all(numeric) and tier_limits


class BeamSearchPolicy(ContractModel):
    seed: NonNegativeInt = 0
    replay_width: Annotated[int, Field(ge=1, le=64)] = 8
    simulated_width: Annotated[int, Field(ge=1, le=32)] = 4
    materialized_width: Annotated[int, Field(ge=1, le=16)] = 2
    uncertainty_bonus: Annotated[float, Field(ge=0.0, le=1.0)] = 0.25
    minimum_fidelity: Probability = 0.25
    repeated_nondeterminism_limit: Annotated[int, Field(ge=1, le=100)] = 2

    def width(self, tier: WorldTier) -> int:
        return {
            WorldTier.REPLAY: self.replay_width,
            WorldTier.SIMULATED: self.simulated_width,
            WorldTier.MATERIALIZED: self.materialized_width,
        }[tier]


class SearchDecision(ContractModel):
    candidate_id: ContractId
    source_tier: WorldTier
    target_tier: WorldTier
    disposition: DecisionDisposition
    reason_codes: tuple[ReasonCode, ...]
    priority: Priority
    reservation_id: ContractId | None = None
    deduplicated_to: ContractId | None = None

    @model_validator(mode="after")
    def decision_shape_is_coherent(self) -> SearchDecision:
        if not self.reason_codes or len(self.reason_codes) != len(set(self.reason_codes)):
            raise ValueError("search decision reason codes must be nonempty and unique")
        if self.disposition is DecisionDisposition.PROMOTE:
            if self.reason_codes != (ReasonCode.PROMOTED,) or self.reservation_id is None:
                raise ValueError("promotions require exactly one promotion reason and reservation")
            if self.deduplicated_to is not None:
                raise ValueError("promoted candidates cannot be deduplicated")
        elif self.reservation_id is not None:
            raise ValueError("pruned candidates cannot consume budget")
        deduplication_reason = any(
            reason in {ReasonCode.DUPLICATE_STATE, ReasonCode.DOMINATED_BY_CHEAPER_WORLD}
            for reason in self.reason_codes
        )
        if deduplication_reason != (self.deduplicated_to is not None):
            raise ValueError("deduplication reason and target must be coherent")
        return self


class SearchResult(ContractModel):
    source_tier: WorldTier
    target_tier: WorldTier
    decisions: tuple[SearchDecision, ...]
    promoted_candidate_ids: tuple[ContractId, ...]
    ledger: BudgetLedger
    input_fingerprint: Sha256Digest

    @model_validator(mode="after")
    def result_is_complete(self) -> SearchResult:
        identifiers = [item.candidate_id for item in self.decisions]
        if len(identifiers) != len(set(identifiers)) or identifiers != sorted(identifiers):
            raise ValueError("search decisions must be unique and canonical")
        promoted = tuple(
            item.candidate_id
            for item in self.decisions
            if item.disposition is DecisionDisposition.PROMOTE
        )
        if tuple(sorted(promoted)) != self.promoted_candidate_ids:
            raise ValueError("promoted candidate index is inconsistent")
        reservations = {item.reservation_id: item for item in self.ledger.reservations}
        if any(
            item.reservation_id not in reservations
            or reservations[item.reservation_id].candidate_id != item.candidate_id
            or reservations[item.reservation_id].target_tier is not item.target_tier
            for item in self.decisions
            if item.disposition is DecisionDisposition.PROMOTE
        ):
            raise ValueError("promoted decisions must bind an immutable budget reservation")
        return self

    @property
    def fingerprint(self) -> str:
        return sha256_digest(self)


def _reservation_id(
    candidate_id: str,
    target_tier: WorldTier,
    sequence: int,
    cost: PromotionCost,
) -> str:
    return (
        "reservation."
        + sha256_digest(
            {
                "candidate_id": candidate_id,
                "target_tier": target_tier,
                "sequence": sequence,
                "cost": cost,
            }
        ).removeprefix("sha256:")[:24]
    )
