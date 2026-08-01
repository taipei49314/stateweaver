"""Pure deterministic beam search over typed synthetic state candidates."""

from __future__ import annotations

from collections.abc import Iterable

from stateweaver.contracts import ProvenanceKind, WorldTier, sha256_digest

from .models import (
    BeamSearchPolicy,
    BudgetLedger,
    DecisionDisposition,
    PolicyGateOutcome,
    ReasonCode,
    SearchBatch,
    SearchCandidate,
    SearchDecision,
    SearchResult,
)

_NEXT_TIER = {
    WorldTier.GHOST: WorldTier.REPLAY,
    WorldTier.REPLAY: WorldTier.SIMULATED,
    WorldTier.SIMULATED: WorldTier.MATERIALIZED,
}


class TieredSearchController:
    """Apply hard gates, deduplication, diversity, beam width, and budget in that order."""

    def __init__(self, policy: BeamSearchPolicy | None = None) -> None:
        supplied = policy or BeamSearchPolicy()
        self.policy = BeamSearchPolicy.model_validate(supplied.model_dump(mode="python"))

    def advance(self, batch: SearchBatch, ledger: BudgetLedger) -> SearchResult:
        batch = SearchBatch.model_validate(batch.model_dump(mode="python"))
        ledger = BudgetLedger.model_validate(ledger.model_dump(mode="python"))
        source_tier = batch.candidates[0].tier
        target_tier = _NEXT_TIER[source_tier]
        decisions: dict[str, SearchDecision] = {}
        eligible: list[SearchCandidate] = []

        for candidate in batch.candidates:
            reasons = self._gate_reasons(candidate, target_tier)
            if reasons:
                decisions[candidate.candidate_id] = self._pruned(candidate, target_tier, reasons)
            else:
                eligible.append(candidate)

        ranked = self._ranked(eligible)
        deduplicated, duplicates = self._deduplicate(ranked)
        decisions.update(duplicates)
        selection_order = self._diverse_order(deduplicated)

        current_ledger = ledger
        promoted = 0
        for candidate in selection_order:
            if promoted >= self.policy.width(target_tier):
                decisions[candidate.candidate_id] = self._pruned(
                    candidate, target_tier, (ReasonCode.BEAM_CAPACITY,)
                )
                continue
            if any(
                item.candidate_id == candidate.candidate_id and item.target_tier is target_tier
                for item in current_ledger.reservations
            ):
                decisions[candidate.candidate_id] = self._pruned(
                    candidate, target_tier, (ReasonCode.ALREADY_PROMOTED,)
                )
                continue
            if not current_ledger.can_reserve(
                target_tier, candidate.promotion_cost, candidate.candidate_id
            ):
                decisions[candidate.candidate_id] = self._pruned(
                    candidate, target_tier, (ReasonCode.BUDGET_EXCEEDED,)
                )
                continue
            current_ledger = current_ledger.reserve(
                candidate.candidate_id, target_tier, candidate.promotion_cost
            )
            reservation = current_ledger.reservations[-1]
            decisions[candidate.candidate_id] = SearchDecision(
                candidate_id=candidate.candidate_id,
                source_tier=candidate.tier,
                target_tier=target_tier,
                disposition=DecisionDisposition.PROMOTE,
                reason_codes=(ReasonCode.PROMOTED,),
                priority=self._priority(candidate),
                reservation_id=reservation.reservation_id,
            )
            promoted += 1

        canonical_decisions = tuple(decisions[item.candidate_id] for item in batch.candidates)
        promoted_ids = tuple(
            sorted(
                item.candidate_id
                for item in canonical_decisions
                if item.disposition is DecisionDisposition.PROMOTE
            )
        )
        return SearchResult(
            source_tier=source_tier,
            target_tier=target_tier,
            decisions=canonical_decisions,
            promoted_candidate_ids=promoted_ids,
            ledger=current_ledger,
            input_fingerprint=sha256_digest(batch),
        )

    def _gate_reasons(
        self, candidate: SearchCandidate, target_tier: WorldTier
    ) -> tuple[ReasonCode, ...]:
        gates = candidate.gates
        reasons: list[ReasonCode] = []
        if not gates.in_scope:
            reasons.append(ReasonCode.OUT_OF_SCOPE)
        if gates.policy_outcome is PolicyGateOutcome.DENY:
            reasons.append(ReasonCode.POLICY_DENIED)
        if (
            gates.policy_outcome is PolicyGateOutcome.REQUIRE_APPROVAL
            and gates.approval_ref is None
        ):
            reasons.append(ReasonCode.NON_REVERSIBLE_ACTION_NOT_APPROVED)
        if not gates.reversible and gates.approval_ref is None:
            reasons.append(ReasonCode.NON_REVERSIBLE_ACTION_NOT_APPROVED)
        if not set(gates.required_capabilities) <= set(gates.available_capabilities):
            reasons.append(ReasonCode.UNSUPPORTED_ADAPTER_CAPABILITY)
        if gates.new_fact_count == 0:
            reasons.append(ReasonCode.NO_NEW_FACTS)
        if (
            candidate.scores.fidelity.value < self.policy.minimum_fidelity
            and not gates.calibration_path
        ):
            reasons.append(ReasonCode.LOW_FIDELITY_WITHOUT_CALIBRATION_PATH)
        if gates.repeated_nondeterminism >= self.policy.repeated_nondeterminism_limit:
            reasons.append(ReasonCode.REPEATED_NONDETERMINISM)

        if target_tier is WorldTier.MATERIALIZED:
            fragment_evidence = {
                evidence_id
                for fragment in candidate.transition_fragments
                for evidence_id in fragment.evidence_ids
            }
            fragments_are_evidence_bound = (
                bool(candidate.transition_fragments)
                and fragment_evidence <= set(gates.evidence_ids)
                and all(
                    fragment.evidence_ids
                    and fragment.source not in {ProvenanceKind.HYPOTHESIZED, ProvenanceKind.UNKNOWN}
                    for fragment in candidate.transition_fragments
                )
            )
            if not gates.evidence_ids or not fragments_are_evidence_bound:
                reasons.append(ReasonCode.MISSING_EVIDENCE)
            if not gates.action_plan_refs:
                reasons.append(ReasonCode.MISSING_ACTION_PLAN)
            if not gates.expected_observations:
                reasons.append(ReasonCode.MISSING_EXPECTED_OBSERVATION)
            if not gates.oracle_refs:
                reasons.append(ReasonCode.MISSING_MACHINE_ORACLE)
            if not gates.snapshot_capable:
                reasons.append(ReasonCode.MISSING_SNAPSHOT_CAPABILITY)
        return tuple(dict.fromkeys(reasons))

    def _priority(self, candidate: SearchCandidate) -> float:
        return candidate.scores.priority(candidate.uncertainty.value, self.policy.uncertainty_bonus)

    def _ranked(self, candidates: Iterable[SearchCandidate]) -> list[SearchCandidate]:
        return sorted(
            candidates,
            key=lambda candidate: (
                -self._priority(candidate),
                sha256_digest({"seed": self.policy.seed, "candidate_id": candidate.candidate_id}),
                candidate.candidate_id,
            ),
        )

    def _deduplicate(
        self, ranked: list[SearchCandidate]
    ) -> tuple[list[SearchCandidate], dict[str, SearchDecision]]:
        retained: dict[str, SearchCandidate] = {}
        duplicates: dict[str, SearchDecision] = {}
        for candidate in ranked:
            winner = retained.get(candidate.state_fingerprint)
            if winner is None:
                retained[candidate.state_fingerprint] = candidate
                continue
            dominated = _cost_tuple(winner) <= _cost_tuple(candidate)
            reason = (
                ReasonCode.DOMINATED_BY_CHEAPER_WORLD if dominated else ReasonCode.DUPLICATE_STATE
            )
            duplicates[candidate.candidate_id] = self._pruned(
                candidate,
                _NEXT_TIER[candidate.tier],
                (reason,),
                deduplicated_to=winner.candidate_id,
            )
        return list(retained.values()), duplicates

    @staticmethod
    def _diverse_order(ranked: list[SearchCandidate]) -> list[SearchCandidate]:
        first: list[SearchCandidate] = []
        deferred: list[SearchCandidate] = []
        seen: set[str] = set()
        for candidate in ranked:
            if candidate.diversity_key in seen:
                deferred.append(candidate)
            else:
                seen.add(candidate.diversity_key)
                first.append(candidate)
        return [*first, *deferred]

    def _pruned(
        self,
        candidate: SearchCandidate,
        target_tier: WorldTier,
        reasons: tuple[ReasonCode, ...],
        *,
        deduplicated_to: str | None = None,
    ) -> SearchDecision:
        return SearchDecision(
            candidate_id=candidate.candidate_id,
            source_tier=candidate.tier,
            target_tier=target_tier,
            disposition=DecisionDisposition.PRUNE,
            reason_codes=reasons,
            priority=self._priority(candidate),
            deduplicated_to=deduplicated_to,
        )


def _cost_tuple(candidate: SearchCandidate) -> tuple[int, int, int, int]:
    cost = candidate.promotion_cost
    return (cost.target_requests, cost.write_requests, cost.cpu_seconds, cost.llm_calls)
