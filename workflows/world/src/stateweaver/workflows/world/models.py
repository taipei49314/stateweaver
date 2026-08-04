"""Closed, immutable records for offline promotion orchestration."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, cast

from pydantic import ConfigDict, Field, JsonValue, TypeAdapter, field_validator, model_validator
from stateweaver.compiler import RootState
from stateweaver.contracts import (
    ContractId,
    EventEnvelope,
    EventHistory,
    EventType,
    RequestedBy,
    RequesterType,
    Sha256Digest,
    WorldTier,
    canonical_json_bytes,
    sha256_digest,
)
from stateweaver.contracts.base import AwareTimestampMixin, ContractModel, IdentityHandle
from stateweaver.search import (
    BeamSearchPolicy,
    BudgetLedger,
    DecisionDisposition,
    ReasonCode,
    SearchBatch,
    SearchResult,
    TieredSearchController,
)

_PROMOTION_EVENT_ACTOR = RequestedBy(
    type=RequesterType.WORKFLOW,
    role="world-promotion-workflow",
)
_PROMOTION_TRACE_DOMAIN = "stateweaver.world-promotion.trace.v2"
_PROMOTION_RESULT_DOMAIN = "stateweaver.world-promotion.result.v2"


class PromotionLifecyclePhase(StrEnum):
    """Canonical result-semantic phases; these are not callback telemetry."""

    SEARCH_BLOCKED = "search_blocked"
    RESERVED = "reserved"
    ALLOCATED = "allocated"
    CAPTURED = "captured"
    COMMITTED = "committed"
    NOT_COMMITTED = "not_committed"


class AllocationRequest(ContractModel):
    candidate_id: ContractId
    source_tier: WorldTier
    target_tier: WorldTier
    state_fingerprint: Sha256Digest
    reservation_id: ContractId


class AllocatedWorld(ContractModel):
    allocation_id: ContractId
    candidate_id: ContractId
    target_tier: WorldTier
    state_fingerprint: Sha256Digest
    sibling_identity: IdentityHandle


class CaptureReceipt(ContractModel):
    allocation_id: ContractId
    candidate_id: ContractId
    state_fingerprint: Sha256Digest
    compiler_root: RootState
    evidence_ref: ContractId
    oracle_ref: ContractId
    oracle_passed: bool

    @model_validator(mode="after")
    def compiler_root_binds_allocation(self) -> CaptureReceipt:
        if self.compiler_root.world_id != self.allocation_id:
            raise ValueError("captured compiler root must bind the allocation")
        return self


class PromotionRecord(ContractModel):
    candidate_id: ContractId
    target_tier: WorldTier
    reservation_id: ContractId
    allocation: AllocatedWorld
    capture: CaptureReceipt

    @model_validator(mode="after")
    def capture_binds_allocation(self) -> PromotionRecord:
        if (
            self.candidate_id != self.allocation.candidate_id
            or self.candidate_id != self.capture.candidate_id
            or self.allocation.target_tier is not self.target_tier
            or self.allocation.allocation_id != self.capture.allocation_id
            or self.allocation.state_fingerprint != self.capture.state_fingerprint
            or not self.capture.oracle_passed
        ):
            raise ValueError("promotion record must bind a successful matching capture")
        return self


class PromotionRunContext(AwareTimestampMixin):
    """Caller-supplied occurrence context bound into every canonical lifecycle event."""

    model_config = ConfigDict(revalidate_instances="always")

    experiment_id: ContractId
    run_id: ContractId
    recorded_at: datetime

    @field_validator("recorded_at")
    @classmethod
    def recorded_at_is_absolute(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("recorded_at must include a UTC offset")
        return value


class _LifecyclePayload(ContractModel):
    schema_version: Literal["world-promotion-lifecycle-v2"] = "world-promotion-lifecycle-v2"
    candidate_id: ContractId
    source_tier: WorldTier
    target_tier: WorldTier
    decision_hash: Sha256Digest
    result_projection_hash: Sha256Digest


class SearchBlockedPayload(_LifecyclePayload):
    phase: Literal[PromotionLifecyclePhase.SEARCH_BLOCKED] = PromotionLifecyclePhase.SEARCH_BLOCKED
    reason_codes: tuple[ReasonCode, ...]


class _ReservedPayload(_LifecyclePayload):
    provisional_reservation_id: ContractId
    provisional_reservation_hash: Sha256Digest


class ReservedPayload(_ReservedPayload):
    phase: Literal[PromotionLifecyclePhase.RESERVED] = PromotionLifecyclePhase.RESERVED


class AllocatedPayload(_ReservedPayload):
    phase: Literal[PromotionLifecyclePhase.ALLOCATED] = PromotionLifecyclePhase.ALLOCATED
    allocation_id: ContractId
    state_fingerprint: Sha256Digest
    sibling_identity: IdentityHandle
    allocation_hash: Sha256Digest


class CapturedPayload(_ReservedPayload):
    phase: Literal[PromotionLifecyclePhase.CAPTURED] = PromotionLifecyclePhase.CAPTURED
    allocation_id: ContractId
    evidence_ref: ContractId
    oracle_ref: ContractId
    compiler_root_hash: Sha256Digest
    capture_hash: Sha256Digest


class CommittedPayload(_ReservedPayload):
    phase: Literal[PromotionLifecyclePhase.COMMITTED] = PromotionLifecyclePhase.COMMITTED
    committed_reservation_id: ContractId
    committed_reservation_hash: Sha256Digest
    allocation_id: ContractId
    promotion_hash: Sha256Digest


class NotCommittedPayload(_ReservedPayload):
    phase: Literal[PromotionLifecyclePhase.NOT_COMMITTED] = PromotionLifecyclePhase.NOT_COMMITTED


type PromotionLifecyclePayload = Annotated[
    SearchBlockedPayload
    | ReservedPayload
    | AllocatedPayload
    | CapturedPayload
    | CommittedPayload
    | NotCommittedPayload,
    Field(discriminator="phase"),
]
_PAYLOAD_ADAPTER: TypeAdapter[PromotionLifecyclePayload] = TypeAdapter(PromotionLifecyclePayload)


def promotion_lifecycle_payload(event: EventEnvelope) -> PromotionLifecyclePayload:
    """Parse one lifecycle envelope through the closed discriminated payload union."""

    closed_event = EventEnvelope.model_validate(event.model_dump(mode="python"))
    if closed_event.event_type is not EventType.WORLD_PROMOTION_LIFECYCLE:
        raise ValueError("event is not a world promotion lifecycle event")
    return _PAYLOAD_ADAPTER.validate_json(canonical_json_bytes(closed_event.payload))


class WorkflowResult(ContractModel):
    """One promotion result with an independently reconstructable canonical history."""

    model_config = ConfigDict(revalidate_instances="always")

    context: PromotionRunContext
    input_ledger: BudgetLedger
    search_policy: BeamSearchPolicy
    search_batch: SearchBatch
    search: SearchResult
    committed_ledger: BudgetLedger
    promotions: tuple[PromotionRecord, ...]
    event_history: EventHistory

    @model_validator(mode="after")
    def result_is_consistent(self) -> WorkflowResult:
        context = PromotionRunContext.model_validate(self.context.model_dump(mode="python"))
        input_ledger = BudgetLedger.model_validate(self.input_ledger.model_dump(mode="python"))
        search_policy = BeamSearchPolicy.model_validate(
            self.search_policy.model_dump(mode="python")
        )
        search_batch = SearchBatch.model_validate(self.search_batch.model_dump(mode="python"))
        search = SearchResult.model_validate(self.search.model_dump(mode="python"))
        committed_ledger = BudgetLedger.model_validate(
            self.committed_ledger.model_dump(mode="python")
        )
        promotions = tuple(
            PromotionRecord.model_validate(item.model_dump(mode="python"))
            for item in self.promotions
        )
        event_history = EventHistory.model_validate(self.event_history.model_dump(mode="python"))
        expected_search = TieredSearchController(search_policy).advance(
            search_batch,
            input_ledger,
        )
        if search != expected_search:
            raise ValueError("search result must exactly replay from its bound batch and policy")
        _validate_result_relations(
            input_ledger=input_ledger,
            search_batch=search_batch,
            search=search,
            committed_ledger=committed_ledger,
            promotions=promotions,
        )
        expected = _build_promotion_history(
            context=context,
            input_ledger=input_ledger,
            search_policy=search_policy,
            search_batch=search_batch,
            search=search,
            committed_ledger=committed_ledger,
            promotions=promotions,
        )
        if event_history != expected:
            raise ValueError(
                "promotion event history must exactly match the canonical result semantics"
            )
        return self

    @classmethod
    def create(
        cls,
        *,
        context: PromotionRunContext,
        input_ledger: BudgetLedger,
        search_policy: BeamSearchPolicy,
        search_batch: SearchBatch,
        search: SearchResult,
        committed_ledger: BudgetLedger,
        promotions: tuple[PromotionRecord, ...],
    ) -> WorkflowResult:
        closed_context = PromotionRunContext.model_validate(context.model_dump(mode="python"))
        closed_input = BudgetLedger.model_validate(input_ledger.model_dump(mode="python"))
        closed_policy = BeamSearchPolicy.model_validate(search_policy.model_dump(mode="python"))
        closed_batch = SearchBatch.model_validate(search_batch.model_dump(mode="python"))
        closed_search = SearchResult.model_validate(search.model_dump(mode="python"))
        closed_committed = BudgetLedger.model_validate(committed_ledger.model_dump(mode="python"))
        closed_promotions = tuple(
            PromotionRecord.model_validate(item.model_dump(mode="python")) for item in promotions
        )
        expected_search = TieredSearchController(closed_policy).advance(
            closed_batch,
            closed_input,
        )
        if closed_search != expected_search:
            raise ValueError("search result must exactly replay from its bound batch and policy")
        _validate_result_relations(
            input_ledger=closed_input,
            search_batch=closed_batch,
            search=closed_search,
            committed_ledger=closed_committed,
            promotions=closed_promotions,
        )
        history = _build_promotion_history(
            context=closed_context,
            input_ledger=closed_input,
            search_policy=closed_policy,
            search_batch=closed_batch,
            search=closed_search,
            committed_ledger=closed_committed,
            promotions=closed_promotions,
        )
        return cls(
            context=closed_context,
            input_ledger=closed_input,
            search_policy=closed_policy,
            search_batch=closed_batch,
            search=closed_search,
            committed_ledger=closed_committed,
            promotions=closed_promotions,
            event_history=history,
        )

    @property
    def events(self) -> tuple[EventEnvelope, ...]:
        """Expose canonical envelopes without retaining the legacy free-form event contract."""

        return self.event_history.events

    @property
    def blocked_candidate_ids(self) -> tuple[str, ...]:
        terminal_phases = {
            PromotionLifecyclePhase.SEARCH_BLOCKED,
            PromotionLifecyclePhase.NOT_COMMITTED,
        }
        return tuple(
            payload.candidate_id
            for event in self.event_history.events
            if (payload := promotion_lifecycle_payload(event)).phase in terminal_phases
        )

    @property
    def not_committed_candidate_ids(self) -> tuple[str, ...]:
        return tuple(
            payload.candidate_id
            for event in self.event_history.events
            if (payload := promotion_lifecycle_payload(event)).phase
            is PromotionLifecyclePhase.NOT_COMMITTED
        )


def _validate_result_relations(
    *,
    input_ledger: BudgetLedger,
    search_batch: SearchBatch,
    search: SearchResult,
    committed_ledger: BudgetLedger,
    promotions: tuple[PromotionRecord, ...],
) -> None:
    if (
        search.ledger.limits != input_ledger.limits
        or committed_ledger.limits != input_ledger.limits
    ):
        raise ValueError("search and committed ledgers must retain the input limits")
    input_count = len(input_ledger.reservations)
    if search.ledger.reservations[:input_count] != input_ledger.reservations:
        raise ValueError("search ledger must preserve the complete input history")
    if committed_ledger.reservations[:input_count] != input_ledger.reservations:
        raise ValueError("committed ledger must preserve the complete input history")

    decisions = {item.candidate_id: item for item in search.decisions}
    promoted_decisions = {
        item.candidate_id: item
        for item in search.decisions
        if item.disposition is DecisionDisposition.PROMOTE
    }
    provisional = search.ledger.reservations[input_count:]
    if len(provisional) != len(promoted_decisions):
        raise ValueError("provisional ledger suffix must exactly cover promoted decisions")
    provisional_by_candidate = {item.candidate_id: item for item in provisional}
    if set(provisional_by_candidate) != set(promoted_decisions):
        raise ValueError("provisional reservations must exactly match promoted candidates")
    for candidate_id, reservation in provisional_by_candidate.items():
        decision = promoted_decisions[candidate_id]
        if (
            decision.reservation_id != reservation.reservation_id
            or decision.target_tier is not reservation.target_tier
            or decision.source_tier is not search.source_tier
            or decision.target_tier is not search.target_tier
        ):
            raise ValueError("provisional reservation must bind its promoted decision")

    promotion_ids = [item.candidate_id for item in promotions]
    allocation_ids = [item.allocation.allocation_id for item in promotions]
    identities = [item.allocation.sibling_identity for item in promotions]
    if (
        len(promotion_ids) != len(set(promotion_ids))
        or len(allocation_ids) != len(set(allocation_ids))
        or len(identities) != len(set(identities))
    ):
        raise ValueError(
            "committed promotions require unique candidates, allocations, and sibling identities"
        )
    if any(candidate_id not in promoted_decisions for candidate_id in promotion_ids):
        raise ValueError("committed promotions must be a subset of promoted decisions")

    candidates = {item.candidate_id: item for item in search_batch.candidates}
    for promotion in promotions:
        candidate = candidates[promotion.candidate_id]
        if (
            candidate.state_fingerprint != promotion.allocation.state_fingerprint
            or promotion.capture.evidence_ref not in candidate.gates.evidence_ids
            or promotion.capture.oracle_ref not in candidate.gates.oracle_refs
            or candidate.tier is not search.source_tier
            or promotion.target_tier is not search.target_tier
        ):
            raise ValueError(
                "promotion allocation and capture must bind the admitted search candidate"
            )

    committed = committed_ledger.reservations[input_count:]
    if len(committed) != len(promotions):
        raise ValueError("committed ledger suffix must exactly cover promotion records")
    for reservation, promotion in zip(committed, promotions, strict=True):
        decision = decisions[promotion.candidate_id]
        provisional_reservation = provisional_by_candidate[promotion.candidate_id]
        if (
            reservation.reservation_id != promotion.reservation_id
            or reservation.candidate_id != promotion.candidate_id
            or reservation.target_tier is not promotion.target_tier
            or reservation.cost != provisional_reservation.cost
            or decision.target_tier is not promotion.target_tier
            or promotion.allocation.target_tier is not promotion.target_tier
        ):
            raise ValueError("promotion must bind the exact committed reservation semantics")


def _build_promotion_history(
    *,
    context: PromotionRunContext,
    input_ledger: BudgetLedger,
    search_policy: BeamSearchPolicy,
    search_batch: SearchBatch,
    search: SearchResult,
    committed_ledger: BudgetLedger,
    promotions: tuple[PromotionRecord, ...],
) -> EventHistory:
    input_count = len(input_ledger.reservations)
    provisional = search.ledger.reservations[input_count:]
    committed = committed_ledger.reservations[input_count:]
    committed_by_candidate = {item.candidate_id: item for item in committed}
    promotions_by_candidate = {item.candidate_id: item for item in promotions}
    events: list[EventEnvelope] = []
    trace_id = _promotion_trace_id(context)
    result_projection_hash = _result_projection_hash(
        input_ledger=input_ledger,
        search_policy=search_policy,
        search_batch=search_batch,
        search=search,
        committed_ledger=committed_ledger,
        promotions=promotions,
    )

    def append(payload: PromotionLifecyclePayload, *, world_id: str | None = None) -> None:
        events.append(
            EventEnvelope.create(
                event_type=EventType.WORLD_PROMOTION_LIFECYCLE,
                experiment_id=context.experiment_id,
                run_id=context.run_id,
                world_id=world_id,
                actor=_PROMOTION_EVENT_ACTOR,
                trace_id=trace_id,
                timestamp=context.recorded_at,
                sequence=len(events) + 1,
                prev_event_hash=events[-1].semantic_hash if events else None,
                payload=cast(
                    Mapping[str, JsonValue],
                    payload.model_dump(mode="json", by_alias=True, exclude_none=False),
                ),
            )
        )

    for decision in search.decisions:
        if decision.disposition is DecisionDisposition.PRUNE:
            append(
                SearchBlockedPayload(
                    candidate_id=decision.candidate_id,
                    source_tier=decision.source_tier,
                    target_tier=decision.target_tier,
                    decision_hash=sha256_digest(decision),
                    result_projection_hash=result_projection_hash,
                    reason_codes=decision.reason_codes,
                )
            )

    for reservation in provisional:
        decision = next(
            item for item in search.decisions if item.candidate_id == reservation.candidate_id
        )
        decision_hash = sha256_digest(decision)
        reservation_hash = sha256_digest(reservation)
        append(
            ReservedPayload(
                candidate_id=decision.candidate_id,
                source_tier=decision.source_tier,
                target_tier=decision.target_tier,
                decision_hash=decision_hash,
                result_projection_hash=result_projection_hash,
                provisional_reservation_id=reservation.reservation_id,
                provisional_reservation_hash=reservation_hash,
            )
        )
        promotion = promotions_by_candidate.get(reservation.candidate_id)
        if promotion is None:
            append(
                NotCommittedPayload(
                    candidate_id=decision.candidate_id,
                    source_tier=decision.source_tier,
                    target_tier=decision.target_tier,
                    decision_hash=decision_hash,
                    result_projection_hash=result_projection_hash,
                    provisional_reservation_id=reservation.reservation_id,
                    provisional_reservation_hash=reservation_hash,
                )
            )
            continue
        allocation = promotion.allocation
        capture = promotion.capture
        committed_reservation = committed_by_candidate[promotion.candidate_id]
        append(
            AllocatedPayload(
                candidate_id=decision.candidate_id,
                source_tier=decision.source_tier,
                target_tier=decision.target_tier,
                decision_hash=decision_hash,
                result_projection_hash=result_projection_hash,
                provisional_reservation_id=reservation.reservation_id,
                provisional_reservation_hash=reservation_hash,
                allocation_id=allocation.allocation_id,
                state_fingerprint=allocation.state_fingerprint,
                sibling_identity=allocation.sibling_identity,
                allocation_hash=sha256_digest(allocation),
            ),
            world_id=allocation.allocation_id,
        )
        append(
            CapturedPayload(
                candidate_id=decision.candidate_id,
                source_tier=decision.source_tier,
                target_tier=decision.target_tier,
                decision_hash=decision_hash,
                result_projection_hash=result_projection_hash,
                provisional_reservation_id=reservation.reservation_id,
                provisional_reservation_hash=reservation_hash,
                allocation_id=allocation.allocation_id,
                evidence_ref=capture.evidence_ref,
                oracle_ref=capture.oracle_ref,
                compiler_root_hash=sha256_digest(capture.compiler_root),
                capture_hash=sha256_digest(capture),
            ),
            world_id=allocation.allocation_id,
        )
        append(
            CommittedPayload(
                candidate_id=decision.candidate_id,
                source_tier=decision.source_tier,
                target_tier=decision.target_tier,
                decision_hash=decision_hash,
                result_projection_hash=result_projection_hash,
                provisional_reservation_id=reservation.reservation_id,
                provisional_reservation_hash=reservation_hash,
                committed_reservation_id=committed_reservation.reservation_id,
                committed_reservation_hash=sha256_digest(committed_reservation),
                allocation_id=allocation.allocation_id,
                promotion_hash=sha256_digest(promotion),
            ),
            world_id=allocation.allocation_id,
        )

    return EventHistory.create(
        experiment_id=context.experiment_id,
        run_id=context.run_id,
        events=tuple(events),
    )


def _promotion_trace_id(context: PromotionRunContext) -> str:
    digest = sha256_digest(
        {
            "domain": _PROMOTION_TRACE_DOMAIN,
            "experiment_id": context.experiment_id,
            "run_id": context.run_id,
        }
    )
    return digest.removeprefix("sha256:")[:32]


def _result_projection_hash(
    *,
    input_ledger: BudgetLedger,
    search_policy: BeamSearchPolicy,
    search_batch: SearchBatch,
    search: SearchResult,
    committed_ledger: BudgetLedger,
    promotions: tuple[PromotionRecord, ...],
) -> Sha256Digest:
    return sha256_digest(
        {
            "domain": _PROMOTION_RESULT_DOMAIN,
            "input_ledger": input_ledger,
            "search_policy": search_policy,
            "search_batch": search_batch,
            "search": search,
            "committed_ledger": committed_ledger,
            "promotions": promotions,
        }
    )
