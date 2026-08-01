"""Fail-closed, in-memory orchestration around the pure search controller."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable

from stateweaver.contracts import WorldTier
from stateweaver.search import (
    BeamSearchPolicy,
    BudgetLedger,
    DecisionDisposition,
    PolicyGateOutcome,
    SearchBatch,
    SearchCandidate,
    TieredSearchController,
)

from .models import (
    AllocatedWorld,
    AllocationRequest,
    CaptureReceipt,
    PromotionEvent,
    PromotionEventKind,
    PromotionRecord,
    WorkflowResult,
)
from .ports import WorldAllocator, WorldCapture


class WorldPromotionWorkflow:
    """Allocate only controller-promoted candidates through closed async ports.

    `TieredSearchController` produces provisional reservations. This workflow
    commits only reservations with a matching allocation and capture receipt;
    failed callbacks are released and rolled back before the next caller can
    observe the ledger.
    """

    def __init__(
        self,
        *,
        allocator: WorldAllocator,
        capture: WorldCapture,
        ledger: BudgetLedger,
        policy: BeamSearchPolicy | None = None,
    ) -> None:
        self._allocator = allocator
        self._capture = capture
        self._controller = TieredSearchController(policy)
        self._ledger = BudgetLedger.model_validate(ledger.model_dump(mode="python"))
        self._active: dict[str, AllocatedWorld] = {}
        self._identities: set[str] = set()
        self._lock = asyncio.Lock()

    @property
    def ledger(self) -> BudgetLedger:
        """Return a closed copy of the committed budget state."""

        return BudgetLedger.model_validate(self._ledger.model_dump(mode="python"))

    async def advance(self, batch: SearchBatch) -> WorkflowResult:
        """Promote one source tier; callback failures become rollback events."""

        closed_batch = SearchBatch.model_validate(batch.model_dump(mode="python"))
        async with self._lock:
            before = self._ledger
            search = self._controller.advance(closed_batch, before)
            candidates = {item.candidate_id: item for item in closed_batch.candidates}
            newly_reserved = search.ledger.reservations[len(before.reservations) :]
            events: list[PromotionEvent] = []
            for decision in search.decisions:
                if decision.disposition is DecisionDisposition.PRUNE:
                    events.append(
                        PromotionEvent(
                            sequence=len(events) + 1,
                            kind=PromotionEventKind.BLOCKED,
                            candidate_id=decision.candidate_id,
                            target_tier=decision.target_tier,
                            detail="search_pruned:"
                            + ",".join(reason.value for reason in decision.reason_codes),
                        )
                    )
            accepted: list[
                tuple[SearchCandidate, AllocationRequest, AllocatedWorld, CaptureReceipt]
            ] = []

            try:
                for reservation in newly_reserved:
                    candidate = candidates[reservation.candidate_id]
                    request = AllocationRequest(
                        candidate_id=candidate.candidate_id,
                        source_tier=candidate.tier,
                        target_tier=reservation.target_tier,
                        state_fingerprint=candidate.state_fingerprint,
                        reservation_id=reservation.reservation_id,
                    )
                    self._event(events, PromotionEventKind.RESERVED, request, "hard_reservation")
                    gate_error = _workflow_gate_error(candidate, reservation.target_tier)
                    if gate_error is not None:
                        self._event(events, PromotionEventKind.BLOCKED, request, gate_error)
                        self._event(events, PromotionEventKind.ROLLED_BACK, request, gate_error)
                        continue
                    allocation: AllocatedWorld | None = None
                    try:
                        allocation = await self._allocate(request)
                        self._validate_allocation(request, allocation, accepted)
                        self._event(
                            events,
                            PromotionEventKind.ALLOCATED,
                            request,
                            "allocator_accepted",
                            allocation_id=allocation.allocation_id,
                        )
                        receipt = await self._capture.capture(request, allocation)
                        self._validate_capture(candidate, request, allocation, receipt)
                        self._event(
                            events,
                            PromotionEventKind.CAPTURED,
                            request,
                            "capture_accepted",
                            allocation_id=allocation.allocation_id,
                        )
                    except asyncio.CancelledError:
                        if allocation is not None:
                            await self._release_after_failure(allocation)
                        raise
                    except Exception as error:  # Callback boundaries must not promote on error.
                        if allocation is not None:
                            await self._release_after_failure(allocation)
                        self._event(
                            events,
                            PromotionEventKind.ROLLED_BACK,
                            request,
                            _safe_error_detail(error),
                        )
                        continue
                    accepted.append((candidate, request, allocation, receipt))
            except BaseException:
                await self._release_uncommitted(item[2] for item in accepted)
                raise

            committed = before
            records: list[PromotionRecord] = []
            for candidate, request, allocation, receipt in accepted:
                committed = committed.reserve(
                    candidate.candidate_id, request.target_tier, candidate.promotion_cost
                )
                reservation = committed.reservations[-1]
                self._active[allocation.allocation_id] = allocation
                self._identities.add(allocation.sibling_identity)
                record = PromotionRecord(
                    candidate_id=candidate.candidate_id,
                    target_tier=request.target_tier,
                    reservation_id=reservation.reservation_id,
                    allocation=allocation,
                    capture=receipt,
                )
                records.append(record)
                self._event(
                    events,
                    PromotionEventKind.COMMITTED,
                    AllocationRequest(
                        candidate_id=request.candidate_id,
                        source_tier=request.source_tier,
                        target_tier=request.target_tier,
                        state_fingerprint=request.state_fingerprint,
                        reservation_id=reservation.reservation_id,
                    ),
                    "capture_and_reservation_committed",
                )
            self._ledger = committed
            return WorkflowResult(
                search=search,
                committed_ledger=committed,
                promotions=tuple(records),
                events=tuple(events),
            )

    async def close(self) -> None:
        """Release every committed abstract allocation; retryable failures remain tracked."""

        async with self._lock:
            remaining: dict[str, AllocatedWorld] = {}
            for allocation_id, allocation in self._active.items():
                try:
                    await self._allocator.release(allocation)
                except Exception:
                    remaining[allocation_id] = allocation
            self._active = remaining
            self._identities = {item.sibling_identity for item in remaining.values()}

    async def _allocate(self, request: AllocationRequest) -> AllocatedWorld:
        allocation = await self._allocator.allocate(request)
        if not isinstance(allocation, AllocatedWorld):
            raise TypeError("allocator returned an invalid allocation")
        return allocation

    def _validate_allocation(
        self,
        request: AllocationRequest,
        allocation: AllocatedWorld,
        accepted: list[tuple[SearchCandidate, AllocationRequest, AllocatedWorld, CaptureReceipt]],
    ) -> None:
        if (
            allocation.candidate_id != request.candidate_id
            or allocation.target_tier is not request.target_tier
            or allocation.state_fingerprint != request.state_fingerprint
            or allocation.allocation_id in self._active
            or allocation.sibling_identity in self._identities
            or any(item[2].sibling_identity == allocation.sibling_identity for item in accepted)
        ):
            raise ValueError("allocator violated closed request or sibling isolation identity")

    @staticmethod
    def _validate_capture(
        candidate: SearchCandidate,
        request: AllocationRequest,
        allocation: AllocatedWorld,
        receipt: object,
    ) -> CaptureReceipt:
        if not isinstance(receipt, CaptureReceipt):
            raise TypeError("capture returned an invalid receipt")
        if (
            receipt.allocation_id != allocation.allocation_id
            or receipt.candidate_id != request.candidate_id
            or receipt.state_fingerprint != request.state_fingerprint
            or not receipt.oracle_passed
            or receipt.evidence_ref not in candidate.gates.evidence_ids
            or receipt.oracle_ref not in candidate.gates.oracle_refs
        ):
            raise ValueError("capture receipt failed evidence or oracle binding")
        return receipt

    async def _release_after_failure(self, allocation: AllocatedWorld) -> None:
        try:
            await self._allocator.release(allocation)
        except Exception:
            return

    async def _release_uncommitted(self, allocations: Iterable[AllocatedWorld]) -> None:
        for allocation in allocations:
            await self._release_after_failure(allocation)

    @staticmethod
    def _event(
        events: list[PromotionEvent],
        kind: PromotionEventKind,
        request: AllocationRequest,
        detail: str,
        *,
        allocation_id: str | None = None,
    ) -> None:
        events.append(
            PromotionEvent(
                sequence=len(events) + 1,
                kind=kind,
                candidate_id=request.candidate_id,
                target_tier=request.target_tier,
                reservation_id=request.reservation_id,
                allocation_id=allocation_id,
                detail=detail,
            )
        )


def _workflow_gate_error(candidate: SearchCandidate, target_tier: WorldTier) -> str | None:
    """Apply independent mandatory gates before any callback receives a request."""

    gates = candidate.gates
    if not gates.in_scope:
        return "out_of_scope"
    if gates.policy_outcome is PolicyGateOutcome.DENY:
        return "policy_denied"
    if gates.policy_outcome is PolicyGateOutcome.REQUIRE_APPROVAL and gates.approval_ref is None:
        return "approval_missing"
    if not set(gates.required_capabilities) <= set(gates.available_capabilities):
        return "capability_missing"
    if not gates.evidence_ids:
        return "evidence_missing"
    if not gates.oracle_refs:
        return "oracle_missing"
    if target_tier is WorldTier.MATERIALIZED and not gates.snapshot_capable:
        return "snapshot_missing"
    return None


def _safe_error_detail(error: Exception) -> str:
    """Record a stable class name without propagating callback text or secrets."""

    return f"callback_failed:{type(error).__name__.lower()}"
