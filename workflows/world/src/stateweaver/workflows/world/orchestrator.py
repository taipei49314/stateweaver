"""Fail-closed, in-memory orchestration around the pure search controller."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable

from stateweaver.contracts import WorldTier
from stateweaver.search import (
    BeamSearchPolicy,
    BudgetLedger,
    PolicyGateOutcome,
    SearchBatch,
    SearchCandidate,
    TieredSearchController,
)

from .models import (
    AllocatedWorld,
    AllocationRequest,
    CaptureReceipt,
    PromotionRecord,
    PromotionRunContext,
    WorkflowResult,
)
from .ports import WorldAllocator, WorldCapture


class _AllocationIdCollision(ValueError):
    """An allocator returned an ownership handle already retained by the workflow."""

    def __init__(self, *, release_current: bool) -> None:
        super().__init__("allocator returned a duplicate allocation ID")
        self.release_current = release_current


class WorldPromotionWorkflow:
    """Allocate only controller-promoted candidates through closed async ports.

    `TieredSearchController` produces provisional reservations. This workflow
    commits only reservations with a matching allocation and capture receipt;
    failed callbacks never enter the committed ledger, and allocations whose
    compensating release fails remain tracked for a later `close()` retry.
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
        self._cleanup_pending: dict[int, AllocatedWorld] = {}
        self._cleanup_token = 0
        self._identities: set[str] = set()
        self._lock = asyncio.Lock()

    @property
    def ledger(self) -> BudgetLedger:
        """Return a closed copy of the committed budget state."""

        return BudgetLedger.model_validate(self._ledger.model_dump(mode="python"))

    @property
    def cleanup_pending_allocation_ids(self) -> tuple[str, ...]:
        """Return non-committed allocations retained after a failed release."""

        return tuple(sorted(item.allocation_id for item in self._cleanup_pending.values()))

    async def advance(
        self,
        batch: SearchBatch,
        *,
        context: PromotionRunContext,
    ) -> WorkflowResult:
        """Promote one source tier and return a canonical result-semantic history."""

        closed_batch = SearchBatch.model_validate(batch.model_dump(mode="python"))
        closed_context = PromotionRunContext.model_validate(context.model_dump(mode="python"))
        async with self._lock:
            before = self._ledger
            search = self._controller.advance(closed_batch, before)
            candidates = {item.candidate_id: item for item in closed_batch.candidates}
            newly_reserved = search.ledger.reservations[len(before.reservations) :]
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
                    gate_error = _workflow_gate_error(candidate, reservation.target_tier)
                    if gate_error is not None:
                        continue
                    allocation: AllocatedWorld | None = None
                    try:
                        allocation = await self._allocate(request)
                        self._validate_allocation(request, allocation, accepted)
                        receipt = await self._capture.capture(request, allocation)
                        receipt = self._validate_capture(
                            candidate,
                            request,
                            allocation,
                            receipt,
                        )
                    except asyncio.CancelledError:
                        if allocation is not None:
                            await self._release_after_failure(allocation)
                        raise
                    except _AllocationIdCollision as error:
                        collided = next(
                            (
                                item
                                for item in accepted
                                if allocation is not None
                                and item[2].allocation_id == allocation.allocation_id
                            ),
                            None,
                        )
                        cleanup: list[AllocatedWorld] = []
                        if collided is not None:
                            accepted.remove(collided)
                            cleanup.append(collided[2])
                        if error.release_current and allocation is not None:
                            cleanup.append(allocation)
                        elif allocation is not None:
                            # A duplicate of retained ownership cannot be safely released now:
                            # quarantine it until explicit workflow shutdown.
                            self._retain_cleanup(allocation)
                        await self._release_uncommitted(cleanup)
                        continue
                    except Exception:  # Callback boundaries must not promote on error.
                        if allocation is not None:
                            await self._release_after_failure(allocation)
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
            self._ledger = committed
            return WorkflowResult.create(
                context=closed_context,
                input_ledger=before,
                search_policy=self._controller.policy,
                search_batch=closed_batch,
                search=search,
                committed_ledger=committed,
                promotions=tuple(records),
            )

    async def close(self) -> None:
        """Release committed and cleanup-pending allocations; retain retryable failures."""

        async with self._lock:
            tagged = [
                ("active", allocation_id, allocation)
                for allocation_id, allocation in self._active.items()
            ] + [
                ("cleanup", cleanup_key, allocation)
                for cleanup_key, allocation in self._cleanup_pending.items()
            ]
            remaining_active: dict[str, AllocatedWorld] = {}
            remaining_cleanup: dict[int, AllocatedWorld] = {}
            for index, (kind, key, allocation) in enumerate(tagged):
                try:
                    await self._allocator.release(allocation)
                except asyncio.CancelledError:
                    self._retain_close_item(
                        kind,
                        key,
                        allocation,
                        remaining_active,
                        remaining_cleanup,
                    )
                    for pending_kind, pending_key, pending_allocation in tagged[index + 1 :]:
                        self._retain_close_item(
                            pending_kind,
                            pending_key,
                            pending_allocation,
                            remaining_active,
                            remaining_cleanup,
                        )
                    self._replace_retained(remaining_active, remaining_cleanup)
                    raise
                except Exception:
                    self._retain_close_item(
                        kind,
                        key,
                        allocation,
                        remaining_active,
                        remaining_cleanup,
                    )
            self._replace_retained(remaining_active, remaining_cleanup)

    async def _allocate(self, request: AllocationRequest) -> AllocatedWorld:
        allocation = await self._allocator.allocate(request)
        if not isinstance(allocation, AllocatedWorld):
            raise TypeError("allocator returned an invalid allocation")
        try:
            return AllocatedWorld.model_validate(allocation.model_dump(mode="python"))
        except (AttributeError, TypeError, ValueError) as error:
            raise TypeError("allocator returned an invalid allocation") from error

    def _validate_allocation(
        self,
        request: AllocationRequest,
        allocation: AllocatedWorld,
        accepted: list[tuple[SearchCandidate, AllocationRequest, AllocatedWorld, CaptureReceipt]],
    ) -> None:
        retained_ids = {
            *self._active,
            *(item.allocation_id for item in self._cleanup_pending.values()),
        }
        if allocation.allocation_id in retained_ids:
            raise _AllocationIdCollision(release_current=False)
        if any(item[2].allocation_id == allocation.allocation_id for item in accepted):
            raise _AllocationIdCollision(release_current=True)
        if (
            allocation.candidate_id != request.candidate_id
            or allocation.target_tier is not request.target_tier
            or allocation.state_fingerprint != request.state_fingerprint
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
        try:
            closed_receipt = CaptureReceipt.model_validate(receipt.model_dump(mode="python"))
        except (AttributeError, TypeError, ValueError) as error:
            raise TypeError("capture returned an invalid receipt") from error
        if (
            closed_receipt.allocation_id != allocation.allocation_id
            or closed_receipt.candidate_id != request.candidate_id
            or closed_receipt.state_fingerprint != request.state_fingerprint
            or not closed_receipt.oracle_passed
            or closed_receipt.evidence_ref not in candidate.gates.evidence_ids
            or closed_receipt.oracle_ref not in candidate.gates.oracle_refs
        ):
            raise ValueError("capture receipt failed evidence or oracle binding")
        return closed_receipt

    async def _release_after_failure(self, allocation: AllocatedWorld) -> None:
        try:
            await self._allocator.release(allocation)
        except asyncio.CancelledError:
            self._retain_cleanup(allocation)
            raise
        except Exception:
            self._retain_cleanup(allocation)

    def _retain_cleanup(self, allocation: AllocatedWorld) -> None:
        self._cleanup_token += 1
        self._cleanup_pending[self._cleanup_token] = allocation
        self._identities.add(allocation.sibling_identity)

    async def _release_uncommitted(self, allocations: Iterable[AllocatedWorld]) -> None:
        closed = tuple(allocations)
        for index, allocation in enumerate(closed):
            try:
                await self._release_after_failure(allocation)
            except asyncio.CancelledError:
                for pending in closed[index + 1 :]:
                    self._retain_cleanup(pending)
                raise

    @staticmethod
    def _retain_close_item(
        kind: str,
        key: str | int,
        allocation: AllocatedWorld,
        active: dict[str, AllocatedWorld],
        cleanup: dict[int, AllocatedWorld],
    ) -> None:
        if kind == "active":
            assert isinstance(key, str)
            active[key] = allocation
        else:
            assert isinstance(key, int)
            cleanup[key] = allocation

    def _replace_retained(
        self,
        active: dict[str, AllocatedWorld],
        cleanup: dict[int, AllocatedWorld],
    ) -> None:
        self._active = active
        self._cleanup_pending = cleanup
        self._identities = {item.sibling_identity for item in (*active.values(), *cleanup.values())}


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
