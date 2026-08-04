"""Closed, immutable records for offline promotion orchestration."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated

from pydantic import Field, model_validator
from stateweaver.compiler import RootState
from stateweaver.contracts import (
    ContractId,
    Sha256Digest,
    WorldTier,
)
from stateweaver.contracts.base import ContractModel, IdentityHandle
from stateweaver.search import BeamSearchPolicy, BudgetLedger, SearchResult


class PromotionEventKind(StrEnum):
    RESERVED = "reserved"
    ALLOCATED = "allocated"
    CAPTURED = "captured"
    COMMITTED = "committed"
    BLOCKED = "blocked"
    ROLLED_BACK = "rolled_back"


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


class PromotionEvent(ContractModel):
    sequence: Annotated[int, Field(ge=1)]
    kind: PromotionEventKind
    candidate_id: ContractId
    target_tier: WorldTier
    reservation_id: ContractId | None = None
    allocation_id: ContractId | None = None
    detail: str

    @model_validator(mode="after")
    def allocation_shape_is_coherent(self) -> PromotionEvent:
        if self.kind is not PromotionEventKind.BLOCKED and self.reservation_id is None:
            raise ValueError("non-blocked events require a reservation ID")
        if self.kind in {PromotionEventKind.ALLOCATED, PromotionEventKind.CAPTURED}:
            if self.allocation_id is None:
                raise ValueError("allocation events require an allocation ID")
        elif self.allocation_id is not None:
            raise ValueError("only allocation and capture events may carry an allocation ID")
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


class WorkflowResult(ContractModel):
    input_ledger: BudgetLedger
    search_policy: BeamSearchPolicy
    search: SearchResult
    committed_ledger: BudgetLedger
    promotions: tuple[PromotionRecord, ...]
    events: tuple[PromotionEvent, ...]

    @model_validator(mode="after")
    def result_is_consistent(self) -> WorkflowResult:
        prefix = self.committed_ledger.reservations[: len(self.input_ledger.reservations)]
        if prefix != self.input_ledger.reservations:
            raise ValueError("committed ledger must preserve the complete input history")
        if tuple(event.sequence for event in self.events) != tuple(range(1, len(self.events) + 1)):
            raise ValueError("promotion events must have a contiguous sequence")
        ids = [item.candidate_id for item in self.promotions]
        allocation_ids = [item.allocation.allocation_id for item in self.promotions]
        identities = [item.allocation.sibling_identity for item in self.promotions]
        if (
            len(ids) != len(set(ids))
            or len(allocation_ids) != len(set(allocation_ids))
            or len(identities) != len(set(identities))
        ):
            raise ValueError(
                "committed promotions require unique candidates, allocations, "
                "and sibling identities"
            )
        reservations = {item.reservation_id for item in self.committed_ledger.reservations}
        if any(item.reservation_id not in reservations for item in self.promotions):
            raise ValueError("promotion must bind a committed reservation")
        return self

    @property
    def blocked_candidate_ids(self) -> tuple[str, ...]:
        return tuple(
            event.candidate_id for event in self.events if event.kind is PromotionEventKind.BLOCKED
        )
