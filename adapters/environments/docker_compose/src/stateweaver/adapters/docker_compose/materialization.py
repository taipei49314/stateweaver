"""Closed M4 mutation and six-provider observation contracts."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from stateweaver.contracts import ContractId, Sha256Digest, WorldTier, sha256_digest

ProviderName = Literal["cache", "clock", "database", "filesystem", "queue", "session"]
_PROVIDERS: tuple[ProviderName, ...] = (
    "cache",
    "clock",
    "database",
    "filesystem",
    "queue",
    "session",
)
_NEXT_TIER = {
    WorldTier.GHOST: WorldTier.REPLAY,
    WorldTier.REPLAY: WorldTier.SIMULATED,
    WorldTier.SIMULATED: WorldTier.MATERIALIZED,
}
_TICK_OFFSET = {
    WorldTier.REPLAY: 100,
    WorldTier.SIMULATED: 200,
    WorldTier.MATERIALIZED: 300,
}


class _MaterializationModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class MaterializedCandidateRequest(_MaterializationModel):
    """No-command request for one pre-admitted observed candidate."""

    allocation_id: ContractId
    candidate_id: ContractId
    source_tier: WorldTier
    target_tier: WorldTier
    candidate_fingerprint: Sha256Digest
    observed_transition_digest: Sha256Digest
    evidence_ref: ContractId
    oracle_ref: ContractId
    ordinal: Annotated[int, Field(ge=0, lt=24)]

    @model_validator(mode="after")
    def tier_step_is_exact(self) -> MaterializedCandidateRequest:
        if self.source_tier is WorldTier.MATERIALIZED:
            raise ValueError("materialized candidates cannot be promoted again")
        if _NEXT_TIER[self.source_tier] is not self.target_tier:
            raise ValueError("materialization request must advance exactly one tier")
        return self

    @property
    def marker(self) -> str:
        digest = sha256_digest(self).removeprefix("sha256:")
        return f"m4-{digest[:24]}"

    @property
    def tick(self) -> int:
        return _TICK_OFFSET[self.target_tier] + self.ordinal + 1


class ProviderStateChange(_MaterializationModel):
    provider: ProviderName
    before_sha256: Sha256Digest
    after_sha256: Sha256Digest

    @model_validator(mode="after")
    def provider_changed(self) -> ProviderStateChange:
        if self.before_sha256 == self.after_sha256:
            raise ValueError("materialized provider did not change")
        return self


class MaterializedProviderReceipt(_MaterializationModel):
    """Atomic before/mutate/after observation from one real-provider sibling."""

    schema_version: Literal["stateweaver-m4-provider-materialization-v1"]
    request: MaterializedCandidateRequest
    request_digest: Sha256Digest
    environment_id: ContractId
    marker: str
    tick: Annotated[int, Field(ge=1, le=324)]
    providers: tuple[ProviderStateChange, ...]
    changed_provider_count: Literal[6]
    elapsed_ns: Annotated[int, Field(ge=0)]
    provider_state_digest: Sha256Digest
    oracle_passed: Literal[True]
    receipt_digest: Sha256Digest

    @model_validator(mode="after")
    def receipt_is_content_bound(self) -> MaterializedProviderReceipt:
        if self.request_digest != sha256_digest(self.request):
            raise ValueError("materialization request digest is invalid")
        if self.marker != self.request.marker or self.tick != self.request.tick:
            raise ValueError("materialization marker is not request-derived")
        if tuple(item.provider for item in self.providers) != _PROVIDERS:
            raise ValueError("materialization receipt must cover every provider exactly once")
        after = {item.provider: item.after_sha256 for item in self.providers}
        if self.provider_state_digest != sha256_digest(after):
            raise ValueError("materialized provider state digest is invalid")
        expected = sha256_digest(self.model_dump(mode="python", exclude={"receipt_digest"}))
        if self.receipt_digest != expected:
            raise ValueError("materialization receipt digest is invalid")
        return self

    @classmethod
    def create(
        cls,
        *,
        request: MaterializedCandidateRequest,
        environment_id: ContractId,
        before: dict[str, str],
        after: dict[str, str],
        elapsed_ns: int,
    ) -> MaterializedProviderReceipt:
        if tuple(sorted(before)) != _PROVIDERS or tuple(sorted(after)) != _PROVIDERS:
            raise ValueError("materialization capture does not cover the fixed providers")
        providers = tuple(
            ProviderStateChange(
                provider=provider,
                before_sha256=before[provider],
                after_sha256=after[provider],
            )
            for provider in _PROVIDERS
        )
        values: dict[str, object] = {
            "schema_version": "stateweaver-m4-provider-materialization-v1",
            "request": request,
            "request_digest": sha256_digest(request),
            "environment_id": environment_id,
            "marker": request.marker,
            "tick": request.tick,
            "providers": providers,
            "changed_provider_count": 6,
            "elapsed_ns": elapsed_ns,
            "provider_state_digest": sha256_digest(
                {item.provider: item.after_sha256 for item in providers}
            ),
            "oracle_passed": True,
        }
        return cls.model_validate({**values, "receipt_digest": sha256_digest(values)})


__all__ = [
    "MaterializedCandidateRequest",
    "MaterializedProviderReceipt",
    "ProviderStateChange",
]
