"""M4 materialized-search qualification regressions."""

from __future__ import annotations

import asyncio
from copy import deepcopy

import pytest
from stateweaver.adapters.docker_compose import (
    MaterializedCandidateRequest,
    MaterializedProviderReceipt,
    RealDockerComposeEnvironmentAdapter,
)
from stateweaver.contracts import ProvenanceKind, WorldTier, canonical_json_bytes, sha256_digest
from stateweaver.search import ScoreSource
from stateweaver.worlds import (
    EnvironmentHandle,
    ResourceQuotas,
    SnapshotManifest,
    TargetSpec,
    WorldNamespace,
)

from stateweaver.cli.materialized_search_qualification import (
    MaterializedSearchQualificationError,
    MaterializedSearchQualificationReceipt,
    _execute_materialized_search,
    derive_ghost_search_batch,
    qualify_materialized_search,
)
from stateweaver.cli.runtime_qualification import qualify_runtime_observation

MARKER = "4" * 40
_PROVIDERS = ("cache", "clock", "database", "filesystem", "queue", "session")


class _MemoryRealProviderAdapter:
    """Port double for receipt/tier adversarial tests; the live test uses Docker."""

    def __init__(self) -> None:
        self._pin = RealDockerComposeEnvironmentAdapter().capabilities().pin
        self._counter = 0
        self._live: set[str] = set()
        self.allocated = 0
        self.max_live = 0

    def _handle(self) -> EnvironmentHandle:
        self._counter += 1
        token = f"{self._counter:032x}"
        environment_id = f"environment:{token}"
        self._live.add(environment_id)
        self.allocated += 1
        self.max_live = max(self.max_live, len(self._live))
        return EnvironmentHandle(
            adapter=self._pin,
            environment_id=environment_id,
            opaque_ref=f"memory:{token}",
            namespace=WorldNamespace(
                network=f"network:{token}",
                database=f"database:{token}",
                cache=f"cache:{token}",
                queue=f"queue:{token}",
                session=f"session:{token}",
                storage=f"storage:{token}",
            ),
            quotas=ResourceQuotas(
                cpu_seconds=60,
                memory_mb=512,
                pids=64,
                requests=1_000,
                concurrent_actions=4,
            ),
        )

    @staticmethod
    def _hashes(marker: str) -> dict[str, str]:
        return {
            provider: sha256_digest({"provider": provider, "marker": marker})
            for provider in _PROVIDERS
        }

    async def prepare(self, target: TargetSpec) -> EnvironmentHandle:
        assert target == TargetSpec(target_id="real-provider-demo", target_version="1.0.0")
        return self._handle()

    async def snapshot(self, env: EnvironmentHandle) -> SnapshotManifest:
        hashes = self._hashes("baseline")
        return SnapshotManifest(
            snapshot_id=f"snapshot:{env.environment_id.removeprefix('environment:')}",
            root_snapshot_id="root:m4-memory",
            source_environment_id=env.environment_id,
            target=TargetSpec(target_id="real-provider-demo", target_version="1.0.0"),
            adapter=self._pin,
            content_hashes=hashes,
            state_fingerprint=SnapshotManifest.derive_state_fingerprint(hashes),
        )

    async def fork(self, snapshot: SnapshotManifest) -> EnvironmentHandle:
        assert snapshot.root_snapshot_id == "root:m4-memory"
        return self._handle()

    async def materialize_observed_candidate(
        self,
        env: EnvironmentHandle,
        request: MaterializedCandidateRequest,
    ) -> MaterializedProviderReceipt:
        return MaterializedProviderReceipt.create(
            request=request,
            environment_id=env.environment_id,
            before=self._hashes("baseline"),
            after=self._hashes(request.marker),
            elapsed_ns=1,
        )

    async def destroy(self, env: EnvironmentHandle) -> None:
        self._live.discard(env.environment_id)


def test_ghost_batch_is_derived_from_the_exact_m3_observation() -> None:
    observed = qualify_runtime_observation(MARKER)

    batch = derive_ghost_search_batch(observed)

    assert len(batch.candidates) == 24
    assert {item.tier for item in batch.candidates} == {WorldTier.GHOST}
    assert len({item.candidate_id for item in batch.candidates}) == 24
    assert len({item.state_fingerprint for item in batch.candidates}) == 24
    assert all(
        item.transition_fragments == (observed.projection.transition_fragment,)
        for item in batch.candidates
    )
    assert all(
        item.transition_fragments[0].source is ProvenanceKind.OBSERVED for item in batch.candidates
    )
    assert all(
        set(item.transition_fragments[0].evidence_ids) <= set(item.gates.evidence_ids)
        for item in batch.candidates
    )
    assert all(
        item.scores.information_gain.source is ScoreSource.DETERMINISTIC
        and item.scores.novelty.source is ScoreSource.DETERMINISTIC
        and item.scores.fidelity.source is ScoreSource.DETERMINISTIC
        for item in batch.candidates
    )


def test_ghost_scores_change_with_the_admitted_m3_semantic_receipt() -> None:
    first = derive_ghost_search_batch(qualify_runtime_observation("4" * 40))
    second = derive_ghost_search_batch(qualify_runtime_observation("5" * 40))

    assert tuple(item.scores for item in first.candidates) != tuple(
        item.scores for item in second.candidates
    )


def test_non_sha_repository_marker_is_rejected_before_docker_execution() -> None:
    with pytest.raises(MaterializedSearchQualificationError, match="exact Git SHA"):
        qualify_materialized_search("local-working-tree")


def test_complete_receipt_conserves_budget_and_never_materializes_the_ghost_set() -> None:
    observed = qualify_runtime_observation(MARKER)
    adapter = _MemoryRealProviderAdapter()

    receipt = asyncio.run(_execute_materialized_search(observed, adapter=adapter))

    assert receipt.promotion_counts == (4, 2, 1)
    assert adapter.allocated == 8  # one root plus the seven admitted promotions
    assert adapter.max_live == 4
    assert receipt.peak_live_allocations == 4
    assert len(receipt.provider_receipts) == 7
    assert len(receipt.released_allocation_ids) == 7
    assert not receipt.residual_allocation_ids
    assert receipt.final_ledger.usage().target_requests == 7
    assert (
        MaterializedSearchQualificationReceipt.model_validate_json(canonical_json_bytes(receipt))
        == receipt
    )


def test_rehashed_stage_substitution_is_rejected() -> None:
    observed = qualify_runtime_observation(MARKER)
    receipt = asyncio.run(
        _execute_materialized_search(
            observed,
            adapter=_MemoryRealProviderAdapter(),
        )
    )
    substituted = deepcopy(receipt.model_dump(mode="json"))
    substituted["winner_priority"] = 0.0
    substituted["receipt_digest"] = sha256_digest(
        {key: value for key, value in substituted.items() if key != "receipt_digest"}
    )

    with pytest.raises(ValueError, match="winner"):
        MaterializedSearchQualificationReceipt.model_validate_json(
            canonical_json_bytes(substituted)
        )
