"""M4 materialized search derived only from an admitted M3 observation."""

from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from pathlib import Path
from typing import Annotated, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator
from stateweaver.adapters.docker_compose import (
    MaterializedCandidateRequest,
    MaterializedProviderReceipt,
    RealDockerComposeEnvironmentAdapter,
)
from stateweaver.compiler import RootState
from stateweaver.contracts import (
    CanonicalSecurityState,
    ContractId,
    EstimatedCost,
    Hypothesis,
    OracleType,
    PredictedBoundary,
    Sha256Digest,
    StateCondition,
    TransitionFragment,
    WorldTier,
    canonical_json_bytes,
    sha256_digest,
)
from stateweaver.evidence import RuntimeObservationQualificationReceipt
from stateweaver.search import (
    BeamSearchPolicy,
    BudgetLedger,
    BudgetLimits,
    PolicyGateOutcome,
    PositiveScoreSignal,
    PromotionCost,
    PromotionGates,
    ScoreSignal,
    ScoreSource,
    SearchBatch,
    SearchCandidate,
    SearchScores,
)
from stateweaver.workflows.world import (
    AllocatedWorld,
    AllocationRequest,
    CaptureReceipt,
    PromotionRunContext,
    WorkflowResult,
    WorldPromotionWorkflow,
)
from stateweaver.worlds import EnvironmentHandle, SnapshotManifest, TargetSpec

from .runtime_qualification import qualify_runtime_observation_chain

_GHOST_COUNT = 24
_PROMOTION_COUNTS = (4, 2, 1)
_REPOSITORY_MARKER_RE = re.compile(r"^[0-9a-f]{40}$")
RepositoryMarker = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{40}$"),
]
_LIMITATIONS = (
    "This qualifies fixed six-provider Docker materialization for the exact retained M3 receipt.",
    "It is not an M5 chain, external-trust, independent-benchmark, or release receipt.",
)


class MaterializedSearchQualificationError(RuntimeError):
    """The real M4 run could not produce the exact closed qualification."""


class _QualificationModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class _M4EnvironmentAdapter(Protocol):
    async def prepare(self, target: TargetSpec) -> EnvironmentHandle: ...

    async def snapshot(self, env: EnvironmentHandle) -> SnapshotManifest: ...

    async def fork(self, snapshot: SnapshotManifest) -> EnvironmentHandle: ...

    async def materialize_observed_candidate(
        self,
        env: EnvironmentHandle,
        request: MaterializedCandidateRequest,
    ) -> MaterializedProviderReceipt: ...

    async def destroy(self, env: EnvironmentHandle) -> None: ...


def _signal(value: float, source: ScoreSource) -> ScoreSignal:
    return ScoreSignal(value=value, source=source)


def _evidence_score(semantic_digest: Sha256Digest, ordinal: int) -> float:
    score_digest = sha256_digest(
        {
            "m3_semantic_digest": semantic_digest,
            "mutation_ordinal": ordinal,
        }
    ).removeprefix("sha256:")
    fraction = int(score_digest[:12], 16) / float(0xFFFFFFFFFFFF)
    return 0.50 + fraction * 0.24


def derive_ghost_search_batch(
    observation: RuntimeObservationQualificationReceipt,
    observed_chain: tuple[RuntimeObservationQualificationReceipt, ...] | None = None,
) -> SearchBatch:
    """Derive the fixed 24-candidate Ghost frontier from one exact M3 receipt."""

    admitted = RuntimeObservationQualificationReceipt.model_validate(
        observation.model_dump(mode="python")
    )
    chain = (
        (admitted,)
        if observed_chain is None
        else tuple(
            RuntimeObservationQualificationReceipt.model_validate(item.model_dump(mode="python"))
            for item in observed_chain
        )
    )
    if not chain or chain[0] != admitted:
        raise MaterializedSearchQualificationError("M4 observed chain does not start at M3")
    fragments = tuple(item.projection.transition_fragment for item in chain)
    evidence_ids = tuple(
        sorted({evidence_id for fragment in fragments for evidence_id in fragment.evidence_ids})
    )
    semantic_digest = sha256_digest(tuple(item.semantic_digest for item in chain))
    seed = semantic_digest.removeprefix("sha256:")[:16]
    candidates: list[SearchCandidate] = []
    for index in range(_GHOST_COUNT):
        suffix = f"{index:02d}"
        score = _evidence_score(semantic_digest, index)
        state = CanonicalSecurityState(
            sessions=(),
            capabilities=("docker_compose_real_provider_snapshot",),
            controlled_time_bucket=index + 1,
            audit_metadata={
                "m3_semantic_digest": admitted.semantic_digest,
                "observed_chain_digest": semantic_digest,
                "mutation_ordinal": index,
            },
        )
        hypothesis = Hypothesis(
            hypothesis_id=f"hypothesis.m4.{seed}.{suffix}",
            claim=(
                "Observed session-retention transition remains distinguishable "
                f"in materialized sibling variant {suffix}"
            ),
            required_facts=("session_evidence_count",),
            predicted_boundary=PredictedBoundary(type=OracleType.AUTHORIZATION),
            novelty_score=score,
            information_gain=score,
            estimated_cost=EstimatedCost(
                llm_calls=0,
                target_requests=1,
                materialized_worlds=1,
            ),
            suggested_mutations=("session.retention_variant",),
        )
        oracle_ref = f"oracle.m4.provider-delta.{seed}.{suffix}"
        candidates.append(
            SearchCandidate(
                candidate_id=f"candidate.m4.{seed}.{suffix}",
                hypothesis=hypothesis,
                tier=WorldTier.GHOST,
                state=state,
                state_fingerprint=state.fingerprint(),
                diversity_key=f"family.m4.{index % 4}",
                scores=SearchScores(
                    boundary_impact=_signal(score, ScoreSource.DETERMINISTIC),
                    information_gain=_signal(score, ScoreSource.DETERMINISTIC),
                    novelty=_signal(score, ScoreSource.DETERMINISTIC),
                    composability=_signal(score, ScoreSource.DETERMINISTIC),
                    fidelity=_signal(score, ScoreSource.DETERMINISTIC),
                    reachability=_signal(score, ScoreSource.DETERMINISTIC),
                    normalized_cost=PositiveScoreSignal(
                        value=0.5,
                        source=ScoreSource.DETERMINISTIC,
                    ),
                    operational_risk=PositiveScoreSignal(
                        value=0.5,
                        source=ScoreSource.POLICY,
                    ),
                ),
                uncertainty=_signal(0.25, ScoreSource.DETERMINISTIC),
                transition_fragments=fragments,
                state_predicates=tuple(
                    condition for fragment in fragments for condition in fragment.preconditions
                ),
                gates=PromotionGates(
                    in_scope=True,
                    policy_outcome=PolicyGateOutcome.ALLOW,
                    policy_decision_ref=f"policy.m4.fixed-lab.{seed}.{suffix}",
                    reversible=True,
                    action_plan_refs=tuple(
                        f"plan.m4.{sha256_digest(fragment).removeprefix('sha256:')[:16]}.{suffix}"
                        for fragment in fragments
                    ),
                    expected_observations=tuple(
                        condition for fragment in fragments for condition in fragment.observables
                    ),
                    oracle_refs=(oracle_ref,),
                    evidence_ids=evidence_ids,
                    required_capabilities=("docker_compose_real_provider_snapshot",),
                    available_capabilities=("docker_compose_real_provider_snapshot",),
                    snapshot_capable=True,
                    new_fact_count=1,
                    calibration_path=True,
                ),
                promotion_cost=PromotionCost(
                    target_requests=1,
                    write_requests=1,
                    cpu_seconds=1,
                ),
            )
        )
    return SearchBatch(candidates=tuple(candidates))


def _retier(item: SearchCandidate, tier: WorldTier) -> SearchCandidate:
    return SearchCandidate.model_validate({**item.model_dump(mode="python"), "tier": tier})


class MaterializedSearchQualificationReceipt(_QualificationModel):
    """Self-validating M3→M4 receipt for 24→4→2→1 real-world search."""

    schema_version: Literal["stateweaver-m4-materialized-search-qualification-v2"]
    status: Literal["MATERIALIZED_SEARCH_QUALIFIED"]
    repository_marker: RepositoryMarker
    m3_qualification: RuntimeObservationQualificationReceipt
    m3_semantic_digest: Sha256Digest
    observed_chain: tuple[RuntimeObservationQualificationReceipt, ...]
    observed_chain_digest: Sha256Digest
    observed_transition_digest: Sha256Digest
    ghost_evaluation_count: Literal[24]
    promotion_counts: tuple[Literal[4], Literal[2], Literal[1]]
    materialized_world_count: Literal[7]
    peak_live_allocations: Literal[4]
    stages: tuple[WorkflowResult, WorkflowResult, WorkflowResult]
    provider_receipts: tuple[MaterializedProviderReceipt, ...]
    final_ledger: BudgetLedger
    winner: SearchCandidate
    winner_priority: Annotated[float, Field(ge=0.0)]
    winner_state_fingerprint: Sha256Digest
    winner_transition: TransitionFragment
    released_allocation_ids: tuple[ContractId, ...]
    residual_allocation_ids: tuple[ContractId, ...]
    limitations: tuple[str, ...]
    release_eligible: Literal[False]
    receipt_digest: Sha256Digest

    @model_validator(mode="after")
    def qualification_is_closed(self) -> MaterializedSearchQualificationReceipt:
        m3 = self.m3_qualification
        chain = self.observed_chain
        transitions = tuple(item.projection.transition_fragment for item in chain)
        if (
            self.repository_marker != m3.projection.repository_marker
            or self.m3_semantic_digest != m3.semantic_digest
            or len(chain) != 3
            or chain[0] != m3
            or any(item.projection.repository_marker != self.repository_marker for item in chain)
            or len({item.projection.action_digest for item in chain}) != 3
            or len({item.projection.transition_id for item in chain}) != 3
            or any(
                previous.projection.after_capture.payload_digest
                != following.projection.before_capture.payload_digest
                for previous, following in pairwise(chain)
            )
            or self.observed_chain_digest != sha256_digest(chain)
            or self.observed_transition_digest != sha256_digest(transitions)
        ):
            raise ValueError("M4 receipt does not bind the exact M3 qualification")
        if self.stages[0].search_batch != derive_ghost_search_batch(m3, chain):
            raise ValueError("M4 Ghost frontier is not derived from M3")
        expected_pairs = (
            (WorldTier.GHOST, WorldTier.REPLAY),
            (WorldTier.REPLAY, WorldTier.SIMULATED),
            (WorldTier.SIMULATED, WorldTier.MATERIALIZED),
        )
        for index, (stage, tiers, count) in enumerate(
            zip(self.stages, expected_pairs, _PROMOTION_COUNTS, strict=True)
        ):
            if (
                (stage.search.source_tier, stage.search.target_tier) != tiers
                or len(stage.promotions) != count
                or len(stage.search_batch.candidates) != (24, 4, 2)[index]
            ):
                raise ValueError("M4 stage does not preserve 24-to-4-to-2-to-1")
            if index and stage.input_ledger != self.stages[index - 1].committed_ledger:
                raise ValueError("M4 budget ledger is not conserved across stages")
            if index:
                previous = {
                    item.candidate_id: item
                    for item in self.stages[index - 1].search_batch.candidates
                }
                expected = tuple(
                    sorted(
                        (
                            _retier(previous[item.candidate_id], tiers[0])
                            for item in self.stages[index - 1].promotions
                        ),
                        key=lambda item: item.candidate_id,
                    )
                )
                if stage.search_batch.candidates != expected:
                    raise ValueError("M4 promotion frontier was substituted between stages")
        usage = self.final_ledger.usage()
        if (
            self.final_ledger != self.stages[-1].committed_ledger
            or (usage.replay_worlds, usage.simulated_worlds, usage.materialized_worlds)
            != _PROMOTION_COUNTS
            or usage.target_requests != 7
            or usage.write_requests != 7
            or usage.cpu_seconds != 7
        ):
            raise ValueError("M4 final budget ledger is invalid")
        promotions = tuple(item for stage in self.stages for item in stage.promotions)
        if len(self.provider_receipts) != 7 or len(promotions) != 7:
            raise ValueError("M4 receipt must bind exactly seven promoted real worlds")
        for promotion, provider in zip(promotions, self.provider_receipts, strict=True):
            request = provider.request
            if (
                request.allocation_id != promotion.allocation.allocation_id
                or request.candidate_id != promotion.candidate_id
                or request.source_tier
                is not self.stages[
                    (WorldTier.REPLAY, WorldTier.SIMULATED, WorldTier.MATERIALIZED).index(
                        promotion.target_tier
                    )
                ].search.source_tier
                or request.target_tier is not promotion.target_tier
                or request.candidate_fingerprint != promotion.allocation.state_fingerprint
                or request.observed_transition_digest != self.observed_transition_digest
                or request.evidence_ref != promotion.capture.evidence_ref
                or request.oracle_ref != promotion.capture.oracle_ref
                or not provider.oracle_passed
            ):
                raise ValueError("M4 provider receipt does not bind its promotion")
        final_promotion = self.stages[-1].promotions[0]
        final_candidates = {
            item.candidate_id: item for item in self.stages[-1].search_batch.candidates
        }
        expected_winner = final_candidates[final_promotion.candidate_id]
        if (
            self.winner != expected_winner
            or self.winner_state_fingerprint != expected_winner.state_fingerprint
            or self.winner_transition != transitions[-1]
            or expected_winner.transition_fragments != transitions
            or self.winner_priority
            != expected_winner.scores.priority(expected_winner.uncertainty.value, 0.25)
        ):
            raise ValueError("M4 winner is not derived from the materialized search")
        allocation_ids = tuple(item.allocation.allocation_id for item in promotions)
        if self.released_allocation_ids != allocation_ids or self.residual_allocation_ids:
            raise ValueError("M4 cleanup did not reclaim every materialized allocation")
        if self.limitations != _LIMITATIONS:
            raise ValueError("M4 qualification limitations are invalid")
        expected_digest = sha256_digest(self.model_dump(mode="python", exclude={"receipt_digest"}))
        if self.receipt_digest != expected_digest:
            raise ValueError("M4 qualification receipt digest is invalid")
        return self


class _DockerMaterializedWorldPort:
    """Production allocator/capture port backed by fixed M2 real-provider worlds."""

    def __init__(
        self,
        observation: RuntimeObservationQualificationReceipt,
        candidates: SearchBatch,
        *,
        observed_transition_digest: Sha256Digest,
        compiler_root_conditions: tuple[StateCondition, ...],
        adapter: _M4EnvironmentAdapter | None = None,
    ) -> None:
        self._observation = observation
        self._candidates = {item.candidate_id: item for item in candidates.candidates}
        self._observed_transition_digest = observed_transition_digest
        self._compiler_root_conditions = compiler_root_conditions
        self._adapter: _M4EnvironmentAdapter = (
            RealDockerComposeEnvironmentAdapter() if adapter is None else adapter
        )
        self._root_snapshot: SnapshotManifest | None = None
        self._environments: dict[str, EnvironmentHandle] = {}
        self._requests: dict[str, MaterializedCandidateRequest] = {}
        self._provider_receipts: list[MaterializedProviderReceipt] = []
        self._released: list[str] = []
        self._peak_live_allocations = 0

    @property
    def provider_receipts(self) -> tuple[MaterializedProviderReceipt, ...]:
        return tuple(self._provider_receipts)

    @property
    def released_allocation_ids(self) -> tuple[str, ...]:
        return tuple(self._released)

    @property
    def residual_allocation_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._environments))

    @property
    def peak_live_allocations(self) -> int:
        return self._peak_live_allocations

    async def open(self) -> None:
        if self._root_snapshot is not None:
            raise MaterializedSearchQualificationError("materializer is already open")
        root: EnvironmentHandle | None = None
        try:
            root = await self._adapter.prepare(
                TargetSpec(target_id="real-provider-demo", target_version="1.0.0")
            )
            self._root_snapshot = await self._adapter.snapshot(root)
        finally:
            if root is not None:
                await self._adapter.destroy(root)

    async def allocate(self, request: AllocationRequest) -> AllocatedWorld:
        if self._root_snapshot is None:
            raise MaterializedSearchQualificationError("materializer is not open")
        candidate = self._candidates.get(request.candidate_id)
        if candidate is None or candidate.state_fingerprint != request.state_fingerprint:
            raise MaterializedSearchQualificationError("promotion candidate is not admitted")
        ordinal = int(candidate.candidate_id.rsplit(".", maxsplit=1)[-1])
        seed = self._observation.semantic_digest.removeprefix("sha256:")[:16]
        allocation_id = f"allocation.m4.{request.target_tier.value}.{seed}.{ordinal:02d}"
        materialization = MaterializedCandidateRequest(
            allocation_id=allocation_id,
            candidate_id=request.candidate_id,
            source_tier=request.source_tier,
            target_tier=request.target_tier,
            candidate_fingerprint=request.state_fingerprint,
            observed_transition_digest=self._observed_transition_digest,
            evidence_ref=candidate.gates.evidence_ids[0],
            oracle_ref=candidate.gates.oracle_refs[0],
            ordinal=ordinal,
        )
        environment = await self._adapter.fork(self._root_snapshot)
        self._environments[allocation_id] = environment
        self._requests[allocation_id] = materialization
        self._peak_live_allocations = max(
            self._peak_live_allocations,
            len(self._environments),
        )
        return AllocatedWorld(
            allocation_id=allocation_id,
            candidate_id=request.candidate_id,
            target_tier=request.target_tier,
            state_fingerprint=request.state_fingerprint,
            sibling_identity=f"identity:world.m4.{environment.environment_id.removeprefix('environment:')}",
        )

    async def capture(
        self,
        request: AllocationRequest,
        allocation: AllocatedWorld,
    ) -> CaptureReceipt:
        environment = self._environments.get(allocation.allocation_id)
        materialization = self._requests.get(allocation.allocation_id)
        if environment is None or materialization is None:
            raise MaterializedSearchQualificationError("allocation is not retained")
        provider = await self._adapter.materialize_observed_candidate(
            environment,
            materialization,
        )
        self._provider_receipts.append(provider)
        return CaptureReceipt(
            allocation_id=allocation.allocation_id,
            candidate_id=request.candidate_id,
            state_fingerprint=request.state_fingerprint,
            compiler_root=RootState(
                root_seed_id=(
                    "root.m4.real-provider."
                    + self._observation.semantic_digest.removeprefix("sha256:")[:16]
                ),
                world_id=allocation.allocation_id,
                conditions=self._compiler_root_conditions,
            ),
            evidence_ref=materialization.evidence_ref,
            oracle_ref=materialization.oracle_ref,
            oracle_passed=provider.oracle_passed,
        )

    async def release(self, allocation: AllocatedWorld) -> None:
        environment = self._environments.get(allocation.allocation_id)
        if environment is None:
            return
        await self._adapter.destroy(environment)
        self._environments.pop(allocation.allocation_id)
        self._requests.pop(allocation.allocation_id, None)
        self._released.append(allocation.allocation_id)


def _ledger() -> BudgetLedger:
    return BudgetLedger(
        limits=BudgetLimits(
            max_llm_calls=0,
            max_target_requests=7,
            max_write_requests=7,
            max_cpu_seconds=7,
            max_ghost=24,
            max_replay=4,
            max_simulated=2,
            max_materialized=1,
        )
    )


async def _execute_materialized_search(
    observation: RuntimeObservationQualificationReceipt,
    *,
    observed_chain: tuple[RuntimeObservationQualificationReceipt, ...] | None = None,
    adapter: _M4EnvironmentAdapter | None = None,
) -> MaterializedSearchQualificationReceipt:
    if observed_chain is None:
        raise MaterializedSearchQualificationError("M4 requires the complete observed chain")
    chain = observed_chain
    ghosts = derive_ghost_search_batch(observation, chain)
    all_candidates = SearchBatch(candidates=ghosts.candidates)
    observed_transition_digest = sha256_digest(
        tuple(item.projection.transition_fragment for item in chain)
    )
    port = _DockerMaterializedWorldPort(
        observation,
        all_candidates,
        observed_transition_digest=observed_transition_digest,
        compiler_root_conditions=tuple(
            condition
            for item in chain
            for condition in item.projection.transition_fragment.preconditions
        ),
        adapter=adapter,
    )
    policy = BeamSearchPolicy(
        seed=19,
        replay_width=4,
        simulated_width=2,
        materialized_width=1,
        uncertainty_bonus=0.25,
    )
    workflow = WorldPromotionWorkflow(
        allocator=port,
        capture=port,
        ledger=_ledger(),
        policy=policy,
    )
    stages: list[WorkflowResult] = []
    started = datetime.now(UTC)
    await port.open()
    try:
        current = ghosts
        for index, next_tier in enumerate(
            (WorldTier.REPLAY, WorldTier.SIMULATED, WorldTier.MATERIALIZED)
        ):
            result = await workflow.advance(
                current,
                context=PromotionRunContext(
                    experiment_id="experiment.m4.materialized-search",
                    run_id=f"run.m4.materialized-search.{index + 1}",
                    recorded_at=started + timedelta(microseconds=index),
                ),
            )
            stages.append(result)
            if len(result.promotions) != _PROMOTION_COUNTS[index]:
                raise MaterializedSearchQualificationError(
                    "real materialization did not preserve the fixed beam width"
                )
            source = {item.candidate_id: item for item in current.candidates}
            if next_tier is not WorldTier.MATERIALIZED:
                current = SearchBatch(
                    candidates=tuple(
                        _retier(source[item.candidate_id], next_tier) for item in result.promotions
                    )
                )
            for promotion in result.promotions:
                await port.release(promotion.allocation)
        final_source = {item.candidate_id: item for item in current.candidates}
        winner = final_source[stages[-1].promotions[0].candidate_id]
    finally:
        await workflow.close()
    if port.residual_allocation_ids:
        raise MaterializedSearchQualificationError("materialized allocations remain after close")
    values: dict[str, object] = {
        "schema_version": "stateweaver-m4-materialized-search-qualification-v2",
        "status": "MATERIALIZED_SEARCH_QUALIFIED",
        "repository_marker": observation.projection.repository_marker,
        "m3_qualification": observation,
        "m3_semantic_digest": observation.semantic_digest,
        "observed_chain": chain,
        "observed_chain_digest": sha256_digest(chain),
        "observed_transition_digest": observed_transition_digest,
        "ghost_evaluation_count": 24,
        "promotion_counts": _PROMOTION_COUNTS,
        "materialized_world_count": 7,
        "peak_live_allocations": port.peak_live_allocations,
        "stages": tuple(stages),
        "provider_receipts": port.provider_receipts,
        "final_ledger": workflow.ledger,
        "winner": winner,
        "winner_priority": winner.scores.priority(winner.uncertainty.value, 0.25),
        "winner_state_fingerprint": winner.state_fingerprint,
        "winner_transition": chain[-1].projection.transition_fragment,
        "released_allocation_ids": port.released_allocation_ids,
        "residual_allocation_ids": port.residual_allocation_ids,
        "limitations": _LIMITATIONS,
        "release_eligible": False,
    }
    return MaterializedSearchQualificationReceipt.model_validate(
        {**values, "receipt_digest": sha256_digest(values)}
    )


def qualify_materialized_search(
    repository_marker: str,
) -> MaterializedSearchQualificationReceipt:
    """Execute M3 once, then qualify the exact 24→4→2→1 real-world search."""

    if _REPOSITORY_MARKER_RE.fullmatch(repository_marker) is None:
        raise MaterializedSearchQualificationError("repository marker must be an exact Git SHA")
    chain = qualify_runtime_observation_chain(repository_marker)
    return asyncio.run(_execute_materialized_search(chain[0], observed_chain=chain))


def write_materialized_search_qualification(
    output: Path,
    receipt: MaterializedSearchQualificationReceipt,
) -> None:
    """Validate and atomically-shaped-write one canonical M4 receipt."""

    admitted = MaterializedSearchQualificationReceipt.model_validate(
        receipt.model_dump(mode="python")
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical_json_bytes(admitted) + b"\n")


__all__ = [
    "MaterializedSearchQualificationError",
    "MaterializedSearchQualificationReceipt",
    "derive_ghost_search_batch",
    "qualify_materialized_search",
    "write_materialized_search_qualification",
]
