"""Socket-free M3 -> M4 -> M5 proof over the same observed fragments."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from search_test_fixtures import candidate, ledger
from stateweaver.adapters.telemetry.opentelemetry import (
    ADAPTER_NAME,
    ADAPTER_VERSION,
    TraceIngestRequest,
    canonical_spans_sha256,
    decode_otlp_json,
    ingest_otlp_json,
)
from stateweaver.compiler import CompilerFragment, RootState, TerminalGoal
from stateweaver.contracts import (
    ActionEnvelope,
    ActionGuard,
    ActionTarget,
    ComparisonOperator,
    EffectOperation,
    EvidenceKind,
    EvidenceProducer,
    EvidenceRecord,
    ExpectedEffect,
    FidelityLevel,
    FidelityProfile,
    HttpMethod,
    HttpRequestAction,
    Provenance,
    ProvenanceKind,
    RequestedBy,
    RequesterType,
    RiskClass,
    ScopeAction,
    StateCondition,
    StateEffect,
    Taint,
    TraceContext,
    TransitionFragment,
    WorldTier,
    sha256_digest,
)
from stateweaver.search import (
    BeamSearchPolicy,
    PolicyGateOutcome,
    PromotionGates,
    SearchBatch,
    SearchCandidate,
)
from stateweaver.twin import SecuritySemanticTwinBuilder, StateDelta, TwinBuildInput
from stateweaver.workflows.world import (
    AllocatedWorld,
    AllocationRequest,
    CaptureReceipt,
    PromotionRunContext,
    WorldPromotionWorkflow,
    compile_observed_promotion,
)

EPOCH = datetime(2026, 1, 1, tzinfo=UTC)
RESOURCE_ID = "resource.pipeline.state"
PRIMARY_ID = "candidate.synthetic.900"
TERMINAL_CONDITION = StateCondition(
    path="capability.foreign_read",
    operator=ComparisonOperator.EQ,
    value=True,
)
ROOT_CONDITIONS = (
    StateCondition(
        path="session.retained",
        operator=ComparisonOperator.EQ,
        value=False,
    ),
    StateCondition(
        path="cache.stale",
        operator=ComparisonOperator.EQ,
        value=False,
    ),
    StateCondition(
        path="capability.foreign_read",
        operator=ComparisonOperator.EQ,
        value=False,
    ),
)


def _attribute(key: str, kind: str, value: object) -> dict[str, Any]:
    return {"key": key, "value": {kind: value}}


def _otlp_document(*, index: int, method: str, route: str, status: int) -> dict[str, Any]:
    trace_id = f"{index + 1:032x}"
    span_id = f"{index + 1:016x}"
    start = 1_767_225_600_000_000_000 + index * 20_000_000
    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [_attribute("service.name", "stringValue", "pipeline-testclient")]
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "pipeline-testclient", "version": "1.0.0"},
                        "spans": [
                            {
                                "traceId": trace_id,
                                "spanId": span_id,
                                "name": f"{method} {route}",
                                "kind": "SPAN_KIND_SERVER",
                                "startTimeUnixNano": str(start),
                                "endTimeUnixNano": str(start + 10_000_000),
                                "attributes": [
                                    _attribute("http.request.method", "stringValue", method),
                                    _attribute("http.route", "stringValue", route),
                                    _attribute(
                                        "http.response.status_code", "intValue", str(status)
                                    ),
                                ],
                            }
                        ],
                    }
                ],
            }
        ]
    }


def _observed_fragments() -> tuple[TransitionFragment, ...]:
    app = FastAPI(title="StateWeaver pipeline lab", version="1.0.0")
    state = {
        "session_retained": False,
        "cache_stale": False,
        "foreign_read": False,
    }

    @app.post("/pipeline/retain")
    def retain_session() -> dict[str, bool]:
        state["session_retained"] = True
        return {"retained": state["session_retained"]}

    @app.post("/pipeline/stale-cache")
    def stale_cache() -> dict[str, bool]:
        assert state["session_retained"] is True
        state["cache_stale"] = True
        return {"stale": state["cache_stale"]}

    @app.post("/pipeline/foreign-read")
    def foreign_read() -> dict[str, bool]:
        assert state["cache_stale"] is True
        state["foreign_read"] = True
        return {"allowed": state["foreign_read"]}

    specifications = (
        (
            "/pipeline/retain",
            "transition.pipeline.01",
            "session retained",
            StateCondition(
                path="session.retained",
                operator=ComparisonOperator.EQ,
                value=False,
            ),
            StateEffect(
                path="session.retained",
                operation=EffectOperation.SET,
                value=True,
            ),
            StateCondition(
                path="response.retained",
                operator=ComparisonOperator.EQ,
                value=True,
            ),
        ),
        (
            "/pipeline/stale-cache",
            "transition.pipeline.02",
            "stale cache retained authorization",
            StateCondition(
                path="session.retained",
                operator=ComparisonOperator.EQ,
                value=True,
            ),
            StateEffect(
                path="cache.stale",
                operation=EffectOperation.SET,
                value=True,
            ),
            StateCondition(
                path="response.stale",
                operator=ComparisonOperator.EQ,
                value=True,
            ),
        ),
        (
            "/pipeline/foreign-read",
            "transition.pipeline.03",
            "foreign read capability",
            StateCondition(
                path="cache.stale",
                operator=ComparisonOperator.EQ,
                value=True,
            ),
            StateEffect(
                path="capability.foreign_read",
                operation=EffectOperation.SET,
                value=True,
            ),
            StateCondition(
                path="response.allowed",
                operator=ComparisonOperator.EQ,
                value=True,
            ),
        ),
    )
    records: list[EvidenceRecord] = []
    flows = []
    with TestClient(app, base_url="http://localhost") as client:
        for index, (
            path,
            transition_id,
            name,
            precondition,
            effect,
            observable,
        ) in enumerate(specifications):
            response = client.post(path)
            assert response.status_code == 200
            assert response.request.url.host == "localhost"
            document = _otlp_document(
                index=index,
                method=response.request.method,
                route=path,
                status=response.status_code,
            )
            spans = decode_otlp_json(document)
            span = spans[0]
            trace_evidence = EvidenceRecord(
                evidence_id=f"evidence.pipeline.trace.{index + 1:02d}",
                kind=EvidenceKind.OTEL_TRACE,
                artifact_uri=f"artifact://synthetic/pipeline/trace/{index + 1:02d}",
                sha256=canonical_spans_sha256(spans),
                produced_by=EvidenceProducer(
                    adapter=ADAPTER_NAME,
                    version=ADAPTER_VERSION,
                ),
                trace_context=TraceContext(
                    trace_id=span.trace_id,
                    span_id=span.span_id,
                ),
                redaction_policy_version="synthetic-v1",
                taint=Taint.TRUSTED_RUNTIME,
                created_at=EPOCH + timedelta(milliseconds=index * 20 + 10),
            )
            state_evidence = EvidenceRecord(
                evidence_id=f"evidence.pipeline.state.{index + 1:02d}",
                kind=EvidenceKind.STATE_SNAPSHOT,
                artifact_uri=f"artifact://synthetic/pipeline/state/{index + 1:02d}",
                sha256=sha256_digest(
                    {
                        "transition_id": transition_id,
                        "precondition": precondition,
                        "effect": effect,
                        "observable": observable,
                        "response": cast(dict[str, object], response.json()),
                    }
                ),
                produced_by=EvidenceProducer(
                    adapter="testclient-state-observer",
                    version="0.1.0",
                ),
                redaction_policy_version="synthetic-v1",
                taint=Taint.TRUSTED_RUNTIME,
                created_at=EPOCH + timedelta(milliseconds=index * 20 + 10),
            )
            delta = StateDelta(
                delta_id=f"delta.pipeline.{index + 1:02d}",
                subject=RESOURCE_ID,
                precondition=precondition,
                effect=effect,
                observable=observable,
                provenance=Provenance(
                    kind=ProvenanceKind.OBSERVED,
                    evidence_ids=(state_evidence.evidence_id,),
                    adapter=state_evidence.produced_by.adapter,
                    adapter_version=state_evidence.produced_by.version,
                ),
                observed_at=EPOCH + timedelta(milliseconds=index * 20 + 5),
            )
            action = HttpRequestAction(
                method=HttpMethod.POST,
                target=ActionTarget(
                    scheme="http",
                    host="localhost",
                    port=response.request.url.port or 80,
                    path=path,
                ),
                expected_statuses=(response.status_code,),
            )
            flows.append(
                ingest_otlp_json(
                    TraceIngestRequest(
                        transition_id=transition_id,
                        name=name,
                        action=action,
                        expected_route=path,
                        trace_evidence=trace_evidence,
                        state_deltas=(delta,),
                        fidelity=FidelityProfile(
                            code=FidelityLevel.EXACT,
                            timing=FidelityLevel.OBSERVED,
                        ),
                    ),
                    document,
                )
            )
            records.extend((trace_evidence, state_evidence))

    twin = SecuritySemanticTwinBuilder().build(
        TwinBuildInput(
            twin_id="twin.pipeline.integration",
            evidence_records=tuple(records),
            telemetry_flows=tuple(flows),
        )
    )
    assert len(twin.transitions) == 3
    assert all(item.source is ProvenanceKind.OBSERVED for item in twin.transitions)
    return twin.transitions


def _primary_candidate(fragments: tuple[TransitionFragment, ...]) -> SearchCandidate:
    base = candidate(
        900,
        tier=WorldTier.GHOST,
        score=0.99,
        diversity="family.pipeline.observed",
        with_fragment=False,
    )
    evidence_ids = tuple(
        sorted({evidence_id for fragment in fragments for evidence_id in fragment.evidence_ids})
    )
    gates = PromotionGates(
        in_scope=True,
        policy_outcome=PolicyGateOutcome.ALLOW,
        policy_decision_ref="policy.pipeline.observed",
        reversible=True,
        action_plan_refs=("plan.pipeline.observed",),
        expected_observations=(
            TERMINAL_CONDITION,
            *(item for fragment in fragments for item in fragment.observables),
        ),
        oracle_refs=("oracle.pipeline.terminal",),
        evidence_ids=evidence_ids,
        required_capabilities=("synthetic_snapshot",),
        available_capabilities=("synthetic_snapshot",),
        snapshot_capable=True,
        new_fact_count=3,
        calibration_path=False,
    )
    payload = base.model_dump(mode="python")
    payload.update(transition_fragments=fragments, gates=gates)
    return SearchCandidate.model_validate(payload)


def _retier(item: SearchCandidate, tier: WorldTier) -> SearchCandidate:
    payload = item.model_dump(mode="python")
    payload["tier"] = tier
    return SearchCandidate.model_validate(payload)


@dataclass
class _MemoryAllocator:
    allocated: list[AllocatedWorld] = field(default_factory=list)
    released: list[AllocatedWorld] = field(default_factory=list)

    async def allocate(self, request: AllocationRequest) -> AllocatedWorld:
        suffix = request.candidate_id.removeprefix("candidate.")
        allocation = AllocatedWorld(
            allocation_id=f"allocation.{request.target_tier.value}.{suffix}",
            candidate_id=request.candidate_id,
            target_tier=request.target_tier,
            state_fingerprint=request.state_fingerprint,
            sibling_identity=f"identity:world.{request.target_tier.value}.{suffix}",
        )
        self.allocated.append(allocation)
        return allocation

    async def release(self, allocation: AllocatedWorld) -> None:
        self.released.append(allocation)


@dataclass(frozen=True)
class _MemoryCapture:
    refs: dict[str, tuple[str, str]]

    async def capture(
        self, request: AllocationRequest, allocation: AllocatedWorld
    ) -> CaptureReceipt:
        evidence_ref, oracle_ref = self.refs[request.candidate_id]
        return CaptureReceipt(
            allocation_id=allocation.allocation_id,
            candidate_id=request.candidate_id,
            state_fingerprint=request.state_fingerprint,
            compiler_root=RootState(
                root_seed_id="root.pipeline.clean",
                world_id=allocation.allocation_id,
                conditions=ROOT_CONDITIONS,
            ),
            evidence_ref=evidence_ref,
            oracle_ref=oracle_ref,
            oracle_passed=True,
        )


def _compiler_fragments(
    fragments: tuple[TransitionFragment, ...], world_id: str
) -> tuple[CompilerFragment, ...]:
    output = []
    for index, fragment in enumerate(fragments, start=1):
        precondition = fragment.preconditions[0]
        effect = fragment.effects[0]
        envelope = ActionEnvelope(
            action_id=f"action.pipeline.{index:02d}",
            experiment_id="experiment.pipeline.observed",
            world_id=world_id,
            scope_action=ScopeAction.HTTP_REQUEST,
            action=fragment.action,
            preconditions=(ActionGuard(path=precondition.path, expected=precondition.value),),
            expected_effects=(
                ExpectedEffect(
                    path=effect.path,
                    operation=effect.operation,
                    value=effect.value,
                ),
            ),
            risk_class=RiskClass.REVERSIBLE_STATE_CHANGE,
            idempotency_key=sha256_digest({"experiment": "pipeline-observed", "index": index}),
            requested_by=RequestedBy(
                type=RequesterType.WORKFLOW,
                role="observed-chain-compiler",
            ),
            policy_decision_ref="policy.pipeline.observed",
            sequence=99 - index,
        )
        output.append(
            CompilerFragment(
                fragment=fragment,
                envelope=envelope,
                world_id=world_id,
            )
        )
    return tuple(output)


@pytest.mark.asyncio
async def test_same_observed_fragments_flow_24_to_4_to_2_to_1_and_compile() -> None:
    fragments = _observed_fragments()
    primary = _primary_candidate(fragments)
    ghosts = SearchBatch(
        candidates=(
            primary,
            *(candidate(index, score=0.40 + index / 100) for index in range(23)),
        )
    )
    refs = {
        item.candidate_id: (item.gates.evidence_ids[0], item.gates.oracle_refs[0])
        for item in ghosts.candidates
    }
    allocator = _MemoryAllocator()
    workflow = WorldPromotionWorkflow(
        allocator=allocator,
        capture=_MemoryCapture(refs),
        ledger=ledger(max_replay=4, max_simulated=2, max_materialized=1),
        policy=BeamSearchPolicy(
            seed=23,
            replay_width=4,
            simulated_width=2,
            materialized_width=1,
        ),
    )

    replay = await workflow.advance(
        ghosts,
        context=PromotionRunContext(
            experiment_id="experiment.pipeline.observed",
            run_id="run.pipeline.replay",
            recorded_at=EPOCH + timedelta(hours=1),
        ),
    )
    assert len(replay.promotions) == 4
    assert PRIMARY_ID in {item.candidate_id for item in replay.promotions}
    ghosts_by_id = {item.candidate_id: item for item in ghosts.candidates}
    replay_batch = SearchBatch(
        candidates=tuple(
            _retier(ghosts_by_id[item.candidate_id], WorldTier.REPLAY) for item in replay.promotions
        )
    )

    simulated = await workflow.advance(
        replay_batch,
        context=PromotionRunContext(
            experiment_id="experiment.pipeline.observed",
            run_id="run.pipeline.simulated",
            recorded_at=EPOCH + timedelta(hours=2),
        ),
    )
    assert len(simulated.promotions) == 2
    assert PRIMARY_ID in {item.candidate_id for item in simulated.promotions}
    replay_by_id = {item.candidate_id: item for item in replay_batch.candidates}
    simulated_batch = SearchBatch(
        candidates=tuple(
            _retier(replay_by_id[item.candidate_id], WorldTier.SIMULATED)
            for item in simulated.promotions
        )
    )

    materialized = await workflow.advance(
        simulated_batch,
        context=PromotionRunContext(
            experiment_id="experiment.pipeline.observed",
            run_id="run.pipeline.materialized",
            recorded_at=EPOCH + timedelta(hours=3),
        ),
    )
    assert tuple(item.candidate_id for item in materialized.promotions) == (PRIMARY_ID,)
    promotion = materialized.promotions[0]
    admitted_candidate = next(
        item for item in simulated_batch.candidates if item.candidate_id == PRIMARY_ID
    )
    assert admitted_candidate.transition_fragments == fragments
    assert (
        workflow.ledger.usage().replay_worlds,
        workflow.ledger.usage().simulated_worlds,
        workflow.ledger.usage().materialized_worlds,
    ) == (4, 2, 1)

    compiler_fragments = _compiler_fragments(
        admitted_candidate.transition_fragments,
        promotion.allocation.allocation_id,
    )
    admission = compile_observed_promotion(
        batch=simulated_batch,
        workflow=materialized,
        candidate_id=PRIMARY_ID,
        chain_id="chain.pipeline.observed",
        fragments=reversed(compiler_fragments),
        goal=TerminalGoal(
            goal_id="goal.pipeline.foreign-read",
            conditions=(TERMINAL_CONDITION,),
        ),
    )

    assert admission.compiled_chain.fragment_ids == tuple(item.transition_id for item in fragments)
    assert admission.compiled_chain.world_id == promotion.allocation.allocation_id
    assert admission.compiled_chain.requires_policy_reauthorization is True
    replay_plan = admission.compiled_chain.to_replay_plan(plan_id="plan.pipeline.clean-replay")
    assert tuple(step.action.action for step in replay_plan.steps) == tuple(
        item.action for item in fragments
    )
    assert tuple(step.action.sequence for step in replay_plan.steps) == (0, 1, 2)
    assert admission.chain_fingerprint == sha256_digest(admission.compiled_chain)
    assert admission.admission_fingerprint == sha256_digest(admission.admission_projection())

    await workflow.close()
    assert len(allocator.released) == 7
