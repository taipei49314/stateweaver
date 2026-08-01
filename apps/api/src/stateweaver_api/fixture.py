"""Deterministic, in-process saved-run data. No external resources are consulted."""

from __future__ import annotations

from typing import Literal, cast

from stateweaver_api.models import (
    EvidenceManifestEntry,
    Fidelity,
    HealthResponse,
    InspectorSelection,
    NodeId,
    ObservationProvenance,
    OracleBinding,
    OverviewResponse,
    Provenance,
    RedactedObservation,
    ReplayLane,
    ReplayResponse,
    ReplayStep,
    RequiredFragment,
    RunHashes,
    RunSignature,
    RuntimeTrace,
    SatisfiedControl,
    Stage,
    StateDelta,
    TierCounts,
    TransitionFact,
    TwinFragment,
    TwinResponse,
    VerdictCard,
    WorldEdge,
    WorldNode,
    WorldsResponse,
    canonical_sha256,
)


def _digest(value: object) -> str:
    """Return the real canonical SHA-256 of closed synthetic fixture content."""
    return canonical_sha256(value)


def _bound_digest(**values: object) -> str:
    return _digest(values)


MANIFEST_SPECS = (
    ("evidence-01", "Recorded event summary"),
    ("evidence-02", "Typed state delta"),
    ("evidence-03", "Oracle comparison"),
    ("evidence-04", "Policy snapshot"),
    ("evidence-05", "Replay signature"),
)
MANIFEST_PAYLOAD = [
    {
        "digest": _bound_digest(entry_id=entry_id, label=label, verification="digest-only fixture"),
        "entry_id": entry_id,
        "label": label,
        "verification": "digest-only fixture",
    }
    for entry_id, label in MANIFEST_SPECS
]
ROOT_HASH = _bound_digest(node_id="root-00", pruned=False, status="RECORDED", tier="ROOT")
PLAN_HASH = _digest(
    {
        "fixture": "stateweaver-local-plan-v1",
        "steps": [
            "Session state retained",
            "Policy state compared",
            "Decision outcome recorded",
        ],
    }
)
ORACLE_HASH = _digest(
    {
        "fixture": "stateweaver-local-oracle-v1",
        "invariant": "patched lane blocks the synthetic terminal condition",
    }
)
EVIDENCE_HASH = _digest(MANIFEST_PAYLOAD)


DEMO_PROVENANCE = Provenance(
    boundary_label="SYNTHETIC LOCAL LAB",
    run_id="sw_demo_01",
    commit_placeholder="0000000000000000000000000000000000000000",
    mode="deterministic",
    oracle="deterministic",
    model_calls=0,
    workspace="local-lab",
    certification="not release-certified",
    fixture_status="saved synthetic implementation evidence",
    proof_status="not materialized proof",
)
DEMO_HASHES = RunHashes(
    root_hash=ROOT_HASH,
    plan_hash=PLAN_HASH,
    oracle_hash=ORACLE_HASH,
    evidence_hash=EVIDENCE_HASH,
)
DEMO_TIER_COUNTS = TierCounts(
    root=1,
    ghost=24,
    replay=4,
    simulated=2,
    materialized=1,
    pruned=17,
    flow="24 → 4 → 2 → 1",
)
IDENTICAL_SIGNATURE = _digest(
    {
        "oracle_hash": ORACLE_HASH,
        "patched": "BLOCKED_BY_FIX",
        "plan_hash": PLAN_HASH,
        "root_hash": ROOT_HASH,
        "vulnerable": "VIOLATED",
    }
)
DEMO_RUN_MARKERS = (
    RunSignature(ordinal=1, signature=IDENTICAL_SIGNATURE, status="matching fixture"),
    RunSignature(ordinal=2, signature=IDENTICAL_SIGNATURE, status="matching fixture"),
    RunSignature(ordinal=3, signature=IDENTICAL_SIGNATURE, status="matching fixture"),
    RunSignature(ordinal=4, signature=IDENTICAL_SIGNATURE, status="matching fixture"),
    RunSignature(ordinal=5, signature=IDENTICAL_SIGNATURE, status="matching fixture"),
)
DEMO_HEALTH = HealthResponse(status="ok", mode="read-only", provenance=DEMO_PROVENANCE)

DEMO_OVERVIEW = OverviewResponse(
    provenance=DEMO_PROVENANCE,
    hashes=DEMO_HASHES,
    title="Deterministic state exploration",
    stages=(
        Stage(
            sequence=1,
            label="Root captured",
            status="READY",
            evidence_digest=_bound_digest(label="Root captured", sequence=1, status="READY"),
        ),
        Stage(
            sequence=2,
            label="World search",
            status="READY",
            evidence_digest=_bound_digest(label="World search", sequence=2, status="READY"),
        ),
        Stage(
            sequence=3,
            label="Chain compiled",
            status="READY",
            evidence_digest=_bound_digest(label="Chain compiled", sequence=3, status="READY"),
        ),
        Stage(
            sequence=4,
            label="Clean replay",
            status="READY",
            evidence_digest=_bound_digest(label="Clean replay", sequence=4, status="READY"),
        ),
        Stage(
            sequence=5,
            label="Patched comparison",
            status="BLOCKED_BY_FIX",
            evidence_digest=_bound_digest(
                label="Patched comparison", sequence=5, status="BLOCKED_BY_FIX"
            ),
        ),
        Stage(
            sequence=6,
            label="Fixture integrity checked",
            status="READY",
            evidence_digest=_bound_digest(
                label="Fixture integrity checked", sequence=6, status="READY"
            ),
        ),
    ),
    tier_counts=DEMO_TIER_COUNTS,
    required_fragments=(
        RequiredFragment(
            fragment_id="fragment-a",
            label="Fragment A",
            semantic_label="historic session retained",
            evidence_digest=_bound_digest(
                fragment_id="fragment-a",
                label="Fragment A",
                semantic_label="historic session retained",
            ),
        ),
        RequiredFragment(
            fragment_id="fragment-b",
            label="Fragment B",
            semantic_label="async policy propagation delayed",
            evidence_digest=_bound_digest(
                fragment_id="fragment-b",
                label="Fragment B",
                semantic_label="async policy propagation delayed",
            ),
        ),
        RequiredFragment(
            fragment_id="fragment-c",
            label="Fragment C",
            semantic_label="stale authorization decision observed",
            evidence_digest=_bound_digest(
                fragment_id="fragment-c",
                label="Fragment C",
                semantic_label="stale authorization decision observed",
            ),
        ),
    ),
    run_markers=DEMO_RUN_MARKERS,
    verdicts=(
        VerdictCard(
            lane="Vulnerable",
            verdict="VIOLATED",
            color="violation",
            evidence_digest=_bound_digest(color="violation", lane="Vulnerable", verdict="VIOLATED"),
        ),
        VerdictCard(
            lane="Patched",
            verdict="BLOCKED_BY_FIX",
            color="blocked",
            evidence_digest=_bound_digest(
                color="blocked", lane="Patched", verdict="BLOCKED_BY_FIX"
            ),
        ),
        VerdictCard(
            lane="Control A",
            verdict="SATISFIED",
            color="satisfied",
            evidence_digest=_bound_digest(color="satisfied", lane="Control A", verdict="SATISFIED"),
        ),
        VerdictCard(
            lane="Control B",
            verdict="SATISFIED",
            color="satisfied",
            evidence_digest=_bound_digest(color="satisfied", lane="Control B", verdict="SATISFIED"),
        ),
    ),
)

GHOST_IDS = (
    "ghost-01",
    "ghost-02",
    "ghost-03",
    "ghost-04",
    "ghost-05",
    "ghost-06",
    "ghost-07",
    "ghost-08",
    "ghost-09",
    "ghost-10",
    "ghost-11",
    "ghost-12",
    "ghost-13",
    "ghost-14",
    "ghost-15",
    "ghost-16",
    "ghost-17",
    "ghost-18",
    "ghost-19",
    "ghost-20",
    "ghost-21",
    "ghost-22",
    "ghost-23",
    "ghost-24",
)


def _world_node(
    node_id: NodeId,
    tier: Literal["ROOT", "GHOST", "REPLAY", "SIMULATED", "MATERIALIZED"],
    *,
    pruned: bool,
    status: Literal["ACTIVE", "PRUNED", "RECORDED"],
) -> WorldNode:
    return WorldNode(
        node_id=node_id,
        tier=tier,
        fingerprint=_bound_digest(node_id=node_id, pruned=pruned, status=status, tier=tier),
        pruned=pruned,
        status=status,
    )


GHOST_NODES = tuple(
    _world_node(
        cast(NodeId, node_id),
        tier="GHOST",
        pruned=number <= 17,
        status="PRUNED" if number <= 17 else "ACTIVE",
    )
    for number, node_id in enumerate(GHOST_IDS, start=1)
)
REPLAY_NODES = (
    _world_node(
        "replay-01",
        tier="REPLAY",
        pruned=False,
        status="RECORDED",
    ),
    _world_node(
        "replay-02",
        tier="REPLAY",
        pruned=False,
        status="RECORDED",
    ),
    _world_node(
        "replay-03",
        tier="REPLAY",
        pruned=False,
        status="RECORDED",
    ),
    _world_node(
        "replay-04",
        tier="REPLAY",
        pruned=False,
        status="RECORDED",
    ),
)
SIMULATED_NODES = (
    _world_node(
        "simulated-01",
        tier="SIMULATED",
        pruned=False,
        status="RECORDED",
    ),
    _world_node(
        "simulated-02",
        tier="SIMULATED",
        pruned=False,
        status="RECORDED",
    ),
)
MATERIALIZED_NODE = _world_node(
    "materialized-01",
    tier="MATERIALIZED",
    pruned=False,
    status="RECORDED",
)
ROOT_NODE = _world_node(
    "root-00",
    tier="ROOT",
    pruned=False,
    status="RECORDED",
)
ROOT_EDGES = tuple(
    WorldEdge(
        from_node_id="root-00",
        to_node_id=cast(NodeId, node_id),
        relation="explores",
        pruned=number <= 17,
    )
    for number, node_id in enumerate(GHOST_IDS, start=1)
)
PATH_EDGES = (
    WorldEdge(from_node_id="ghost-18", to_node_id="replay-01", relation="replays", pruned=False),
    WorldEdge(from_node_id="ghost-21", to_node_id="replay-02", relation="replays", pruned=False),
    WorldEdge(from_node_id="ghost-22", to_node_id="replay-03", relation="replays", pruned=False),
    WorldEdge(from_node_id="ghost-24", to_node_id="replay-04", relation="replays", pruned=False),
    WorldEdge(
        from_node_id="replay-01", to_node_id="simulated-01", relation="simulates", pruned=False
    ),
    WorldEdge(
        from_node_id="replay-02", to_node_id="simulated-01", relation="simulates", pruned=False
    ),
    WorldEdge(
        from_node_id="replay-03", to_node_id="simulated-02", relation="simulates", pruned=False
    ),
    WorldEdge(
        from_node_id="replay-04", to_node_id="simulated-02", relation="simulates", pruned=False
    ),
    WorldEdge(
        from_node_id="simulated-01",
        to_node_id="materialized-01",
        relation="materializes",
        pruned=False,
    ),
    WorldEdge(
        from_node_id="simulated-02",
        to_node_id="materialized-01",
        relation="materializes",
        pruned=False,
    ),
)
DEMO_WORLDS = WorldsResponse(
    provenance=DEMO_PROVENANCE,
    hashes=DEMO_HASHES,
    tier_counts=DEMO_TIER_COUNTS,
    nodes=(ROOT_NODE, *GHOST_NODES, *REPLAY_NODES, *SIMULATED_NODES, MATERIALIZED_NODE),
    edges=(*ROOT_EDGES, *PATH_EDGES),
    selected_inspector=InspectorSelection(
        node_id="materialized-01",
        fingerprint=MATERIALIZED_NODE.fingerprint,
        tier="MATERIALIZED",
        parent_node_ids=("simulated-01", "simulated-02"),
        status="SELECTED",
    ),
)

COMMON_FIDELITY = Fidelity(
    completeness="fixture-only",
    ordering="deterministic fixture",
    timing="not modeled",
    determinism="deterministic",
)
COMMON_STATE_DELTA = (
    StateDelta(field="session_retention", before="retained", after="retained", effect="unchanged"),
    StateDelta(field="policy_propagation", before="delayed", after="propagated", effect="updated"),
    StateDelta(field="decision_freshness", before="stale", after="observed", effect="recorded"),
)


def _fact(
    label: Literal["precondition", "typed action", "effect", "evidence"], summary: str, index: int
) -> TransitionFact:
    del index
    return TransitionFact(
        label=label, summary=summary, digest=_bound_digest(label=label, summary=summary)
    )


def _twin_fragment(
    fragment_id: Literal["fragment-a", "fragment-b", "fragment-c"],
    label: Literal["Fragment A", "Fragment B", "Fragment C"],
    semantic_label: Literal[
        "historic session retained",
        "async policy propagation delayed",
        "stale authorization decision observed",
    ],
    source_node_id: Literal["replay-01", "replay-02", "replay-03"],
    source_fingerprint: str,
    trace_id: Literal["trace-local-fragment-a", "trace-local-fragment-b", "trace-local-fragment-c"],
    index: int,
) -> TwinFragment:
    return TwinFragment(
        fragment_id=fragment_id,
        label=label,
        semantic_label=semantic_label,
        provenance=ObservationProvenance(
            observation_status="SYNTHETIC",
            source_node_id=source_node_id,
            source_fingerprint=source_fingerprint,
        ),
        precondition=_fact("precondition", "recorded local state is available", index + 1),
        typed_action=_fact("typed action", "compare recorded typed state", index + 2),
        effect=_fact("effect", "recorded state transition is displayed", index + 3),
        evidence=_fact("evidence", "saved synthetic evidence is bound", index + 4),
        fidelity=COMMON_FIDELITY,
        state_delta=COMMON_STATE_DELTA,
        runtime_trace=RuntimeTrace(
            trace_id=trace_id,
            trace_digest=_bound_digest(runtime="local synthetic runtime", trace_id=trace_id),
            runtime="local synthetic runtime",
        ),
        oracle_binding=OracleBinding(
            oracle="deterministic",
            binding_digest=_bound_digest(
                oracle="deterministic", oracle_hash=DEMO_HASHES.oracle_hash
            ),
            oracle_hash=DEMO_HASHES.oracle_hash,
        ),
    )


DEMO_TWIN = TwinResponse(
    provenance=DEMO_PROVENANCE,
    hashes=DEMO_HASHES,
    title="Security Semantic Twin",
    fragments=(
        _twin_fragment(
            "fragment-a",
            "Fragment A",
            "historic session retained",
            "replay-01",
            REPLAY_NODES[0].fingerprint,
            "trace-local-fragment-a",
            500,
        ),
        _twin_fragment(
            "fragment-b",
            "Fragment B",
            "async policy propagation delayed",
            "replay-02",
            REPLAY_NODES[1].fingerprint,
            "trace-local-fragment-b",
            600,
        ),
        _twin_fragment(
            "fragment-c",
            "Fragment C",
            "stale authorization decision observed",
            "replay-03",
            REPLAY_NODES[2].fingerprint,
            "trace-local-fragment-c",
            700,
        ),
    ),
    selected_fragment_id="fragment-c",
)

STEP_LABELS: tuple[
    Literal["Session state retained"],
    Literal["Policy state compared"],
    Literal["Decision outcome recorded"],
] = ("Session state retained", "Policy state compared", "Decision outcome recorded")


def _replay_step(
    sequence: Literal[1, 2, 3],
    label: Literal["Session state retained", "Policy state compared", "Decision outcome recorded"],
    verdict: Literal["SATISFIED", "VIOLATED", "BLOCKED_BY_FIX"],
) -> ReplayStep:
    return ReplayStep(
        sequence=sequence,
        label=label,
        evidence_digest=_bound_digest(label=label, sequence=sequence, verdict=verdict),
        verdict=verdict,
    )


DEMO_VULNERABLE = ReplayLane(
    lane="Vulnerable",
    plan_hash=DEMO_HASHES.plan_hash,
    steps=(
        _replay_step(1, STEP_LABELS[0], "SATISFIED"),
        _replay_step(2, STEP_LABELS[1], "SATISFIED"),
        _replay_step(3, STEP_LABELS[2], "VIOLATED"),
    ),
    terminal_verdict="VIOLATED",
)
DEMO_PATCHED = ReplayLane(
    lane="Patched",
    plan_hash=DEMO_HASHES.plan_hash,
    steps=(
        _replay_step(1, STEP_LABELS[0], "SATISFIED"),
        _replay_step(2, STEP_LABELS[1], "SATISFIED"),
        _replay_step(3, STEP_LABELS[2], "BLOCKED_BY_FIX"),
    ),
    terminal_verdict="BLOCKED_BY_FIX",
)
DEMO_REPLAY = ReplayResponse(
    provenance=DEMO_PROVENANCE,
    hashes=DEMO_HASHES,
    title="Clean-root replay",
    vulnerable=DEMO_VULNERABLE,
    patched=DEMO_PATCHED,
    controls=(
        SatisfiedControl(
            control_id="control-a",
            label="Control A",
            verdict="SATISFIED",
            color="satisfied",
            evidence_digest=_bound_digest(
                color="satisfied",
                control_id="control-a",
                label="Control A",
                verdict="SATISFIED",
            ),
        ),
        SatisfiedControl(
            control_id="control-b",
            label="Control B",
            verdict="SATISFIED",
            color="satisfied",
            evidence_digest=_bound_digest(
                color="satisfied",
                control_id="control-b",
                label="Control B",
                verdict="SATISFIED",
            ),
        ),
    ),
    selected_observation=RedactedObservation(
        label="Observation (redacted)",
        summary="synthetic-local decision observation [redacted]",
        digest=_bound_digest(
            label="Observation (redacted)",
            summary="synthetic-local decision observation [redacted]",
        ),
    ),
    evidence_manifest=(
        EvidenceManifestEntry(
            entry_id="evidence-01",
            label="Recorded event summary",
            digest=MANIFEST_PAYLOAD[0]["digest"],
            verification="digest-only fixture",
        ),
        EvidenceManifestEntry(
            entry_id="evidence-02",
            label="Typed state delta",
            digest=MANIFEST_PAYLOAD[1]["digest"],
            verification="digest-only fixture",
        ),
        EvidenceManifestEntry(
            entry_id="evidence-03",
            label="Oracle comparison",
            digest=MANIFEST_PAYLOAD[2]["digest"],
            verification="digest-only fixture",
        ),
        EvidenceManifestEntry(
            entry_id="evidence-04",
            label="Policy snapshot",
            digest=MANIFEST_PAYLOAD[3]["digest"],
            verification="digest-only fixture",
        ),
        EvidenceManifestEntry(
            entry_id="evidence-05",
            label="Replay signature",
            digest=MANIFEST_PAYLOAD[4]["digest"],
            verification="digest-only fixture",
        ),
    ),
    run_markers=DEMO_RUN_MARKERS,
)
