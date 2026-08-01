"""Closed, immutable response schemas for the built-in local saved run."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

type Sha256Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
type NodeId = Literal[
    "root-00",
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
    "replay-01",
    "replay-02",
    "replay-03",
    "replay-04",
    "simulated-01",
    "simulated-02",
    "materialized-01",
]


def canonical_sha256(value: object) -> str:
    """Hash a JSON-compatible value with the demo's closed canonical encoding."""
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


_FIXED_MANIFEST_SPECS = (
    ("evidence-01", "Recorded event summary"),
    ("evidence-02", "Typed state delta"),
    ("evidence-03", "Oracle comparison"),
    ("evidence-04", "Policy snapshot"),
    ("evidence-05", "Replay signature"),
)
_FIXED_MANIFEST = [
    {
        "digest": canonical_sha256(
            {"entry_id": entry_id, "label": label, "verification": "digest-only fixture"}
        ),
        "entry_id": entry_id,
        "label": label,
        "verification": "digest-only fixture",
    }
    for entry_id, label in _FIXED_MANIFEST_SPECS
]
FIXED_RUN_HASHES = {
    "root_hash": canonical_sha256(
        {"node_id": "root-00", "pruned": False, "status": "RECORDED", "tier": "ROOT"}
    ),
    "plan_hash": canonical_sha256(
        {
            "fixture": "stateweaver-local-plan-v1",
            "steps": [
                "Session state retained",
                "Policy state compared",
                "Decision outcome recorded",
            ],
        }
    ),
    "oracle_hash": canonical_sha256(
        {
            "fixture": "stateweaver-local-oracle-v1",
            "invariant": "patched lane blocks the synthetic terminal condition",
        }
    ),
    "evidence_hash": canonical_sha256(_FIXED_MANIFEST),
}


def _matching_markers(markers: tuple[RunSignature, ...]) -> bool:
    return (
        [marker.ordinal for marker in markers] == [1, 2, 3, 4, 5]
        and len({marker.signature for marker in markers}) == 1
        and all(marker.status == "matching fixture" for marker in markers)
    )


class StrictFrozenModel(BaseModel):
    """Public data is immutable and rejects undeclared fields at every boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class Provenance(StrictFrozenModel):
    boundary_label: Literal["SYNTHETIC LOCAL LAB"]
    run_id: Literal["sw_demo_01"]
    commit_placeholder: Literal["0000000000000000000000000000000000000000"]
    mode: Literal["deterministic"]
    oracle: Literal["deterministic"]
    model_calls: Literal[0]
    workspace: Literal["local-lab"]
    certification: Literal["not release-certified"]
    fixture_status: Literal["saved synthetic implementation evidence"]
    proof_status: Literal["not materialized proof"]


class RunHashes(StrictFrozenModel):
    root_hash: Sha256Digest
    plan_hash: Sha256Digest
    oracle_hash: Sha256Digest
    evidence_hash: Sha256Digest

    @model_validator(mode="after")
    def hashes_are_domain_separated(self) -> Self:
        if len({self.root_hash, self.plan_hash, self.oracle_hash, self.evidence_hash}) != 4:
            raise ValueError("run hashes must be distinct")
        if self.model_dump(mode="python") != FIXED_RUN_HASHES:
            raise ValueError("run hashes must bind the exact built-in fixture")
        return self


class RunSignature(StrictFrozenModel):
    ordinal: Literal[1, 2, 3, 4, 5]
    signature: Sha256Digest
    status: Literal["matching fixture"]


class HealthResponse(StrictFrozenModel):
    status: Literal["ok"]
    mode: Literal["read-only"]
    provenance: Provenance


class Stage(StrictFrozenModel):
    sequence: Literal[1, 2, 3, 4, 5, 6]
    label: Literal[
        "Root captured",
        "World search",
        "Chain compiled",
        "Clean replay",
        "Patched comparison",
        "Fixture integrity checked",
    ]
    status: Literal["READY", "BLOCKED_BY_FIX"]
    evidence_digest: Sha256Digest

    @model_validator(mode="after")
    def digest_binds_stage(self) -> Self:
        expected = canonical_sha256(
            {"label": self.label, "sequence": self.sequence, "status": self.status}
        )
        if self.evidence_digest != expected:
            raise ValueError("stage evidence digest does not bind stage content")
        return self


class TierCounts(StrictFrozenModel):
    root: Literal[1]
    ghost: Literal[24]
    replay: Literal[4]
    simulated: Literal[2]
    materialized: Literal[1]
    pruned: Literal[17]
    flow: Literal["24 → 4 → 2 → 1"]


class RequiredFragment(StrictFrozenModel):
    fragment_id: Literal["fragment-a", "fragment-b", "fragment-c"]
    label: Literal["Fragment A", "Fragment B", "Fragment C"]
    semantic_label: Literal[
        "historic session retained",
        "async policy propagation delayed",
        "stale authorization decision observed",
    ]
    evidence_digest: Sha256Digest

    @model_validator(mode="after")
    def digest_binds_fragment(self) -> Self:
        expected = canonical_sha256(
            {
                "fragment_id": self.fragment_id,
                "label": self.label,
                "semantic_label": self.semantic_label,
            }
        )
        if self.evidence_digest != expected:
            raise ValueError("fragment evidence digest does not bind fragment content")
        return self


class VerdictCard(StrictFrozenModel):
    lane: Literal["Vulnerable", "Patched", "Control A", "Control B"]
    verdict: Literal["VIOLATED", "BLOCKED_BY_FIX", "SATISFIED"]
    color: Literal["violation", "blocked", "satisfied"]
    evidence_digest: Sha256Digest

    @model_validator(mode="after")
    def digest_binds_verdict(self) -> Self:
        expected = canonical_sha256(
            {"color": self.color, "lane": self.lane, "verdict": self.verdict}
        )
        if self.evidence_digest != expected:
            raise ValueError("verdict evidence digest does not bind verdict content")
        return self


class OverviewResponse(StrictFrozenModel):
    provenance: Provenance
    hashes: RunHashes
    title: Literal["Deterministic state exploration"]
    stages: tuple[Stage, Stage, Stage, Stage, Stage, Stage] = Field(min_length=6, max_length=6)
    tier_counts: TierCounts
    required_fragments: tuple[RequiredFragment, RequiredFragment, RequiredFragment] = Field(
        min_length=3, max_length=3
    )
    run_markers: tuple[RunSignature, RunSignature, RunSignature, RunSignature, RunSignature] = (
        Field(min_length=5, max_length=5)
    )
    verdicts: tuple[VerdictCard, VerdictCard, VerdictCard, VerdictCard] = Field(
        min_length=4, max_length=4
    )

    @model_validator(mode="after")
    def close_overview_relations(self) -> Self:
        expected_stages = [
            (1, "Root captured", "READY"),
            (2, "World search", "READY"),
            (3, "Chain compiled", "READY"),
            (4, "Clean replay", "READY"),
            (5, "Patched comparison", "BLOCKED_BY_FIX"),
            (6, "Fixture integrity checked", "READY"),
        ]
        if [(item.sequence, item.label, item.status) for item in self.stages] != expected_stages:
            raise ValueError("stages must be the ordered closed causal spine")
        expected_fragments = [
            ("fragment-a", "Fragment A", "historic session retained"),
            ("fragment-b", "Fragment B", "async policy propagation delayed"),
            ("fragment-c", "Fragment C", "stale authorization decision observed"),
        ]
        actual_fragments = [
            (item.fragment_id, item.label, item.semantic_label) for item in self.required_fragments
        ]
        if actual_fragments != expected_fragments:
            raise ValueError("required fragments must be unique and ordered")
        if not _matching_markers(self.run_markers):
            raise ValueError("run markers must be five ordered matches of one fixture signature")
        expected_signature = canonical_sha256(
            {
                "oracle_hash": self.hashes.oracle_hash,
                "patched": "BLOCKED_BY_FIX",
                "plan_hash": self.hashes.plan_hash,
                "root_hash": self.hashes.root_hash,
                "vulnerable": "VIOLATED",
            }
        )
        if self.run_markers[0].signature != expected_signature:
            raise ValueError("run signature does not bind root, plan, oracle, and verdicts")
        expected_verdicts = [
            ("Vulnerable", "VIOLATED", "violation"),
            ("Patched", "BLOCKED_BY_FIX", "blocked"),
            ("Control A", "SATISFIED", "satisfied"),
            ("Control B", "SATISFIED", "satisfied"),
        ]
        if [(item.lane, item.verdict, item.color) for item in self.verdicts] != expected_verdicts:
            raise ValueError("verdict cards must match the closed four-lane comparison")
        return self


class WorldNode(StrictFrozenModel):
    node_id: NodeId
    tier: Literal["ROOT", "GHOST", "REPLAY", "SIMULATED", "MATERIALIZED"]
    fingerprint: Sha256Digest
    pruned: bool
    status: Literal["ACTIVE", "PRUNED", "RECORDED"]

    @model_validator(mode="after")
    def fingerprint_binds_node(self) -> Self:
        expected = canonical_sha256(
            {
                "node_id": self.node_id,
                "pruned": self.pruned,
                "status": self.status,
                "tier": self.tier,
            }
        )
        if self.fingerprint != expected:
            raise ValueError("world fingerprint does not bind node content")
        return self


class WorldEdge(StrictFrozenModel):
    from_node_id: NodeId
    to_node_id: NodeId
    relation: Literal["explores", "replays", "simulates", "materializes"]
    pruned: bool


class InspectorSelection(StrictFrozenModel):
    node_id: Literal["materialized-01"]
    fingerprint: Sha256Digest
    tier: Literal["MATERIALIZED"]
    parent_node_ids: tuple[Literal["simulated-01"], Literal["simulated-02"]] = Field(
        min_length=2, max_length=2
    )
    status: Literal["SELECTED"]


class WorldsResponse(StrictFrozenModel):
    provenance: Provenance
    hashes: RunHashes
    tier_counts: TierCounts
    nodes: tuple[WorldNode, ...] = Field(min_length=32, max_length=32)
    edges: tuple[WorldEdge, ...] = Field(min_length=34, max_length=34)
    selected_inspector: InspectorSelection

    @model_validator(mode="after")
    def close_world_graph(self) -> Self:
        nodes = {node.node_id: node for node in self.nodes}
        if len(nodes) != len(self.nodes):
            raise ValueError("world node ids must be unique")
        if len({node.fingerprint for node in self.nodes}) != len(self.nodes):
            raise ValueError("world fingerprints must be unique")
        expected_nodes = [
            ("root-00", "ROOT", False, "RECORDED"),
            *[
                (
                    f"ghost-{number:02d}",
                    "GHOST",
                    number <= 17,
                    "PRUNED" if number <= 17 else "ACTIVE",
                )
                for number in range(1, 25)
            ],
            *[(f"replay-{number:02d}", "REPLAY", False, "RECORDED") for number in range(1, 5)],
            ("simulated-01", "SIMULATED", False, "RECORDED"),
            ("simulated-02", "SIMULATED", False, "RECORDED"),
            ("materialized-01", "MATERIALIZED", False, "RECORDED"),
        ]
        if [
            (node.node_id, node.tier, node.pruned, node.status) for node in self.nodes
        ] != expected_nodes:
            raise ValueError("world nodes must match the exact ordered fixture")
        expected_counts = {
            "ROOT": 1,
            "GHOST": 24,
            "REPLAY": 4,
            "SIMULATED": 2,
            "MATERIALIZED": 1,
        }
        if Counter(node.tier for node in self.nodes) != expected_counts:
            raise ValueError("world nodes do not match the declared tier counts")
        roots = [node for node in self.nodes if node.tier == "ROOT"]
        if roots[0].node_id != "root-00" or roots[0].fingerprint != self.hashes.root_hash:
            raise ValueError("the unique root must bind the response root hash")
        if sum(node.pruned for node in self.nodes) != self.tier_counts.pruned:
            raise ValueError("pruned node count does not match tier counts")
        for node in self.nodes:
            expected_status = (
                "PRUNED" if node.pruned else "ACTIVE" if node.tier == "GHOST" else "RECORDED"
            )
            if node.status != expected_status or (node.pruned and node.tier != "GHOST"):
                raise ValueError("world status, pruning, and tier are inconsistent")

        edge_keys = {(edge.from_node_id, edge.to_node_id, edge.relation) for edge in self.edges}
        if len(edge_keys) != len(self.edges):
            raise ValueError("world edges must be unique")
        expected_edges = [
            ("root-00", f"ghost-{number:02d}", "explores", number <= 17) for number in range(1, 25)
        ] + [
            ("ghost-18", "replay-01", "replays", False),
            ("ghost-21", "replay-02", "replays", False),
            ("ghost-22", "replay-03", "replays", False),
            ("ghost-24", "replay-04", "replays", False),
            ("replay-01", "simulated-01", "simulates", False),
            ("replay-02", "simulated-01", "simulates", False),
            ("replay-03", "simulated-02", "simulates", False),
            ("replay-04", "simulated-02", "simulates", False),
            ("simulated-01", "materialized-01", "materializes", False),
            ("simulated-02", "materialized-01", "materializes", False),
        ]
        if [
            (edge.from_node_id, edge.to_node_id, edge.relation, edge.pruned) for edge in self.edges
        ] != expected_edges:
            raise ValueError("world edges must match the exact ordered fixture")
        expected_relations = {
            "explores": ("ROOT", "GHOST", 24),
            "replays": ("GHOST", "REPLAY", 4),
            "simulates": ("REPLAY", "SIMULATED", 4),
            "materializes": ("SIMULATED", "MATERIALIZED", 2),
        }
        for relation, (from_tier, to_tier, count) in expected_relations.items():
            if sum(edge.relation == relation for edge in self.edges) != count:
                raise ValueError("world relation counts do not match the closed DAG")
            for edge in (item for item in self.edges if item.relation == relation):
                if edge.from_node_id == edge.to_node_id:
                    raise ValueError("world edges cannot be self loops")
                if edge.from_node_id not in nodes or edge.to_node_id not in nodes:
                    raise ValueError("world edges must reference declared nodes")
                source, target = nodes[edge.from_node_id], nodes[edge.to_node_id]
                if source.tier != from_tier or target.tier != to_tier:
                    raise ValueError("world edge relation does not match endpoint tiers")
                expected_pruned = relation == "explores" and target.pruned
                if edge.pruned != expected_pruned:
                    raise ValueError("world edge pruning does not match its target")
        if any(
            sum(edge.to_node_id == node.node_id for edge in self.edges) == 0
            for node in self.nodes
            if node.tier != "ROOT"
        ):
            raise ValueError("every non-root world must have a parent")

        selected = nodes[self.selected_inspector.node_id]
        if (
            selected.tier != self.selected_inspector.tier
            or selected.fingerprint != self.selected_inspector.fingerprint
        ):
            raise ValueError("selected inspector does not bind the selected world")
        materialized_parents = tuple(
            edge.from_node_id
            for edge in self.edges
            if edge.to_node_id == selected.node_id and edge.relation == "materializes"
        )
        if materialized_parents != self.selected_inspector.parent_node_ids:
            raise ValueError("selected inspector parents do not match the DAG")
        return self


class ObservationProvenance(StrictFrozenModel):
    observation_status: Literal["SYNTHETIC"]
    source_node_id: NodeId
    source_fingerprint: Sha256Digest


class TransitionFact(StrictFrozenModel):
    label: Literal["precondition", "typed action", "effect", "evidence"]
    summary: str = Field(min_length=1, max_length=96)
    digest: Sha256Digest

    @model_validator(mode="after")
    def digest_binds_fact(self) -> Self:
        if self.digest != canonical_sha256({"label": self.label, "summary": self.summary}):
            raise ValueError("transition fact digest does not bind fact content")
        return self


class Fidelity(StrictFrozenModel):
    completeness: Literal["fixture-only"]
    ordering: Literal["deterministic fixture"]
    timing: Literal["not modeled"]
    determinism: Literal["deterministic"]


class StateDelta(StrictFrozenModel):
    field: Literal["session_retention", "policy_propagation", "decision_freshness"]
    before: Literal["retained", "delayed", "stale"]
    after: Literal["retained", "propagated", "observed"]
    effect: Literal["unchanged", "updated", "recorded"]


class RuntimeTrace(StrictFrozenModel):
    trace_id: Literal["trace-local-fragment-a", "trace-local-fragment-b", "trace-local-fragment-c"]
    trace_digest: Sha256Digest
    runtime: Literal["local synthetic runtime"]

    @model_validator(mode="after")
    def digest_binds_trace(self) -> Self:
        if self.trace_digest != canonical_sha256(
            {"runtime": self.runtime, "trace_id": self.trace_id}
        ):
            raise ValueError("trace digest does not bind trace content")
        return self


class OracleBinding(StrictFrozenModel):
    oracle: Literal["deterministic"]
    binding_digest: Sha256Digest
    oracle_hash: Sha256Digest

    @model_validator(mode="after")
    def digest_binds_oracle(self) -> Self:
        if self.binding_digest != canonical_sha256(
            {"oracle": self.oracle, "oracle_hash": self.oracle_hash}
        ):
            raise ValueError("oracle binding digest does not bind oracle identity")
        return self


class TwinFragment(StrictFrozenModel):
    fragment_id: Literal["fragment-a", "fragment-b", "fragment-c"]
    label: Literal["Fragment A", "Fragment B", "Fragment C"]
    semantic_label: Literal[
        "historic session retained",
        "async policy propagation delayed",
        "stale authorization decision observed",
    ]
    provenance: ObservationProvenance
    precondition: TransitionFact
    typed_action: TransitionFact
    effect: TransitionFact
    evidence: TransitionFact
    fidelity: Fidelity
    state_delta: tuple[StateDelta, StateDelta, StateDelta] = Field(min_length=3, max_length=3)
    runtime_trace: RuntimeTrace
    oracle_binding: OracleBinding


class TwinResponse(StrictFrozenModel):
    provenance: Provenance
    hashes: RunHashes
    title: Literal["Security Semantic Twin"]
    fragments: tuple[TwinFragment, TwinFragment, TwinFragment] = Field(min_length=3, max_length=3)
    selected_fragment_id: Literal["fragment-c"]

    @model_validator(mode="after")
    def close_twin_fragments(self) -> Self:
        expected = [
            (
                "fragment-a",
                "Fragment A",
                "historic session retained",
                "replay-01",
                "trace-local-fragment-a",
            ),
            (
                "fragment-b",
                "Fragment B",
                "async policy propagation delayed",
                "replay-02",
                "trace-local-fragment-b",
            ),
            (
                "fragment-c",
                "Fragment C",
                "stale authorization decision observed",
                "replay-03",
                "trace-local-fragment-c",
            ),
        ]
        actual = [
            (
                item.fragment_id,
                item.label,
                item.semantic_label,
                item.provenance.source_node_id,
                item.runtime_trace.trace_id,
            )
            for item in self.fragments
        ]
        if actual != expected:
            raise ValueError("twin fragments must be the three ordered closed fixture fragments")
        if len({item.provenance.source_fingerprint for item in self.fragments}) != 3:
            raise ValueError("twin fragment source fingerprints must be unique")
        expected_delta = [
            ("session_retention", "retained", "retained", "unchanged"),
            ("policy_propagation", "delayed", "propagated", "updated"),
            ("decision_freshness", "stale", "observed", "recorded"),
        ]
        expected_facts = [
            ("precondition", "recorded local state is available"),
            ("typed action", "compare recorded typed state"),
            ("effect", "recorded state transition is displayed"),
            ("evidence", "saved synthetic evidence is bound"),
        ]
        for fragment in self.fragments:
            if [
                (delta.field, delta.before, delta.after, delta.effect)
                for delta in fragment.state_delta
            ] != expected_delta:
                raise ValueError("state delta must match the exact ordered fixture")
            if [
                (fact.label, fact.summary)
                for fact in (
                    fragment.precondition,
                    fragment.typed_action,
                    fragment.effect,
                    fragment.evidence,
                )
            ] != expected_facts:
                raise ValueError("transition facts must match their exact fixture roles")
            if fragment.oracle_binding.oracle_hash != self.hashes.oracle_hash:
                raise ValueError("fragment oracle identity must match the response")
            expected_source_fingerprint = canonical_sha256(
                {
                    "node_id": fragment.provenance.source_node_id,
                    "pruned": False,
                    "status": "RECORDED",
                    "tier": "REPLAY",
                }
            )
            if fragment.provenance.source_fingerprint != expected_source_fingerprint:
                raise ValueError("fragment provenance does not bind its synthetic source world")
        if self.selected_fragment_id not in {item.fragment_id for item in self.fragments}:
            raise ValueError("selected twin fragment must exist")
        return self


class ReplayStep(StrictFrozenModel):
    sequence: Literal[1, 2, 3]
    label: Literal["Session state retained", "Policy state compared", "Decision outcome recorded"]
    evidence_digest: Sha256Digest
    verdict: Literal["SATISFIED", "VIOLATED", "BLOCKED_BY_FIX"]

    @model_validator(mode="after")
    def digest_binds_step(self) -> Self:
        expected = canonical_sha256(
            {"label": self.label, "sequence": self.sequence, "verdict": self.verdict}
        )
        if self.evidence_digest != expected:
            raise ValueError("replay evidence digest does not bind step content")
        return self


class ReplayLane(StrictFrozenModel):
    lane: Literal["Vulnerable", "Patched"]
    plan_hash: Sha256Digest
    steps: tuple[ReplayStep, ReplayStep, ReplayStep] = Field(min_length=3, max_length=3)
    terminal_verdict: Literal["VIOLATED", "BLOCKED_BY_FIX"]


class SatisfiedControl(StrictFrozenModel):
    control_id: Literal["control-a", "control-b"]
    label: Literal["Control A", "Control B"]
    verdict: Literal["SATISFIED"]
    color: Literal["satisfied"]
    evidence_digest: Sha256Digest

    @model_validator(mode="after")
    def digest_binds_control(self) -> Self:
        expected = canonical_sha256(
            {
                "color": self.color,
                "control_id": self.control_id,
                "label": self.label,
                "verdict": self.verdict,
            }
        )
        if self.evidence_digest != expected:
            raise ValueError("control evidence digest does not bind control content")
        return self


class RedactedObservation(StrictFrozenModel):
    label: Literal["Observation (redacted)"]
    summary: Literal["synthetic-local decision observation [redacted]"]
    digest: Sha256Digest

    @model_validator(mode="after")
    def digest_binds_observation(self) -> Self:
        if self.digest != canonical_sha256({"label": self.label, "summary": self.summary}):
            raise ValueError("observation digest does not bind redacted content")
        return self


class EvidenceManifestEntry(StrictFrozenModel):
    entry_id: Literal["evidence-01", "evidence-02", "evidence-03", "evidence-04", "evidence-05"]
    label: Literal[
        "Recorded event summary",
        "Typed state delta",
        "Oracle comparison",
        "Policy snapshot",
        "Replay signature",
    ]
    digest: Sha256Digest
    verification: Literal["digest-only fixture"]

    @model_validator(mode="after")
    def digest_binds_manifest_entry(self) -> Self:
        expected = canonical_sha256(
            {"entry_id": self.entry_id, "label": self.label, "verification": self.verification}
        )
        if self.digest != expected:
            raise ValueError("manifest digest does not bind manifest entry")
        return self


class ReplayResponse(StrictFrozenModel):
    provenance: Provenance
    hashes: RunHashes
    title: Literal["Clean-root replay"]
    vulnerable: ReplayLane
    patched: ReplayLane
    controls: tuple[SatisfiedControl, SatisfiedControl] = Field(min_length=2, max_length=2)
    selected_observation: RedactedObservation
    evidence_manifest: tuple[
        EvidenceManifestEntry,
        EvidenceManifestEntry,
        EvidenceManifestEntry,
        EvidenceManifestEntry,
        EvidenceManifestEntry,
    ] = Field(min_length=5, max_length=5)
    run_markers: tuple[RunSignature, RunSignature, RunSignature, RunSignature, RunSignature] = (
        Field(min_length=5, max_length=5)
    )

    @model_validator(mode="after")
    def close_replay_and_manifest(self) -> Self:
        vulnerable, patched = self.vulnerable, self.patched
        if vulnerable.lane != "Vulnerable" or patched.lane != "Patched":
            raise ValueError("replay lanes must be vulnerable then patched")
        if (
            vulnerable.plan_hash != self.hashes.plan_hash
            or patched.plan_hash != self.hashes.plan_hash
        ):
            raise ValueError("both replay lanes must bind the response plan hash")
        expected_steps = [
            (1, "Session state retained"),
            (2, "Policy state compared"),
            (3, "Decision outcome recorded"),
        ]
        for lane in (vulnerable, patched):
            if [(step.sequence, step.label) for step in lane.steps] != expected_steps:
                raise ValueError("replay steps must be aligned and ordered")
            if lane.steps[-1].verdict != lane.terminal_verdict:
                raise ValueError("terminal verdict must match the terminal step")
            if any(step.verdict != "SATISFIED" for step in lane.steps[:-1]):
                raise ValueError("non-terminal replay steps must be satisfied")
        if (
            vulnerable.terminal_verdict != "VIOLATED"
            or patched.terminal_verdict != "BLOCKED_BY_FIX"
        ):
            raise ValueError("replay lanes must preserve vulnerable/patched semantics")
        if [(item.control_id, item.label) for item in self.controls] != [
            ("control-a", "Control A"),
            ("control-b", "Control B"),
        ]:
            raise ValueError("controls must be unique and ordered")
        expected_manifest = [
            ("evidence-01", "Recorded event summary"),
            ("evidence-02", "Typed state delta"),
            ("evidence-03", "Oracle comparison"),
            ("evidence-04", "Policy snapshot"),
            ("evidence-05", "Replay signature"),
        ]
        if [(item.entry_id, item.label) for item in self.evidence_manifest] != expected_manifest:
            raise ValueError("evidence manifest entries must be complete, unique, and ordered")
        manifest_payload = [item.model_dump(mode="json") for item in self.evidence_manifest]
        if canonical_sha256(manifest_payload) != self.hashes.evidence_hash:
            raise ValueError("evidence hash does not bind the canonical manifest")
        if not _matching_markers(self.run_markers):
            raise ValueError("run markers must be five ordered matches of one fixture signature")
        expected_signature = canonical_sha256(
            {
                "oracle_hash": self.hashes.oracle_hash,
                "patched": patched.terminal_verdict,
                "plan_hash": self.hashes.plan_hash,
                "root_hash": self.hashes.root_hash,
                "vulnerable": vulnerable.terminal_verdict,
            }
        )
        if self.run_markers[0].signature != expected_signature:
            raise ValueError(
                "run signature does not bind root, plan, oracle, and terminal verdicts"
            )
        return self
