"""Contract tests for the closed, read-only local-demo surface."""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import pytest_asyncio
from fastapi.routing import APIRoute
from pydantic import ValidationError

from stateweaver_api.app import LOCAL_ALLOWED_HOSTS, LOCAL_DEV_ORIGINS, SECURITY_HEADERS, app
from stateweaver_api.fixture import (
    DEMO_HASHES,
    DEMO_HEALTH,
    DEMO_OVERVIEW,
    DEMO_REPLAY,
    DEMO_TWIN,
    DEMO_WORLDS,
)
from stateweaver_api.models import (
    EvidenceManifestEntry,
    HealthResponse,
    OverviewResponse,
    ReplayResponse,
    TwinResponse,
    WorldNode,
    WorldsResponse,
    canonical_sha256,
)


@pytest_asyncio.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as test_client:
        yield test_client


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    ["/healthz", "/v1/demo/overview", "/v1/demo/worlds", "/v1/demo/twin", "/v1/demo/replay"],
)
async def test_public_get_responses_are_json_and_provenanced(
    client: httpx.AsyncClient, path: str
) -> None:
    response = await client.get(path)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    provenance = response.json()["provenance"]
    assert provenance["boundary_label"] == "SYNTHETIC LOCAL LAB"
    assert provenance["run_id"] == "sw_demo_01"
    assert provenance["commit_placeholder"] == "0" * 40
    assert provenance["mode"] == provenance["oracle"] == "deterministic"
    assert provenance["model_calls"] == 0
    assert provenance["workspace"] == "local-lab"
    assert provenance["certification"] == "not release-certified"
    assert {name: response.headers[name] for name in SECURITY_HEADERS} == SECURITY_HEADERS


@pytest.mark.asyncio
async def test_host_and_browser_security_policy_are_fixed_and_fail_closed() -> None:
    assert LOCAL_ALLOWED_HOSTS == ("127.0.0.1", "localhost", "testserver")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://public.example") as client:
        response = await client.get("/healthz")
    assert response.status_code == 400
    assert b"Invalid host header" in response.content


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    ["/healthz", "/v1/demo/overview", "/v1/demo/worlds", "/v1/demo/twin", "/v1/demo/replay"],
)
async def test_repeated_responses_have_deterministic_bytes(
    client: httpx.AsyncClient, path: str
) -> None:
    first = await client.get(path)
    second = await client.get(path)

    assert first.content == second.content
    assert json.loads(first.content) == json.loads(second.content)


def test_fixture_models_are_frozen_strict_and_deterministic() -> None:
    fixtures = (DEMO_HEALTH, DEMO_OVERVIEW, DEMO_WORLDS, DEMO_TWIN, DEMO_REPLAY)
    assert all(fixture.model_dump_json() == fixture.model_dump_json() for fixture in fixtures)

    health_input = DEMO_HEALTH.model_dump()
    health_input["unexpected"] = "field"
    with pytest.raises(ValidationError):
        HealthResponse.model_validate(health_input)
    with pytest.raises(ValidationError):
        EvidenceManifestEntry(
            entry_id="evidence-01",
            label="Recorded event summary",
            digest="not-a-sha256-digest",
            verification="digest-only fixture",
        )
    invalid_node = DEMO_WORLDS.nodes[0].model_dump()
    invalid_node["node_id"] = "unlisted-node"
    with pytest.raises(ValidationError):
        WorldNode.model_validate(invalid_node)
    with pytest.raises(ValidationError):
        DEMO_OVERVIEW.title = "changed"  # type: ignore[assignment]


def test_overview_has_fixed_causal_spine_counts_fragments_markers_and_verdicts() -> None:
    assert [stage.sequence for stage in DEMO_OVERVIEW.stages] == [1, 2, 3, 4, 5, 6]
    assert [stage.label for stage in DEMO_OVERVIEW.stages] == [
        "Root captured",
        "World search",
        "Chain compiled",
        "Clean replay",
        "Patched comparison",
        "Fixture integrity checked",
    ]
    assert DEMO_OVERVIEW.stages[4].status == "BLOCKED_BY_FIX"
    assert DEMO_OVERVIEW.tier_counts.flow == "24 → 4 → 2 → 1"
    assert len(DEMO_OVERVIEW.required_fragments) == 3
    assert len(DEMO_OVERVIEW.run_markers) == 5
    assert len({marker.signature for marker in DEMO_OVERVIEW.run_markers}) == 1
    verdicts = {card.lane: (card.verdict, card.color) for card in DEMO_OVERVIEW.verdicts}
    assert verdicts == {
        "Vulnerable": ("VIOLATED", "violation"),
        "Patched": ("BLOCKED_BY_FIX", "blocked"),
        "Control A": ("SATISFIED", "satisfied"),
        "Control B": ("SATISFIED", "satisfied"),
    }


def test_world_counts_ids_fingerprints_edges_and_selection_are_closed() -> None:
    counts = Counter(node.tier for node in DEMO_WORLDS.nodes)
    assert counts == {"ROOT": 1, "GHOST": 24, "REPLAY": 4, "SIMULATED": 2, "MATERIALIZED": 1}
    assert sum(node.pruned for node in DEMO_WORLDS.nodes) == 17
    assert len(DEMO_WORLDS.nodes) == 32
    assert len(DEMO_WORLDS.edges) == 34
    node_ids = {node.node_id for node in DEMO_WORLDS.nodes}
    fingerprints = {node.fingerprint for node in DEMO_WORLDS.nodes}
    assert len(node_ids) == len(DEMO_WORLDS.nodes)
    assert len(fingerprints) == len(DEMO_WORLDS.nodes)
    assert all(
        edge.from_node_id in node_ids and edge.to_node_id in node_ids for edge in DEMO_WORLDS.edges
    )
    assert all(edge.from_node_id != edge.to_node_id for edge in DEMO_WORLDS.edges)
    assert DEMO_WORLDS.selected_inspector.node_id in node_ids
    assert DEMO_WORLDS.selected_inspector.fingerprint in fingerprints
    assert all(
        parent_id in node_ids for parent_id in DEMO_WORLDS.selected_inspector.parent_node_ids
    )


def test_twin_uses_only_the_three_safe_semantic_fragments() -> None:
    assert DEMO_TWIN.selected_fragment_id == "fragment-c"
    assert [fragment.semantic_label for fragment in DEMO_TWIN.fragments] == [
        "historic session retained",
        "async policy propagation delayed",
        "stale authorization decision observed",
    ]
    for fragment in DEMO_TWIN.fragments:
        assert fragment.provenance.observation_status == "SYNTHETIC"
        assert fragment.fidelity.completeness == "fixture-only"
        assert fragment.fidelity.timing == "not modeled"
        assert fragment.fidelity.determinism == "deterministic"
        assert len(fragment.state_delta) == 3
        assert fragment.oracle_binding.oracle_hash == DEMO_HASHES.oracle_hash


def test_replay_lanes_are_aligned_use_the_same_plan_and_have_closed_terminal_semantics() -> None:
    vulnerable = DEMO_REPLAY.vulnerable
    patched = DEMO_REPLAY.patched

    assert DEMO_OVERVIEW.hashes.plan_hash == vulnerable.plan_hash == patched.plan_hash
    assert vulnerable.plan_hash == DEMO_HASHES.plan_hash
    assert [(step.sequence, step.label) for step in vulnerable.steps] == [
        (step.sequence, step.label) for step in patched.steps
    ]
    assert vulnerable.steps[-1].verdict == vulnerable.terminal_verdict == "VIOLATED"
    assert patched.steps[-1].verdict == patched.terminal_verdict == "BLOCKED_BY_FIX"
    assert all(
        control.verdict == "SATISFIED" and control.color == "satisfied"
        for control in DEMO_REPLAY.controls
    )
    assert len(DEMO_REPLAY.evidence_manifest) == 5
    assert len(DEMO_REPLAY.run_markers) == 5
    assert len({marker.signature for marker in DEMO_REPLAY.run_markers}) == 1
    assert {marker.status for marker in DEMO_REPLAY.run_markers} == {"matching fixture"}


def test_cross_endpoint_hashes_and_manifest_are_closed() -> None:
    hashed_responses = (DEMO_OVERVIEW, DEMO_WORLDS, DEMO_TWIN, DEMO_REPLAY)
    assert len({response.hashes for response in hashed_responses}) == 1
    manifest_payload = [entry.model_dump(mode="json") for entry in DEMO_REPLAY.evidence_manifest]
    assert canonical_sha256(manifest_payload) == DEMO_HASHES.evidence_hash
    assert DEMO_WORLDS.nodes[0].fingerprint == DEMO_HASHES.root_hash
    assert DEMO_TWIN.hashes.oracle_hash == DEMO_REPLAY.hashes.oracle_hash


def test_overview_rejects_valid_but_duplicated_stages_fragments_and_mismatched_markers() -> None:
    duplicate_stage = DEMO_OVERVIEW.model_dump(mode="python")
    stages = list(duplicate_stage["stages"])
    stages[1] = stages[0]
    duplicate_stage["stages"] = tuple(stages)
    with pytest.raises(ValidationError):
        OverviewResponse.model_validate(duplicate_stage)

    duplicate_fragment = DEMO_OVERVIEW.model_dump(mode="python")
    fragments = list(duplicate_fragment["required_fragments"])
    fragments[1] = fragments[0]
    duplicate_fragment["required_fragments"] = tuple(fragments)
    with pytest.raises(ValidationError):
        OverviewResponse.model_validate(duplicate_fragment)

    mismatched_marker = DEMO_OVERVIEW.model_dump(mode="python")
    markers = list(mismatched_marker["run_markers"])
    markers[-1] = {**markers[-1], "signature": canonical_sha256("different-run")}
    mismatched_marker["run_markers"] = tuple(markers)
    with pytest.raises(ValidationError):
        OverviewResponse.model_validate(mismatched_marker)

    opaque_hash_substitution = DEMO_OVERVIEW.model_dump(mode="python")
    substituted_plan = canonical_sha256("different-but-well-shaped-plan")
    opaque_hash_substitution["hashes"]["plan_hash"] = substituted_plan
    signature = canonical_sha256(
        {
            "oracle_hash": opaque_hash_substitution["hashes"]["oracle_hash"],
            "patched": "BLOCKED_BY_FIX",
            "plan_hash": substituted_plan,
            "root_hash": opaque_hash_substitution["hashes"]["root_hash"],
            "vulnerable": "VIOLATED",
        }
    )
    opaque_hash_substitution["run_markers"] = tuple(
        {**marker, "signature": signature} for marker in opaque_hash_substitution["run_markers"]
    )
    with pytest.raises(ValidationError):
        OverviewResponse.model_validate(opaque_hash_substitution)


def test_worlds_reject_duplicate_roots_self_loops_and_selection_substitution() -> None:
    duplicate_roots = DEMO_WORLDS.model_dump(mode="python")
    duplicate_roots["nodes"] = tuple([duplicate_roots["nodes"][0]] * 32)
    with pytest.raises(ValidationError):
        WorldsResponse.model_validate(duplicate_roots)

    self_loop = DEMO_WORLDS.model_dump(mode="python")
    edges = list(self_loop["edges"])
    edges[-1] = {
        **edges[-1],
        "from_node_id": "materialized-01",
        "to_node_id": "materialized-01",
    }
    self_loop["edges"] = tuple(edges)
    with pytest.raises(ValidationError):
        WorldsResponse.model_validate(self_loop)

    selected_substitution = DEMO_WORLDS.model_dump(mode="python")
    selected_substitution["selected_inspector"]["fingerprint"] = canonical_sha256(
        "different-selection"
    )
    with pytest.raises(ValidationError):
        WorldsResponse.model_validate(selected_substitution)

    alternate_valid_shape = DEMO_WORLDS.model_dump(mode="python")
    edges = list(alternate_valid_shape["edges"])
    replay_edges = [index for index, edge in enumerate(edges) if edge["relation"] == "replays"]
    first, second = replay_edges[:2]
    edges[first] = {**edges[first], "to_node_id": "replay-02"}
    edges[second] = {**edges[second], "to_node_id": "replay-01"}
    alternate_valid_shape["edges"] = tuple(edges)
    with pytest.raises(ValidationError):
        WorldsResponse.model_validate(alternate_valid_shape)


def test_twin_rejects_fragment_duplication_and_source_fingerprint_substitution() -> None:
    duplicate_fragment = DEMO_TWIN.model_dump(mode="python")
    fragments = list(duplicate_fragment["fragments"])
    fragments[1] = fragments[0]
    duplicate_fragment["fragments"] = tuple(fragments)
    with pytest.raises(ValidationError):
        TwinResponse.model_validate(duplicate_fragment)

    substituted_source = DEMO_TWIN.model_dump(mode="python")
    fragments = list(substituted_source["fragments"])
    fragments[0]["provenance"]["source_fingerprint"] = canonical_sha256("different-world")
    substituted_source["fragments"] = tuple(fragments)
    with pytest.raises(ValidationError):
        TwinResponse.model_validate(substituted_source)

    alternate_summary = DEMO_TWIN.model_dump(mode="python")
    fragments = list(alternate_summary["fragments"])
    fragments[0]["precondition"]["summary"] = "different locally coherent fixture fact"
    fragments[0]["precondition"]["digest"] = canonical_sha256(
        {
            "label": fragments[0]["precondition"]["label"],
            "summary": fragments[0]["precondition"]["summary"],
        }
    )
    alternate_summary["fragments"] = tuple(fragments)
    with pytest.raises(ValidationError):
        TwinResponse.model_validate(alternate_summary)


def test_replay_rejects_plan_terminal_manifest_hash_and_signature_substitution() -> None:
    plan_substitution = DEMO_REPLAY.model_dump(mode="python")
    plan_substitution["patched"]["plan_hash"] = canonical_sha256("different-plan")
    with pytest.raises(ValidationError):
        ReplayResponse.model_validate(plan_substitution)

    terminal_substitution = DEMO_REPLAY.model_dump(mode="python")
    terminal_substitution["patched"]["terminal_verdict"] = "VIOLATED"
    with pytest.raises(ValidationError):
        ReplayResponse.model_validate(terminal_substitution)

    repeated_manifest = DEMO_REPLAY.model_dump(mode="python")
    repeated_manifest["evidence_manifest"] = tuple([repeated_manifest["evidence_manifest"][0]] * 5)
    with pytest.raises(ValidationError):
        ReplayResponse.model_validate(repeated_manifest)

    evidence_hash_substitution = DEMO_REPLAY.model_dump(mode="python")
    evidence_hash_substitution["hashes"]["evidence_hash"] = canonical_sha256("different-manifest")
    with pytest.raises(ValidationError):
        ReplayResponse.model_validate(evidence_hash_substitution)

    marker_substitution = DEMO_REPLAY.model_dump(mode="python")
    markers = list(marker_substitution["run_markers"])
    markers[-1] = {**markers[-1], "signature": canonical_sha256("different-run")}
    marker_substitution["run_markers"] = tuple(markers)
    with pytest.raises(ValidationError):
        ReplayResponse.model_validate(marker_substitution)


def _walk_mappings(value: object) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_mappings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_mappings(child)


def test_all_digest_fields_have_the_required_sha256_shape() -> None:
    sha256 = re.compile(r"^[a-f0-9]{64}$")
    fixtures = (DEMO_HEALTH, DEMO_OVERVIEW, DEMO_WORLDS, DEMO_TWIN, DEMO_REPLAY)

    for fixture in fixtures:
        for mapping in _walk_mappings(fixture.model_dump(mode="json")):
            for key, value in mapping.items():
                if key.endswith(("hash", "digest", "signature", "fingerprint")):
                    assert isinstance(value, str)
                    assert sha256.fullmatch(value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    ["/healthz", "/v1/demo/overview", "/v1/demo/worlds", "/v1/demo/twin", "/v1/demo/replay"],
)
async def test_state_changing_methods_are_not_exposed(client: httpx.AsyncClient, path: str) -> None:
    response = await client.post(path)

    assert response.status_code == 405


@pytest.mark.asyncio
async def test_unknown_route_is_not_exposed(client: httpx.AsyncClient) -> None:
    response = await client.get("/v1/demo/unknown")

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_get_routes_reject_query_parameters_and_request_bodies(
    client: httpx.AsyncClient,
) -> None:
    query_response = await client.get("/healthz?unexpected=1")
    body_response = await client.request("GET", "/healthz", content=b"{}")

    assert query_response.status_code == 400
    assert body_response.status_code == 400
    assert (
        query_response.json()
        == body_response.json()
        == {"detail": "demo GET endpoints accept no query parameters or request body"}
    )


def test_routes_are_get_only_and_declare_exact_response_models() -> None:
    routes = {route.path: route for route in app.routes if isinstance(route, APIRoute)}

    assert set(routes) == {
        "/healthz",
        "/v1/demo/overview",
        "/v1/demo/worlds",
        "/v1/demo/twin",
        "/v1/demo/replay",
    }
    assert routes["/healthz"].response_model is type(DEMO_HEALTH)
    assert routes["/v1/demo/overview"].response_model is type(DEMO_OVERVIEW)
    assert routes["/v1/demo/worlds"].response_model is type(DEMO_WORLDS)
    assert routes["/v1/demo/twin"].response_model is type(DEMO_TWIN)
    assert routes["/v1/demo/replay"].response_model is type(DEMO_REPLAY)
    assert all(route.methods == {"GET"} for route in routes.values())


@pytest.mark.asyncio
async def test_cors_allows_only_exact_local_development_origins(client: httpx.AsyncClient) -> None:
    for origin in LOCAL_DEV_ORIGINS:
        response = await client.get("/healthz", headers={"Origin": origin})
        assert response.headers["access-control-allow-origin"] == origin

    denied = await client.get("/healthz", headers={"Origin": "http://localhost:3001"})
    assert "access-control-allow-origin" not in denied.headers


@pytest.mark.asyncio
async def test_preflight_allows_only_get_for_exact_origin(client: httpx.AsyncClient) -> None:
    response = await client.options(
        "/v1/demo/overview",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert response.headers["access-control-allow-methods"] == "GET"


def test_responses_have_no_external_target_or_arbitrary_action_fields() -> None:
    forbidden_keys = {
        "command",
        "credential",
        "hostname",
        "password",
        "path",
        "payload",
        "secret",
        "token",
        "url",
    }
    fixtures = (DEMO_HEALTH, DEMO_OVERVIEW, DEMO_WORLDS, DEMO_TWIN, DEMO_REPLAY)

    for fixture in fixtures:
        for mapping in _walk_mappings(fixture.model_dump(mode="json")):
            assert not forbidden_keys.intersection(mapping)


def test_api_source_has_no_external_io_clients_or_execution_modules() -> None:
    source_root = Path(__file__).parents[1] / "src" / "stateweaver_api"
    source = "\n".join(path.read_text(encoding="utf-8") for path in source_root.glob("*.py"))

    for forbidden in ("import socket", "import subprocess", "import docker", "import requests"):
        assert forbidden not in source
