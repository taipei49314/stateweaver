from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient
from statechainbench import (
    BudgetLimits,
    DatasetSplit,
    EqualBudgetRunner,
    GeneratorConfig,
    generate_dataset,
)
from stateweaver.cli.foundation import verify_foundation
from stateweaver_api.app import app


def _json(client: TestClient, path: str) -> dict[str, Any]:
    response = client.get(path)
    assert response.status_code == 200
    payload = response.json()
    assert isinstance(payload, dict)
    return payload


def test_closed_local_public_journey_is_coherent_across_foundation_benchmark_and_api() -> None:
    foundation = verify_foundation()
    comparison = EqualBudgetRunner(
        generate_dataset(GeneratorConfig(seed=1729, variants_per_family=4))
    ).compare(
        BudgetLimits(max_action_cost=40, max_world_cost=30, max_latency_units=250),
        split=DatasetSplit.HOLDOUT,
    )

    assert foundation.accepted is True
    assert foundation.vulnerable_deterministic is True
    assert len(foundation.vulnerable) == 5
    assert comparison.baseline.metrics.successes == 4
    assert comparison.full.metrics.successes == 8
    assert (
        comparison.baseline.metrics.challenge_count == comparison.full.metrics.challenge_count == 8
    )

    client = TestClient(app)
    overview = _json(client, "/v1/demo/overview")
    worlds = _json(client, "/v1/demo/worlds")
    twin = _json(client, "/v1/demo/twin")
    replay = _json(client, "/v1/demo/replay")

    provenances = [payload["provenance"] for payload in (overview, worlds, twin, replay)]
    assert all(item == provenances[0] for item in provenances)
    assert provenances[0] == {
        "boundary_label": "SYNTHETIC LOCAL LAB",
        "run_id": "sw_demo_01",
        "commit_placeholder": "0" * 40,
        "mode": "deterministic",
        "oracle": "deterministic",
        "model_calls": 0,
        "workspace": "local-lab",
        "certification": "not release-certified",
        "fixture_status": "saved synthetic implementation evidence",
        "proof_status": "not materialized proof",
    }

    assert overview["tier_counts"]["flow"] == "24 → 4 → 2 → 1"
    assert len(worlds["nodes"]) == 32
    assert len(worlds["edges"]) == 34
    assert sum(node["pruned"] for node in worlds["nodes"]) == 17
    node_ids = {node["node_id"] for node in worlds["nodes"]}
    assert worlds["selected_inspector"]["node_id"] in node_ids
    assert set(worlds["selected_inspector"]["parent_node_ids"]) <= node_ids

    overview_fragments = {item["fragment_id"] for item in overview["required_fragments"]}
    twin_fragments = {item["fragment_id"] for item in twin["fragments"]}
    assert overview_fragments == twin_fragments == {"fragment-a", "fragment-b", "fragment-c"}
    assert all(
        item["provenance"]["observation_status"] == "SYNTHETIC" for item in twin["fragments"]
    )

    assert replay["vulnerable"]["plan_hash"] == replay["patched"]["plan_hash"]
    assert replay["vulnerable"]["plan_hash"] == overview["hashes"]["plan_hash"]
    assert replay["vulnerable"]["steps"][-1]["verdict"] == "VIOLATED"
    assert replay["patched"]["steps"][-1]["verdict"] == "BLOCKED_BY_FIX"
    assert {item["verdict"] for item in replay["controls"]} == {"SATISFIED"}
    assert len({item["signature"] for item in replay["run_markers"]}) == 1
    assert len(replay["run_markers"]) == 5


def test_public_experience_keeps_a_read_only_closed_route_surface() -> None:
    client = TestClient(app)
    for path in (
        "/v1/demo/overview",
        "/v1/demo/worlds",
        "/v1/demo/twin",
        "/v1/demo/replay",
    ):
        assert client.post(path, json={"target": "unexpected"}).status_code == 405
    assert client.get("/v1/demo/arbitrary").status_code == 404
