from __future__ import annotations

from pathlib import Path

_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_WORKFLOW_PATH = _REPOSITORY_ROOT / ".github" / "workflows" / "docker-compose-live.yml"
_CANDIDATE_WORKFLOW_PATH = _REPOSITORY_ROOT / ".github" / "workflows" / "candidate.yml"


def _workflow() -> str:
    return _WORKFLOW_PATH.read_text(encoding="utf-8")


def _step(workflow: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    assert workflow.count(marker) == 1
    return workflow.split(marker, 1)[1].split("\n      - name: ", 1)[0]


def test_hosted_workflow_builds_exact_sha_materialized_application() -> None:
    workflow = _workflow()
    build = _step(
        workflow,
        "Acquire and bind the real provider and materialized application images",
    )

    assert "timeout-minutes: 60" in workflow
    exact_build = (
        "docker build \\\n"
        "            --tag stateweaver-materialized-lab:local \\\n"
        "            --build-arg STATEWEAVER_SOURCE_SHA=$GITHUB_SHA \\\n"
        "            --file adapters/environments/docker_compose/src/stateweaver/"
        "adapters/docker_compose/MaterializedLabDockerfile \\\n"
        "            ."
    )
    assert exact_build in build
    assert "stateweaver-materialized-lab:local" in build.split("docker image inspect \\", 1)[1]


def test_hosted_workflow_retains_materialized_source_inventory() -> None:
    workflow = _workflow()
    provenance = _step(workflow, "Record Docker runtime")
    expected_sources = (
        "adapters/environments/docker_compose/src/stateweaver/adapters/docker_compose/MaterializedLabDockerfile",
        "adapters/environments/docker_compose/src/stateweaver/adapters/docker_compose/materialized_lab_requirements.txt",
        "adapters/environments/docker_compose/src/stateweaver/adapters/docker_compose/materialized_lab_runtime.py",
        "labs/multitenant-saas/stateweaver_lab/asgi.py",
        "labs/multitenant-saas/stateweaver_lab/provider_checkpoint.py",
        "labs/multitenant-saas/stateweaver_lab/state.py",
    )

    for source in expected_sources:
        assert provenance.count(source) == 1
    assert "> artifacts/m2-live/source-sha256.txt" in provenance


def test_hosted_workflow_runs_one_exact_actual_asgi_qualifier_after_observed_chain() -> None:
    workflow = _workflow()
    observed_name = "Compile retained M4 bytes and replay the observed chain over five clean roots"
    actual_name = "Execute and qualify the fixed ten-scenario actual-ASGI M5 chain"
    observed = _step(workflow, observed_name)
    actual = _step(workflow, actual_name)

    assert workflow.index(observed_name) < workflow.index(actual_name)
    assert workflow.count("foundation qualify-materialized-chain") == 1
    assert "foundation qualify-observed-chain" in observed
    assert "--m4-receipt artifacts/m4-live/materialized-search-receipt.json" in actual
    assert "--process-receipt artifacts/m5-clean-root/observed-chain-receipt.json" in actual
    assert '--repository-marker "$GITHUB_SHA"' in actual
    assert "--output artifacts/m5-clean-root/materialized-chain-replay.json" in actual
    assert "materialized-provider-receipt.json" not in workflow


def test_hosted_workflow_preserves_runtime_and_global_cleanup_gates() -> None:
    workflow = _workflow()
    actual_name = "Execute and qualify the fixed ten-scenario actual-ASGI M5 chain"
    cleanup_name = "Record and enforce cleanup inventory"
    cleanup = _step(workflow, cleanup_name)

    assert workflow.index(actual_name) < workflow.index(cleanup_name)
    assert "if: always()" in cleanup
    for resource in ("containers", "networks", "volumes"):
        assert f"swm2-{resource}-after.txt" in cleanup
        assert f"test ! -s artifacts/m2-live/swm2-{resource}-after.txt" in cleanup
    assert "test ! -s artifacts/m2-live/managed-processes-after.txt" in cleanup
    assert "test ! -s artifacts/m2-live/dirty-after.txt" in cleanup


def test_hosted_workflow_retains_exact_m2_m5_attestation_subject() -> None:
    workflow = _workflow()
    producer = _step(workflow, "Retain the hosted M2-M5 qualification")
    exact_subject = _step(workflow, "Require the exact subject and source")
    attestation = _step(workflow, "Attest the hosted qualification receipt")

    assert "path: artifacts/hosted-qualification/hosted-docker-qualification.json" in producer
    assert '[[ "$(git rev-parse HEAD)" == "$GITHUB_SHA" ]]' in exact_subject
    assert '[[ "${#subjects[@]}" -eq 1 ]]' in exact_subject
    assert (
        '[[ "$(basename "${subjects[0]}")" == "hosted-docker-qualification.json" ]]'
        in exact_subject
    )
    assert "subject-path: hosted-qualification/hosted-docker-qualification.json" in attestation


def test_candidate_downloads_and_reverifies_the_exact_hosted_subject() -> None:
    candidate = _CANDIDATE_WORKFLOW_PATH.read_text(encoding="utf-8")
    consumer = _step(
        candidate,
        "Verify the source workflow identity and download exact artifacts",
    )

    assert 'run.get("head_sha") == expected_sha' in consumer
    assert 'run.get("path") == ".github/workflows/docker-compose-live.yml"' in consumer
    assert 'receipt_name="hosted-docker-qualification-$QUALIFICATION_RUN_ID-$attempt"' in consumer
    assert 'bundle_name="$receipt_name-attestation"' in consumer
    assert consumer.count('gh run download "$QUALIFICATION_RUN_ID"') == 2
    assert '[[ "${#receipts[@]}" -eq 1 && "${#bundles[@]}" -eq 1 ]]' in consumer
    assert "foundation admit-hosted-docker" in consumer
    assert '--repository-marker "$SOURCE_SHA"' in consumer


def test_candidate_admits_exact_sha_m2_m5_without_overclaiming_remaining_gates() -> None:
    candidate = _CANDIDATE_WORKFLOW_PATH.read_text(encoding="utf-8")
    summary = _step(candidate, "Report candidate-only status")

    assert "name: Admit exact-SHA hosted M2-M5 actual qualification" in candidate
    assert "Download the exact-SHA hosted M2-M5 actual admission" in candidate
    assert (
        'expected = {"blocked": 21, "failed": 0, "not_run": 0, "passed": 71, "required": 92}'
    ) in candidate
    assert "M5 ten-scenario actual-ASGI clean-root replay" in summary
    assert "Acceptance registry: 71 PASS, 21 BLOCKED, 92 required." in summary
    assert "SW-M2-LIVE still requires a separate clean host" in summary
    assert "M6-M8 retain implementation and external-qualification blockers" in summary
    assert "SW-M5-CHAIN remains unadmitted" not in candidate
    assert "M2-M4 admission with M5 receipt" not in candidate
