"""M4 materialized-search qualification regressions."""

from __future__ import annotations

import asyncio
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest
from stateweaver.adapters.docker_compose import (
    M4MaterializedStateBinding,
    M5MaterializedProviderRunReceipt,
    M5MaterializedProviderRunRequest,
    M5MaterializedProviderStep,
    M5ProviderDigest,
    MaterializedCandidateRequest,
    MaterializedProviderReceipt,
    RealDockerComposeEnvironmentAdapter,
)
from stateweaver.adapters.in_process_lab import CANONICAL_RANDOM_SEED, InProcessLabEnvironment
from stateweaver.contracts import (
    OracleOutcome,
    ProvenanceKind,
    WorldTier,
    canonical_json_bytes,
    sha256_digest,
)
from stateweaver.evidence.hosted_qualification import (
    HostedQualificationError,
    hosted_qualification_admissions,
    hosted_qualification_payloads,
    validate_hosted_qualification_admission,
)
from stateweaver.replay import ReplayRunStatus
from stateweaver.search import ScoreSource
from stateweaver.worlds import (
    EnvironmentHandle,
    ResourceQuotas,
    SnapshotManifest,
    TargetSpec,
    WorldNamespace,
)
from stateweaver_lab import LabMode

from stateweaver.cli.hosted_qualification import (
    admit_hosted_qualification,
    build_hosted_docker_qualification,
    build_hosted_qualification_admission,
    write_hosted_receipt,
)
from stateweaver.cli.materialized_chain_qualification import (
    MaterializedChainQualificationReceipt,
    qualify_materialized_chain,
    write_materialized_chain_qualification,
)
from stateweaver.cli.materialized_search_qualification import (
    MaterializedSearchQualificationError,
    MaterializedSearchQualificationReceipt,
    _execute_materialized_search,
    derive_ghost_search_batch,
    qualify_materialized_search,
)
from stateweaver.cli.observed_chain_qualification import (
    M5_REPLAY_COUNT,
    ObservedChainQualificationError,
    _compiler_admission,
    _ExactObservedEnvironment,
    _fresh_plan,
    qualify_observed_chain,
)
from stateweaver.cli.runtime_qualification import (
    qualify_runtime_observation,
    qualify_runtime_observation_chain,
)

MARKER = "4" * 40
_PROVIDERS = ("cache", "clock", "database", "filesystem", "queue", "session")


def _canonical_file(path: Path, value: object) -> None:
    path.write_bytes(canonical_json_bytes(value) + b"\n")


def _junit(classname: str, names: tuple[str, ...]) -> bytes:
    cases = "".join(f'<testcase classname="{classname}" name="{name}" />' for name in names)
    return (
        f'<testsuite tests="{len(names)}" failures="0" errors="0" skipped="0">{cases}</testsuite>'
    ).encode()


def _hosted_roots(
    tmp_path: Path,
    *,
    m4: MaterializedSearchQualificationReceipt,
    marker: str,
    tree_sha: str,
) -> tuple[Path, Path, Path]:
    m2_root = tmp_path / "m2-live"
    m4_root = tmp_path / "m4-live"
    m5_root = tmp_path / "m5-clean-root"
    m2_root.mkdir()
    m4_root.mkdir()
    m5_root.mkdir()
    (m2_root / "commit.txt").write_bytes(f"{marker}\n".encode("ascii"))
    (m2_root / "tree.txt").write_bytes(f"{tree_sha}\n".encode("ascii"))
    (m2_root / "junit.xml").write_bytes(
        _junit(
            "tests.integration.worlds.test_live_docker_compose",
            ("test_four_live_siblings_overlap_isolate_and_restore",),
        )
    )
    (m2_root / "real-provider-junit.xml").write_bytes(
        _junit(
            "tests.integration.worlds.test_live_real_providers",
            (
                "test_four_real_provider_siblings_overlap_isolate_restore_and_cleanup",
                "test_real_provider_start_timeout_returns_inventory_to_zero",
                "test_real_provider_cancellation_returns_inventory_to_zero",
                "test_real_provider_partial_failure_returns_inventory_to_zero",
            ),
        )
    )
    baseline = {name: sha256_digest({"provider": name, "phase": "baseline"}) for name in _PROVIDERS}
    _canonical_file(
        m2_root / "real-provider-receipt.json",
        {
            "schema_version": "stateweaver-m2-real-provider-observation-v1",
            "adapter": "docker-compose-real-providers@0.1.0",
            "target": "real-provider-demo@1.0.0",
            "providers": list(_PROVIDERS),
            "siblings": 4,
            "overlap": {"fork_max_in_flight": 4, "restore_max_in_flight": 4},
            "worlds": [
                {
                    "baseline": baseline,
                    "mutated": {
                        name: sha256_digest({"provider": name, "phase": "mutated", "world": world})
                        for name in _PROVIDERS
                    },
                    "restored": baseline,
                }
                for world in range(4)
            ],
            "cleanup": {"adapter_owned_worlds": 0, "status": "PASS"},
            "status": "PASS",
        },
    )
    for case in ("success", "timeout", "cancellation", "partial-failure"):
        _canonical_file(
            m2_root / f"cleanup-{case}.json",
            {
                "schema_version": "stateweaver-m2-cleanup-case-v1",
                "case": case,
                "containers_after": 0,
                "networks_after": 0,
                "volumes_after": 0,
                "status": "PASS",
            },
        )
    for stem, content in (
        ("containers", b"CONTAINER ID IMAGE\n"),
        ("networks", b"NETWORK ID NAME\n"),
        ("volumes", b"DRIVER VOLUME NAME\n"),
    ):
        (m2_root / f"{stem}-before.txt").write_bytes(content)
        (m2_root / f"{stem}-after.txt").write_bytes(content)
    for name in (
        "dirty-before.txt",
        "dirty-after.txt",
        "managed-processes-before.txt",
        "managed-processes-after.txt",
        "swm2-containers-after.txt",
        "swm2-networks-after.txt",
        "swm2-volumes-after.txt",
    ):
        (m2_root / name).write_bytes(b"")
    for name in (
        "compose-version.txt",
        "docker-version.txt",
        "processes-before.txt",
        "processes-after.txt",
        "real-provider-images-inspect.json",
        "source-sha256.txt",
        "synthetic-image-inspect.json",
    ):
        (m2_root / name).write_bytes(b"retained-provenance\n")
    (m4_root / "junit.xml").write_bytes(
        _junit(
            "tests.integration.worlds.test_live_materialized_search",
            ("test_observed_search_materializes_only_four_two_one_and_reclaims_every_world",),
        )
    )
    (m4_root / "materialized-search-receipt.json").write_bytes(canonical_json_bytes(m4) + b"\n")
    m5 = qualify_observed_chain(
        m4_receipt_path=m4_root / "materialized-search-receipt.json",
        repository_marker=marker,
    )
    (m5_root / "observed-chain-receipt.json").write_bytes(canonical_json_bytes(m5) + b"\n")
    materialized = qualify_materialized_chain(
        m4_receipt_path=m4_root / "materialized-search-receipt.json",
        process_receipt_path=m5_root / "observed-chain-receipt.json",
        repository_marker=marker,
        adapter=_MemoryM5ProviderAdapter(),
    )
    write_materialized_chain_qualification(
        m5_root / "materialized-provider-receipt.json",
        materialized,
    )
    return m2_root, m4_root, m5_root


class _MemoryRealProviderAdapter:
    """Port double for receipt/tier adversarial tests; the live test uses Docker."""

    def __init__(self) -> None:
        self._pin = RealDockerComposeEnvironmentAdapter().capabilities().pin
        self._counter = 0
        self._live: set[str] = set()
        self.allocated = 0
        self.max_live = 0
        self._fork_snapshot: SnapshotManifest | None = None

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
        self._fork_snapshot = snapshot
        return self._handle()

    async def materialize_observed_candidate(
        self,
        env: EnvironmentHandle,
        request: MaterializedCandidateRequest,
    ) -> MaterializedProviderReceipt:
        if self._fork_snapshot is None:
            raise AssertionError("memory M4 provider was not forked from a snapshot")
        after = self._hashes(request.marker)
        binding = M4MaterializedStateBinding.create(
            adapter_pin=self._pin,
            bridge_image_id=sha256_digest({"memory": "bridge-image"}),
            provider_image_refs=("memory-provider@sha256:" + "0" * 64,),
            source_snapshot=self._fork_snapshot,
            after_archive_digest=sha256_digest({"memory_provider_state": after}),
            provider_state_digest=sha256_digest(after),
        )
        return MaterializedProviderReceipt.create(
            request=request,
            environment_id=env.environment_id,
            before=self._hashes("baseline"),
            after=after,
            elapsed_ns=1,
            state_binding=binding,
        )

    async def destroy(self, env: EnvironmentHandle) -> None:
        self._live.discard(env.environment_id)


class _MemoryM5ProviderAdapter:
    """Typed provider-run double; the live workflow uses the real Docker bridge."""

    async def run_m5_materialized_provider(
        self,
        request: M5MaterializedProviderRunRequest,
    ) -> M5MaterializedProviderRunReceipt:
        current = tuple(
            M5ProviderDigest(provider=item.provider, sha256=item.after_sha256)
            for item in request.m4_provider_receipt.providers
        )
        steps: list[M5MaterializedProviderStep] = []
        for index, action in enumerate(request.actions, start=1):
            after = tuple(
                M5ProviderDigest(
                    provider=item.provider,
                    sha256=sha256_digest(
                        {
                            "provider": item.provider,
                            "action": sha256_digest(action),
                            "step": index,
                        }
                    ),
                )
                for item in current
            )
            steps.append(
                M5MaterializedProviderStep(
                    step_id=f"step.{index:02d}",
                    action=action,
                    action_digest=sha256_digest(action),
                    response_status=(
                        request.expected_response_status if index == len(request.actions) else 200
                    ),
                    oracle_outcome=(
                        request.expected_oracle_outcome
                        if index == len(request.actions)
                        else "INCONCLUSIVE"
                    ),
                    before=current,
                    after=after,
                )
            )
            current = after
        baseline = tuple(
            M5ProviderDigest(provider=item.provider, sha256=item.after_sha256)
            for item in request.m4_provider_receipt.providers
        )
        values: dict[str, object] = {
            "schema_version": "stateweaver-m5-materialized-provider-run-v1",
            "status": "M5_MATERIALIZED_PROVIDER_RUN_QUALIFIED",
            "request": request,
            "request_digest": sha256_digest(request),
            "steps": tuple(steps),
            "final_provider_state": current,
            "restored_provider_state": baseline,
            "cleanup_status": "PASS",
            "destroyed": True,
        }
        return M5MaterializedProviderRunReceipt.model_validate(
            {**values, "receipt_digest": sha256_digest(values)}
        )


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
    chain = qualify_runtime_observation_chain(MARKER)
    observed = chain[0]
    adapter = _MemoryRealProviderAdapter()

    receipt = asyncio.run(
        _execute_materialized_search(observed, observed_chain=chain, adapter=adapter)
    )

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
    chain = qualify_runtime_observation_chain(MARKER)
    observed = chain[0]
    receipt = asyncio.run(
        _execute_materialized_search(
            observed,
            observed_chain=chain,
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


def test_rehashed_winner_provider_image_or_state_substitution_is_rejected() -> None:
    chain = qualify_runtime_observation_chain(MARKER)
    receipt = asyncio.run(
        _execute_materialized_search(
            chain[0], observed_chain=chain, adapter=_MemoryRealProviderAdapter()
        )
    )
    substituted = deepcopy(receipt.model_dump(mode="json"))
    binding = substituted["provider_receipts"][-1]["state_binding"]
    binding["bridge_image_id"] = sha256_digest({"forged": "bridge-image"})
    binding["after_archive_digest"] = sha256_digest({"forged": "provider-state"})
    binding["binding_digest"] = sha256_digest(
        {key: value for key, value in binding.items() if key != "binding_digest"}
    )
    provider = substituted["provider_receipts"][-1]
    provider["receipt_digest"] = sha256_digest(
        {key: value for key, value in provider.items() if key != "receipt_digest"}
    )
    substituted["receipt_digest"] = sha256_digest(
        {key: value for key, value in substituted.items() if key != "receipt_digest"}
    )

    with pytest.raises(ValueError, match="winner"):
        MaterializedSearchQualificationReceipt.model_validate_json(
            canonical_json_bytes(substituted)
        )


def test_exact_m4_bytes_compile_and_replay_five_clean_actual_asgi_roots(
    tmp_path: Path,
) -> None:
    chain = qualify_runtime_observation_chain(MARKER)
    m4 = asyncio.run(
        _execute_materialized_search(
            chain[0],
            observed_chain=chain,
            adapter=_MemoryRealProviderAdapter(),
        )
    )
    retained = tmp_path / "materialized-search-receipt.json"
    retained.write_bytes(canonical_json_bytes(m4) + b"\n")

    receipt = qualify_observed_chain(m4_receipt_path=retained, repository_marker=MARKER)

    assert len(receipt.runs) == M5_REPLAY_COUNT
    assert receipt.cleanup_count == 10
    assert receipt.determinism.deterministic
    assert receipt.determinism.all_runs_succeeded
    assert len(receipt.compiler_admission.compiled_chain.fragment_ids) == 8
    assert all(item.status is ReplayRunStatus.SUCCEEDED for item in receipt.runs)
    assert all(
        item.steps[-1].oracle_results[-1].result is OracleOutcome.VIOLATED for item in receipt.runs
    )
    assert all(
        item.steps[-1].observations[-1].payload["response_status"] == 200 for item in receipt.runs
    )
    assert receipt.patched_run.status is ReplayRunStatus.FAILED
    assert receipt.patched_run.failed_step_id == "step.08"
    assert receipt.patched_run.steps[-1].failure_code == "ORACLE_EXPECTATION_MISMATCH"
    assert receipt.patched_run.steps[-1].oracle_results[-1].result is OracleOutcome.SATISFIED
    assert receipt.patched_run.steps[-1].observations[-1].payload["response_status"] == 403
    assert receipt.patched_plan_digest == receipt.replay_plan_digest
    assert tuple(item.name for item in receipt.negative_controls) == (
        "masked_response",
        "mock_only_response",
        "fresh_session",
        "same_tenant_document",
    )
    assert all(
        item.result.status is ReplayRunStatus.SUCCEEDED for item in receipt.negative_controls
    )
    assert receipt.m4_receipt_json.encode("utf-8") == retained.read_bytes()

    substituted_plan = deepcopy(receipt.model_dump(mode="json"))
    first_action = substituted_plan["replay_plan"]["steps"][0]["action"]
    first_action["timeout_ms"] += 1
    substituted_plan["replay_plan_digest"] = sha256_digest(substituted_plan["replay_plan"])
    substituted_plan["patched_plan_digest"] = substituted_plan["replay_plan_digest"]
    substituted_plan["receipt_digest"] = sha256_digest(
        {key: value for key, value in substituted_plan.items() if key != "receipt_digest"}
    )
    with pytest.raises(ValueError, match="incoherent"):
        type(receipt).model_validate_json(canonical_json_bytes(substituted_plan))

    substituted_control = deepcopy(receipt.model_dump(mode="json"))
    substituted_control["negative_controls"][0]["plan_digest"] = "sha256:" + "0" * 64
    substituted_control["receipt_digest"] = sha256_digest(
        {key: value for key, value in substituted_control.items() if key != "receipt_digest"}
    )
    with pytest.raises(ValueError, match="negative control"):
        type(receipt).model_validate_json(canonical_json_bytes(substituted_control))

    substituted_patched_root = deepcopy(receipt.model_dump(mode="json"))
    substituted_patched_root["patched_root"]["target_version"] = "lab-vulnerable"
    substituted_patched_root["receipt_digest"] = sha256_digest(
        {key: value for key, value in substituted_patched_root.items() if key != "receipt_digest"}
    )
    with pytest.raises(ValueError, match="incoherent"):
        type(receipt).model_validate_json(canonical_json_bytes(substituted_patched_root))

    retained.write_bytes(retained.read_bytes() + b" ")
    with pytest.raises(ObservedChainQualificationError, match="invalid"):
        qualify_observed_chain(m4_receipt_path=retained, repository_marker=MARKER)


def test_m5_rejects_action_and_root_substitution_before_state_change() -> None:
    chain = qualify_runtime_observation_chain(MARKER)
    m4 = asyncio.run(
        _execute_materialized_search(
            chain[0],
            observed_chain=chain,
            adapter=_MemoryRealProviderAdapter(),
        )
    )
    admission = _compiler_admission(m4)

    async def exercise() -> None:
        plan, registry = _fresh_plan(admission)
        delegate = InProcessLabEnvironment(mode=LabMode.VULNERABLE, registry=registry)
        root = await delegate.create_root_seed(
            root_seed_id=admission.compiled_chain.root_seed_id,
            random_seed=CANONICAL_RANDOM_SEED,
        )
        environment = _ExactObservedEnvironment(delegate, plan=plan, root=root)
        await environment.reset(root)
        before = await environment.capture()
        substituted = plan.steps[0].action.model_copy(
            update={"timeout_ms": plan.steps[0].action.timeout_ms + 1}
        )
        with pytest.raises(PermissionError, match="substitution"):
            await environment.execute(substituted)
        assert await environment.capture() == before

        drifted_root = root.model_copy(update={"random_seed": root.random_seed + 1})
        with pytest.raises(ValueError, match="root identity"):
            await environment.reset(drifted_root)
        assert await environment.capture() == before
        await environment.cleanup()

    asyncio.run(exercise())


def test_hosted_receipt_admits_exact_m2_m4_rows_but_not_missing_clean_host(
    tmp_path: Path,
) -> None:
    chain = qualify_runtime_observation_chain(MARKER)
    m4 = asyncio.run(
        _execute_materialized_search(
            chain[0],
            observed_chain=chain,
            adapter=_MemoryRealProviderAdapter(),
        )
    )
    tree_sha = "a" * 40
    m2_root, m4_root, m5_root = _hosted_roots(
        tmp_path,
        m4=m4,
        marker=MARKER,
        tree_sha=tree_sha,
    )
    producer = build_hosted_docker_qualification(
        m2_root=m2_root,
        m4_root=m4_root,
        m5_root=m5_root,
        repository_marker=MARKER,
        tree_sha=tree_sha,
        workflow_run_id=123456,
        workflow_run_attempt=1,
        workflow_run_url=("https://github.com/taipei49314/stateweaver/actions/runs/123456"),
        runner_os="Linux",
        runner_arch="X64",
    )
    bundle = tmp_path / "attestation.json"
    bundle.write_bytes(b'{"verificationMaterial":{}}\n')
    admission = build_hosted_qualification_admission(
        qualification_receipt=producer,
        attestation_bundle=bundle,
    )
    admitted = validate_hosted_qualification_admission(
        admission.model_dump(mode="json"),
        expected_repository_marker=MARKER,
    )

    admitted_rows = hosted_qualification_admissions(admitted)
    assert len(hosted_qualification_payloads(admitted)) == 12
    assert "SW-M5-CHAIN" not in admitted_rows

    materialized = MaterializedChainQualificationReceipt.model_validate_json(
        (m5_root / "materialized-provider-receipt.json").read_bytes()
    )
    substituted = materialized.model_dump(mode="python")
    first_run = substituted["clean_root_runs"][0]
    provider_receipt = first_run["provider_run_receipt"]
    provider_request = provider_receipt["request"]
    provider_request["plan_digest"] = f"sha256:{'0' * 64}"
    provider_receipt["request_digest"] = sha256_digest(provider_request)
    provider_receipt["receipt_digest"] = sha256_digest(
        {key: value for key, value in provider_receipt.items() if key != "receipt_digest"}
    )
    first_run["provider_run_receipt_digest"] = provider_receipt["receipt_digest"]
    substituted["receipt_digest"] = sha256_digest(
        {key: value for key, value in substituted.items() if key != "receipt_digest"}
    )
    with pytest.raises(ValueError, match="provider composite is incoherent"):
        MaterializedChainQualificationReceipt.model_validate(substituted)
    assert {
        "M2-W01",
        "M2-W02",
        "M2-W03",
        "M2-W04",
        "M2-W05",
        "M2-X01",
        "SW-M2-4WAY",
        "SW-M2-PROVIDERS",
        "SW-M2-CLEANUP",
        "M4-X01",
        "SW-M4-MATERIALIZED",
    } <= set(admitted_rows)
    assert "SW-M2-LIVE" not in admitted_rows
    assert "SW-M5-CHAIN" not in admitted_rows

    (m2_root / "dirty-after.txt").write_bytes(b"untracked\n")
    with pytest.raises(HostedQualificationError, match="dirty state"):
        build_hosted_docker_qualification(
            m2_root=m2_root,
            m4_root=m4_root,
            m5_root=m5_root,
            repository_marker=MARKER,
            tree_sha=tree_sha,
            workflow_run_id=123456,
            workflow_run_attempt=1,
            workflow_run_url=("https://github.com/taipei49314/stateweaver/actions/runs/123456"),
            runner_os="Linux",
            runner_arch="X64",
        )


def test_hosted_admission_runs_the_exact_constrained_attestation_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    chain = qualify_runtime_observation_chain(MARKER)
    m4 = asyncio.run(
        _execute_materialized_search(
            chain[0],
            observed_chain=chain,
            adapter=_MemoryRealProviderAdapter(),
        )
    )
    tree_sha = "a" * 40
    m2_root, m4_root, m5_root = _hosted_roots(
        tmp_path,
        m4=m4,
        marker=MARKER,
        tree_sha=tree_sha,
    )
    producer = build_hosted_docker_qualification(
        m2_root=m2_root,
        m4_root=m4_root,
        m5_root=m5_root,
        repository_marker=MARKER,
        tree_sha=tree_sha,
        workflow_run_id=123456,
        workflow_run_attempt=1,
        workflow_run_url=("https://github.com/taipei49314/stateweaver/actions/runs/123456"),
        runner_os="Linux",
        runner_arch="X64",
    )
    producer_path = tmp_path / "hosted-docker-qualification.json"
    write_hosted_receipt(producer_path, producer)
    bundle_path = tmp_path / "attestation.json"
    bundle_path.write_bytes(b'{"verificationMaterial":{}}\n')
    fake_gh = tmp_path / "gh"
    fake_gh.write_bytes(b"fixed verifier executable")
    observed_argv: list[tuple[str, ...]] = []

    def fake_run(
        argv: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        observed_argv.append(argv)
        assert kwargs == {
            "check": False,
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
            "timeout": 120,
            "shell": False,
        }
        assert Path(argv[3]).read_bytes() == producer_path.read_bytes()
        bundle_index = argv.index("--bundle") + 1
        assert Path(argv[bundle_index]).read_bytes() == bundle_path.read_bytes()
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr("stateweaver.cli.hosted_qualification.shutil.which", lambda _: str(fake_gh))
    monkeypatch.setattr("stateweaver.cli.hosted_qualification.subprocess.run", fake_run)

    admission = admit_hosted_qualification(
        qualification_receipt_path=producer_path,
        attestation_bundle_path=bundle_path,
        expected_repository_marker=MARKER,
    )

    assert admission.status == "HOSTED_QUALIFICATION_ADMITTED"
    assert len(observed_argv) == 1
    argv = observed_argv[0]
    assert argv[:3] == (str(fake_gh.resolve()), "attestation", "verify")
    assert argv[argv.index("--repo") + 1] == "taipei49314/stateweaver"
    assert argv[argv.index("--signer-workflow") + 1] == (
        "github.com/taipei49314/stateweaver/.github/workflows/docker-compose-live.yml"
    )
    assert argv[argv.index("--signer-digest") + 1] == MARKER
    assert argv[argv.index("--source-digest") + 1] == MARKER
    assert argv[argv.index("--source-ref") + 1] == "refs/heads/main"
    assert "--deny-self-hosted-runners" in argv
