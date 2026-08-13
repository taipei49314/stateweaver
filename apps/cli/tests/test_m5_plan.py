"""The shared M5 plan compiler has one deterministic, closed output."""

from __future__ import annotations

import asyncio
import importlib
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import cast

import pytest
from stateweaver.adapters.docker_compose import (
    M4MaterializedStateBinding,
    MaterializedCandidateRequest,
    MaterializedProviderReceipt,
    RealDockerComposeEnvironmentAdapter,
)
from stateweaver.contracts import OracleOutcome, ScopeMetadata, canonical_json_bytes, sha256_digest
from stateweaver.policy import PolicyAuthorization, PolicyRequest, evaluate_policy
from stateweaver.worlds import (
    EnvironmentHandle,
    ResourceQuotas,
    SnapshotManifest,
    TargetSpec,
    WorldNamespace,
)

from stateweaver.cli.m5_plan import M5ControlPlan, M5ExecutionPlan, compile_m5_plan
from stateweaver.cli.materialized_search_qualification import (
    MaterializedSearchQualificationReceipt,
    _execute_materialized_search,
)
from stateweaver.cli.observed_chain_qualification import qualify_observed_chain
from stateweaver.cli.runtime_qualification import qualify_runtime_observation_chain

MARKER = "4" * 40
_PROVIDERS = ("cache", "clock", "database", "filesystem", "queue", "session")


class _M4MemoryProvider:
    """Minimal typed M4 port double; it creates no M5 policy or oracle behavior."""

    def __init__(self) -> None:
        self._pin = RealDockerComposeEnvironmentAdapter().capabilities().pin
        self._counter = 0
        self._live: set[str] = set()
        self._fork_snapshot: SnapshotManifest | None = None

    def _handle(self) -> EnvironmentHandle:
        self._counter += 1
        token = f"{self._counter:032x}"
        environment_id = f"environment:{token}"
        self._live.add(environment_id)
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
        assert self._fork_snapshot is not None
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


def _m4_receipt() -> MaterializedSearchQualificationReceipt:
    chain = qualify_runtime_observation_chain(MARKER)
    return asyncio.run(
        _execute_materialized_search(
            chain[0],
            observed_chain=chain,
            adapter=_M4MemoryProvider(),
        )
    )


def test_compile_m5_plan_is_exact_and_covers_observed_and_control_paths() -> None:
    m4 = _m4_receipt()

    first = compile_m5_plan(m4)
    second = compile_m5_plan(m4)

    assert canonical_json_bytes(_execution_bytes(first)) == canonical_json_bytes(
        _execution_bytes(second)
    )
    assert len(first.replay_plan.steps) == 8
    assert tuple(step.step_id for step in first.replay_plan.steps) == tuple(
        f"step.{index:02d}" for index in range(1, 9)
    )
    assert len({step.action.idempotency_key for step in first.replay_plan.steps}) == 8
    assert len({item.policy_decision_ref for item in first.policy_authorizations}) == 8
    assert len(first.policy_requests) == 8
    assert tuple(item.action_envelope for item in first.policy_requests) == tuple(
        step.action for step in first.replay_plan.steps
    )
    assert tuple(item.fingerprint() for item in first.policy_requests) == tuple(
        item.policy_request_hash for item in first.policy_authorizations
    )
    assert tuple(item.action_id for item in first.policy_authorizations) == tuple(
        step.action.action_id for step in first.replay_plan.steps
    )
    assert tuple(item.name for item in first.negative_controls) == (
        "masked_response",
        "mock_only_response",
        "fresh_session",
        "same_tenant_document",
    )
    assert all(
        control.replay_plan.steps[-1].oracle_expectations[0].allowed_results
        == frozenset({control.expected_outcome.value})
        for control in first.negative_controls
    )
    assert first.negative_controls[1].expected_outcome is OracleOutcome.INCONCLUSIVE


def _execution_bytes(plan: M5ExecutionPlan) -> dict[str, object]:
    """Serialize the public plan bytes without registry implementation details."""

    return {
        "replay_plan": plan.replay_plan,
        "policy_requests": plan.policy_requests,
        "policy_authorizations": plan.policy_authorizations,
        "controls": tuple(
            (
                control.name,
                control.expected_outcome,
                control.expected_status,
                control.replay_plan,
                control.policy_requests,
                control.policy_authorizations,
            )
            for control in plan.negative_controls
        ),
    }


def test_m5_execution_plan_rejects_plan_and_control_substitution() -> None:
    compiled = compile_m5_plan(_m4_receipt())

    with pytest.raises(ValueError, match="admitted M4 chain"):
        M5ExecutionPlan(
            m4_receipt_digest=compiled.m4_receipt_digest,
            observed_chain_digest=compiled.observed_chain_digest,
            compiler_admission=compiled.compiler_admission,
            scope_manifest=compiled.scope_manifest,
            replay_plan=compiled.replay_plan.model_copy(
                update={"root_seed_id": "root.substituted"}
            ),
            policy_requests=compiled.policy_requests,
            policy_authorizations=compiled.policy_authorizations,
            registry=compiled.registry,
            negative_controls=compiled.negative_controls,
        )

    with pytest.raises(ValueError, match="control"):
        M5ControlPlan(
            name=compiled.negative_controls[0].name,
            expected_outcome=compiled.negative_controls[0].expected_outcome,
            expected_status=compiled.negative_controls[0].expected_status + 1,
            replay_plan=compiled.negative_controls[0].replay_plan,
            policy_requests=compiled.negative_controls[0].policy_requests,
            policy_authorizations=compiled.negative_controls[0].policy_authorizations,
            registry=compiled.negative_controls[0].registry,
        )


def _rebuild_execution(
    compiled: M5ExecutionPlan,
    *,
    policy_requests: tuple[PolicyRequest, ...],
    policy_authorizations: tuple[PolicyAuthorization, ...] | None = None,
) -> M5ExecutionPlan:
    return M5ExecutionPlan(
        m4_receipt_digest=compiled.m4_receipt_digest,
        observed_chain_digest=compiled.observed_chain_digest,
        compiler_admission=compiled.compiler_admission,
        scope_manifest=compiled.scope_manifest,
        replay_plan=compiled.replay_plan,
        policy_requests=policy_requests,
        policy_authorizations=(
            compiled.policy_authorizations
            if policy_authorizations is None
            else policy_authorizations
        ),
        registry=compiled.registry,
        negative_controls=compiled.negative_controls,
    )


def test_m5_execution_plan_rejects_policy_request_substitutions() -> None:
    compiled = compile_m5_plan(_m4_receipt())
    original = compiled.policy_requests[0]
    assert original.scope_manifest is not None
    assert original.budget is not None
    assert original.evaluated_at is not None

    substituted_scope = original.scope_manifest.model_copy(
        update={"metadata": ScopeMetadata(name="m5-substituted")}
    )
    substitutions = (
        original.model_copy(update={"scope_manifest": substituted_scope}),
        original.model_copy(
            update={
                "budget": original.budget.model_copy(
                    update={"requests_in_window": original.budget.requests_in_window + 1}
                )
            }
        ),
        original.model_copy(update={"evaluated_at": original.evaluated_at + timedelta(seconds=1)}),
        original.model_copy(update={"action_envelope": compiled.replay_plan.steps[1].action}),
    )
    for substituted in substitutions:
        requests = (substituted, *compiled.policy_requests[1:])
        with pytest.raises(ValueError, match=r"policy request|registry content"):
            _rebuild_execution(compiled, policy_requests=requests)

    with pytest.raises(ValueError, match=r"policy request|registry content"):
        _rebuild_execution(
            compiled,
            policy_requests=tuple(reversed(compiled.policy_requests)),
        )


def test_m5_execution_plan_rejects_rehashed_request_and_evaluator_substitution() -> None:
    compiled = compile_m5_plan(_m4_receipt())
    original = compiled.policy_requests[0]
    assert original.budget is not None
    substituted = original.model_copy(
        update={"budget": original.budget.model_copy(update={"request_window_seconds": 2.0})}
    )
    decision = evaluate_policy(substituted)
    rebound = PolicyAuthorization.bind(compiled.replay_plan.steps[0].action, substituted, decision)
    requests = (substituted, *compiled.policy_requests[1:])
    authorizations = (rebound, *compiled.policy_authorizations[1:])

    with pytest.raises(ValueError, match="registry content"):
        _rebuild_execution(
            compiled,
            policy_requests=requests,
            policy_authorizations=authorizations,
        )

    substituted_decision = evaluate_policy(object())
    substituted_authorization = compiled.policy_authorizations[0].model_copy(
        update={"decision": substituted_decision}
    )
    with pytest.raises(ValueError, match="registry content"):
        _rebuild_execution(
            compiled,
            policy_requests=compiled.policy_requests,
            policy_authorizations=(
                substituted_authorization,
                *compiled.policy_authorizations[1:],
            ),
        )


def test_observed_qualification_consumes_the_shared_execution_plan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    m4 = _m4_receipt()
    retained = tmp_path / "materialized-search-receipt.json"
    retained.write_bytes(canonical_json_bytes(m4) + b"\n")
    calls: list[MaterializedSearchQualificationReceipt] = []
    observed_qualification = importlib.import_module("stateweaver.cli.observed_chain_qualification")
    compiler_name = "compile_m5_plan"
    original = cast(
        Callable[[MaterializedSearchQualificationReceipt], M5ExecutionPlan],
        getattr(observed_qualification, compiler_name),
    )

    def tracked(m4_input: MaterializedSearchQualificationReceipt) -> M5ExecutionPlan:
        calls.append(m4_input)
        return original(m4_input)

    monkeypatch.setattr(observed_qualification, "compile_m5_plan", tracked)

    receipt = qualify_observed_chain(m4_receipt_path=retained, repository_marker=MARKER)

    assert calls == [m4]
    assert receipt.replay_plan == original(m4).replay_plan
