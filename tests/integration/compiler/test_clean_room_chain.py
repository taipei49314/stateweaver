from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest
from stateweaver.compiler import ChainCompiler, CompilationError
from stateweaver.contracts import (
    ActionGuard,
    ExpectedEffect,
    RequestedBy,
    RequesterType,
    RiskClass,
    TimeAdvanceAction,
    sha256_digest,
)
from stateweaver.replay import (
    DeterminismClassification,
    ReplayKernel,
    ReplayRunStatus,
    ReplayStepStatus,
)

from ._synthetic import (
    AuthorizedReplay,
    InMemoryEffectsEnvironment,
    TerminalStateOracle,
    chain_fragments,
    compile_chain,
    fresh_plan,
    goal,
    root_seed,
    root_state,
)


def _environment() -> tuple[AuthorizedReplay, InMemoryEffectsEnvironment]:
    authorized = fresh_plan(compile_chain())
    return authorized, InMemoryEffectsEnvironment(
        authorized=authorized,
        expected_root=root_seed(),
    )


@pytest.mark.asyncio
async def test_three_fragment_chain_fresh_authorization_terminal_oracle_and_five_clean_roots() -> (
    None
):
    chain = compile_chain()
    assert chain.fragment_ids == ("fragment.prepare", "fragment.cache", "fragment.terminal")
    assert chain.requires_policy_reauthorization is True
    authorized = fresh_plan(chain)
    plan = authorized.plan
    environment = InMemoryEffectsEnvironment(
        authorized=authorized,
        expected_root=root_seed(),
    )
    kernel = ReplayKernel(environment, {TerminalStateOracle.id: TerminalStateOracle()})

    first = await kernel.replay(run_id="run.clean-room.01", plan=plan, root=root_seed())
    report = await kernel.verify_determinism(
        plan=plan,
        root=root_seed(),
        run_ids=(
            "run.clean-root.01",
            "run.clean-root.02",
            "run.clean-root.03",
            "run.clean-root.04",
            "run.clean-root.05",
        ),
    )

    assert first.status is ReplayRunStatus.SUCCEEDED
    terminal_step = first.steps[-1]
    terminal_oracle = terminal_step.oracle_results[0]
    assert terminal_oracle.result.value == "VIOLATED"
    observed_evidence = {
        evidence_id
        for observation in terminal_step.observations
        for evidence_id in observation.evidence_ids
    }
    assert set(terminal_oracle.evidence_ids) <= observed_evidence
    assert report.deterministic is True
    assert report.all_runs_succeeded is True
    assert report.classification is DeterminismClassification.DETERMINISTIC
    assert len(set(report.signatures)) == 1
    assert environment.cleanup_calls == 6


@pytest.mark.asyncio
async def test_stale_precompile_authorization_fails_closed_before_typed_effects() -> None:
    chain = compile_chain()
    authorized = fresh_plan(chain)
    stale = chain.to_replay_plan(plan_id=authorized.plan.plan_id)
    environment = InMemoryEffectsEnvironment(
        authorized=authorized,
        expected_root=root_seed(),
    )

    result = await ReplayKernel(environment, {}).replay(
        run_id="run.stale", plan=stale, root=root_seed()
    )

    assert result.status is ReplayRunStatus.FAILED
    assert result.steps[0].status is ReplayStepStatus.FAILED
    assert result.steps[0].failure_code == "EXECUTE_FAILURE"
    assert result.final_fingerprint == root_seed().capture.fingerprint


def test_compiler_minimizer_cannot_remove_any_required_fragment() -> None:
    fragments = chain_fragments()
    expected = {"fragment.prepare", "fragment.cache", "fragment.terminal"}
    assert set(compile_chain().fragment_ids) == expected

    for identifier in expected:
        reduced = tuple(item for item in fragments if item.fragment_id != identifier)
        with pytest.raises(CompilationError):
            ChainCompiler().compile(
                chain_id="chain.clean-room-reduced",
                root=root_state(),
                fragments=reduced,
                goal=goal(),
            )


def test_fresh_authorizations_retain_exact_policy_request_decision_and_fragment_bindings() -> None:
    authorized = fresh_plan(compile_chain())

    assert type(authorized.grants).__name__ == "mappingproxy"
    assert tuple(authorized.grants) == tuple(
        step.action.action_id for step in authorized.plan.steps
    )
    for step in authorized.plan.steps:
        grant = authorized.grants[step.action.action_id]
        assert grant.request.action_envelope == step.action
        assert grant.request.fingerprint() == grant.request_digest
        assert grant.decision.fingerprint() == grant.decision_digest
        assert grant.decision.allowed is True
        assert grant.action_digest == sha256_digest(step.action)
        assert grant.root_digest == authorized.root_digest
        assert grant.chain_hash == authorized.chain_hash
        assert grant.fragment.source.value == "mocked"
        assert grant.fragment.fidelity.code.value == "partial"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field",
    [
        "action_id",
        "experiment_id",
        "world_id",
        "risk_class",
        "idempotency_key",
        "requested_by",
        "policy_decision_ref",
        "sequence",
        "timeout_ms",
        "action",
        "preconditions",
    ],
)
async def test_any_action_envelope_substitution_fails_before_state_change(field: str) -> None:
    authorized, environment = _environment()
    action = authorized.plan.steps[0].action
    updates: dict[str, object] = {
        "action_id": "action.substituted",
        "experiment_id": "experiment.substituted",
        "world_id": "world.substituted",
        "risk_class": RiskClass.READ_ONLY,
        "idempotency_key": sha256_digest({"substituted": field}),
        "requested_by": RequestedBy(type=RequesterType.ADAPTER, role="substituted"),
        "policy_decision_ref": "policy.substituted",
        "sequence": 99,
        "timeout_ms": 29_999,
        "action": TimeAdvanceAction(milliseconds=2),
        "preconditions": (ActionGuard(path="root.ready", expected=False),),
    }
    substituted = action.model_copy(update={field: updates[field]})
    clean = await environment.reset(root_seed())

    with pytest.raises(PermissionError):
        await environment.execute(substituted)

    assert (await environment.capture()).fingerprint == clean.fingerprint


@pytest.mark.asyncio
async def test_effect_substitution_is_rejected_and_no_external_effect_map_exists() -> None:
    authorized, environment = _environment()
    action = authorized.plan.steps[0].action
    substituted_effect = ExpectedEffect(
        path=action.expected_effects[0].path,
        operation=action.expected_effects[0].operation,
        value=False,
    )
    substituted = action.model_copy(update={"expected_effects": (substituted_effect,)})
    clean = await environment.reset(root_seed())

    with pytest.raises(PermissionError):
        await environment.execute(substituted)

    assert not hasattr(environment, "_effects")
    assert (await environment.capture()).fingerprint == clean.fingerprint


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("root_seed_id", "root.substituted"),
        ("target_version", "synthetic-clean-room-v2"),
        ("random_seed", 54321),
        ("adapter_versions", {"in_memory_effects": "2.0"}),
    ],
)
async def test_full_root_identity_substitution_is_rejected(field: str, value: object) -> None:
    _authorized, environment = _environment()
    substituted = root_seed().model_copy(update={field: value})

    with pytest.raises(ValueError, match="unrecognized clean root"):
        await environment.reset(substituted)


@pytest.mark.asyncio
async def test_fresh_authorization_and_idempotency_are_one_use_per_clean_root() -> None:
    authorized, environment = _environment()
    action = authorized.plan.steps[0].action
    await environment.reset(root_seed())

    await environment.execute(action)
    after_first = await environment.capture()
    with pytest.raises(PermissionError, match="exact fresh authorization"):
        await environment.execute(action)
    assert (await environment.capture()).fingerprint == after_first.fingerprint

    await environment.reset(root_seed())
    await environment.execute(action)


def test_grant_or_fragment_substitution_is_rejected_during_environment_construction() -> None:
    authorized = fresh_plan(compile_chain())
    action_id = authorized.plan.steps[0].action.action_id
    grant = authorized.grants[action_id]

    bad_decision_grants = dict(authorized.grants)
    bad_decision_grants[action_id] = replace(
        grant,
        decision_digest=sha256_digest({"substituted": "decision"}),
    )
    with pytest.raises(ValueError, match="causally closed"):
        InMemoryEffectsEnvironment(
            authorized=replace(authorized, grants=bad_decision_grants),
            expected_root=root_seed(),
        )

    extended_grants = dict(authorized.grants)
    extended_grants[action_id] = replace(
        grant,
        expires_at=grant.expires_at + timedelta(days=3650),
    )
    with pytest.raises(ValueError, match="causally closed"):
        InMemoryEffectsEnvironment(
            authorized=replace(authorized, grants=extended_grants),
            expected_root=root_seed(),
        )

    decoy = next(item for item in chain_fragments() if item.fragment_id == "fragment.decoy")
    bad_fragment_grants = dict(authorized.grants)
    bad_fragment_grants[action_id] = replace(
        grant,
        fragment=decoy.fragment,
        fragment_digest=sha256_digest(decoy.fragment),
        effect_digest=sha256_digest(decoy.fragment.effects),
    )
    with pytest.raises(ValueError, match="causally closed"):
        InMemoryEffectsEnvironment(
            authorized=replace(authorized, grants=bad_fragment_grants),
            expected_root=root_seed(),
        )
