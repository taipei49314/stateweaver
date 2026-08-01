from __future__ import annotations

import pytest
from stateweaver.contracts import sha256_digest

from statechainbench import (
    AblationFeature,
    AblationReport,
    AblationResult,
    AblationSpec,
    BenchmarkAuditError,
    BudgetAttemptKind,
    BudgetEventKind,
    BudgetExhaustion,
    BudgetLedger,
    BudgetLimits,
    CandidateSubmission,
    ChallengeFamily,
    ComparisonReport,
    DatasetSplit,
    EqualBudgetRunner,
    GeneratorConfig,
    LinearBaseline,
    OracleReason,
    OracleVerdict,
    PublicChallenge,
    StateWeaverTieredSystem,
    StopReason,
    SystemRun,
    aggregate_metrics,
    generate_dataset,
)


def _budget() -> BudgetLimits:
    return BudgetLimits(
        max_action_cost=40,
        max_world_cost=30,
        max_latency_units=250,
    )


def test_holdout_comparison_uses_raw_matched_results_and_shows_tiered_gain() -> None:
    runner = EqualBudgetRunner(generate_dataset(GeneratorConfig(seed=1729, variants_per_family=4)))
    comparison = runner.compare(_budget(), split=DatasetSplit.HOLDOUT)

    baseline_raw = {item.challenge_id: item for item in comparison.baseline.raw_results}
    full_raw = {item.challenge_id: item for item in comparison.full.raw_results}
    assert baseline_raw.keys() == full_raw.keys()
    assert baseline_raw
    assert all(item.budget == _budget() for item in (*baseline_raw.values(), *full_raw.values()))
    assert all(
        item.run.ledger.limits == _budget()
        and item.run.ledger.usage.action_cost <= _budget().max_action_cost
        and item.run.ledger.usage.world_cost <= _budget().max_world_cost
        and item.run.ledger.usage.latency_units <= _budget().max_latency_units
        for item in (*baseline_raw.values(), *full_raw.values())
    )

    baseline_successes = sum(result.verdict.success for result in baseline_raw.values())
    full_successes = sum(result.verdict.success for result in full_raw.values())
    baseline_request_successes = sum(
        result.verdict.success
        for result in baseline_raw.values()
        if result.family is ChallengeFamily.REQUEST_ORDERING
    )
    full_request_successes = sum(
        result.verdict.success
        for result in full_raw.values()
        if result.family is ChallengeFamily.REQUEST_ORDERING
    )

    assert comparison.baseline.metrics == aggregate_metrics(comparison.baseline.raw_results)
    assert comparison.full.metrics == aggregate_metrics(comparison.full.raw_results)
    assert comparison.baseline.metrics.successes == baseline_successes
    assert comparison.full.metrics.successes == full_successes
    assert full_successes > baseline_successes
    assert full_request_successes > baseline_request_successes
    assert ChallengeFamily.REQUEST_ORDERING in comparison.improved_families
    assert all(item.run.search_fingerprints for item in full_raw.values())


def test_equal_budget_result_is_reproducible_byte_for_byte() -> None:
    first = EqualBudgetRunner(
        generate_dataset(GeneratorConfig(seed=611, variants_per_family=2))
    ).compare(_budget(), split=DatasetSplit.HOLDOUT)
    second = EqualBudgetRunner(
        generate_dataset(GeneratorConfig(seed=611, variants_per_family=2))
    ).compare(_budget(), split=DatasetSplit.HOLDOUT)

    assert first.canonical_bytes() == second.canonical_bytes()


def test_comparison_rejects_dataset_evaluator_and_challenge_provenance_substitution() -> None:
    comparison = EqualBudgetRunner(
        generate_dataset(GeneratorConfig(seed=612, variants_per_family=1))
    ).compare(_budget(), split=DatasetSplit.HOLDOUT)

    forged_report = comparison.full.model_copy(
        update={"dataset_digest": sha256_digest({"different": "dataset"})}
    )
    with pytest.raises(ValueError, match="dataset and evaluator provenance"):
        ComparisonReport(
            split=comparison.split,
            budget=comparison.budget,
            baseline=comparison.baseline,
            full=forged_report,
            improved_families=comparison.improved_families,
        )

    changed_result = comparison.full.raw_results[0].model_copy(
        update={"challenge_digest": sha256_digest({"different": "challenge"})}
    )
    changed_report = comparison.full.model_copy(
        update={"raw_results": (changed_result, *comparison.full.raw_results[1:])}
    )
    with pytest.raises(ValueError, match="complete challenge provenance"):
        ComparisonReport(
            split=comparison.split,
            budget=comparison.budget,
            baseline=comparison.baseline,
            full=changed_report,
            improved_families=comparison.improved_families,
        )


@pytest.mark.parametrize("seed", [0, 1, 7, 42, 999])
def test_request_ordering_holdout_gain_is_not_specific_to_one_seed(seed: int) -> None:
    comparison = EqualBudgetRunner(
        generate_dataset(GeneratorConfig(seed=seed, variants_per_family=1))
    ).compare(
        _budget(),
        split=DatasetSplit.HOLDOUT,
        families=(ChallengeFamily.REQUEST_ORDERING,),
    )
    baseline_raw_successes = sum(
        result.verdict.success for result in comparison.baseline.raw_results
    )
    full_raw_successes = sum(result.verdict.success for result in comparison.full.raw_results)

    assert full_raw_successes > baseline_raw_successes
    assert comparison.full.metrics.successes == full_raw_successes
    assert comparison.baseline.metrics.successes == baseline_raw_successes


def test_report_rejects_a_summary_not_derived_from_raw_results() -> None:
    report = (
        EqualBudgetRunner(generate_dataset(GeneratorConfig(seed=19, variants_per_family=1)))
        .compare(_budget(), split=DatasetSplit.HOLDOUT)
        .full
    )
    payload = report.model_dump(mode="python")
    payload["metrics"] = report.metrics.model_copy(
        update={
            "successes": report.metrics.successes - 1,
            "success_rate": (report.metrics.successes - 1) / report.metrics.challenge_count,
        }
    )

    try:
        type(report).model_validate(payload)
    except ValueError as error:
        assert "recomputed from raw" in str(error)
    else:
        raise AssertionError("a forged aggregate summary was accepted")


class _UnderreportingSystem:
    @property
    def system_id(self) -> str:
        return "system.underreporting_test"

    @property
    def system_config_digest(self) -> str:
        return sha256_digest({"system": self.system_id})

    def solve(self, challenge: PublicChallenge, budget: BudgetLimits) -> SystemRun:
        action = challenge.actions[0]
        wrong_cost = 1 if action.action_cost != 1 else 2
        ledger = BudgetLedger(limits=budget).reserve(
            kind=BudgetEventKind.ACTION,
            operation_key="execute.000000000000000000000002",
            action_token=action.token,
            action_cost=wrong_cost,
            latency_units=wrong_cost,
        )
        return SystemRun(
            system_id=self.system_id,
            system_config_digest=self.system_config_digest,
            submission=CandidateSubmission(
                challenge_id=challenge.challenge_id,
                action_tokens=(action.token,),
            ),
            ledger=ledger,
            anchor_requested=True,
            stop_reason=StopReason.NO_PROGRESS,
        )


def test_runner_rejects_unregistered_solver_before_it_can_claim_a_ledger() -> None:
    runner = EqualBudgetRunner(
        generate_dataset(
            GeneratorConfig(
                seed=88,
                variants_per_family=1,
                families=(ChallengeFamily.SESSION_CACHE,),
            )
        )
    )

    try:
        runner.run(_UnderreportingSystem(), _budget(), split=DatasetSplit.TRAIN)
    except BenchmarkAuditError as error:
        assert "registered trusted" in str(error)
    else:
        raise AssertionError("an unregistered solver was accepted")


def test_runner_rejects_a_subclass_of_a_builtin_solver() -> None:
    class SpoofedLinearBaseline(LinearBaseline):
        pass

    runner = EqualBudgetRunner(generate_dataset(GeneratorConfig(seed=89, variants_per_family=1)))
    with pytest.raises(BenchmarkAuditError, match="registered trusted"):
        runner.run(SpoofedLinearBaseline(), _budget(), split=DatasetSplit.TRAIN)


def test_work_tariff_is_retained_and_world_tier_ablation_does_not_claim_world_work() -> None:
    runner = EqualBudgetRunner(generate_dataset(GeneratorConfig(seed=90, variants_per_family=1)))
    baseline = runner.run(LinearBaseline(), _budget(), split=DatasetSplit.TRAIN)
    for result in baseline.raw_results:
        catalog = {
            action.token: action.action_cost
            for action in next(
                descriptor
                for descriptor in runner._dataset.descriptors
                if descriptor.public.challenge_id == result.challenge_id
            ).public.actions
        }
        for event in result.run.ledger.events:
            if event.kind is BudgetEventKind.PLAN:
                assert event.action_cost == event.world_cost == 0
                assert event.latency_units == 1
            elif event.kind is BudgetEventKind.ACTION:
                assert event.action_token is not None
                assert event.action_cost == catalog[event.action_token]
                assert event.action_cost == event.latency_units
                assert event.action_cost > 0
            else:
                assert event.world_cost == 1
                assert event.action_cost == 0
                assert event.latency_units == 2

    no_world = runner.run(
        StateWeaverTieredSystem(ablation=AblationSpec(disabled=(AblationFeature.WORLD_TIERS,))),
        _budget(),
        split=DatasetSplit.TRAIN,
    )
    assert all(
        event.kind is not BudgetEventKind.WORLD
        for result in no_world.raw_results
        for event in result.run.ledger.events
    )
    assert no_world.metrics.total_world_cost == 0


def test_full_system_identity_binds_every_solver_configuration_field() -> None:
    default = StateWeaverTieredSystem()
    changed_seed = StateWeaverTieredSystem(seed=1)
    changed_beam = StateWeaverTieredSystem(beam_width=4)
    changed_ablation = StateWeaverTieredSystem(
        ablation=AblationSpec(disabled=(AblationFeature.CHAIN_COMPILER,))
    )

    configurations = {
        item.system_config_digest
        for item in (
            default,
            changed_seed,
            changed_beam,
            changed_ablation,
        )
    }
    identities = {
        item.system_id
        for item in (
            default,
            changed_seed,
            changed_beam,
            changed_ablation,
        )
    }
    assert len(configurations) == len(identities) == 4


def test_audit_rejects_zero_work_and_action_without_prior_plan() -> None:
    dataset = generate_dataset(GeneratorConfig(seed=55, variants_per_family=1))
    descriptor = dataset.for_split(DatasetSplit.TRAIN)[0]
    system = LinearBaseline()
    empty = SystemRun(
        system_id=system.system_id,
        system_config_digest=system.system_config_digest,
        submission=CandidateSubmission(
            challenge_id=descriptor.public.challenge_id,
            action_tokens=(),
        ),
        ledger=BudgetLedger(limits=_budget()),
        anchor_requested=True,
        stop_reason=StopReason.NO_PROGRESS,
    )
    with pytest.raises(BenchmarkAuditError, match="zero-work"):
        EqualBudgetRunner._audit_run(
            descriptor=descriptor,
            run=empty,
            expected_system_id=system.system_id,
            expected_system_config_digest=system.system_config_digest,
            budget=_budget(),
            require_world_events=True,
        )

    action = descriptor.public.actions[0]
    action_only = BudgetLedger(limits=_budget()).reserve(
        kind=BudgetEventKind.ACTION,
        operation_key="execute.000000000000000000000001",
        action_token=action.token,
        action_cost=action.action_cost,
        latency_units=action.action_cost,
    )
    with pytest.raises(BenchmarkAuditError, match="prior planning"):
        EqualBudgetRunner._audit_run(
            descriptor=descriptor,
            run=empty.model_copy(update={"ledger": action_only}),
            expected_system_id=system.system_id,
            expected_system_config_digest=system.system_config_digest,
            budget=_budget(),
            require_world_events=True,
        )

    planned_only = BudgetLedger(limits=_budget()).reserve(
        kind=BudgetEventKind.PLAN,
        operation_key="plan.000000000000000000000001",
        action_token=action.token,
    )
    with pytest.raises(BenchmarkAuditError, match="retained planning"):
        EqualBudgetRunner._audit_run(
            descriptor=descriptor,
            run=empty.model_copy(update={"ledger": planned_only}),
            expected_system_id=system.system_id,
            expected_system_config_digest=system.system_config_digest,
            budget=_budget(),
            require_world_events=True,
        )
    with pytest.raises(BenchmarkAuditError, match="execution charges"):
        EqualBudgetRunner._audit_run(
            descriptor=descriptor,
            run=empty.model_copy(
                update={
                    "ledger": planned_only,
                    "submission": CandidateSubmission(
                        challenge_id=descriptor.public.challenge_id,
                        action_tokens=(action.token,),
                    ),
                }
            ),
            expected_system_id=system.system_id,
            expected_system_config_digest=system.system_config_digest,
            budget=_budget(),
            require_world_events=True,
        )


def test_budget_event_namespace_and_exhaustion_proof_are_fail_closed() -> None:
    dataset = generate_dataset(GeneratorConfig(seed=551, variants_per_family=1))
    descriptor = dataset.for_split(DatasetSplit.TRAIN)[0]
    action = descriptor.public.actions[0]
    system = LinearBaseline()

    with pytest.raises(ValueError, match="operation namespace"):
        BudgetLedger(limits=_budget()).reserve(
            kind=BudgetEventKind.PLAN,
            operation_key="execute.000000000000000000000001",
            action_token=action.token,
        )

    with pytest.raises(ValueError, match="retained exhaustion"):
        SystemRun(
            system_id=system.system_id,
            system_config_digest=system.system_config_digest,
            submission=CandidateSubmission(
                challenge_id=descriptor.public.challenge_id,
                action_tokens=(),
            ),
            ledger=BudgetLedger(limits=_budget()),
            anchor_requested=True,
            stop_reason=StopReason.BUDGET_EXHAUSTED,
        )

    for attempt_kind, action_cost, world_cost, latency, message in (
        (BudgetAttemptKind.ACTION, 0, 0, 1, "positive catalog action"),
        (BudgetAttemptKind.ACTION_WORLD, 0, 1, 2, "positive catalog action"),
        (BudgetAttemptKind.PLAN, 0, 0, 2, "exact attempted tariff"),
        (BudgetAttemptKind.ACTION, 2, 1, 2, "exact attempted tariff"),
    ):
        with pytest.raises(ValueError, match=message):
            BudgetExhaustion(
                attempt_kind=attempt_kind,
                action_token=action.token,
                base_usage=BudgetLedger(limits=_budget()).usage,
                action_cost_delta=action_cost,
                world_cost_delta=world_cost,
                latency_units_delta=latency,
            )

    fit_exhaustion = BudgetExhaustion(
        attempt_kind=BudgetAttemptKind.PLAN,
        action_token=action.token,
        base_usage=BudgetLedger(limits=_budget()).usage,
        action_cost_delta=0,
        world_cost_delta=0,
        latency_units_delta=1,
    )
    forged = SystemRun(
        system_id=system.system_id,
        system_config_digest=system.system_config_digest,
        submission=CandidateSubmission(
            challenge_id=descriptor.public.challenge_id,
            action_tokens=(),
        ),
        ledger=BudgetLedger(limits=_budget()),
        anchor_requested=True,
        stop_reason=StopReason.BUDGET_EXHAUSTED,
        budget_exhaustion=fit_exhaustion,
    )
    with pytest.raises(BenchmarkAuditError, match="would have fit"):
        EqualBudgetRunner._audit_run(
            descriptor=descriptor,
            run=forged,
            expected_system_id=system.system_id,
            expected_system_config_digest=system.system_config_digest,
            budget=_budget(),
            require_world_events=True,
        )
    with pytest.raises(BenchmarkAuditError, match="non-budget stop"):
        EqualBudgetRunner._audit_run(
            descriptor=descriptor,
            run=forged.model_copy(update={"stop_reason": StopReason.NO_PROGRESS}),
            expected_system_id=system.system_id,
            expected_system_config_digest=system.system_config_digest,
            budget=_budget(),
            require_world_events=True,
        )
    with pytest.raises(BenchmarkAuditError, match="ledger and catalog"):
        EqualBudgetRunner._audit_run(
            descriptor=descriptor,
            run=forged.model_copy(
                update={
                    "budget_exhaustion": fit_exhaustion.model_copy(
                        update={"action_token": "action.ffffffffffffffffffffffff"}
                    )
                }
            ),
            expected_system_id=system.system_id,
            expected_system_config_digest=system.system_config_digest,
            budget=_budget(),
            require_world_events=True,
        )


def test_real_budget_stops_retain_first_failed_reservation() -> None:
    runner = EqualBudgetRunner(generate_dataset(GeneratorConfig(seed=552, variants_per_family=1)))
    plan_limited = runner.run(
        LinearBaseline(),
        BudgetLimits(max_action_cost=0, max_world_cost=0, max_latency_units=0),
        split=DatasetSplit.TRAIN,
    )
    assert all(
        result.run.stop_reason is StopReason.BUDGET_EXHAUSTED
        and result.run.budget_exhaustion is not None
        and result.run.budget_exhaustion.attempt_kind is BudgetAttemptKind.PLAN
        for result in plan_limited.raw_results
    )

    world_limited = runner.run(
        LinearBaseline(),
        BudgetLimits(max_action_cost=16, max_world_cost=0, max_latency_units=100),
        split=DatasetSplit.TRAIN,
    )
    assert all(
        result.run.stop_reason is StopReason.BUDGET_EXHAUSTED
        and result.run.budget_exhaustion is not None
        and result.run.budget_exhaustion.attempt_kind is BudgetAttemptKind.ACTION_WORLD
        for result in world_limited.raw_results
    )


def test_audit_rejects_goal_stop_that_disagrees_with_oracle() -> None:
    report = EqualBudgetRunner(
        generate_dataset(GeneratorConfig(seed=56, variants_per_family=1))
    ).run(LinearBaseline(), _budget(), split=DatasetSplit.HOLDOUT)
    result = report.raw_results[0]
    assert result.verdict.success
    forged = result.run.model_copy(update={"stop_reason": StopReason.NO_PROGRESS})

    with pytest.raises(BenchmarkAuditError, match="inconsistent"):
        EqualBudgetRunner._audit_verdict(run=forged, verdict=result.verdict)
    with pytest.raises(BenchmarkAuditError, match="disabled-anchor"):
        EqualBudgetRunner._audit_verdict(
            run=result.run,
            verdict=OracleVerdict(
                challenge_id=result.challenge_id,
                valid=False,
                success=False,
                reason=OracleReason.REALITY_ANCHOR_DISABLED,
                final_state_fingerprint=result.verdict.final_state_fingerprint,
                evaluated_actions=0,
            ),
        )


def test_ablation_labels_cannot_reuse_one_report_and_reports_close_provenance() -> None:
    runner = EqualBudgetRunner(generate_dataset(GeneratorConfig(seed=57, variants_per_family=1)))
    report = runner.run(LinearBaseline(), _budget(), split=DatasetSplit.TRAIN)
    assert report.dataset_digest == runner._dataset.dataset_digest
    assert report.evaluator_digest == runner._dataset.evaluator_digest
    assert report.generator_config_digest == runner._dataset.config.config_digest
    assert (
        report.report_digest
        != report.model_copy(
            update={"dataset_digest": runner._dataset.evaluator_digest}
        ).report_digest
    )

    reused = tuple(
        AblationResult(spec=AblationSpec(disabled=(feature,)), report=report)
        for feature in AblationFeature
    )
    with pytest.raises(ValueError, match="cannot reuse"):
        AblationReport(seed=0, beam_width=3, results=reused)

    distinct_reports = tuple(
        report.model_copy(update={"dataset_digest": sha256_digest({"variant": index})})
        for index, _feature in enumerate(AblationFeature)
    )
    same_config = tuple(
        AblationResult(spec=AblationSpec(disabled=(feature,)), report=variant_report)
        for feature, variant_report in zip(AblationFeature, distinct_reports, strict=True)
    )
    with pytest.raises(ValueError, match="distinct solver"):
        AblationReport(seed=0, beam_width=3, results=same_config)


def test_ablation_specs_cannot_be_rotated_across_honest_distinct_reports() -> None:
    runner = EqualBudgetRunner(generate_dataset(GeneratorConfig(seed=58, variants_per_family=1)))
    honest = runner.ablate(_budget(), split=DatasetSplit.HOLDOUT, seed=7, beam_width=3)
    rotated = tuple(
        AblationResult(
            spec=item.spec,
            report=honest.results[(index + 1) % len(honest.results)].report,
        )
        for index, item in enumerate(honest.results)
    )

    with pytest.raises(ValueError, match="spec does not bind"):
        AblationReport(seed=honest.seed, beam_width=honest.beam_width, results=rotated)


def test_all_ablation_reports_retain_raw_results_and_reality_anchor_fails_closed() -> None:
    runner = EqualBudgetRunner(generate_dataset(GeneratorConfig(seed=101, variants_per_family=1)))
    ablations = runner.ablate(_budget(), split=DatasetSplit.HOLDOUT)

    assert {item.spec.disabled[0] for item in ablations.results} == set(AblationFeature)
    assert all(item.report.raw_results for item in ablations.results)
    assert all(
        item.report.metrics == aggregate_metrics(item.report.raw_results)
        for item in ablations.results
    )
    reality_anchor = next(
        item
        for item in ablations.results
        if item.spec.disabled == (AblationFeature.REALITY_ANCHOR,)
    )
    assert all(not result.verdict.valid for result in reality_anchor.report.raw_results)
    assert {result.verdict.reason for result in reality_anchor.report.raw_results} == {
        OracleReason.REALITY_ANCHOR_DISABLED
    }
