"""Equal-budget execution and evaluator-side audit for StateChainBench."""

from __future__ import annotations

from collections.abc import Iterable

from .generator import GeneratedDataset, family_split
from .models import (
    AblationFeature,
    AblationReport,
    AblationResult,
    AblationSpec,
    BudgetAttemptKind,
    BudgetEventKind,
    BudgetLimits,
    ChallengeDescriptor,
    ChallengeFamily,
    ChallengeResult,
    ComparisonReport,
    DatasetSplit,
    OracleReason,
    OracleVerdict,
    StopReason,
    SystemBenchmarkReport,
    SystemRun,
    aggregate_metrics,
)
from .oracle import anchor_disabled_verdict
from .systems import BenchmarkSystem, LinearBaseline, StateWeaverTieredSystem


class BenchmarkAuditError(ValueError):
    """Fail-closed rejection of an unauditable system run."""


class EqualBudgetRunner:
    """Run systems locally while retaining hidden metadata on the evaluator side."""

    __slots__ = ("_dataset",)

    def __init__(self, dataset: GeneratedDataset) -> None:
        if not dataset.descriptors:
            raise ValueError("equal-budget runner requires a nonempty dataset")
        identifiers = [item.public.challenge_id for item in dataset.descriptors]
        if identifiers != sorted(identifiers) or len(identifiers) != len(set(identifiers)):
            raise ValueError("dataset descriptors must be canonical and unique")
        if any(item.split is not family_split(item.family) for item in dataset.descriptors):
            raise ValueError("dataset descriptor violates the frozen family split")
        self._dataset = dataset

    def run(
        self,
        system: BenchmarkSystem,
        budget: BudgetLimits,
        *,
        split: DatasetSplit,
        families: Iterable[ChallengeFamily] | None = None,
    ) -> SystemBenchmarkReport:
        """Execute one system on a frozen split and derive metrics from raw results."""

        if type(system) not in {LinearBaseline, StateWeaverTieredSystem}:
            raise BenchmarkAuditError("runner accepts only registered trusted local solvers")

        budget = BudgetLimits.model_validate(budget.model_dump(mode="python"))
        descriptors = self._select(split=split, families=families)
        expected_system_id = system.system_id
        results: list[ChallengeResult] = []
        for descriptor in descriptors:
            # Only the closed public view crosses the solver boundary.
            public = descriptor.public.model_copy(deep=True)
            raw_run = system.solve(public, budget.model_copy(deep=True))
            run = SystemRun.model_validate(raw_run.model_dump(mode="python"))
            self._audit_run(
                descriptor=descriptor,
                run=run,
                expected_system_id=expected_system_id,
                expected_system_config_digest=system.system_config_digest,
                budget=budget,
                require_world_events=not (
                    isinstance(system, StateWeaverTieredSystem)
                    and system.ablation.has(AblationFeature.WORLD_TIERS)
                ),
            )
            verdict = (
                self._dataset.oracle.evaluate(descriptor.public, run.submission)
                if run.anchor_requested
                else anchor_disabled_verdict(descriptor.public)
            )
            self._audit_verdict(run=run, verdict=verdict)
            results.append(
                ChallengeResult(
                    challenge_id=descriptor.public.challenge_id,
                    challenge_digest=descriptor.challenge_digest,
                    family=descriptor.family,
                    split=descriptor.split,
                    budget=budget,
                    run=run,
                    verdict=verdict,
                )
            )

        ordered = tuple(sorted(results, key=lambda item: item.challenge_id))
        return SystemBenchmarkReport(
            system_id=expected_system_id,
            system_config_digest=system.system_config_digest,
            dataset_digest=self._dataset.dataset_digest,
            evaluator_digest=self._dataset.evaluator_digest,
            generator_config_digest=self._dataset.config.config_digest,
            raw_results=ordered,
            metrics=aggregate_metrics(ordered),
        )

    def compare(
        self,
        budget: BudgetLimits,
        *,
        split: DatasetSplit,
        families: Iterable[ChallengeFamily] | None = None,
        baseline: BenchmarkSystem | None = None,
        full: BenchmarkSystem | None = None,
    ) -> ComparisonReport:
        """Compare the linear and tiered systems over identical instances and limits."""

        selected_families = tuple(families) if families is not None else None
        baseline_report = self.run(
            baseline or LinearBaseline(), budget, split=split, families=selected_families
        )
        full_report = self.run(
            full or StateWeaverTieredSystem(), budget, split=split, families=selected_families
        )
        baseline_families = {item.family for item in baseline_report.raw_results}
        improved = tuple(
            family
            for family in sorted(baseline_families, key=lambda item: item.value)
            if _successes(full_report, family) > _successes(baseline_report, family)
        )
        return ComparisonReport(
            split=split,
            budget=budget,
            baseline=baseline_report,
            full=full_report,
            improved_families=improved,
        )

    def ablate(
        self,
        budget: BudgetLimits,
        *,
        split: DatasetSplit,
        families: Iterable[ChallengeFamily] | None = None,
        seed: int = 0,
        beam_width: int = 3,
    ) -> AblationReport:
        """Run one deterministic leave-one-feature-out experiment per architecture feature."""

        results = []
        selected_families = tuple(families) if families is not None else None
        for feature in AblationFeature:
            spec = AblationSpec(disabled=(feature,))
            report = self.run(
                StateWeaverTieredSystem(
                    seed=seed,
                    beam_width=beam_width,
                    ablation=spec,
                ),
                budget,
                split=split,
                families=selected_families,
            )
            results.append(AblationResult(spec=spec, report=report))
        return AblationReport(seed=seed, beam_width=beam_width, results=tuple(results))

    def _select(
        self,
        *,
        split: DatasetSplit,
        families: Iterable[ChallengeFamily] | None,
    ) -> tuple[ChallengeDescriptor, ...]:
        requested = None if families is None else frozenset(families)
        if requested is not None and not requested:
            raise ValueError("family selection cannot be empty")
        selected = tuple(
            descriptor
            for descriptor in self._dataset.descriptors
            if descriptor.split is split and (requested is None or descriptor.family in requested)
        )
        if not selected:
            raise ValueError("selected split and families contain no challenges")
        if requested is not None and {item.family for item in selected} != requested:
            raise ValueError("requested families do not all belong to the selected split")
        return selected

    @staticmethod
    def _audit_run(
        *,
        descriptor: ChallengeDescriptor,
        run: SystemRun,
        expected_system_id: str,
        expected_system_config_digest: str,
        budget: BudgetLimits,
        require_world_events: bool,
    ) -> None:
        challenge = descriptor.public
        if run.system_id != expected_system_id:
            raise BenchmarkAuditError("system identity changed during a benchmark run")
        if run.system_config_digest != expected_system_config_digest:
            raise BenchmarkAuditError("system configuration changed during a benchmark run")
        if run.submission.challenge_id != challenge.challenge_id:
            raise BenchmarkAuditError("submission is bound to the wrong challenge")
        if run.ledger.limits != budget:
            raise BenchmarkAuditError("system replaced the equal-budget limits")

        actions = {item.token: item for item in challenge.actions}
        exhaustion = run.budget_exhaustion
        if run.stop_reason is StopReason.BUDGET_EXHAUSTED:
            if exhaustion is None:
                raise BenchmarkAuditError("budget stop lacks retained exhaustion evidence")
            action = actions.get(exhaustion.action_token)
            if action is None or exhaustion.base_usage != run.ledger.usage:
                raise BenchmarkAuditError("budget exhaustion is not bound to ledger and catalog")
            expected_delta = {
                BudgetAttemptKind.PLAN: (0, 0, 1),
                BudgetAttemptKind.ACTION: (action.action_cost, 0, action.action_cost),
                BudgetAttemptKind.ACTION_WORLD: (
                    action.action_cost,
                    1,
                    action.action_cost + 2,
                ),
            }[exhaustion.attempt_kind]
            actual_delta = (
                exhaustion.action_cost_delta,
                exhaustion.world_cost_delta,
                exhaustion.latency_units_delta,
            )
            if actual_delta != expected_delta or (
                exhaustion.attempt_kind is BudgetAttemptKind.ACTION_WORLD
                and not require_world_events
            ):
                raise BenchmarkAuditError("budget exhaustion does not match the runner tariff")
            attempted = (
                exhaustion.base_usage.action_cost + exhaustion.action_cost_delta,
                exhaustion.base_usage.world_cost + exhaustion.world_cost_delta,
                exhaustion.base_usage.latency_units + exhaustion.latency_units_delta,
            )
            limits = (
                budget.max_action_cost,
                budget.max_world_cost,
                budget.max_latency_units,
            )
            if all(value <= limit for value, limit in zip(attempted, limits, strict=True)):
                raise BenchmarkAuditError("retained budget exhaustion would have fit the limits")
        elif exhaustion is not None:
            raise BenchmarkAuditError("non-budget stop cannot retain exhaustion evidence")

        executed: set[str] = set()
        if not run.ledger.events and exhaustion is None:
            raise BenchmarkAuditError("zero-work runs cannot be reported as benchmark evidence")
        planned: set[str] = set()
        awaiting_world: str | None = None
        prior_action_token: str | None = None
        seen_action = False
        for event in run.ledger.events:
            token = event.action_token
            if token is None or token not in actions:
                raise BenchmarkAuditError("every budget event must bind a catalog action")
            action = actions[token]
            if event.kind is BudgetEventKind.PLAN and event.latency_units != 1:
                raise BenchmarkAuditError("planning latency proxy was under- or over-reported")
            if event.kind is BudgetEventKind.PLAN:
                planned.add(token)
                prior_action_token = None
            if event.kind is BudgetEventKind.ACTION:
                if awaiting_world is not None:
                    raise BenchmarkAuditError(
                        "action events must be settled by world evidence in order"
                    )
                if token not in planned:
                    raise BenchmarkAuditError("action events require prior planning evidence")
                if (
                    event.action_cost != action.action_cost
                    or event.latency_units != action.action_cost
                ):
                    raise BenchmarkAuditError("action cost does not match the public catalog")
                executed.add(token)
                seen_action = True
                awaiting_world = token if require_world_events else None
                prior_action_token = token
            if event.kind is BudgetEventKind.WORLD:
                if prior_action_token is None or token != prior_action_token:
                    raise BenchmarkAuditError(
                        "world events must immediately settle the matching action"
                    )
                if event.world_cost != 1 or event.latency_units != 2:
                    raise BenchmarkAuditError("world-tier cost does not match the benchmark tariff")
                awaiting_world = None
                prior_action_token = None

        if not set(run.submission.action_tokens).issubset(executed):
            raise BenchmarkAuditError("submitted actions lack retained execution charges")
        if (not planned or not seen_action) and exhaustion is None:
            raise BenchmarkAuditError("runs require retained planning evidence")
        if awaiting_world is not None:
            raise BenchmarkAuditError("action evidence lacks a matching world event")

    @staticmethod
    def _audit_verdict(*, run: SystemRun, verdict: OracleVerdict) -> None:
        """Reject stop/outcome combinations that would misstate evaluator evidence."""

        if not run.anchor_requested:
            if verdict.reason is not OracleReason.REALITY_ANCHOR_DISABLED:
                raise BenchmarkAuditError("unanchored runs must retain the disabled-anchor verdict")
            return
        if verdict.reason is OracleReason.REALITY_ANCHOR_DISABLED:
            raise BenchmarkAuditError("anchored runs cannot use a disabled-anchor verdict")
        if (run.stop_reason is StopReason.GOAL_REACHED) != verdict.success:
            raise BenchmarkAuditError("goal stop reason is inconsistent with oracle outcome")


def _successes(report: SystemBenchmarkReport, family: ChallengeFamily) -> int:
    return sum(result.verdict.success for result in report.raw_results if result.family is family)
