"""Closed, immutable schemas for deterministic StateChainBench experiments."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, field_validator, model_validator
from stateweaver.contracts import Sha256Digest, sha256_digest
from stateweaver.contracts.base import ContractModel

ChallengeId = Annotated[
    str,
    StringConstraints(pattern=r"^challenge\.[0-9a-f]{24}$"),
]
ActionToken = Annotated[
    str,
    StringConstraints(pattern=r"^action\.[0-9a-f]{24}$"),
]
StateKey = Annotated[
    str,
    StringConstraints(pattern=r"^state\.[0-9a-f]{16}$"),
]
OperationKey = Annotated[
    str,
    StringConstraints(pattern=r"^(?:plan|execute|world)\.[0-9a-f]{24}$"),
]
EventId = Annotated[
    str,
    StringConstraints(pattern=r"^event\.[0-9a-f]{24}$"),
]
SystemId = Annotated[
    str,
    StringConstraints(pattern=r"^system\.[a-z][a-z0-9_-]{2,63}$"),
]


class ChallengeFamily(StrEnum):
    SESSION_CACHE = "session_cache"
    QUEUE_ROLE_TRANSITION = "queue_role_transition"
    REQUEST_ORDERING = "request_ordering"
    VERSION_FLAG_SKEW = "version_flag_skew"


class DatasetSplit(StrEnum):
    TRAIN = "train"
    HOLDOUT = "holdout"


class BenchmarkTrack(StrEnum):
    SYNTHETIC = "synthetic"


class BudgetEventKind(StrEnum):
    PLAN = "plan"
    ACTION = "action"
    WORLD = "world"


class BudgetAttemptKind(StrEnum):
    PLAN = "plan"
    ACTION = "action"
    ACTION_WORLD = "action_world"


class StopReason(StrEnum):
    GOAL_REACHED = "GOAL_REACHED"
    NO_PROGRESS = "NO_PROGRESS"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    CHAIN_COMPILER_DISABLED = "CHAIN_COMPILER_DISABLED"


class OracleReason(StrEnum):
    SUCCESS = "SUCCESS"
    GOAL_NOT_REACHED = "GOAL_NOT_REACHED"
    UNKNOWN_ACTION = "UNKNOWN_ACTION"
    DUPLICATE_ACTION = "DUPLICATE_ACTION"
    PRECONDITION_FAILED = "PRECONDITION_FAILED"
    CHAIN_TOO_LONG = "CHAIN_TOO_LONG"
    CHALLENGE_MISMATCH = "CHALLENGE_MISMATCH"
    PUBLIC_CHALLENGE_MISMATCH = "PUBLIC_CHALLENGE_MISMATCH"
    REALITY_ANCHOR_DISABLED = "REALITY_ANCHOR_DISABLED"


class AblationFeature(StrEnum):
    SEMANTIC_TWIN = "semantic_twin"
    WORLD_TIERS = "world_tiers"
    STATE_FINGERPRINT_DEDUP = "state_fingerprint_dedup"
    CHAIN_COMPILER = "chain_compiler"
    REALITY_ANCHOR = "reality_anchor"
    BUDGET_AWARE_SCHEDULER = "budget_aware_scheduler"


class StateCell(ContractModel):
    key: StateKey
    value: bool


class PublicAction(ContractModel):
    token: ActionToken
    preconditions: tuple[StateCell, ...]
    effects: tuple[StateCell, ...]
    action_cost: Annotated[int, Field(ge=1, le=16)] = 1

    @field_validator("preconditions", "effects")
    @classmethod
    def cells_are_canonical(cls, value: tuple[StateCell, ...]) -> tuple[StateCell, ...]:
        if not value:
            raise ValueError("benchmark actions require nonempty state semantics")
        keys = [item.key for item in value]
        if len(keys) != len(set(keys)):
            raise ValueError("benchmark action state keys must be unique")
        return tuple(sorted(value, key=lambda item: item.key))


class PublicChallenge(ContractModel):
    """The only challenge view a benchmark system is allowed to receive."""

    challenge_id: ChallengeId
    track: BenchmarkTrack = BenchmarkTrack.SYNTHETIC
    initial_state: tuple[StateCell, ...]
    goal: StateCell
    actions: tuple[PublicAction, ...]
    max_chain_length: Annotated[int, Field(ge=3, le=32)]

    @field_validator("initial_state")
    @classmethod
    def initial_state_is_canonical(cls, value: tuple[StateCell, ...]) -> tuple[StateCell, ...]:
        keys = [item.key for item in value]
        if not value or len(keys) != len(set(keys)):
            raise ValueError("initial state keys must be nonempty and unique")
        return tuple(sorted(value, key=lambda item: item.key))

    @model_validator(mode="after")
    def public_schema_is_a_nontrivial_state_chain(self) -> PublicChallenge:
        tokens = [item.token for item in self.actions]
        if len(self.actions) < 5 or len(tokens) != len(set(tokens)):
            raise ValueError("challenge actions must be nontrivial and uniquely tokenized")
        state_keys = {item.key for item in self.initial_state}
        if self.goal.key not in state_keys or not self.goal.value:
            raise ValueError("public goal must be a positive condition in the initial state schema")
        initial = self.initial_mapping()
        if initial[self.goal.key] is self.goal.value:
            raise ValueError("challenge goal cannot already hold in the initial state")
        if any(
            cell.key not in state_keys
            for action in self.actions
            for cell in (*action.preconditions, *action.effects)
        ):
            raise ValueError("challenge actions cannot introduce undeclared state keys")
        terminal_actions = [action for action in self.actions if self.goal in action.effects]
        if not terminal_actions or max(len(item.preconditions) for item in terminal_actions) < 3:
            raise ValueError("challenge goal must require at least three joint state conditions")
        if self.max_chain_length > len(self.actions):
            raise ValueError("maximum chain length cannot exceed the closed action catalog")
        return self

    @property
    def fingerprint(self) -> str:
        return sha256_digest(self)

    def initial_mapping(self) -> dict[str, bool]:
        return {item.key: item.value for item in self.initial_state}


class ChallengeDescriptor(ContractModel):
    """Evaluator metadata kept outside the public solver view."""

    family: ChallengeFamily
    split: DatasetSplit
    variant: Annotated[int, Field(ge=0, le=63)]
    generator_version: Literal["statechainbench-generator-v2"]
    public: PublicChallenge

    @property
    def challenge_digest(self) -> str:
        """Digest of the complete evaluator-visible challenge record."""

        return sha256_digest(self)


class GeneratorConfig(ContractModel):
    seed: Annotated[int, Field(ge=0, le=2**31 - 1)]
    variants_per_family: Annotated[int, Field(ge=1, le=64)] = 4
    families: tuple[ChallengeFamily, ...] = tuple(ChallengeFamily)
    generator_version: Literal["statechainbench-generator-v2"] = "statechainbench-generator-v2"

    @field_validator("families")
    @classmethod
    def families_are_canonical(
        cls, value: tuple[ChallengeFamily, ...]
    ) -> tuple[ChallengeFamily, ...]:
        if not value or len(value) != len(set(value)):
            raise ValueError("generator families must be nonempty and unique")
        return tuple(sorted(value, key=lambda item: item.value))

    @property
    def config_digest(self) -> str:
        return sha256_digest(self)


class BudgetLimits(ContractModel):
    max_action_cost: Annotated[int, Field(ge=0, le=1_000_000)]
    max_world_cost: Annotated[int, Field(ge=0, le=1_000_000)]
    max_latency_units: Annotated[int, Field(ge=0, le=10_000_000)]


class BudgetUsage(ContractModel):
    action_cost: Annotated[int, Field(ge=0)] = 0
    world_cost: Annotated[int, Field(ge=0)] = 0
    latency_units: Annotated[int, Field(ge=0)] = 0


class BudgetEvent(ContractModel):
    event_id: EventId
    sequence: Annotated[int, Field(ge=1)]
    kind: BudgetEventKind
    operation_key: OperationKey
    action_token: ActionToken | None = None
    action_cost: Annotated[int, Field(ge=0)] = 0
    world_cost: Annotated[int, Field(ge=0)] = 0
    latency_units: Annotated[int, Field(ge=1)] = 1

    @model_validator(mode="after")
    def event_shape_and_identifier_are_bound(self) -> BudgetEvent:
        expected_prefix = {
            BudgetEventKind.PLAN: "plan.",
            BudgetEventKind.ACTION: "execute.",
            BudgetEventKind.WORLD: "world.",
        }[self.kind]
        if not self.operation_key.startswith(expected_prefix):
            raise ValueError("budget event kind must match its operation namespace")
        if self.kind is BudgetEventKind.PLAN and (self.action_cost != 0 or self.world_cost != 0):
            raise ValueError("planning events cannot claim action or world cost")
        if self.kind is BudgetEventKind.ACTION and (
            self.action_token is None or self.action_cost == 0 or self.world_cost != 0
        ):
            raise ValueError("action events require one typed action cost")
        if self.kind is BudgetEventKind.WORLD and (self.action_cost != 0 or self.world_cost == 0):
            raise ValueError("world events require one positive world cost")
        expected = budget_event_id(
            sequence=self.sequence,
            kind=self.kind,
            operation_key=self.operation_key,
            action_token=self.action_token,
            action_cost=self.action_cost,
            world_cost=self.world_cost,
            latency_units=self.latency_units,
        )
        if self.event_id != expected:
            raise ValueError("budget event ID must bind the immutable event content")
        return self


class BudgetExceededError(ValueError):
    """Fail-closed rejection raised before an over-budget event is appended."""


class BudgetLedger(ContractModel):
    limits: BudgetLimits
    events: tuple[BudgetEvent, ...] = ()

    @field_validator("events")
    @classmethod
    def events_are_append_only(cls, value: tuple[BudgetEvent, ...]) -> tuple[BudgetEvent, ...]:
        if tuple(item.sequence for item in value) != tuple(range(1, len(value) + 1)):
            raise ValueError("budget event sequence must be contiguous")
        event_ids = [item.event_id for item in value]
        operation_keys = [item.operation_key for item in value]
        if len(event_ids) != len(set(event_ids)) or len(operation_keys) != len(set(operation_keys)):
            raise ValueError("budget events and operations must be unique")
        return value

    @model_validator(mode="after")
    def history_is_within_limits(self) -> BudgetLedger:
        if not self._fits(self.usage):
            raise ValueError("budget ledger cannot contain overspent history")
        return self

    @property
    def usage(self) -> BudgetUsage:
        return BudgetUsage(
            action_cost=sum(item.action_cost for item in self.events),
            world_cost=sum(item.world_cost for item in self.events),
            latency_units=sum(item.latency_units for item in self.events),
        )

    def reserve(
        self,
        *,
        kind: BudgetEventKind,
        operation_key: str,
        action_token: str | None = None,
        action_cost: int = 0,
        world_cost: int = 0,
        latency_units: int = 1,
    ) -> BudgetLedger:
        sequence = len(self.events) + 1
        event = BudgetEvent(
            event_id=budget_event_id(
                sequence=sequence,
                kind=kind,
                operation_key=operation_key,
                action_token=action_token,
                action_cost=action_cost,
                world_cost=world_cost,
                latency_units=latency_units,
            ),
            sequence=sequence,
            kind=kind,
            operation_key=operation_key,
            action_token=action_token,
            action_cost=action_cost,
            world_cost=world_cost,
            latency_units=latency_units,
        )
        proposed = BudgetUsage(
            action_cost=self.usage.action_cost + event.action_cost,
            world_cost=self.usage.world_cost + event.world_cost,
            latency_units=self.usage.latency_units + event.latency_units,
        )
        if not self._fits(proposed):
            raise BudgetExceededError("benchmark budget would be exceeded")
        return BudgetLedger(limits=self.limits, events=(*self.events, event))

    def _fits(self, usage: BudgetUsage) -> bool:
        return (
            usage.action_cost <= self.limits.max_action_cost
            and usage.world_cost <= self.limits.max_world_cost
            and usage.latency_units <= self.limits.max_latency_units
        )


class CandidateSubmission(ContractModel):
    challenge_id: ChallengeId
    action_tokens: tuple[ActionToken, ...]

    @field_validator("action_tokens")
    @classmethod
    def actions_are_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("candidate submissions cannot repeat actions")
        return value


class BudgetExhaustion(ContractModel):
    """Retained reservation that proves why a run stopped at a hard budget boundary."""

    attempt_kind: BudgetAttemptKind
    action_token: ActionToken
    base_usage: BudgetUsage
    action_cost_delta: Annotated[int, Field(ge=0)]
    world_cost_delta: Annotated[int, Field(ge=0)]
    latency_units_delta: Annotated[int, Field(ge=1)]

    @model_validator(mode="after")
    def attempted_tariff_is_closed(self) -> BudgetExhaustion:
        if self.attempt_kind is BudgetAttemptKind.PLAN:
            expected = (0, 0, 1)
        elif self.attempt_kind is BudgetAttemptKind.ACTION:
            if self.action_cost_delta == 0:
                raise ValueError("action exhaustion requires a positive catalog action cost")
            expected = (self.action_cost_delta, 0, self.action_cost_delta)
        else:
            if self.action_cost_delta == 0:
                raise ValueError("action/world exhaustion requires a positive catalog action cost")
            expected = (self.action_cost_delta, 1, self.action_cost_delta + 2)
        actual = (self.action_cost_delta, self.world_cost_delta, self.latency_units_delta)
        if actual != expected:
            raise ValueError("budget exhaustion must retain the exact attempted tariff")
        return self


class SystemRun(ContractModel):
    system_id: SystemId
    system_config_digest: Sha256Digest
    submission: CandidateSubmission
    ledger: BudgetLedger
    anchor_requested: bool
    stop_reason: StopReason
    budget_exhaustion: BudgetExhaustion | None = None
    search_fingerprints: tuple[Sha256Digest, ...] = ()

    @field_validator("search_fingerprints")
    @classmethod
    def search_results_are_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("search result fingerprints must be unique")
        return value

    @model_validator(mode="after")
    def budget_stop_has_retained_exhaustion(self) -> SystemRun:
        stopped_for_budget = self.stop_reason is StopReason.BUDGET_EXHAUSTED
        if stopped_for_budget != (self.budget_exhaustion is not None):
            raise ValueError("budget stop reason and retained exhaustion must agree")
        return self


class OracleVerdict(ContractModel):
    challenge_id: ChallengeId
    valid: bool
    success: bool
    reason: OracleReason
    final_state_fingerprint: Sha256Digest
    evaluated_actions: Annotated[int, Field(ge=0)]

    @model_validator(mode="after")
    def verdict_is_coherent(self) -> OracleVerdict:
        expected = {
            OracleReason.SUCCESS: (True, True),
            OracleReason.GOAL_NOT_REACHED: (True, False),
            OracleReason.UNKNOWN_ACTION: (False, False),
            OracleReason.DUPLICATE_ACTION: (False, False),
            OracleReason.PRECONDITION_FAILED: (False, False),
            OracleReason.CHAIN_TOO_LONG: (False, False),
            OracleReason.CHALLENGE_MISMATCH: (False, False),
            OracleReason.PUBLIC_CHALLENGE_MISMATCH: (False, False),
            OracleReason.REALITY_ANCHOR_DISABLED: (False, False),
        }[self.reason]
        if (self.valid, self.success) != expected:
            raise ValueError("oracle reason, validity, and success must agree")
        return self


class ChallengeResult(ContractModel):
    challenge_id: ChallengeId
    challenge_digest: Sha256Digest
    family: ChallengeFamily
    split: DatasetSplit
    budget: BudgetLimits
    run: SystemRun
    verdict: OracleVerdict

    @model_validator(mode="after")
    def result_bindings_are_exact(self) -> ChallengeResult:
        if (
            self.run.submission.challenge_id != self.challenge_id
            or self.verdict.challenge_id != self.challenge_id
            or self.run.ledger.limits != self.budget
        ):
            raise ValueError("challenge result bindings are inconsistent")
        return self


class AggregateMetrics(ContractModel):
    challenge_count: Annotated[int, Field(ge=1)]
    successes: Annotated[int, Field(ge=0)]
    valid_submissions: Annotated[int, Field(ge=0)]
    success_rate: Annotated[float, Field(ge=0.0, le=1.0)]
    validity_rate: Annotated[float, Field(ge=0.0, le=1.0)]
    total_world_cost: Annotated[int, Field(ge=0)]
    total_action_cost: Annotated[int, Field(ge=0)]
    total_latency_proxy: Annotated[int, Field(ge=0)]
    mean_world_cost: Annotated[float, Field(ge=0.0)]
    mean_action_cost: Annotated[float, Field(ge=0.0)]
    mean_latency_proxy: Annotated[float, Field(ge=0.0)]

    @model_validator(mode="after")
    def counts_and_rates_are_coherent(self) -> AggregateMetrics:
        if self.successes > self.valid_submissions or self.valid_submissions > self.challenge_count:
            raise ValueError("aggregate success and validity counts are impossible")
        if self.success_rate != self.successes / self.challenge_count:
            raise ValueError("success rate must derive from aggregate counts")
        if self.validity_rate != self.valid_submissions / self.challenge_count:
            raise ValueError("validity rate must derive from aggregate counts")
        if self.mean_world_cost != self.total_world_cost / self.challenge_count:
            raise ValueError("mean world cost must derive from aggregate totals")
        if self.mean_action_cost != self.total_action_cost / self.challenge_count:
            raise ValueError("mean action cost must derive from aggregate totals")
        if self.mean_latency_proxy != self.total_latency_proxy / self.challenge_count:
            raise ValueError("mean latency proxy must derive from aggregate totals")
        return self


class SystemBenchmarkReport(ContractModel):
    system_id: SystemId
    system_config_digest: Sha256Digest
    dataset_digest: Sha256Digest
    evaluator_digest: Sha256Digest
    generator_config_digest: Sha256Digest
    raw_results: tuple[ChallengeResult, ...]
    metrics: AggregateMetrics

    @model_validator(mode="after")
    def summary_must_derive_from_raw_results(self) -> SystemBenchmarkReport:
        if not self.raw_results:
            raise ValueError("benchmark reports require raw per-challenge results")
        if any(item.run.system_id != self.system_id for item in self.raw_results):
            raise ValueError("benchmark report mixes system identities")
        if any(
            item.run.system_config_digest != self.system_config_digest for item in self.raw_results
        ):
            raise ValueError("benchmark report mixes solver configurations")
        identifiers = [item.challenge_id for item in self.raw_results]
        if identifiers != sorted(identifiers) or len(identifiers) != len(set(identifiers)):
            raise ValueError("raw challenge results must be canonical and unique")
        if len({item.split for item in self.raw_results}) != 1:
            raise ValueError("one system report cannot mix dataset splits")
        if len({item.budget for item in self.raw_results}) != 1:
            raise ValueError("one system report cannot mix budget limits")
        if self.metrics != aggregate_metrics(self.raw_results):
            raise ValueError("benchmark metrics must be recomputed from raw challenge results")
        return self

    @property
    def report_digest(self) -> str:
        """Digest closing report, raw results, dataset, evaluator, and configs."""

        return sha256_digest(self)


class ComparisonReport(ContractModel):
    split: DatasetSplit
    budget: BudgetLimits
    baseline: SystemBenchmarkReport
    full: SystemBenchmarkReport
    improved_families: tuple[ChallengeFamily, ...]

    @model_validator(mode="after")
    def comparison_is_equal_budget_and_raw_bound(self) -> ComparisonReport:
        baseline_provenance = (
            self.baseline.dataset_digest,
            self.baseline.evaluator_digest,
            self.baseline.generator_config_digest,
        )
        full_provenance = (
            self.full.dataset_digest,
            self.full.evaluator_digest,
            self.full.generator_config_digest,
        )
        if baseline_provenance != full_provenance:
            raise ValueError("comparison systems must share dataset and evaluator provenance")
        baseline_by_id = {item.challenge_id: item for item in self.baseline.raw_results}
        full_by_id = {item.challenge_id: item for item in self.full.raw_results}
        if set(baseline_by_id) != set(full_by_id):
            raise ValueError("comparison systems must run identical challenges")
        if any(
            (
                baseline_by_id[challenge_id].challenge_digest,
                baseline_by_id[challenge_id].family,
                baseline_by_id[challenge_id].split,
                baseline_by_id[challenge_id].budget,
            )
            != (
                full_by_id[challenge_id].challenge_digest,
                full_by_id[challenge_id].family,
                full_by_id[challenge_id].split,
                full_by_id[challenge_id].budget,
            )
            for challenge_id in baseline_by_id
        ):
            raise ValueError("comparison systems must preserve complete challenge provenance")
        if any(
            item.split is not self.split or item.budget != self.budget
            for item in (*self.baseline.raw_results, *self.full.raw_results)
        ):
            raise ValueError("comparison must preserve one split and equal budget")
        families = sorted(
            {item.family for item in self.baseline.raw_results}, key=lambda item: item.value
        )
        improved = tuple(
            family
            for family in families
            if sum(item.verdict.success for item in self.full.raw_results if item.family is family)
            > sum(
                item.verdict.success for item in self.baseline.raw_results if item.family is family
            )
        )
        if self.improved_families != improved:
            raise ValueError("improved-family claims must derive from raw challenge results")
        return self


class AblationSpec(ContractModel):
    disabled: tuple[AblationFeature, ...]

    @field_validator("disabled")
    @classmethod
    def features_are_canonical(
        cls, value: tuple[AblationFeature, ...]
    ) -> tuple[AblationFeature, ...]:
        if len(value) != len(set(value)):
            raise ValueError("ablation features must be unique")
        return tuple(sorted(value, key=lambda item: item.value))

    def has(self, feature: AblationFeature) -> bool:
        return feature in self.disabled


def tiered_system_config_digest(*, seed: int, beam_width: int, ablation: AblationSpec) -> str:
    """Bind every explicit local tiered-solver configuration field."""

    return sha256_digest(
        {
            "solver": "stateweaver_tiered",
            "seed": seed,
            "beam_width": beam_width,
            "ablation": ablation,
        }
    )


class AblationResult(ContractModel):
    spec: AblationSpec
    report: SystemBenchmarkReport


class AblationReport(ContractModel):
    seed: Annotated[int, Field(ge=0, le=2**31 - 1)]
    beam_width: Annotated[int, Field(ge=1, le=16)]
    results: tuple[AblationResult, ...]

    @model_validator(mode="after")
    def ablations_are_unique(self) -> AblationReport:
        disabled = [item.spec.disabled for item in self.results]
        if not disabled or len(disabled) != len(set(disabled)):
            raise ValueError("ablation report entries must be nonempty and unique")
        if any(len(features) != 1 for features in disabled):
            raise ValueError("ablation suite must disable exactly one feature per entry")
        if {features[0] for features in disabled} != set(AblationFeature):
            raise ValueError("ablation suite must cover every architecture feature")
        report_digests = [item.report.report_digest for item in self.results]
        if len(report_digests) != len(set(report_digests)):
            raise ValueError("ablation labels cannot reuse the same benchmark report")
        system_configs = [item.report.system_config_digest for item in self.results]
        if len(system_configs) != len(set(system_configs)):
            raise ValueError("ablation labels must bind distinct solver configurations")
        for item in self.results:
            expected_config = tiered_system_config_digest(
                seed=self.seed,
                beam_width=self.beam_width,
                ablation=item.spec,
            )
            expected_system = f"system.stateweaver_{expected_config.removeprefix('sha256:')[:12]}"
            if (
                item.report.system_config_digest != expected_config
                or item.report.system_id != expected_system
            ):
                raise ValueError("ablation spec does not bind its exact solver report")
        return self


def aggregate_metrics(results: tuple[ChallengeResult, ...]) -> AggregateMetrics:
    if not results:
        raise ValueError("cannot aggregate an empty benchmark result set")
    count = len(results)
    successes = sum(item.verdict.success for item in results)
    valid = sum(item.verdict.valid for item in results)
    world = sum(item.run.ledger.usage.world_cost for item in results)
    action = sum(item.run.ledger.usage.action_cost for item in results)
    latency = sum(item.run.ledger.usage.latency_units for item in results)
    return AggregateMetrics(
        challenge_count=count,
        successes=successes,
        valid_submissions=valid,
        success_rate=successes / count,
        validity_rate=valid / count,
        total_world_cost=world,
        total_action_cost=action,
        total_latency_proxy=latency,
        mean_world_cost=world / count,
        mean_action_cost=action / count,
        mean_latency_proxy=latency / count,
    )


def budget_event_id(
    *,
    sequence: int,
    kind: BudgetEventKind,
    operation_key: str,
    action_token: str | None,
    action_cost: int,
    world_cost: int,
    latency_units: int,
) -> str:
    suffix = sha256_digest(
        {
            "sequence": sequence,
            "kind": kind,
            "operation_key": operation_key,
            "action_token": action_token,
            "action_cost": action_cost,
            "world_cost": world_cost,
            "latency_units": latency_units,
        }
    ).removeprefix("sha256:")[:24]
    return f"event.{suffix}"


def state_fingerprint(state: dict[str, bool]) -> str:
    return sha256_digest(tuple(sorted(state.items())))


def action_is_applicable(action: PublicAction, state: dict[str, bool]) -> bool:
    return all(state.get(item.key) is item.value for item in action.preconditions)


def apply_action(action: PublicAction, state: dict[str, bool]) -> dict[str, bool]:
    if not action_is_applicable(action, state):
        raise ValueError("public action preconditions are not satisfied")
    output = dict(state)
    for effect in action.effects:
        output[effect.key] = effect.value
    return output


def goal_is_reached(challenge: PublicChallenge, state: dict[str, bool]) -> bool:
    return state.get(challenge.goal.key) is challenge.goal.value
