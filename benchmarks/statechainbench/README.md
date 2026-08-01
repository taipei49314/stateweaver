# StateChainBench core

StateChainBench is a deterministic, local synthetic benchmark for multi-step state reasoning. It
compares a catalog-order linear baseline with StateWeaver's tiered-search adapter under
identical action, world, and latency-proxy limits.

This directory implements the synthetic M7 core; it **does not claim M7 certification**.
Public benchmark audit, independent reproduction, and a retained release evidence bundle
are still pending.

It is not the architecture's full Source-backed Track, which requires a repository,
Compose environment, and instrumentation. The local oracle is a synthetic reality-anchor
surrogate, not evidence of replay against production code or an authorized staging target.

## Safety and evaluator boundary

- Generation and execution are seeded and in-process. There are no model calls, network
  requests, subprocesses, credentials, or real targets.
- This package has no CLI or console-script entry point. Benchmark execution is through the
  in-process Python API only; it cannot launch an arbitrary command or solver process.
- Solver input is only `PublicChallenge`. Family, split, and terminal oracle state remain
  on the evaluator side.
- Challenge IDs bind generator version, seed, family, and variant. They are stable when
  unrelated families, split membership, or generation order changes; public solver input
  still contains no family, split, or solution labels.
- Every contract is closed and frozen. Unknown fields, including attempted answer fields,
  are rejected.
- The hidden oracle exposes only `evaluate`; it never returns its terminal constraints.
- Budget reservations are immutable and fail before an event can exceed a limit. The
  runner accepts only the two exact built-in local solver types, binds their identity to a
  configuration digest, and independently checks tariff and PLAN → ACTION → WORLD ordering.

## Dataset protocol

Families are split before instances are generated:

| Split | Families |
| --- | --- |
| Train | `session_cache`, `queue_role_transition` |
| Holdout | `request_ordering`, `version_flag_skew` |

Each challenge has at least three joint terminal state conditions, ordering constraints,
an interfering transition, and a machine-checkable hidden terminal state. Template family
labels are never passed to either system.

## Evidence and metrics

`EqualBudgetRunner` retains one immutable `ChallengeResult` per system and challenge.
`SystemBenchmarkReport` refuses summaries that do not exactly recompute from those raw
results. Each result retains a challenge digest; each report retains dataset, evaluator,
generator-config, and solver-config digests, and exposes a report digest over that closure.
`ComparisonReport` likewise recomputes improved families from matched challenge IDs and
equal budgets. Ablation reports reject reuse of one report or solver configuration under
different feature labels.

Reported measures are success and validity counts/rates, action cost, world-tier cost, and
latency proxy. Latency proxy is a deterministic accounting tariff—not wall-clock latency or proof
of equivalent computational work. A PLAN costs no action/world units and one latency unit; an
ACTION costs its catalog action cost and the same number of latency units; a WORLD event costs one
world unit and two latency units. PLAN includes considered catalog work, and ACTION/WORLD totals
include promoted exploratory branches rather than only the final submitted path. A budget stop
retains the exact first failed PLAN, ACTION, or atomic ACTION+WORLD reservation and the runner
verifies that it truly exceeded a hard limit. The `world_tiers` ablation intentionally omits WORLD
events, so its reported world cost is zero; this is an architectural ablation, not a claim that an
external world was exercised for free. Ablations disable, one at a time, semantic-twin scoring,
world tiers, state-fingerprint deduplication, chain compilation, the reality anchor, and the
budget-aware scheduler.

The offline core does not measure LLM tokens, human intervention, actual wall-clock time,
algorithm-equivalent compute, or performance on external applications. Those remain work for the
public benchmark.

An in-process run returns a serializable report containing both raw results and derived
statistics:

```python
from statechainbench import (
    BudgetLimits,
    DatasetSplit,
    EqualBudgetRunner,
    GeneratorConfig,
    generate_dataset,
)

dataset = generate_dataset(GeneratorConfig(seed=1729, variants_per_family=4))
report = EqualBudgetRunner(dataset).compare(
    BudgetLimits(max_action_cost=40, max_world_cost=30, max_latency_units=250),
    split=DatasetSplit.HOLDOUT,
)
print(report.model_dump_json(indent=2))
```

## Local gates

From this directory, with the repository development environment available:

```text
python -m pytest
python -m pytest --cov=statechainbench --cov-branch --cov-report=term-missing
python -m mypy src tests
python -m ruff check src tests
python -m ruff format --check src tests
```

No benchmark result should be promoted as a public certification until the public audit
and release evidence work are complete.
