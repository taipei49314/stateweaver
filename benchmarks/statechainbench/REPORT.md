# StateChainBench M7 local credibility report

Status: local synthetic benchmark controls implemented and verified on 2026-08-01.

This report is intentionally limited to the in-process synthetic benchmark in this
directory. It makes no claim of public benchmarking, process isolation, external-target
testing, protocol bypass resistance, or certification.

## Implemented controls

- The runner accepts only the exact built-in `LinearBaseline` and
  `StateWeaverTieredSystem` types (including no subclasses). Arbitrary
  protocol-compatible solvers are rejected. There is no benchmark CLI, subprocess launch,
  or arbitrary program-execution path.
- A solver identity is derived from its complete local configuration. The tiered solver
  binds seed, beam width, and ablation configuration; every run and report retains the
  corresponding configuration digest.
- Challenge IDs bind generator version, seed, family, and variant. They do not depend on
  global generation ordinal or train/holdout split selection.
- The audit rejects zero-work runs, unplanned actions, unmatched submissions, incorrect
  tariffs, and invalid PLAN → ACTION → WORLD evidence ordering. Claimed goal stops must
  agree with an anchored oracle verdict; unanchored runs retain the disabled-anchor verdict.
- The deterministic tariff is: PLAN = one latency unit; ACTION = catalog action cost in
  both action and latency units; WORLD = one world unit and two latency units. The
  `world_tiers` ablation intentionally has no WORLD events and reports zero world cost;
  it does not represent a free external-world interaction.
- Challenge, dataset, evaluator, generator configuration, solver configuration, and report
  digest commitments are retained in the resulting data model.
- Dataset construction regenerates the exact descriptors and hidden-oracle commitment from its
  config. Comparisons require identical dataset/evaluator/config and per-challenge provenance.
- Ablation suites require one entry per feature, recompute each spec-to-solver-config binding, and
  reject report reuse, config reuse, or rotated labels.
- Every budget event binds its kind to the PLAN/ACTION/WORLD operation namespace. Budget stops
  retain the exact failed tariff reservation and prove that the attempted total exceeded a limit.
  Exploratory branch charges remain in totals by design.

The tariff is a deterministic accounting convention, not evidence that the two algorithms perform
equivalent computation. This report therefore makes no equal-work claim.

## Local gates

The focused suite includes adversarial tests for the trusted-solver boundary, configuration
identity, challenge-ID stability, ledger audit failures, oracle consistency, and ablation
reuse. Verified command results:

```text
uv run --group dev pytest benchmarks/statechainbench/tests --cov=statechainbench --cov-branch --cov-report=term-missing -q
29 passed
Required test coverage of 85.0% reached. Total coverage: 86.18%

uv run --group dev ruff check benchmarks/statechainbench
uv run --group dev ruff format --check benchmarks/statechainbench
uv run --group dev mypy benchmarks/statechainbench/src benchmarks/statechainbench/tests
```
