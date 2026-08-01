# StateWeaver Search

`stateweaver-search` is an offline, deterministic M4 controller for typed synthetic
security states. It ranks `Hypothesis` candidates through Ghost, Replay, Simulated,
and Materialized tiers, but it never executes an action or contacts a target.

The default policy is a budget-bounded best-first beam. Scope, policy, approval,
evidence, oracle, observation, snapshot, capability, and nondeterminism gates run
before scoring. Consequently, a high model-provided score cannot promote a blocked
candidate. Canonical state fingerprints are deduplicated, diversity buckets receive
a first selection pass, and uncertainty remains an explicit bounded score signal.

Every promotion creates a new immutable `BudgetLedger`; previous ledgers remain
unchanged. Rejected and pruned candidates retain stable reason codes. Equal inputs,
seed, and policy produce identical canonical output regardless of caller ordering.

This core consumes only contract models and references to already-authorized plans,
evidence, observations, and machine-checkable oracles. World materialization belongs
to a separate workflow and adapter boundary.
