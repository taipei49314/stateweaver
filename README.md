# StateWeaver

> Fork security states, not just agent conversations.

[![CI](https://github.com/taipei49314/stateweaver/actions/workflows/ci.yml/badge.svg)](https://github.com/taipei49314/stateweaver/actions/workflows/ci.yml)
[![Python 3.12–3.13](https://img.shields.io/badge/python-3.12%E2%80%933.13-3776AB.svg?logo=python&logoColor=white)](pyproject.toml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-orange.svg)](docs/architecture/TRACEABILITY.md)

![StateWeaver deterministic local workspace](output/playwright/stateweaver-final/overview-content-verified.png)

StateWeaver is a state-first security research engine for **authorized, reproducible labs**. It
builds evidence-backed security state, explores cheap counterfactual worlds, compiles local
transition fragments into a complete chain, and then returns to a clean reality anchor for a
deterministic verdict.

```text
Root state -> World DAG -> Local transitions -> Chain compiler
           -> Clean replay -> Oracle verdict -> Patched replay
```

## Run the deterministic proof

The bundled proof needs no API key, Docker daemon, model provider, or external target. It runs
entirely against the fixed in-process synthetic lab:

```bash
git clone https://github.com/taipei49314/stateweaver.git
cd stateweaver
uv sync --all-packages --group dev --locked
uv run stateweaver --json doctor
uv run stateweaver --json foundation verify
```

The final command performs five clean-root vulnerable replays, negative controls, and the same
plan against the patched build. It exits nonzero unless the machine-readable proof closes. Start
with the [architecture baseline](ARCHITECTURE.md), [traceability matrix](docs/architecture/TRACEABILITY.md),
or [proof verification guide](docs/PROOF_VERIFICATION.md) for the trust boundaries.

## Why this is different

- **State before chat:** the durable record is facts, transitions, observations, evidence, and
  oracle results—not a transcript.
- **Tiered worlds:** Ghost, Replay, Simulated, and Materialized worlds spend real resources only
  when evidence justifies promotion.
- **Reality is the final oracle:** a model can propose a hypothesis; it cannot confirm a finding.
- **Transitions compose; snapshots do not:** chains are rebuilt from a common root and replayed.
- **Auditable evaluation:** StateChainBench binds its local dataset, evaluator, solver
  configuration, deterministic tariff, raw results, comparisons, and ablations while keeping
  public-benchmark claims behind a higher release bar.

## Current status

StateWeaver is a pre-alpha research implementation. Its fixed synthetic flows have local
formatting, typing, unit, integration, race, simulated-DOM contract, build, and proof gates. The
acceptance collector can derive 58 `PASS` rows from exact passing JUnit identities, source
bindings, a clean-wheel package-install receipt, a separately reproduced M3 runtime-observation
receipt, and seven non-promotable M3–M7 implementation receipts. It keeps the remaining 34 rows
`BLOCKED`; these developer checks are not a complete release qualification. A separately attested,
exact-SHA hosted Docker receipt raises the candidate projection to 71 `PASS` / 21 `BLOCKED` by
admitting its exact M2-M5 rows. `SW-M2-LIVE` remains blocked without a separate clean host.
The hosted Docker workflow retains exact-SHA synthetic and six-provider M2 diagnostics with zero
managed residue. M4 now derives 24 Ghost candidates from an eight-observation M3 chain, materializes only the
4-to-2-to-1 promoted subset in those fixed real-provider worlds, and retains a conserved-ledger,
machine-oracle, winner, and cleanup receipt. The producer/attestation/consumer admission path passed on exact merged SHA
`6f74222bd3705b066cc8b6d048a2c10f9a123ffe`. M5 consumes
the retained M4 bytes, compiles all eight observed fragments, freshly authorizes them, and retains
five repeatable clean-root results, the matching fixed-mode boundary, and four controls. The hosted
path now executes those exact authorized actions through the sealed FastAPI ASGI application over
six immutable provider checkpoint shards, retains per-step state, response, evidence, oracle, image,
source, restore, and cleanup bindings, and admits `SW-M5-CHAIN` only after exact-SHA attestation and
fresh consumer verification. Trusted broker, independently owned equal-work benchmark,
independent new-user, and clean-machine certification remain intentionally unclaimed. No PyPI
package or versioned GitHub Release is offered yet.

<details>
<summary>Implementation and trust-boundary detail (summary)</summary>

Architecture baseline v1 ships milestone-by-milestone. Current implementation and local-test posture:

| Area | Honest status |
|---|---|
| M0/M1 foundation proof | Synthetic proof and canonical 92-row registry exist; CI derives manifest-bound receipts and admits M0-C07 only from a clean wheel installation |
| M2 world engine | Six-provider adapter and four-sibling capture/mutate/restore gate passed in the exact-SHA hosted admission; a separate clean host remains pending |
| M3 semantic twin | Clean-wheel runtime execution binds the repo-owned ASGI lifecycle, source, authorization, trace, captures, state delta, evidence, and one `OBSERVED` fragment; five M3 runtime rows are admitted only after independent semantic re-execution |
| M4 tiered search | Eight-observation M3-derived 24-to-4-to-2-to-1 flow has a production six-provider materializer, seven bound provider receipts, peak-live cap four, and typed hosted proof admission |
| M5 chain compiler | Exact retained M4 bytes compile eight `OBSERVED` fragments; the hosted qualifier runs five vulnerable roots, one patched boundary, and four controls through the sealed ASGI app over six provider checkpoint shards, with exact image/source/state/cleanup admission |
| M6 reality receipt | Strict external-policy/object-closure candidate verifier exists and remains non-promotable; **no** external issuer/store/consumer cert |
| M7 StateChainBench | Fixed subprocess measured diagnostic and producer preregistration exist; not an independently measured protected-holdout benchmark |
| M8 public UX | Fixed loopback API plus retry-free Chromium desktop/mobile, keyboard, WCAG, integrity, error, empty, and console gates exist; no external new-user release journey |

The seven M3–M7 local-deliverable receipts are derived from exact passing test identities and the
canonical registry. They are explicitly `authoritative=false`, `promotable=false`,
`release_eligible=false`, and `exit_criterion_satisfied=false`. Receipts and reports are
**internal-coherence** artifacts, not Reality Broker signatures. Live-provider and clean-machine
M6 certification remain intentionally unclaimed. The separate M3 runtime receipt satisfies only
the process-local M3 observed-flow exit; it remains `release_eligible=false`, requires exact-SHA
workflow provenance, and does not qualify M4, M5, a live target, or an external OTel collector.

Full matrices: [docs/architecture/TRACEABILITY.md](docs/architecture/TRACEABILITY.md),
[docs/PROOF_VERIFICATION.md](docs/PROOF_VERIFICATION.md), [ARCHITECTURE.md](ARCHITECTURE.md).

</details>

| Milestone | Auditable local status | Evidence |
| --- | --- | --- |
| M0 Contracts + Lab | Foundation proof, exact registry, and fail-closed derived row ledger exist; external release qualification remains pending | `packages/contracts/`, `labs/multitenant-saas/`, `packages/evidence/` |
| M1 Deterministic Replay | Five-run clean-root differential is implemented; formal qualification pending | `packages/replay/`, `apps/cli/` |
| M2 World Engine | Synthetic diagnostics plus a six-provider materialized path pass locally; exact-SHA hosted receipt admission is implemented | `packages/worlds/`, `tests/integration/worlds/`, `RealDockerComposeEnvironmentAdapter` |
| M3 Semantic Twin | Application lifecycle, emitted trace, runtime captures, state delta, evidence, and `OBSERVED` fragment are bound in a reproducible clean-wheel receipt; M4/M5 materialization remains separate | `packages/twin/`, `adapters/telemetry/opentelemetry/`, `packages/evidence/src/stateweaver/evidence/runtime_observation.py`, `apps/cli/src/stateweaver/cli/runtime_qualification.py` |
| M4 Search | Exactly 24 Ghost evaluations admit only 4, 2, and 1 real six-provider siblings; budget, provider-oracle, winner, and cleanup bindings are retained | `packages/search/`, `workflows/world/`, `apps/cli/src/stateweaver/cli/materialized_search_qualification.py`, `tests/integration/worlds/test_live_materialized_search.py` |
| M5 Chain Compiler | Eight retained fragments execute five deterministic vulnerable roots, one patched boundary, and four controls through the Docker-backed sealed ASGI application over six immutable provider checkpoint shards | `packages/compiler/`, `apps/cli/src/stateweaver/cli/observed_chain_qualification.py`, `apps/cli/src/stateweaver/cli/materialized_chain_qualification.py` |
| M6 Reality + Proof | V2 reconstruction plus full immutable-object/source closure verifier exist; external authority/store/consumer absent | `packages/contracts/`, `packages/evidence/`, `packages/reporting/`, `tests/e2e/proof_bundle/` |
| M7 StateChainBench | Fixed subprocess measured diagnostic retains all runs/failures under equal ceilings; protected custodian/evaluator accounting remains external | `benchmarks/statechainbench/` |
| M8 Public UX | Read-only fixed API/client have simulated-DOM and real Chromium desktop/mobile QA; artifact-only external journey remains pending | `apps/api/`, `apps/web/`, `tests/e2e/public_release/` |

The current M7 numbers remain producer-visible synthetic observations. A fixed subprocess boundary
now applies the same CPU, RAM, wall, request, token, cost, and output ceilings and retains every
primary, ablation, and failure record. Host sampling is not protected evaluator-owned final
accounting, and the dataset is not an externally preregistered holdout, so this remains neither an
independent equal-work claim nor a public benchmark result.

## Local development

Prerequisites: Python 3.12+, [uv](https://docs.astral.sh/uv/), and Node.js 24 for the web workspace.
Docker Compose is required only for materialized-world integration tests.

```bash
uv sync --all-packages --group dev --locked
uv run stateweaver --json doctor
uv run stateweaver --json foundation verify
uv run stateweaver foundation collect-evidence --help
uv run stateweaver foundation qualify-materialized-search --help
```

The read-only synthetic public workspace runs on two fixed loopback ports:

```bash
uv run uvicorn stateweaver_api.app:app --app-dir apps/api/src --host 127.0.0.1 --port 8000
cd apps/web && npm ci && npm run dev -- --host 127.0.0.1 --port 3000 --strictPort
```

`foundation verify` is the current source-checkout, process-local demo. It performs five vulnerable clean-root
replays, an identical-plan patched replay, and the negative-control matrix entirely in process.
It exits nonzero if the deterministic proof conditions are not met.

The CI path also retains a canonical proof bundle containing the exact five runs, patched replay,
negative controls, full typed action log, policy bindings, Oracle evidence, four JUnit reports, an
exact 92-row registry closure and derived result ledger, and an exact-file SHA-256 manifest.
`stateweaver foundation verify-evidence <run-directory>` validates
file integrity and causal coherence, then independently re-executes the installed fixed foundation
without executing bundle contents. When an M3 receipt is present, the high-level verifier also
re-parses the retained adapter receipt, independently re-executes the fixed operation, compares its
stable semantic projection, and confirms the proof snapshot did not change during re-execution.
The verifier returns `snapshot_sha256`; consumers must not reopen mutable paths and assume they are
the same snapshot. Main-branch CI signs the exact-file manifest with GitHub OIDC provenance; see
[proof verification](docs/PROOF_VERIFICATION.md). Any attestation qualifies only its exact subject
and source SHA and does not by itself prove trusted Reality.

For repository development:

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy packages adapters apps labs workflows benchmarks tests tools/candidate
uv run pytest
```

The lab is synthetic and process-local/localhost-only; the demo has no arbitrary-target or shell
execution path. Read [AGENTS.md](AGENTS.md), [SECURITY.md](SECURITY.md), and
[ABUSE_POLICY.md](ABUSE_POLICY.md) before adding adapters or actions.

## Public release bar

A StateWeaver finding is publishable only when the vulnerable build reproduces from a clean root,
the deterministic oracle reports the invariant violation, negative controls do not violate it,
and the same replay is blocked by the patched build. A revalidated `RealityReplayReceipt` is
necessary but deliberately insufficient for confirmed status; local synthetic results remain
`SYNTHETIC_REPRODUCED`. Every claim must link back to raw evidence. Until a Reality Replay Broker
resolves the receipt's digests against retained artifacts and authenticates its issuer,
`REALITY_REPLAYED` and `PATCH_VERIFIED` remain fail-closed and M6 is not certified.

Licensed under Apache-2.0.
