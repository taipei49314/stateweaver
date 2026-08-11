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
formatting, typing, unit, integration, race, simulated-DOM contract, build, and proof gates. Those
developer checks are not an exact-SHA release-qualification receipt. The first
retained Docker workflow exposed compatibility defects that are being fixed through the normal PR
path; it still exercises a synthetic bridge rather than real providers. Live-provider, trusted
broker, equal-work benchmark, independent new-user, and clean-machine certification remain
intentionally unclaimed. No PyPI package or versioned GitHub Release is offered yet.

<details>
<summary>Implementation and trust-boundary detail (summary)</summary>

Architecture baseline v1 ships milestone-by-milestone. Current implementation and local-test posture:

| Area | Honest status |
|---|---|
| M0/M1 foundation proof | Synthetic proof and canonical 92-row registry exist; CI derives manifest-bound local qualification receipts and admits M0-C07 only from a clean wheel installation, while unresolved and external rows remain `NOT_RUN` or `BLOCKED` |
| M2 world engine | Archive + lifecycle gates exist; ephemeral local synthetic Docker diagnostic only; **no** retained qualification or real-provider proof |
| M3 semantic twin | Runtime-derived process-local observation primitive exists; M4/M5 integration remains pending |
| M4 offline search | 24 → 4 → 2 → 1 flow preserves the observed candidate |
| M5 chain compiler | Admission bridge for observed fragments; synthetic closure only |
| M6 reality receipt | Fail-closed `RealityReplayReceipt` + reporting candidate; **no** trusted broker / M6 cert |
| M7 StateChainBench | Deterministic prototype runner — not equal-work public benchmark |
| M8 public UX | Fixed loopback API + simulated-DOM contract exists; no Playwright/new-user release journey |

Receipts and reports are **internal-coherence** artifacts, not producer
attestation or Reality Broker signatures. Live-provider and clean-machine M6
certification remain intentionally unclaimed.

Full matrices: [docs/architecture/TRACEABILITY.md](docs/architecture/TRACEABILITY.md),
[docs/PROOF_VERIFICATION.md](docs/PROOF_VERIFICATION.md), [ARCHITECTURE.md](ARCHITECTURE.md).

</details>

| Milestone | Auditable local status | Evidence |
| --- | --- | --- |
| M0 Contracts + Lab | Foundation proof, exact registry, and fail-closed derived row ledger exist; external release qualification remains pending | `packages/contracts/`, `labs/multitenant-saas/`, `packages/evidence/` |
| M1 Deterministic Replay | Five-run clean-root differential is implemented; formal qualification pending | `packages/replay/`, `apps/cli/` |
| M2 World Engine | Archive/lifecycle plus synthetic Docker path; real providers remain absent | `packages/worlds/`, `tests/integration/worlds/`, adapter `PARTIAL` |
| M3 Semantic Twin | Process-local exporter and runtime-derived delta primitive; full observed chain pending | `packages/twin/`, `adapters/telemetry/opentelemetry/`, `tests/integration/observation/` |
| M4 Search | Offline 24 → 4 → 2 → 1 flow preserves the observed candidate | `packages/search/`, `workflows/world/`, `tests/integration/pipeline/` |
| M5 Chain Compiler | Three observed fragments cross the admission bridge; synthetic replay closure hardened | `packages/compiler/`, `tests/integration/compiler/`, `tests/integration/pipeline/` |
| M6 Reality + Proof | V2 event reconstruction + traceable publication candidate exist; trusted broker absent | `packages/contracts/`, `packages/evidence/`, `packages/reporting/`, `tests/e2e/proof_bundle/` |
| M7 StateChainBench | Trusted built-in synthetic runner hardened; not equal-work or public-certified | `benchmarks/statechainbench/` |
| M8 Public UX | Read-only fixed API + four-workspace client have local simulated-DOM QA only | `apps/api/`, `apps/web/` |

The current M7 numbers are retained only as a deterministic prototype observation. The runner
accepts only its two exact built-in solver types and closes dataset, evaluator, configuration,
ledger, comparison, and ablation provenance. It still runs in one process and uses a deterministic
tariff rather than equivalent measured compute, so the result is not an equal-work claim or a
public benchmark result.

## Local development

Prerequisites: Python 3.12+, [uv](https://docs.astral.sh/uv/), and Node.js 24 for the web workspace.
Docker Compose is required only for materialized-world integration tests.

```bash
uv sync --all-packages --group dev --locked
uv run stateweaver --json doctor
uv run stateweaver --json foundation verify
uv run stateweaver foundation collect-evidence --help
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
without executing bundle contents. The verifier hashes and parses one captured read of every file
and returns its `snapshot_sha256`; consumers must not reopen mutable paths and assume they are the
same snapshot. Main-branch
[CI run 31239564101](https://github.com/taipei49314/stateweaver/actions/runs/31239564101)
signed the exact-file manifest for SHA `aa60cad5be43f383810bf2e276307c4f4c9cec10` with GitHub
OIDC provenance; see [proof verification](docs/PROOF_VERIFICATION.md). That historical attestation
does not qualify later commits or prove trusted Reality.

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
