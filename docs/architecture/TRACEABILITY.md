# Architecture milestone traceability

This document connects the architecture baseline’s M0–M8 milestones to repository evidence.
A milestone is **not complete** unless every stated exit criterion has passed and its evidence has
been retained. “Implemented foundation” means code and focused tests exist, not that the milestone
exit has been certified.

Run all commands from the repository root after `uv sync --all-packages --group dev`. The
acceptance commands are intentionally local and do not require network access.

## Status summary

| Milestone | Current status | Evidence location |
|---|---|---|
| M0 — Contracts + Lab | Proof-producing foundation passes locally; formal exit audit pending | `packages/contracts/`, `labs/multitenant-saas/`, `packages/policy/`, `packages/evidence/` |
| M1 — Deterministic Replay Kernel | Proof-producing foundation passes locally; formal exit audit pending | `packages/replay/`, `adapters/environments/in_process_lab/`, `apps/cli/` |
| M2 — Materialized World Engine | Synthetic archive + per-world concurrency implemented; live Docker and real-provider proof pending | `packages/worlds/`, `adapters/environments/docker_compose/`, `tests/integration/worlds/` |
| M3 — Security Semantic Twin | Exit flow passes locally; release certification pending | `packages/twin/`, source/OTel adapters, `tests/integration/twin/` |
| M4 — Tiered Search Controller | Offline exit flow passes locally; materialized certification pending | `packages/search/`, `workflows/world/` |
| M5 — Chain Compiler | Synthetic action/auth/effect/root/expiry closure hardened; release evidence pending | `packages/compiler/`, `tests/integration/compiler/` |
| M6 — Reality Anchor + Proof Bundle | Typed Finding gate + immutable-byte candidate resolver implemented; trusted broker pending | `packages/contracts/`, `packages/evidence/`, `apps/cli/` |
| M7 — StateChainBench | Trusted built-in synthetic runner hardened; equal-work/public audit pending | `benchmarks/statechainbench/` |
| M8 — Web UI + Public Release | Fixed synthetic API/client and local browser QA pass; public release pending | `apps/api/`, `apps/web/` |

## M0 — Contracts + Lab

**Architecture deliverables:** `ScopeManifest`, `ActionEnvelope`, Security State IR,
Transition Fragment, World Manifest, Oracle Result, and a vulnerable/patched multi-tenant SaaS
lab.

**Current paths**

- Contracts and deterministic canonicalization: `packages/contracts/src/stateweaver/contracts/`
  and `packages/contracts/tests/`.
- Server-side policy evaluation: `packages/policy/src/stateweaver/policy/` and
  `packages/policy/tests/`.
- Synthetic vulnerable and patched lab plus deterministic oracle:
  `labs/multitenant-saas/stateweaver_lab/` and `labs/multitenant-saas/tests/`.
- Normative M0/M1 acceptance matrix: `docs/architecture/M0_M1_ACCEPTANCE.md`.
- Immutable proof collector and causal verifier: `packages/evidence/`.

**Acceptance command**

```powershell
uv run pytest packages/contracts/tests packages/policy/tests labs/multitenant-saas/tests -q
```

**Exit criterion:** a deterministic, non-LLM oracle accurately distinguishes the intentional
vulnerable scenario from the patched build and negative controls. The repository now produces and
self-verifies the required immutable artifact tree locally and CI is configured to retain it, but
the row-by-row release audit has not yet signed every M0 requirement; therefore M0 remains **not
certified**. Contract validators cover transition observables and
source/evidence/fidelity coherence, provenance/taint boundaries, World lifecycle and parent-lineage
extension, deterministic Oracle evidence, and UTC canonicalization.

## M1 — Deterministic Replay Kernel

**Architecture deliverables:** root seed, captured session/action/state layers, clean reset, exact
replay, and failure localization.

**Current paths**

- Replay models, ports, and kernel: `packages/replay/src/stateweaver/replay/` with tests in
  `packages/replay/tests/`.
- Closed in-process replay environment and oracle adapter:
  `adapters/environments/in_process_lab/src/stateweaver/adapters/in_process_lab/` with tests in
  `adapters/environments/in_process_lab/tests/`.
- Foundation verification entry point: `apps/cli/src/stateweaver/cli/foundation.py` and
  `apps/cli/tests/test_foundation.py`.

**Acceptance command**

```powershell
uv run pytest packages/replay/tests adapters/environments/in_process_lab/tests apps/cli/tests -q
uv run stateweaver --json foundation verify
uv run stateweaver foundation collect-evidence --help
```

**Exit criterion:** the same plan repeatedly replays from a clean root with stable results, and
failure identifies a precise step. The exact five retained vulnerable attempts now drive the
determinism gate, and the bundle binds their plan, root, action log, policy decisions, Oracle
results, patched failure localization, and controls. Formal row-by-row certification remains
pending, so M1 is **not certified**.

## M2 — Materialized World Engine

**Architecture deliverables:** Docker Compose adapter, world fork/restore/destroy, per-world
namespace, fingerprints, and sibling-isolation tests.

**Current paths**

- `adapters/environments/docker_compose/`
- `packages/worlds/`
- `tests/integration/worlds/` — explicit live gate; excluded from default tests and not yet run
- `.github/workflows/docker-compose-live.yml` — manual observation workflow; not acceptance proof

**Local protocol gate**

```powershell
uv run pytest packages/worlds/tests adapters/environments/docker_compose/tests -q
```

**Explicit live observation command**

```powershell
docker build --tag stateweaver-synthetic-demo:local adapters/environments/docker_compose/src/stateweaver/adapters/docker_compose
$env:STATEWEAVER_RUN_DOCKER_INTEGRATION = "1"
uv run pytest -o 'addopts=--strict-config --strict-markers -ra' tests/integration/worlds/test_live_docker_compose.py -m docker_integration -q
```

This command has not been run in the retained local verification because Docker is unavailable. The
test fails rather than skips when explicitly selected without the opt-in. Its code, default
deselection, or an unrun manual workflow is not a live observation, acceptance artifact, or proof.

**Exit criterion:** at least four sibling worlds run in parallel without contamination. The strict
world lifecycle manager, immutable snapshots, namespace uniqueness, timeout/cleanup behavior,
deduplication, restore-manifest revalidation, live-environment source binding, and malicious-adapter
conformance tests exist in `packages/worlds/`. The fixed synthetic adapter canonicalizes a
six-component archive, hashes content with the exact running image identity, switches restored
generations through one commit pointer, re-exports after fork/restore, and rejects forged manifests,
handles, lineage, process replies, and cancellation leaks in its stateful emulator.

Those capabilities remain `PARTIAL`: the bridge models JSON components rather than live PostgreSQL,
Redis, queue, browser-session, filesystem-provider, and controlled-clock capture. The four-sibling
test now uses four-way barriers to prove that separate world creation and snapshot operations overlap
at the runner boundary. `WorldManager` holds one stable asynchronous admission gate per retained
world: snapshot, restore, destroy, transition, and parent-fork operations read and commit entirely
inside that gate, while distinct worlds continue to enter adapters concurrently. Each immutable
`WorldNode` also carries a monotonic revision, and the manager-owned store rejects compare-and-swap
commits based on an older revision. The store issues exactly one opaque writer capability to its
manager; callers receive a `ReadOnlyWorldStore` query facade, so phase changes and destruction cannot
bypass lifecycle admission or adapter cleanup. All asynchronous manager commands bind to one event
loop, and caller-supplied world IDs are fully validated before adapter entry. Before any
prepare/fork/create-ghost operation, the writer reserves the new world identity; before materialized
snapshot or publication, it claims a unique returned environment ID/opaque ownership reference and
then validates all six namespace components against both live and pending worlds. Identity
collisions are rejected without ambiguous cleanup; uniquely owned namespace losers are cleaned up.
Successful cleanup releases the reservation, while cleanup failure retains a quarantine entry.
Deterministic adversarial tests cover the former phase-regression race, same-world serialization,
different-world overlap, snapshot/restore versus destroy ordering, duplicate and malformed IDs
before adapter entry, read-only mutation denial, metadata-only destroy denial, cross-loop rejection,
pending handle/namespace collisions, winner commits during loser cleanup, cross-parent child
collisions, cleanup quarantine, typed ghost creation, disjoint prepare parallelism,
failure/cancellation gate release, writer capability checks, and stale-revision rejection. Adapter
tests add identity-reservation collisions, destroy-versus-waiter revalidation, fork cancellation,
cross-source restore rejection, and cancellation after destructive restore commits. No Docker host
was available, so image build/run, genuinely parallel Compose subprocesses, and live cross-world
contamination checks remain unproved. M2 is therefore **not certified**.

## M3 — Security Semantic Twin

**Architecture deliverables:** OpenAPI ingest, FastAPI/SQLAlchemy extraction, OpenTelemetry ingest,
state-delta learning, and provenance/fidelity tracking.

**Current and planned paths**

- `packages/twin/`
- `adapters/source/fastapi_sqlalchemy/`
- `adapters/telemetry/opentelemetry/`
- `tests/integration/twin/`

**Acceptance command**

```powershell
uv run pytest packages/twin/tests adapters/source/fastapi_sqlalchemy/tests adapters/telemetry/opentelemetry/tests tests/integration/twin -q
```

**Exit criterion:** one real user flow yields a verifiable Transition Fragment. The local synthetic
integration now executes a real FastAPI route through `TestClient`, extracts the running app's
OpenAPI/routes and SQLAlchemy metadata, ingests a causally matching OTLP trace and observed state
delta, and emits an evidence-bound observed `TransitionFragment`. It opens no socket and uses no
external data. The stated M3 exit flow passes locally; retained release evidence and the formal
release audit are still pending, so M3 is **implemented but not release-certified**.

## M4 — Tiered Search Controller

**Architecture deliverables:** hypothesis schema, Ghost/Replay/Simulated tiers, beam frontier,
budget ledger, and promotion/prune gates.

**Current and planned paths**

- `packages/search/`
- `packages/mutations/`
- `workflows/world/`
- `tests/property/search/`

**Acceptance command**

```powershell
uv run pytest packages/search/tests workflows/world/tests -q
```

**Exit criterion:** from 20+ Ghost worlds, promote only a small subset while retaining genuinely
useful conditions. `packages/search/` now provides the closed hypothesis decisions, four tiers,
hard promotion gates, deterministic beam frontier, immutable budget ledger, deduplication, and
diversity selection. Its focused 24-Ghost test promotes only the bounded beam and proves a model
score cannot bypass a failed gate. `workflows/world/` now carries those decisions through abstract
allocation/capture ports with hard reservation, rollback, evidence/Oracle binding, sibling identity
isolation, and a canonical event log. The local 24 → 4 → 2 → 1 synthetic flow passes; real
materialized allocation and retained release evidence are pending, so M4 is **implemented offline,
not release-certified**.

## M5 — Chain Compiler

**Architecture deliverables:** fragment graph, constraint translation, candidate plan generation,
clean-room replay, and chain minimization.

**Current paths**

- `packages/compiler/`
- `tests/integration/compiler/`

**Acceptance command**

```powershell
uv run pytest packages/compiler/tests tests/integration/compiler -q
```

**Exit criterion:** automatically synthesize at least three separate conditions into a replayable
security-violation chain. `packages/compiler/` builds a typed fragment graph, translates
constraints, composes and minimizes deterministic candidate chains, and marks resequenced
candidates as requiring fresh policy authorization. The synthetic clean-room flow composes the
three required fragments and reproduces one terminal signature from five roots. Its integration
harness now binds every action field, typed effect, full root, request, decision, one-second expiry,
and one-use authorization; substitution tests require rejection before state change, and Oracle
evidence is contained in the terminal observation. This closes the local synthetic integrity
review, but retained release evidence and a non-synthetic chain are still pending. M5 is therefore
**locally hardened, not release-certified**.

## M6 — Reality Anchor + Proof Bundle

**Architecture deliverables:** Reality Replay Broker, negative controls, patched-version replay,
finding status machine, and Reality Proof Bundle.

**Planned paths**

- `packages/contracts/` (implemented receipt and finding status gate)
- `packages/replay/` (extension)
- `packages/evidence/`
- `packages/reporting/`
- `tests/e2e/proof_bundle/`

**Planned acceptance command**

```powershell
uv run pytest packages/contracts/tests packages/replay/tests packages/evidence/tests packages/reporting/tests tests/e2e/proof_bundle -q
```

**Exit criterion:** a separate clean machine can reproduce the finding from the bundle. The M0/M1
foundation now has a canonical proof producer and local coherence verifier, including detection of
cross-artifact substitution even after manifest hashes are recomputed. The high-level CLI verifier
also re-executes the installed deterministic foundation and binds its exact semantic output,
installed source and Oracle bytes, and stable locked runtime dependency bytes. It still does not
authenticate a producer or prove execution of producer-supplied JUnit by itself. Main-branch CI is
configured to attest the exact proof manifest with GitHub Actions OIDC, but that trust root is not
evidence until a public run succeeds and its attestation is retained.

The core contract now rejects the former bare `replay_run_id + REPRODUCED` promotion path. A
content-addressed `RealityReplayReceipt` models the necessary input for `REALITY_REPLAYED`, and
`PATCH_VERIFIED` additionally models an exact `BLOCKED_BY_FIX` patched receipt. It binds the
scope, target and adapter locks; chain, plan and clean root; at least two unique attempts with one
semantic signature and trace hash; deterministic `OBSERVED + VIOLATED` Oracle results; non-vacuous
`OBSERVED + SATISFIED` negative controls; and an evidence-manifest digest. All nested receipt
objects are revalidated at the Finding promotion boundary, including Pydantic instances created
without normal validation. `SYNTHETIC_REPRODUCED` is explicitly non-confirmed. The evidence package
now resolves the synthetic profile from one immutable in-memory byte mapping: it enforces exact
pre-receipt coverage, hashes and parses the same bytes, and binds scope, locks, plan/root/chain,
results, action logs, logical traces, Oracles, controls, patch replay, and evidence index. The result
is permanently non-authoritative and non-promotable.

This content hash and candidate resolver prove one supplied snapshot's internal coherence, not
issuer identity, authenticated retention, target/adapter source provenance, or independent
execution. The general Reality Replay Broker, trusted store acquisition, reporting layer, trusted
issuance/attestation, and portable M6 reproduction workflow remain absent. The Finding validator
therefore rejects both reserved confirmed statuses. M6 is **partially implemented and not
certified**. See `docs/architecture/M6_REALITY_RECEIPT.md` for the exact boundary.

## M7 — StateChainBench

**Architecture deliverables:** challenge generator, hidden oracle, baseline adapters, equal-budget
runner, metrics, and ablation report.

**Current paths**

- `benchmarks/statechainbench/`

**Acceptance command**

```powershell
uv run pytest benchmarks/statechainbench/tests -q
```

**Exit criterion:** on at least one holdout challenge family, full StateWeaver materially
outperforms meaningful baselines under genuinely equivalent, closed budgets. The seeded offline
core now accepts only exact trusted built-in solver types; reconstructs datasets and hidden-oracle
commitments from generator config; binds solver config, challenge, comparison, and ablation
provenance; audits PLAN/ACTION/WORLD namespaces and tariffs; and retains the exact failed
reservation for budget stops. PLAN charges considered work, while ACTION/WORLD totals include
exploratory branches, not only the submitted path. This deterministic tariff is not proof of equal
measured compute, and the runner is not a process-isolation boundary for third-party systems.
Stronger baselines, independent reproduction, and retained public evidence remain pending, so M7
is **a hardened local prototype, not a publishable benchmark or certification**.

## M8 — Web UI + Public Release

**Architecture deliverables:** a README-led user path to start the lab, run the benchmark, inspect
the World DAG, and replay a finding.

**Planned paths**

- `apps/api/`
- `apps/web/`
- `docs/benchmark/`
- `tests/e2e/public_release/`

**Planned acceptance command**

```powershell
uv run pytest apps/api/tests tests/e2e/public_release -q
```

The web client has package-local format, lint, type-check, unit-test, and build commands. Its parser
recomputes canonical Web Crypto SHA-256 for every content-bound digest, the fixed run hashes,
manifest, and run signature before rendering.

**Exit criterion:** a new user can follow only the README to complete the stated lab, benchmark,
DAG, and replay journey. A localhost-only synthetic API and four-workspace client are implemented.
API/model closure, browser content-digest substitution tests, all four desktop/mobile routes, the
World/Twin/Replay interactions, and zero-error browser console checks pass locally. Public hosting,
the complete external new-user journey, and retained release attestation remain pending, so M8 is
**locally browser-accepted as a synthetic prototype, not certified**.

## Repository-wide quality gate

```powershell
uv run ruff format --check .
uv run ruff check .
uv run mypy packages adapters apps labs workflows benchmarks tests
uv run pytest --cov --cov-report=term-missing
cd apps/web
npm run format:check
npm run lint
npm run typecheck
npm test
npm run build
```

This quality gate validates the current repository; it does not by itself certify any M0–M8 exit.
