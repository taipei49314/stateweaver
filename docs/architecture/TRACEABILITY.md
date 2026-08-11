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
| M0 — Contracts + Lab | Proof-producing foundation is implemented and locally exercised; formal exit audit pending | `packages/contracts/`, `labs/multitenant-saas/`, `packages/policy/`, `packages/evidence/` |
| M1 — Deterministic Replay Kernel | Proof-producing replay is implemented and locally exercised; formal exit audit pending | `packages/replay/`, `adapters/environments/in_process_lab/`, `apps/cli/` |
| M2 — Materialized World Engine | Synthetic archive + exact-SHA hosted Docker concurrency diagnostic implemented; real providers pending | `packages/worlds/`, `adapters/environments/docker_compose/`, `tests/integration/worlds/` |
| M3 — Security Semantic Twin | Clean-wheel observed-flow receipt implemented and independently reproduced; M4/M5 materialized chain remains separate | `packages/twin/`, source/OTel adapters, `packages/evidence/src/stateweaver/evidence/runtime_observation.py`, `apps/cli/src/stateweaver/cli/runtime_qualification.py` |
| M4 — Tiered Search Controller | Offline exit flow preserves the observed candidate; materialized certification pending | `packages/search/`, `workflows/world/`, `tests/integration/pipeline/` |
| M5 — Chain Compiler | Observed admission bridge and synthetic replay closure are implemented; release evidence pending | `packages/compiler/`, `tests/integration/compiler/`, `tests/integration/pipeline/` |
| M6 — Reality Anchor + Proof Bundle | V2 event reconstruction + immutable-byte candidate resolver implemented; trusted broker pending | `packages/contracts/`, `packages/evidence/`, `apps/cli/` |
| M7 — StateChainBench | Trusted built-in synthetic runner hardened; equal-work/public audit pending | `benchmarks/statechainbench/` |
| M8 — Web UI + Public Release | Fixed synthetic API/client have local simulated-DOM test coverage; browser/new-user/public release pending | `apps/api/`, `apps/web/` |

The acceptance collector derives seven local-deliverable receipts for 22 repo-controlled M3–M7
rows from exact passing JUnit identities, canonical registry statements and evidence roles, and
the proof's source/run bindings. Together with valid clean-wheel package-install and independently
reproduced runtime-observation receipts, the projection is 58 `PASS`, zero `NOT_RUN`, and 34
`BLOCKED`. The seven local-deliverable receipts remain explicitly
non-authoritative, non-promotable, not release-eligible, and insufficient for their milestone exits.
The distinct M3 receipt admits only five runtime-observation rows and remains non-release-eligible;
the other 34 unresolved gates remain fail closed.

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
- `tests/integration/worlds/` — explicit live synthetic gate; excluded from default tests
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

The baseline hosted run first exposed a Compose JSON compatibility defect and failed:
[run 31306321481](https://github.com/taipei49314/stateweaver/actions/runs/31306321481). The current
source accepts the closed v2-array and v5-single-object forms, selects Docker Desktop's fixed Linux
endpoint without loading user Docker configuration, and uses a bounded health timeout that survives
four concurrent `fsync` imports. A successful exact-merged-SHA hosted rerun is still required; code,
local output, default deselection, or an older run is not release evidence.

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
cross-source restore rejection, and cancellation after destructive restore commits. During
2026-08-09 development, an ephemeral local diagnostic was observed to complete four sibling
create/snapshot/restore paths and leave zero `swm2` containers, networks, or volumes. No immutable
exact-SHA log, artifact inventory, or receipt from that diagnostic is retained in this repository.
It is therefore not qualification evidence and does not satisfy the real-provider, hosted exact-SHA,
or independent clean-host gates. M2 is **not certified**.

## M3 — Security Semantic Twin

**Architecture deliverables:** OpenAPI ingest, FastAPI/SQLAlchemy extraction, OpenTelemetry ingest,
state-delta learning, and provenance/fidelity tracking.

**Current and planned paths**

- `packages/twin/`
- `adapters/source/fastapi_sqlalchemy/`
- `adapters/telemetry/opentelemetry/`
- `tests/integration/observation/`
- `tests/integration/twin/`
- `tests/integration/pipeline/`

**Acceptance command**

```powershell
uv run pytest `
  packages/twin/tests `
  adapters/source/fastapi_sqlalchemy/tests `
  adapters/telemetry/opentelemetry/tests `
  tests/integration/observation `
  tests/integration/twin `
  apps/cli/tests/test_runtime_qualification.py `
  packages/evidence/tests `
  -q
```

**Exit criterion:** one real user flow yields a verifiable Transition Fragment. The process-local
`RuntimeObservationController` constructor accepts only an exact `InProcessLabEnvironment`, whose
import-time-fixed repository FastAPI app and replay service share one `LabState`. It submits one
existing `ActionEnvelope` through the environment's policy, budget, idempotency, and timeout
boundary. Before/after capture and one actual socket-free ASGI HTTP lifecycle share the environment
lock; the canonical server span's route, status, and timing come from that lifecycle, not a second
service execution. From task creation through receipt commit, public state reads fail closed; a
timed-out or otherwise uncommitted task quarantines the run until bounded settlement and explicit
cleanup or reset. The receipt binds action/source/authorization/trace/captures/evidence plus the
environment-issued execution ID, execution digest, and one-time observation-claim digest. The
environment owns that claim ledger, so a second controller cannot mint a fresh trusted trace for a
cached execution. Callers cannot supply app, capture callback, source schema, trace bytes, taint,
evidence, or before/after values. Substitution, swap, tamper, order, timeout, and secret-like
attribute controls fail closed. It opens no socket and uses no external data.

The clean-wheel `foundation qualify-runtime-observation` producer retains the canonical adapter
receipt plus an adapter-independent projection. Collection accepts it only after re-parsing the
adapter receipt and executing the same operation again with an identical semantic digest. The
result ledger then attaches the receipt digest to exactly M3-T03, M3-T04, M3-T05, M3-X01, and
SW-M3-OBSERVED; simply adding their evidence paths cannot promote them. `verify-evidence` repeats
the adapter validation and execution and rejects a proof tree that changes while it does so.

This closes the repository-side, process-local M3 observed-flow contract. It is not yet wired into
the 24→4→2→1 materialized search and clean-root compiler execution, and it does not create an
externally authenticated OTel collector or live-target receipt. Those are M4/M5 and later trust
boundaries, not claims made by M3.

The horizontal pipeline test adds three socket-free TestClient flows with caller-constructed
synthetic OTLP and state-delta evidence. Their three resulting `OBSERVED` fragments are preserved
byte-for-byte through search admission and compiler input. This proves local typed data continuity,
not application-emitted telemetry, runtime-derived state learning, authenticated telemetry
provenance, or a live target observation.

## M4 — Tiered Search Controller

**Architecture deliverables:** hypothesis schema, Ghost/Replay/Simulated tiers, beam frontier,
budget ledger, and promotion/prune gates.

**Current and planned paths**

- `packages/search/`
- `packages/mutations/`
- `workflows/world/`
- `tests/property/search/`
- `tests/integration/pipeline/`

**Acceptance command**

```powershell
uv run pytest packages/search/tests workflows/world/tests -q
```

**Exit criterion:** from 20+ Ghost worlds, promote only a small subset while retaining genuinely
useful conditions. `packages/search/` now provides the closed hypothesis decisions, four tiers,
hard promotion gates, deterministic beam frontier, immutable budget ledger, deduplication, and
diversity selection. Its focused 24-Ghost test promotes only the bounded beam and proves a model
score cannot bypass a failed gate. `workflows/world/` now carries those decisions through abstract
allocation/capture ports with hard reservation, compensating release, evidence/Oracle binding,
sibling identity isolation, and canonical `EventEnvelope`/`EventHistory` v2 history. The history is
reconstructed after replaying the exact bound search batch and policy, then binding the search
result, input and committed ledgers, and committed promotions;
each candidate is `search_blocked`, or follows `reserved` -> `allocated` -> `captured` ->
`committed`, or follows `reserved` -> `not_committed`. It is a deterministic audit projection rather
than operational callback telemetry or a wall-clock transcript. Releasing an uncommitted allocation does not claim
transactional rollback or reversal of external effects, and the self-contained hash chain provides
no external freshness attestation. The local 24 → 4 → 2 → 1 synthetic flow is implemented and
covered by a focused test; real
materialized allocation and retained release evidence are pending, so M4 is **implemented offline,
not release-certified**.

The cross-milestone pipeline additionally proves that the winning candidate retains the same three
observed fragments across the 24 -> 4 -> 2 -> 1 reduction and that its in-memory Materialized-tier
promotion record is independently rebound before compilation. Admission replays the controller from
the exact batch, input ledger, and beam policy, then independently checks provisional and committed
reservations. The winning hypothesis/state/score remain hand-authored fixtures rather than Twin-
derived ranking inputs. "Materialized-tier" here is a typed workflow outcome backed by abstract
callbacks; it is not a Docker/provider materialization claim.

## M5 — Chain Compiler

**Architecture deliverables:** fragment graph, constraint translation, candidate plan generation,
clean-room replay, and chain minimization.

**Current paths**

- `packages/compiler/`
- `tests/integration/compiler/`
- `tests/integration/pipeline/`

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

`compile_observed_promotion` now joins M4 to M5 without weakening either trust boundary. It rejects
candidate, promotion, state, evidence, policy, approval, world, goal, or fragment substitution,
revalidates unchecked model instances, takes its exact `RootState` only from the capture receipt,
requires fragment preconditions/effects to equal the action-envelope guards/effects, checks the
compiler output against every closed input, and fails if minimization drops an admitted observed
fragment. The pipeline test compiles all three M3-observed fragments into a deterministic three-step
plan requiring fresh authorization. That plan is not executed by this test; the separate M5
clean-room execution remains synthetic and uses its own mocked fragment fixture.

## M6 — Reality Anchor + Proof Bundle

**Architecture deliverables:** Reality Replay Broker, negative controls, patched-version replay,
finding status machine, and Reality Proof Bundle.

**Current paths**

- `packages/contracts/` (implemented receipt and finding status gate)
- `packages/replay/` (extension)
- `packages/evidence/`
- `packages/reporting/`
- `tests/e2e/proof_bundle/`

**Local acceptance command**

```powershell
uv run pytest packages/contracts/tests packages/replay/tests packages/evidence/tests packages/reporting/tests tests/e2e/proof_bundle -q
```

**Exit criterion:** a separate clean machine can reproduce the finding from the bundle. The M0/M1
foundation now has a canonical proof producer and local coherence verifier, including detection of
cross-artifact substitution even after manifest hashes are recomputed. The high-level CLI verifier
also re-executes the installed deterministic foundation and binds its exact semantic output,
installed source and Oracle bytes, and stable locked runtime dependency bytes. It still does not
authenticate a producer or prove execution of producer-supplied JUnit by itself. Main-branch
[CI run 31239564101](https://github.com/taipei49314/stateweaver/actions/runs/31239564101)
attested the exact proof manifest for SHA `aa60cad5be43f383810bf2e276307c4f4c9cec10`; constrained
offline verification matched its signer workflow, source ref/digest, and subject digest. That is
historical GitHub workflow provenance, not trusted Reality, and it does not qualify later commits.

The core contract now rejects the former bare `replay_run_id + REPRODUCED` promotion path. A
content-addressed `RealityReplayReceipt` models the necessary input for `REALITY_REPLAYED`, and
`PATCH_VERIFIED` additionally models an exact `BLOCKED_BY_FIX` patched receipt. It binds the
scope, target and adapter locks; chain, plan and clean root; at least two unique attempts with one
semantic signature and trace hash; deterministic `OBSERVED + VIOLATED` Oracle results; structurally
non-vacuous `OBSERVED + SATISFIED` negative-control artifacts; and an evidence-manifest digest. All
nested receipt objects are revalidated at the Finding promotion boundary, including Pydantic
instances created without normal validation. `SYNTHETIC_REPRODUCED` is explicitly non-confirmed.
The evidence package now resolves the synthetic profile from one immutable in-memory byte mapping:
it enforces exact pre-receipt coverage, hashes and parses the same bytes, and binds scope, locks,
plan/root/chain,
results, action logs, Oracles, controls, patch replay, and evidence index. The V2 profile additionally
requires every result/action-log row to execute the retained plan envelope exactly, independently
regenerates start/step/completion event semantics for primary, control, and patch lanes, preserves
the complete logical root across the vulnerable/patched differential, and accepts
`BLOCKED_BY_FIX` only at the synthetic Oracle expectation boundary. Generic `EventEnvelope` v2 now
binds all envelope metadata in a domain-separated semantic hash, while `EventHistory` verifies an
exact per-run hash chain. It also retains each control root, requires full primary-root parity, and
reconstructs `reality-control-delta-v2` from the verified raw primary/control plan and root artifact
digests plus both deterministic result signatures. Default-field omission, delta-only coherent
remints, and V1 downgrade are rejected. These self-contained histories and projections do not
provide external freshness. The resolver result is permanently non-authoritative and
non-promotable.

The reporting package now consumes only serialized receipt/manifest bytes and a single-read
in-memory artifact snapshot. It re-runs the pre-receipt resolver, emits a deterministic
`report.md` with one exact artifact link per manifest row, and creates a canonical final payload
manifest that binds the pre-receipt artifacts, pre-receipt manifest, receipt, and report. The final
manifest deliberately excludes itself; its digest is returned out of band for a future trusted
issuer. Verification reconstructs the original pre-receipt projection and report from retained
bytes, so payload omission, substitution, report-only coherent reminting, source-role reminting,
unsafe paths, and default omission fail closed. The publication result is permanently
`authoritative=False`, `promotable=False`, and `attested=False`.

This content hash and candidate resolver prove one supplied snapshot's internal coherence, not
issuer identity, authenticated retention, target/adapter source provenance, or independent
execution. The general Reality Replay Broker, trusted store acquisition, trusted
issuance/attestation, and portable clean-machine M6 reproduction workflow remain absent. The Finding validator
therefore rejects both reserved confirmed statuses. M6 is **partially implemented and not
certified**. Kind-specific typed mutation witnesses, authenticated execution provenance, and
retained source-byte resolution remain open. See `docs/architecture/M6_REALITY_RECEIPT.md` for the
exact boundary.

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

**Current local paths**

- `apps/api/`
- `apps/web/`
- `tests/e2e/public_release/`

**Local contract command**

```powershell
uv run pytest apps/api/tests tests/e2e/public_release -q
```

The web client has package-local format, lint, type-check, unit-test, and build commands. Its parser
recomputes canonical Web Crypto SHA-256 for every content-bound digest, the fixed run hashes,
manifest, and run signature before rendering.

**Exit criterion:** a new user can follow only the README to complete the stated lab, benchmark,
DAG, and replay journey. A localhost-only synthetic API and four-workspace client are implemented.
API/model closure and simulated-DOM content-digest substitution/interaction tests exist and are exercised
by the developer suite; no exact-SHA browser-qualification receipt is retained. The repo has
no Playwright dependency or reproducible desktop/mobile, keyboard, accessibility, or zero-console
browser gate. Public hosting, release-asset installation, the complete external new-user journey,
live-provider use, and retained release attestation remain pending, so M8 is **a local synthetic UI
prototype, not browser-accepted or certified**.

## Repository-wide quality gate

```powershell
uv run ruff format --check .
uv run ruff check .
uv run mypy packages adapters apps labs workflows benchmarks tests tools/candidate
uv run pytest --cov --cov-report=term-missing
cd apps/web
npm run format:check
npm run lint
npm run typecheck
npm test
npm run build
```

This quality gate validates the current repository; it does not by itself certify any M0–M8 exit.
