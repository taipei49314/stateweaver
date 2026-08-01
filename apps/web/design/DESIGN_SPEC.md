# StateWeaver public experience design specification

Status: accepted implementation specification for the M8 synthetic local experience. These
screens visualize a built-in saved-run fixture; the concept images are not proof artifacts.

## Concept sources

- `concepts/experiment-overview.png` — native size 1586 × 992
- `concepts/world-dag.png` — native size 1586 × 992
- `concepts/twin-inspector.png` — native size 1586 × 992
- `concepts/replay-evidence.png` — native size 1586 × 992

All four concepts were generated with the built-in image-generation path from one coordinated
brief: a complete, non-chat StateWeaver research instrument for an authorized local synthetic lab,
with an editorial scientific layout, evidence-first state semantics, exact four-workspace
navigation, and no arbitrary-target or command surface.

## Content lock

Persistent shell copy:

- `StateWeaver`
- `LOCAL SYNTHETIC LAB`
- `Experiment Overview`
- `World DAG`
- `Twin Inspector`
- `Replay / Evidence`
- current run ID and commit placeholder
- `READY`, `Mode: Deterministic`, `Oracle: deterministic`, `Model calls: 0`,
  `Workspace: local-lab`

Overview copy:

- `Deterministic state exploration`
- `Root captured`, `World search`, `Chain compiled`, `Clean replay`,
  `Patched comparison`, `Fixture integrity checked`
- `24 → 4 → 2 → 1`, `3 required fragments`, `5 runs matching fixture`
- `Vulnerable: VIOLATED`, `Patched: BLOCKED BY FIX`, `Controls: SATISFIED`
- `Synthetic implementation evidence`, `Not release-certified`
- `Open World DAG`, `Replay finding`

World copy:

- `Root state`, `Ghost`, `Replay`, `Simulated`, `Materialized`, `PRUNED`
- `24 → 4 → 2 → 1`, `Oracle: deterministic`, `Model calls: 0`

Twin copy:

- `Security Semantic Twin`
- `Fragment A`, `Historic session retained`
- `Fragment B`, `Async policy propagation delayed`
- `Fragment C`, `Stale authorization decision observed`
- `SYNTHETIC`, `precondition`, `typed action`, `effect`, `evidence`, `fixture-only fidelity`
- `Runtime trace`, `State delta`, `Oracle binding`

Replay copy:

- `Clean-root replay`, `Plan hash`, `Vulnerable`, `Patched`, `Controls`
- `Step 01`, `Step 02`, `Step 03`
- `VIOLATED`, `BLOCKED BY FIX`, `SATISFIED`
- `policy`, `trace`, `state delta`, `Oracle`, `Evidence manifest`, `Verify fixture manifest`

No additional claim, percentage, target, credential, production host, maturity status, or
benchmark result may be invented above the fold. Fixture provenance must remain visible.

## Design tokens

The background is cool near-black charcoal, not warm gray, cream, or pure black. Use:

```css
--ink-0: #07131c;
--ink-1: #0a1822;
--ink-2: #0e202c;
--text-strong: #f2f3ef;
--text: #c3c8c8;
--text-muted: #7f8a91;
--rule: #334650;
--rule-strong: #53636b;
--replay: #2f8cff;
--simulated: #b26df2;
--materialized: #f2f3ef;
--blocked: #f0a400;
--violation: #ff4149;
--satisfied: #45c978;
--focus: #4ca0ff;
```

Use `--violation` only for a deterministic machine-verified violation. Use `--blocked` only for
policy/prune/patched-block states. Green is limited to ready, verified, and satisfied controls.
Do not add glow, glass, or decorative gradients. A barely perceptible canvas depth fade is allowed.

## Typography and spacing

- Product wordmark and primary headings: a precise grotesk/sans stack, 600–700 weight.
- Instrument labels, hashes, IDs, controls, table values, and status chrome: monospace stack.
- Body copy: the same sans stack at 14–16 px desktop.
- Controls must declare size, weight, tracking, and line height; never rely on browser defaults.
- Desktop shell: 64 px top bar, 214 px left rail, 56 px bottom status strip, and a 330–340 px
  inspector rail where present.
- Rules are 1 px. Corners are square to 4 px. Buttons use no filled capsule shape.
- Spacing scale: 4, 8, 12, 16, 24, 32, 48 px.

## Container and component model

Use open canvases, rails, aligned timelines, lists, tables, and evidence bands. Do not turn the
screens into a bento grid or surround each section with a large rounded card.

Reusable ownership:

- `AppShell`: top provenance bar, workspace navigation, bottom status bar.
- `WorkspaceNav`: four exact destinations with selected/focus states.
- `ProvenanceRail`: immutable run, boundary, hash, seed, and Oracle information.
- `ExperimentOverview`: six-stage causal spine, world/fragment/verdict bands.
- `WorldDag`: root/tier nodes, evidence-aware edges, tier filters, selected-node inspector.
- `TwinInspector`: fragment index, transition anatomy, state-delta table, evidence rail.
- `ReplayEvidence`: synchronized vulnerable/patched lanes, controls, selected-step evidence.
- Shared `EvidenceLink`, `HashValue`, `StatusMark`, `Icon`, `FocusButton`, and `EmptyErrorState`.

All arrows, controls, state nodes, and status symbols are production-quality inline SVG with a
consistent 1.5 px outline. Do not use text glyph arrows or generic security cliché icons.

## Interaction contract

- Workspace navigation changes URL and selected view without reload.
- Overview stage selection reveals its evidence; the two primary actions navigate to World DAG and
  Replay / Evidence.
- World tier filters hide/show nodes; node selection updates the inspector; fit/reset controls work.
- Twin fragment selection updates transition anatomy, evidence, and delta.
- Replay controls select/reset/advance steps; lane and step selection updates the evidence rail.
- Evidence/hash copy controls write the displayed value and expose an accessible confirmation.
- Manifest verification recomputes the canonical SHA-256 of only the supplied local fixture
  manifest and compares it with the response-bound evidence hash; it never reads an arbitrary path
  or URL. A match is explicitly digest-only fixture integrity, not materialized proof.
- Every loading, failed-fetch, and fallback state must retain the `SYNTHETIC LOCAL LAB` boundary.
- Respect `prefers-reduced-motion`. Motion is limited to one-time causal-path drawing and state
  opacity transitions.

## Responsive contract

- Native fidelity viewport: 1586 × 992.
- At 1100 px or below, move the inspector into an explicit drawer and reduce left navigation to an
  icon-and-label compact rail.
- At 760 px or below, use a top workspace selector; stack comparison lanes while preserving step
  alignment; convert the overview spine to vertical; keep all hashes horizontally scrollable.
- No primary content clipping or page-level horizontal overflow at 390 × 844.

## Data and trust boundary

The UI consumes only the five fixed, read-only local API endpoints. It must not expose a URL input,
filesystem picker, arbitrary command, raw request composer, credential field, or mutation endpoint.
The saved fixture is synthetic implementation evidence, not materialized proof and not M8
certification. Concept image text that differs from the typed API fixture must be replaced by the
fixture value rather than fabricated for visual fidelity.

## Acceptance checklist

1. Four routes/workspaces are functional and keyboard accessible.
2. Exact boundary and provenance remain visible on every screen and error state.
3. Desktop render matches the relevant concept at 1586 × 992.
4. Mobile render works at 390 × 844 without clipped primary content.
5. The world count, fragments, replay verdicts, hashes, and evidence links come from the typed
   synthetic fixture.
6. Build, typecheck, lint, unit/component tests, and browser workflow checks pass.
7. Concept and final render are inspected together with an explicit fidelity ledger.
