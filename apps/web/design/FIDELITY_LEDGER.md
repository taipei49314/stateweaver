# M8 visual fidelity ledger

Status: local browser acceptance evidence for the saved synthetic fixture. The concept images and
screenshots are presentation references, not release evidence or proof of a live replay.

## Compared artifacts

- Accepted concept: `concepts/experiment-overview.png` at 1586 x 992.
- Final desktop render: `output/playwright/stateweaver-final/overview-content-verified.png` at
  1586 x 992, after enabling response-content SHA-256 validation.
- Final desktop route renders were also inspected for World DAG, Twin Inspector, and Replay /
  Evidence.
- Final mobile renders were inspected at 390 x 844 for all four routes.

The accepted overview concept and the final overview render were opened together at original
resolution after implementation.

## Preserved from the accepted direction

- Dark scientific-instrument shell, cool near-black palette, thin rules, and restrained status
  colors.
- Persistent product identity, explicit `LOCAL SYNTHETIC LAB` boundary, four workspaces, and a
  deterministic status strip.
- Six-stage causal spine, `24 -> 4 -> 2 -> 1` reduction, three required fragments, and visible
  verdict hierarchy.
- Evidence-first World DAG, Twin transition anatomy, synchronized replay lanes, and provenance
  details close to every claim.
- Compact editorial grid rather than a dashboard of decorative cards.

## Deliberate truth-driven deviations

- Concept wording `Evidence verified` became `Fixture integrity checked` because the bundled data
  is a deterministic fixture, not independently materialized evidence.
- Twin provenance is `SYNTHETIC`, never `OBSERVED`.
- Repeated-run language is `matching fixture`, never an unsupported claim of identical real runs.
- Manifest verification recomputes canonical Web Crypto SHA-256 over the response-bound fixture
  manifest. The UI labels the result `digest-only fixture`, not release proof.
- Every displayed digest is content-bound fixture data. Placeholder-shaped counters were rejected.
- The World DAG uses a readable responsive node grid with exact typed edges and a selected-node
  inspector. It does not fabricate illustrative paths that are absent from the API.
- Mobile Twin fragment navigation becomes a one-column index so semantic labels remain readable.

## Browser acceptance

- The built-in in-app browser was attempted first, but no browser instance was available.
- Local real-browser QA therefore used the Playwright CLI against the fixed loopback API and Vite
  client only.
- Desktop viewport: 1586 x 992; all four routes rendered without page-level horizontal overflow.
- Mobile viewport: 390 x 844; all four routes reported `scrollWidth === innerWidth`.
- World filters and node selection updated actual data, including deterministic fallback to the
  first visible node when the selected tier was hidden; Twin fragment selection changed the trace;
  replay next/reset controls changed the selected step.
- All endpoint responses passed exact fixture-shape, relationship, and canonical content-digest
  validation in the browser. Canonical fixture manifest verification reported a SHA-256 match.
- Final browser console result: 0 errors and 0 warnings.

This ledger closes local visual fidelity only. It does not claim public deployment, production
traffic, release certification, process isolation, or GitHub artifact attestation.
