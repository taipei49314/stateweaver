# Source-only pre-alpha candidate (prepared, unpublished)

Date: 2026-08-07  
Candidate tip (product / main): `5df5f57eb8a588eda420d610603f4689faaf4b05`  
Branch: `closure/stateweaver-20260807`

This document prepares a **source-only pre-alpha candidate**. It does **not**
publish a GitHub Release, PyPI package, or annotated tag. Final milestone
wording remains reserved for GPT on Monday.

Decision token: `SOURCE_ONLY_PREALPHA_CANDIDATE_PREPARED`

## What this candidate is

- A git source tree that runs the fixed in-process synthetic lab offline.
- Locally re-verified on the product tip above with:
  - `uv run stateweaver --json doctor` â†’ exit 0 (`mode=offline-in-process`)
  - `uv run stateweaver --json foundation verify` â†’ exit 0 (`accepted=true`)
  - normative JUnit suites (contracts / policy / lab / replay) â†’ exit 0
  - `foundation collect-evidence` + `foundation verify-evidence` â†’ exit 0
    (`verified=true`, `valid=true`)

## Exact limitations (non-claims)

Do **not** read this candidate as any of the following:

| Forbidden claim | Honest status |
|---|---|
| Live-provider support | Unclaimed; model/provider keys empty in CI |
| Trusted Reality Broker | Absent; receipts are internal-coherence candidates only |
| M6 clean-machine certification | Intentionally unclaimed |
| PyPI production readiness | No published package; wheel smoke is CI-local only |
| General production readiness | Pre-alpha research implementation / source preview |

Additional truthful limits already reflected in the README/traceability matrix:

- No versioned GitHub Release artifacts for visitors yet
- Materialized / live Docker Compose proof is not part of this candidate bar
- StateChainBench numbers are deterministic prototype observations, not
  equal-work public benchmark certification
- Public UX is local loopback contract/browser QA only

## Intended install path (after owner publish decision)

Until an owner publishes a tag/Release (out of Cursor scope this weekend):

```bash
git clone https://github.com/taipei49314/stateweaver.git
cd stateweaver
git checkout 5df5f57eb8a588eda420d610603f4689faaf4b05   # or later merged tip
uv sync --all-packages --group dev --locked
uv run stateweaver --json doctor
uv run stateweaver --json foundation verify
```

## Dependency queue posture

See [DEPENDENCY_QUEUE.md](DEPENDENCY_QUEUE.md) and
[DEPENDENCY_PR_VERDICTS.md](DEPENDENCY_PR_VERDICTS.md). Dependency verdicts are prepared (DEPENDENCY_QUEUE_CLOSED); merge/close actions remain with the owner.

