# Qualification blockers

StateWeaver is not 100% complete and is not eligible for an RC or stable tag. This file separates
repository-side implementation gaps from conditions that only an independent authority or machine
can satisfy. Passing a narrower test must not change an unrelated row to PASS.

The canonical registry contains 92 required rows: 72 architecture requirements plus the 20
independent qualification gates named below. It contains assertions, evidence contracts, and test
selectors—not result statuses. A required gate with `tests: []` is unresolved, never implicitly
passing.

## Repository-side implementation gaps

| Gate | Repository posture | Still required | Replay command / close criterion |
|---|---|---|---|
| `SW-REGISTRY` | Canonical 92-row registry plus machine-derived `closure.json` and `results.json`; the verifier independently re-derives every row and the proof manifest binds both digests and the exact summary | Retain the derived ledger in an exact-merged-SHA proof whose artifact manifest receives constrained GitHub OIDC provenance | `uv run pytest packages/evidence/tests -q`; close only when the signed candidate-SHA proof covers the exact required-ID set without a missing or substituted row |
| `SW-M2-LIVE`, `SW-M2-4WAY`, `SW-M2-PROVIDERS`, `SW-M2-CLEANUP` | Real PostgreSQL, Redis, RabbitMQ, Chromium session, filesystem, and controlled-clock capture/mutate/restore now pass across four local overlapping siblings with zero residue | Exact-merged-SHA hosted run, typed admission into the proof, and retained timeout/cancel/partial-failure inventories | Run `.github/workflows/docker-compose-live.yml` on the exact merged SHA; close only when the verifier admits the retained provider, overlap, image, and cleanup receipts |
| `SW-M4-MATERIALIZED` | Production M3-derived 24-to-4-to-2-to-1 runner now materializes only the seven promoted candidates in fixed six-provider M2 worlds, binds the conserved ledger and provider receipts, caps live siblings at four, and reclaims every allocation; a local live run passed with zero residue | Exact-merged-SHA hosted Docker run and retained artifact read-back | `STATEWEAVER_RUN_REAL_DOCKER_INTEGRATION=1 uv run pytest -o 'addopts=--strict-config --strict-markers -ra' tests/integration/worlds/test_live_materialized_search.py -m docker_integration -q`; close only when the hosted receipt binds the merged SHA and cleanup inventory |
| `SW-M5-CHAIN` | Strict compiler/admission and separate clean-root replay | Execute the exact M3/M4 observed plan five times in clean roots, including patched/negative controls | `uv run pytest packages/compiler/tests tests/integration/compiler tests/integration/pipeline -q`; close only when one exact-byte chain spans M3→M5 |
| `SW-M6-ACQUIRE`, `SW-M6-TRUST`, `SW-M6-ISSUE`, `SW-M6-REPLAY`, `SW-M6-PROMOTE` | Fail-closed causal candidate receipt | Authenticated immutable acquisition, retained source resolution, server-side gates, typed result construction, revocation/freshness, trusted issuance, detached replay, and promotion policy | `uv run pytest packages/contracts/tests packages/evidence/tests packages/reporting/tests tests/e2e/proof_bundle -q`; local tests cannot close external trust/replay/issuance rows |
| `SW-M7-FAIR`, `SW-M7-PREREG`, `SW-M7-HOLDOUT`, `SW-M7-REPRO` | Deterministic prototype and proxy budget ledger | Measured equal CPU/RAM/time/request/token/cost budget, process isolation, preregistration schema, uncertainty, protected holdout, retained failures, and independent reproduction | `uv run pytest benchmarks/statechainbench/tests -q`; close only against preregistered meaningful baselines |
| `SW-M8-NEWUSER`, `SW-M8-PACKAGE`, `SW-M8-PROVIDER` | Fixed API/client and simulated-DOM contract tests | Playwright desktop/mobile/keyboard/a11y/console gate; byte-identified artifact-only install; README-led journey; allowed live provider | `npm test && npm run build` plus the future release-asset Playwright command; a simulated DOM alone cannot close M8 |

## External qualification inputs

| Gate | Missing external condition | Completion evidence |
|---|---|---|
| `SW-M6-TRUST`, `SW-M6-ISSUE`, `SW-M6-REPLAY`, `SW-M6-PROMOTE` | A producer-external authority must freeze `TRUST_POLICY`, issuer identity/key or exact OIDC subject, immutable store, scope/approval/rate/write/cleanup rules, rotation/revocation/freshness, and a separate consumer machine identity before the run | Detached broker issuance and clean-consumer receipt bound to the candidate `PAYLOAD_MANIFEST` digest |
| `SW-M7-PREREG`, `SW-M7-HOLDOUT`, `SW-M7-REPRO` | A custodian or protected evaluator outside the producer must preregister the hidden challenge commitment, baseline, equal budget, threshold, and tolerance before results | Preregistration timestamp/commitment, complete raw results, and independent reproduction receipt |
| `SW-M8-PROVIDER` | An owner-controlled allowlisted private lab and task-scoped live-provider credential | Redacted typed proposal receipt showing the model cannot alter policy/oracle verdicts |
| `SW-M8-NEWUSER`, `SW-M8-PACKAGE` | A person who did not implement the release, on a separate clean machine | Browser/CLI/screens and artifact-install receipts for the README-only journey, bound to downloaded candidate bytes |
| Post-registry public read-back (release action, not a registry ID) | Public RC hosting after every required row passes | Fresh public download, checksum/SBOM/attestation/install/journey receipt for the same merged SHA and bytes |

`SW-M3-OBSERVED` is no longer a repository implementation blocker. Its clean-wheel producer and
independent semantic re-execution admit exactly five M3 runtime rows; the receipt explicitly makes
no M4/M5, live-provider, external-collector, or release-eligibility claim.

## Promotion rule

The registry itself has no result statuses. Do not create an RC or stable tag unless the
independently derived result for every required row is `PASS`; `FAIL`, `NOT_RUN`, `BLOCKED`,
`PENDING`, `INCOMPLETE`, and missing results all fail closed. Once every row has exact-SHA evidence,
build a candidate from current `main`, verify it
with an independent downloader, complete detached qualification, and only then create an annotated
RC. Stable promotion must reuse byte-identical verified RC assets and pass a second public read-back.

No real secret value is required in this repository. Credential and trust-policy owners must supply
task-scoped inputs through the approved external environment; values must never enter git, logs, or
public artifacts.
