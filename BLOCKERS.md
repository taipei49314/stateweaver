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
| `SW-M2-LIVE`, `SW-M2-4WAY`, `SW-M2-PROVIDERS`, `SW-M2-CLEANUP` | Four-sibling/six-provider execution plus exact-SHA producer receipt, OIDC attestation, consumer admission, and proof derivation are implemented; the admission deliberately does not close `SW-M2-LIVE` | Run the new workflow on the exact merged SHA; a separate clean-host receipt remains required for `SW-M2-LIVE` | Dispatch `.github/workflows/docker-compose-live.yml`, then candidate delivery with its run ID; close only when the independently verified proof retains the admission and no residue |
| `SW-M4-MATERIALIZED` | Eight actual-ASGI M3 observations feed the production 24-to-4-to-2-to-1 materializer; the hosted receipt/admission path binds all seven provider receipts and cleanup | New exact-merged-SHA hosted execution and candidate proof read-back | Close only when the hosted producer receipt, constrained attestation, derived M4 payload, and registry row survive fresh download verification |
| `SW-M5-CHAIN` | Exact retained M4 bytes compile eight `OBSERVED` fragments; the Docker qualifier executes five vulnerable roots, one patched boundary, and four controls through the sealed ASGI app over six immutable provider checkpoint shards, with exact policy, response, evidence, oracle, image/source, restore, and cleanup bindings | Run the new workflow on the exact merged SHA and retain its constrained attestation plus fresh candidate read-back | Dispatch `.github/workflows/docker-compose-live.yml`, then candidate delivery with its run ID; close only when the actual composite admits both `M5-X01` and `SW-M5-CHAIN` and all ten projects prove zero residue |
| `SW-M6-ACQUIRE`, `SW-M6-TRUST`, `SW-M6-ISSUE`, `SW-M6-REPLAY`, `SW-M6-PROMOTE` | Strict external policy/request/receipt contracts plus complete immutable-object, manifest, target-source, and adapter-source candidate verification; result remains hard non-authoritative/non-promotable | Producer-external authenticated store/issuer, trusted time and revocation state, detached issuance, separated clean consumer, and promotion admission | `uv run pytest packages/contracts/tests packages/evidence/tests packages/reporting/tests tests/e2e/proof_bundle -q`; local tests cannot close external trust/replay/issuance rows |
| `SW-M7-FAIR`, `SW-M7-PREREG`, `SW-M7-HOLDOUT`, `SW-M7-REPRO` | Fixed subprocess measured diagnostic with equal CPU/RAM/wall/request/token/cost/output ceilings, complete run/failure/ablation retention, and producer-internal preregistration | Protected holdout, external custodian, evaluator-owned final process-tree accounting, network isolation, and independent reproduction | `uv run pytest benchmarks/statechainbench/tests -q`; local sampling remains a diagnostic and cannot close external rows |
| `SW-M8-NEWUSER`, `SW-M8-PACKAGE`, `SW-M8-PROVIDER` | Fixed API/client plus simulated-DOM and retry-free real Chromium desktop/mobile/keyboard/WCAG/console/loading/error/empty/integrity gates | Byte-identified artifact-only server/install, README-only independent journey, manual accessibility review, and allowlisted live provider | `npm --prefix apps/web run verify:public-release`; loopback source QA cannot close M8 external rows |

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
