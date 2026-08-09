# Historical baseline narrative at `aa60cad`

This is a narrative snapshot of operator-observed work on 2026-08-09, including failures. It is not
an immutable qualification receipt: it lacks a complete timestamped stdout/stderr transcript,
per-command artifact hashes, and before/after process and resource inventories. Later runs do not
rewrite this historical account. The structured narrative is
[baseline-aa60cad.json](baseline-aa60cad.json).

## Result

- The operator recorded live `main`, fresh-clone HEAD, tested SHA, and source SHA as
  `aa60cad5be43f383810bf2e276307c4f4c9cec10`.
- The command ledger records exit code 0 for Python formatting, lint, strict typing, doctor,
  foundation verification, and a pytest summary of `711 passed, 1 deselected` at `86.49%`
  coverage. The underlying command logs are not retained here.
- The command ledger records exit code 0 for web formatting, lint, and typecheck. The first
  `npm test` failed before executing tests
  because the Windows Vitest fork worker did not start within 60 seconds. The checked sequence
  therefore did not run `npm run build` on this first attempt.
- `npm audit` reported one high-severity transitive `nanoid` advisory at this baseline.
- The existing M2 workflow was dispatched for the first time and failed at the Compose health
  parser: [run 31306321481](https://github.com/taipei49314/stateweaver/actions/runs/31306321481).

## Provenance verification

The retained `acceptance-proof` and `acceptance-proof-attestation` artifacts from
[CI run 31239564101](https://github.com/taipei49314/stateweaver/actions/runs/31239564101)
were downloaded outside the repository. Offline verification constrained all of the following:

- repository: `taipei49314/stateweaver`;
- signer workflow: `taipei49314/stateweaver/.github/workflows/ci.yml`;
- source digest: `aa60cad5be43f383810bf2e276307c4f4c9cec10`;
- source ref: `refs/heads/main`;
- subject: `artifact-manifest.sha256`;
- subject SHA-256: `c275c83431e0ae94c8331d1f7998cd3d1956de5126e00f16f497fff378eaf01f`.

This proves workflow provenance for that exact manifest. It does not prove algorithm correctness,
trusted Reality, independent execution, or release qualification.

## Honest baseline gate summary

| Area | Baseline result | Blocking fact |
|---|---|---|
| Phase 0 | `FAIL` | First web test run failed; other listed commands recorded exit code 0, without a complete Phase-0 receipt |
| M0/M1 | `FAIL` | Strong local proof existed, but no exact requirement registry or detached audit |
| M2 | `FAIL` | First live workflow failed; adapter was still a synthetic JSON bridge |
| M3 | `FAIL` | The pipeline constructed its own OTLP/evidence/state deltas |
| M4/M5 | `FAIL` | In-memory materialization; observed plan not executed in clean roots |
| M6 | `BLOCKED` | Broker implementation gaps plus no external trust root/issuer/consumer |
| M7 | `BLOCKED` | Unequal proxy budget plus no custodian/preregistration/reproduction |
| M8 | `FAIL` | No release-asset browser journey or independent new-user receipt |
| Stable release | `BLOCKED` | Global and external gates were not satisfied |

This narrative does not claim trusted or external evidence, complete scope closure, or that an
unrun gate passed. Its command observations cannot qualify a later SHA.
