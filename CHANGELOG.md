# Changelog

All notable changes are recorded here. The project has no published tag or GitHub Release yet.

## Unreleased

### Added

- A canonical, fail-closed 92-row acceptance registry: 72 architecture requirements plus 20
  independent qualification gates, without self-declared status fields.
- Repository-relative executable test selectors, exact unresolved-selector closure, and a pinned
  canonical resource digest for the registry.
- A proof-bound 92-row result ledger derived from exact passing JUnit identities and retained
  evidence paths, with non-local gates held `BLOCKED` and independent verifier re-derivation.
- Seven registry-bound, non-promotable local-deliverable receipts covering 22 repo-controlled
  M3–M7 rows, with exact JUnit and source bindings and explicit exit-criterion limitations.
- A process-local runtime observation controller that issues its own trace and derives state deltas.
- Candidate payload, checksum, SBOM, receipt, reproducibility, and fresh-downloader tooling.
- A historical fresh-clone narrative snapshot and explicit qualification blocker records.

### Fixed

- Docker Compose v2/v5 single-service JSON compatibility and Windows Linux-engine execution without
  loading user Docker configuration.
- Synthetic Docker healthcheck stability during four concurrent volume `fsync` operations.
- Vitest worker startup portability on Windows/constrained runners.
- The transitive `nanoid` advisory reported by the baseline lockfile.
- Stale proof-attestation and closure documentation.

### Security

- Registry, observation, and candidate inputs reject unknown fields, unsafe paths, substitutions,
  incomplete coverage, and caller-supplied trust claims.
- M6, M7, M8, and stable-release status remains fail closed pending the documented implementation
  and external qualification evidence.
