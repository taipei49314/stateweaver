# Changelog

All notable changes are recorded here. The project has no published tag or GitHub Release yet.

## Unreleased

### Added

- A canonical, fail-closed 92-row acceptance registry: 72 architecture requirements plus 20
  independent qualification gates, without self-declared status fields.
- Repository-relative executable test selectors, exact unresolved-selector closure, and a pinned
  canonical resource digest for the registry.
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
