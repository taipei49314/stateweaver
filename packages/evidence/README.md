# StateWeaver acceptance evidence

Offline M0/M1 proof collection and verification. The collector executes no target and no test
command: it accepts the typed foundation JSON plus caller-produced JUnit files, validates their
cross-artifact causal bindings, writes an immutable per-run tree, and hashes every required file.

Use the repository-level `stateweaver foundation collect-evidence` workflow when available. The
lower-level `stateweaver-acceptance-evidence verify <run-directory>` command only verifies an
existing bundle and never executes its contents.

## Trust boundary

The lower-level verifier proves integrity and causal coherence relative to the supplied JUnit
files and caller-supplied independent provenance. A producer able to author every input can still
author a new coherent bundle. The repository-level CLI adds a stronger layer: it re-executes the
installed deterministic foundation and requires its independently derived semantic hash, installed
source digest, Oracle digest, and stable runtime dependency-byte fingerprint to match the bundle.

Neither layer proves that a malicious producer actually executed testcases whose names appear in
JUnit, nor authenticates the producer. Public release artifacts therefore require an external CI
identity/attestation; that M6 trust root is tracked separately from this offline verifier.
