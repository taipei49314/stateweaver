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

The M0/M1 verifier captures the manifest and every required artifact exactly once. Hash checks,
canonical JSON parsing, causal validation, and JUnit parsing all consume those captured bytes, and
a valid result includes a domain-separated `snapshot_sha256`. Validity belongs to that immutable
byte snapshot only. A caller must not verify a mutable directory and then reopen its paths as if
they were the verified content. The path-based adapter also does not claim a race-free, no-follow
filesystem acquisition boundary; verification of an untrusted concurrently mutable tree requires
a trusted archive or snapshotting service before this verifier is called.

## Reality pre-receipt candidate

`verify_reality_pre_receipt_bundle` is the first deliberately narrow M6 resolver. It accepts only
serialized receipt/manifest bytes plus an in-memory `Mapping[str, bytes]`, snapshots each mapping
entry once, and verifies exact manifest coverage, raw-byte digests, typed schemas, and the causal
bindings among scope, target/adapter locks, plan/root/chain, replay results, action logs, logical
trace hashes, Oracle evidence, controls, patch replay, and evidence index.

This `source-backed-synthetic-v1` profile uses the contracts canonical JSON dialect: compact,
sorted-key UTF-8 with no trailing line feed. That is intentionally distinct from the M0/M1
acceptance-artifact dialect, which includes one trailing line feed. The resolver accepts no paths,
issuer claim, signature, caller `verified` flag, or model instance. Even a valid result is always
`authoritative=False` and `promotable=False`; target/adapter source digests remain claims inside
their resolved lock artifacts until a trusted store binds them to retained source bytes. Trace
event rows are content-bound by the manifest, but this profile does not independently recompute
their event attributes from an execution engine.
