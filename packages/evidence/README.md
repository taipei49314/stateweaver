# StateWeaver acceptance evidence

Offline acceptance-proof collection and verification. The collector executes no target and no test
command: it accepts the typed foundation JSON plus caller-produced JUnit files, validates their
cross-artifact causal bindings, writes an immutable per-run tree, and hashes every required file.
It derives eight M0/M1 qualification receipts from the validated seven-layer root plus exact JUnit
testcase identities. It also derives seven local-deliverable receipts covering 22 repo-controlled
M3–M7 rows from exact passing identities, canonical registry statements and roles, and source/run
bindings. The verifier independently regenerates every derived receipt; changing one and rehashing
the file manifest is insufficient to validate it. M0-C07 is optional and remains `NOT_RUN` unless
the collector receives a separately produced, valid clean-wheel package-install receipt.

With that clean-wheel receipt, the local acceptance projection is 53 `PASS`, zero `NOT_RUN`, and
39 `BLOCKED`. The M3–M7 receipts use status `LOCAL_IMPLEMENTATION_QUALIFIED` and permanently state
`authoritative=false`, `promotable=false`, `release_eligible=false`, and
`exit_criterion_satisfied=false`. They qualify only the named local implementation surfaces; they
do not satisfy live-provider, materialized-runtime, trusted-broker, independent-benchmark, or
external-new-user gates.

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
bindings among scope, target/adapter locks, plan/root/chain, replay results, action logs, semantic
trace events, Oracle evidence, controls, patch replay, and evidence index. Every result must execute
the retained plan envelopes exactly. For primary, control, and patch lanes, the resolver rebuilds a
V2 start/step/completion event vector from the typed result and action log and requires byte-parsed
trace semantics to match it exactly.

This `source-backed-synthetic-v2` profile uses the contracts canonical JSON dialect: compact,
sorted-key UTF-8 with no trailing line feed. That is intentionally distinct from the M0/M1
acceptance-artifact dialect, which includes one trailing line feed. The resolver accepts no paths,
issuer claim, signature, caller `verified` flag, or model instance. Even a valid result is always
`authoritative=False` and `promotable=False`; target/adapter source digests remain claims inside
their resolved lock artifacts until a trusted store binds them to retained source bytes. Event
reconstruction proves agreement with the supplied typed replay result, not that an authenticated
execution engine produced that result. For every negative control, the manifest now retains a
separate `CONTROL_ROOT` and the resolver requires it to equal the primary logical root in full,
including random seed, controlled clock, capture, and adapter versions. It then reconstructs a
`reality-control-delta-v2` artifact from the exact verified primary/control plan and root artifact
digests plus both deterministic result signatures, and requires byte-exact equality. This also
rejects default-field omission, arbitrary caller-written state paths, and coherent delta-only
reminting. The enumerated control `kind` remains a producer-authored classification: the V2
artifact fixes `kind_semantics_attested=false`, and the verification result permanently exposes
`control_kind_semantics_verified=False` until an adapter-issued typed mutation witness exists.
