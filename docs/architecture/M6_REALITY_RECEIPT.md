# M6 Reality replay receipt boundary

`RealityReplayReceipt` is the typed candidate record that a future trusted broker must verify before
a `Finding` can cross from a candidate or synthetic result into a reality-confirmed state. It
replaces the former weak shape in which any caller-supplied replay ID plus `REPRODUCED` could claim
confirmation.

This is a typed causal-coherence boundary. The evidence package now includes one narrow
`source-backed-synthetic-v2` immutable-byte resolver for this candidate record. It is not a
signature, an issuer identity, an authenticated retained-artifact store, or a completed Reality
Replay Broker.

No producer-external `TRUST_POLICY`, trusted issuer, immutable authenticated store, or separated
consumer identity is configured in this repository. Repository code and GitHub OIDC provenance
cannot create that trust root for themselves; M6 remains blocked until an independent authority
freezes the policy before evidence production and a separate clean consumer completes replay.

## Finding state machine

| Finding status | Receipt shape |
| --- | --- |
| `CANDIDATE` | No reality receipt |
| `CHAIN_COMPILED` | No reality receipt |
| `SYNTHETIC_REPRODUCED` | No reality receipt; never a confirmed finding |
| `REALITY_REPLAYED` | Reserved; coherent receipt is necessary but rejected until broker attestation exists |
| `PATCH_VERIFIED` | Reserved; coherent receipt + exact patch block are necessary but rejected until broker attestation exists |
| `REJECTED` | No reality receipt |

Legacy `replay_run_id` and `replay_outcome` fields are not accepted by `Finding`. This is an
intentional pre-alpha schema break: historical data cannot silently retain confirmation authority.
`Finding`, `NegativeControl`, and `PatchedVersionReplay` therefore emit schema version `2.0`.
Version `1.0` confirmed findings must be treated as unconfirmed input: only a broker that resolves
complete retained evidence may issue a new receipt and select the corresponding `2.0` status.

## Causal bindings

The receipt and V2 resolver close eight substitution boundaries:

1. Scope and target: scope manifest, target lock, target identity/version, adapter lock, and anchor
   mode are immutable typed fields.
2. Plan and root: chain ID, plan ID/hash, root seed ID, and clean-root fingerprint are pinned. Each
   result step/action-log row must execute the corresponding retained `ReplayPlan` envelope exactly;
   sharing only a plan ID is insufficient. Patched replay must preserve the primary random seed,
   controlled clock, capture, and adapter versions while changing only the target build identity.
3. Determinism: at least two unique replay runs must bind the exact scope, target/build, adapter,
   plan, and root. Each run binds a distinct raw replay-result digest because the serialized result
   contains its run ID; all runs share one action-log digest, semantic signature, and trace hash and
   reproduce the violation. Each trace artifact is separately raw-byte-bound by the manifest and
   carries the logical `replay_trace_hash` that must equal the replay result and receipt value.
4. Event semantics: the `stateweaver.replay-step-events.v1` algorithm regenerates a typed
   start/step/completion vector from every primary, control, and patched `ReplayRunResult`. Each step
   event binds action identity/sequence/policy, trace and envelope hashes, fingerprints,
   observations, Oracles, evidence, and failure semantics. Exact comparison rejects event omission,
   reordering, lane substitution, or coherent narrative reminting. Its semantic hash excludes only
   run occurrence identity so deterministic primary attempts remain comparable.
5. Reality Oracle: every promoted Oracle result must be deterministic, `OBSERVED`, `VIOLATED`,
   evidence-backed, and part of the receipt's canonical Oracle-definition hash.
6. Negative-control causal projection: at least one enumerated control label must produce
   deterministic, `OBSERVED`, `SATISFIED` Oracle results with `NOT_REPRODUCED`; exact target/adapter
   locks, Oracle definitions, and a separately retained control root are required. The control root
   must equal the primary logical root in full, including random seed, controlled clock, capture,
   and adapter versions. `reality-control-delta-v2` is reconstructed from the exact verified
   primary/control plan and root artifact digests plus both deterministic result signatures; a
   byte-exact comparison rejects omitted dimensions, default-field omission, schema downgrade, or
   coherent delta-only reminting. The enum `kind` remains a producer-authored classification and is
   explicitly unattested; no current adapter-issued witness proves that the label describes the
   actual plan mutation. Run IDs and raw replay-result digests are globally unique across primary
   attempts, controls, and patch.
7. Patched replay: `PATCH_VERIFIED` requires the same target identity, adapter lock, plan, logical
   root seed/fingerprint, and Oracle definitions against a different target version and target lock.
   The outcome must be exactly `BLOCKED_BY_FIX`, with an observed satisfied Oracle, distinct replay
   signature, replay-result/action-log digests, and a precise failed step/code. The current synthetic
   profile derives the block only from `ORACLE_EXPECTATION_MISMATCH`; unrelated execution failures
   cannot be relabeled `BLOCKED_BY_FIX`.
8. Content identity: `receipt_hash` is SHA-256 over the canonical causal projection, and
   `receipt_id` is derived from that full digest. The projection binds
   `pre_receipt_evidence_manifest_sha256`: the canonical evidence-only manifest created before the
   receipt. That manifest explicitly excludes the receipt, `finding.json`, final report,
   publication manifest, and broker attestation. The reporting package now layers a final
   publication-candidate manifest over the exact pre-receipt artifacts, pre-receipt manifest,
   receipt, and deterministic report without feeding any of them back into the receipt hash.

The `Finding` validator reconstructs and validates the nested receipt from ordinary data before it
checks chain, Oracle-set, and status coherence. This prevents a nested Pydantic instance created via
`model_construct()` from bypassing that validation path. Pydantic's unsafe `model_construct()` and
`model_copy(update=...)` APIs can still manufacture unchecked in-memory objects, so receipt and
Finding model instances are never themselves trust credentials: every consumer must accept and
revalidate serialized JSON/dict input. The future broker API must do the same. The validator then
rejects confirmed promotion because no trusted broker attestation exists yet; a self-issued, fully
rehashed receipt remains only a candidate record.

`verify_reality_pre_receipt_bundle` accepts only canonical serialized receipt/manifest bytes and an
in-memory `Mapping[str, bytes]`. It snapshots every mapping value once and uses the same bytes for
digest verification and typed parsing. It enforces exact role/path coverage and rejects receipt,
Finding, report, publication-manifest, and attestation paths from the pre-receipt projection. The
profile uses compact sorted-key contracts JSON with no trailing line feed. Its result exposes a
domain-separated snapshot hash, but its `authoritative` and `promotable` properties are permanently
false; it is not accepted by the `Finding` promotion gate.

`build_reality_publication` and `verify_reality_publication` add a deterministic, in-memory
reporting boundary. The builder snapshots caller artifacts once, reruns the pre-receipt resolver,
and derives `report.md` plus a canonical payload manifest. Every report row links to exact retained
bytes and distinguishes a receipt-carried raw digest from a typed causal-verifier binding. The
payload manifest never lists itself, and its exact digest is returned out of band. The verifier
reconstructs the pre-receipt manifest, reruns causal verification, and byte-rederives both report
and final manifest. These APIs accept no filesystem path, issuer assertion, clock, random ID, or
caller-supplied verification result. Their outputs permanently expose `authoritative=False`,
`promotable=False`, `attested=False`, and `control_kind_semantics_attested=False`.

The generic event boundary is independently upgraded to `EventEnvelope`/`EventHistory` schema
`2.0`. `payload_hash` remains a payload-only digest, while a domain-separated `semantic_hash` binds
schema, event type, experiment/run/world, actor, trace, timestamp, sequence, previous hash, and
payload digest. `EventHistory` verifies exact sequence, context, time monotonicity, chain head, and
history hash. This self-contained chain detects partial mutation and splicing; it cannot prove
freshness against a producer that can fully remint history without a trusted checkpoint.

## Trust boundary still open

An actor can recompute an internally coherent receipt hash. Therefore the hash detects inconsistent
substitution; it does not authenticate who executed a replay. The current in-memory resolver proves
that the supplied candidate bytes exist and agree within one snapshot, but it does not prove where
those bytes came from. A complete M6 broker must still:

- acquire the bytes from an immutable authenticated store without a mutable-path race;
- resolve target/adapter source digests against retained source bytes rather than trust the values
  recorded inside their lock artifacts;
- construct the receipt from typed replay results rather than caller claims;
- enforce scope, approval, identity, rate, write, and cleanup gates;
- bind trusted issuance or CI provenance to the receipt and proof bundle;
- reproduce the bundle on a separate clean machine.

The V2 semantic trace proves that the supplied event narrative is the deterministic projection of
the supplied typed replay result. The V2 control delta likewise proves an exact artifact-derived
primary/control projection, but not that an authenticated execution engine produced either result,
not wall-clock OTLP binding, and not the truth of a producer-selected control-kind label. A future
typed mutation witness must close that semantic classification boundary.

Until those checks exist and retained public evidence passes, the repository must describe this as
a hardened promotion contract, not M6 certification.

## Verification

Focused contract tests cover legacy-field rejection, plan/root/target substitution, deterministic
run vectors, Oracle provenance/outcome, negative controls, patch comparison, content-addressed
identity, status shape, and constructed-instance revalidation. Evidence resolver tests additionally
cover single-read snapshots, exact coverage/role closure, digest and logical-trace substitution,
canonical encoding, unsafe paths, control-root parity, delta V1 downgrade, delta-only coherent
reminting, the explicitly unattested kind boundary, and patch replay:

```powershell
uv run pytest packages/contracts/tests/test_reality_receipts.py -q
uv run pytest packages/contracts/tests/test_event_history.py -q
uv run pytest packages/evidence/tests/test_semantic_trace.py packages/evidence/tests/test_reality_bundle.py -q
uv run pytest packages/reporting/tests -q
```
