# M6 Reality replay receipt boundary

`RealityReplayReceipt` is the typed candidate record that a future trusted broker must verify before
a `Finding` can cross from a candidate or synthetic result into a reality-confirmed state. It
replaces the former weak shape in which any caller-supplied replay ID plus `REPRODUCED` could claim
confirmation.

This is a typed causal-coherence boundary. The evidence package now includes one narrow
`source-backed-synthetic-v1` immutable-byte resolver for this candidate record. It is not a
signature, an issuer identity, an authenticated retained-artifact store, or a completed Reality
Replay Broker.

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

The receipt closes seven substitution boundaries:

1. Scope and target: scope manifest, target lock, target identity/version, adapter lock, and anchor
   mode are immutable typed fields.
2. Plan and root: chain ID, plan ID/hash, root seed ID, and clean-root fingerprint are pinned.
3. Determinism: at least two unique replay runs must bind the exact scope, target/build, adapter,
   plan, and root. Each run binds a distinct raw replay-result digest because the serialized result
   contains its run ID; all runs share one action-log digest, semantic signature, and trace hash and
   reproduce the violation. Each trace artifact is separately raw-byte-bound by the manifest and
   carries the logical `replay_trace_hash` that must equal the replay result and receipt value.
4. Reality Oracle: every promoted Oracle result must be deterministic, `OBSERVED`, `VIOLATED`,
   evidence-backed, and part of the receipt's canonical Oracle-definition hash.
5. Negative controls: at least one typed control kind must produce deterministic, `OBSERVED`,
   `SATISFIED` Oracle results with `NOT_REPRODUCED`; exact target/adapter locks, root, and Oracle
   definitions must match while its plan, control-delta digest, and semantic signature differ from
   the primary replay. Run IDs and raw replay-result digests are globally unique across primary
   attempts, controls, and patch.
6. Patched replay: `PATCH_VERIFIED` requires the same target identity, adapter lock, plan, logical
   root seed/fingerprint, and Oracle definitions against a different target version and target lock.
   The outcome must be exactly `BLOCKED_BY_FIX`, with an observed satisfied Oracle, distinct replay
   signature, replay-result/action-log digests, and a precise failed step/code.
7. Content identity: `receipt_hash` is SHA-256 over the canonical causal projection, and
   `receipt_id` is derived from that full digest. The projection binds
   `pre_receipt_evidence_manifest_sha256`: the canonical evidence-only manifest created before the
   receipt. That manifest explicitly excludes the receipt, `finding.json`, final report,
   publication manifest, and broker attestation. A future final publication manifest may include
   all of them without being fed back into the receipt hash.

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

## Trust boundary still open

An actor can recompute an internally coherent receipt hash. Therefore the hash detects inconsistent
substitution; it does not authenticate who executed a replay. The current in-memory resolver proves
that the supplied candidate bytes exist and agree within one snapshot, but it does not prove where
those bytes came from. A complete M6 broker must still:

- acquire the bytes from an immutable authenticated store without a mutable-path race;
- resolve target/adapter source digests against retained source bytes rather than trust the values
  recorded inside their lock artifacts;
- independently reconstruct event-level trace semantics; current event rows are content-bound but
  only their logical replay trace hash is cross-checked against the replay result;
- construct the receipt from typed replay results rather than caller claims;
- enforce scope, approval, identity, rate, write, and cleanup gates;
- bind trusted issuance or CI provenance to the receipt and proof bundle;
- reproduce the bundle on a separate clean machine.

Until those checks exist and retained public evidence passes, the repository must describe this as
a hardened promotion contract, not M6 certification.

## Verification

Focused contract tests cover legacy-field rejection, plan/root/target substitution, deterministic
run vectors, Oracle provenance/outcome, negative controls, patch comparison, content-addressed
identity, status shape, and constructed-instance revalidation. Evidence resolver tests additionally
cover single-read snapshots, exact coverage/role closure, digest and logical-trace substitution,
canonical encoding, unsafe paths, controls, and patch replay:

```powershell
uv run pytest packages/contracts/tests/test_reality_receipts.py -q
uv run pytest packages/evidence/tests/test_reality_bundle.py -q
```
