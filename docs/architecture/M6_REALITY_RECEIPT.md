# M6 Reality replay receipt boundary

`RealityReplayReceipt` is the typed candidate record that a future trusted broker must verify before
a `Finding` can cross from a candidate or synthetic result into a reality-confirmed state. It
replaces the former weak shape in which any caller-supplied replay ID plus `REPRODUCED` could claim
confirmation.

This is a typed causal-coherence boundary. It is not a signature, an issuer identity, a retained
artifact resolver, or a completed Reality Replay Broker.

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
   reproduce the violation.
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

## Trust boundary still open

An actor can recompute an internally coherent receipt hash. Therefore the hash detects inconsistent
substitution; it does not authenticate who executed a replay or prove that referenced artifacts
exist. A complete M6 broker must still:

- resolve every digest against immutable retained artifacts and verify the pre-receipt manifest
  contains only the evidence projection defined above;
- construct the receipt from typed replay results rather than caller claims;
- enforce scope, approval, identity, rate, write, and cleanup gates;
- bind trusted issuance or CI provenance to the receipt and proof bundle;
- reproduce the bundle on a separate clean machine.

Until those checks exist and retained public evidence passes, the repository must describe this as
a hardened promotion contract, not M6 certification.

## Verification

Focused contract tests cover legacy-field rejection, plan/root/target substitution, deterministic
run vectors, Oracle provenance/outcome, negative controls, patch comparison, content-addressed
identity, status shape, and constructed-instance revalidation:

```powershell
uv run pytest packages/contracts/tests/test_reality_receipts.py -q
```
