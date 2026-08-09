# Verifying a StateWeaver foundation proof

The M0/M1 proof has three independent layers:

1. `artifact-manifest.sha256` closes the exact bundle file set and hashes every artifact.
2. `stateweaver foundation verify-evidence` validates the causal model, re-executes the installed
   deterministic foundation, and binds installed source, Oracle, and runtime dependency bytes.
3. The main-branch GitHub workflow uses `actions/attest@v4` to sign the exact-file manifest with
   GitHub Actions OIDC provenance after both Python matrix jobs pass.

The third layer has one retained public baseline example:
[main-branch run 31239564101](https://github.com/taipei49314/stateweaver/actions/runs/31239564101)
completed at source SHA `aa60cad5be43f383810bf2e276307c4f4c9cec10`. Its attestation is historical
evidence for that exact subject and source only; it does not qualify a later commit or release.

## Historical exact-source rebuild and semantic verification

The retained run did **not** publish matching StateWeaver wheels. Rebuild the verifier from the
attested source SHA and its checked-in lock on the producer operating system and Python ABI, then
download the proof artifact and run:

```console
git clone https://github.com/taipei49314/stateweaver.git
cd stateweaver
git checkout --detach aa60cad5be43f383810bf2e276307c4f4c9cec10
uv sync --all-packages --group dev --locked
gh run download 31239564101 \
  --repo taipei49314/stateweaver \
  --name acceptance-proof \
  --dir ../acceptance-proof
uv run stateweaver foundation verify-evidence \
  ../acceptance-proof/runs/ci-31239564101-1 \
  --repository-marker aa60cad5be43f383810bf2e276307c4f4c9cec10
```

Do not substitute the current checkout, an unpinned dependency resolution, or wheels from another
build. A future candidate must carry its own exact source/lock inputs and installable artifacts in
the candidate payload; verify those bytes with `tools/candidate/verify.py` before invoking the
candidate's verifier. The historical artifact alone is insufficient to reconstruct an arbitrary
producer runtime.

The command does not execute content from the bundle. It runs only StateWeaver's fixed local
synthetic foundation under the process-local network guard, then compares the independently
derived semantic and installed-byte fingerprints. The verifier reads the manifest and every
required artifact once; hashing, canonical parsing, causal checks, and JUnit parsing use those same
captured bytes. A successful JSON response includes `snapshot_sha256`, which identifies the run ID,
manifest, and complete captured artifact set with length-delimited domain separation.

The installed-runtime fingerprint deliberately includes platform-specific dependency bytes, such
as compiled wheels. A proof produced on Linux therefore fails the high-level provenance check on a
Windows installation even when the bundle, source, and Oracle are identical. That failure is
reported as `artifact provenance does not match independent expectations`; it is distinct from
`artifact bundle is not causally coherent`. Use the exact producer platform for deterministic
re-execution, and use the manifest hash plus GitHub attestation below for portable provenance
verification.

That result describes the captured bytes, not the future contents of the directory path. Do not
reopen files from a mutable directory and treat them as verified. The local path adapter is not a
race-free no-follow acquisition service; first obtain a trusted immutable archive/snapshot when the
producer can concurrently replace paths, then retain or consume exactly the verified bytes.

## GitHub workflow provenance

Download both `acceptance-proof` and `acceptance-proof-attestation`. For the retained baseline,
verify the offline bundle while constraining repository, signer workflow, source digest, and source
ref (replace the paths with the download locations):

```console
gh attestation verify artifact-manifest.sha256 \
  --bundle ../acceptance-proof-attestation/attestation.json \
  --repo taipei49314/stateweaver \
  --signer-workflow taipei49314/stateweaver/.github/workflows/ci.yml \
  --source-digest aa60cad5be43f383810bf2e276307c4f4c9cec10 \
  --source-ref refs/heads/main
```

The verified subject digest for that baseline is
`c275c83431e0ae94c8331d1f7998cd3d1956de5126e00f16f497fff378eaf01f`. A candidate
or release verifier must substitute its own exact merged SHA and must reject any mismatch.

GitHub documents the attestation permissions, OIDC signing model, and verification command in
[Using artifact attestations to establish provenance for builds](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).
The repository uses the current unified official
[`actions/attest`](https://github.com/actions/attest) action, not the legacy wrapper.

The workflow grants write/OIDC permissions only to a separate main-push attestation job. Pull
request test jobs retain read-only permissions and never receive the attestation authority.

## Remaining trust boundary

An attestation identifies the GitHub workflow, repository, commit, triggering event, and subject
that produced the manifest. Reviewers must still inspect the referenced workflow and source
commit; an attestation proves provenance, not that the code is correct. It is not a trusted Reality
Broker signature, independent consumer identity, or M0-M8 certification.
