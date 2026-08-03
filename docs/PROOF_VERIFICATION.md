# Verifying a StateWeaver foundation proof

The M0/M1 proof has three independent layers:

1. `artifact-manifest.sha256` closes the exact bundle file set and hashes every artifact.
2. `stateweaver foundation verify-evidence` validates the causal model, re-executes the installed
   deterministic foundation, and binds installed source, Oracle, and runtime dependency bytes.
3. The main-branch GitHub workflow uses `actions/attest@v4` to sign the exact-file manifest with
   GitHub Actions OIDC provenance after both Python matrix jobs pass.

The third layer is configured but is not evidence until a public main-branch workflow has actually
completed and its attestation has been retained.

## Local semantic verification

Download the `acceptance-proof` artifact, install the matching locked StateWeaver wheels, and run:

```console
stateweaver foundation verify-evidence \
  runs/ci-RUN_ID-ATTEMPT \
  --repository-marker COMMIT_SHA
```

The command does not execute content from the bundle. It runs only StateWeaver's fixed local
synthetic foundation under the process-local network guard, then compares the independently
derived semantic and installed-byte fingerprints. The verifier reads the manifest and every
required artifact once; hashing, canonical parsing, causal checks, and JUnit parsing use those same
captured bytes. A successful JSON response includes `snapshot_sha256`, which identifies the run ID,
manifest, and complete captured artifact set with length-delimited domain separation.

That result describes the captured bytes, not the future contents of the directory path. Do not
reopen files from a mutable directory and treat them as verified. The local path adapter is not a
race-free no-follow acquisition service; first obtain a trusted immutable archive/snapshot when the
producer can concurrently replace paths, then retain or consume exactly the verified bytes.

## GitHub workflow provenance

From the downloaded run directory:

```console
gh attestation verify artifact-manifest.sha256 -R OWNER/REPOSITORY
```

GitHub documents the attestation permissions, OIDC signing model, and verification command in
[Using artifact attestations to establish provenance for builds](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).
The repository uses the current unified official
[`actions/attest`](https://github.com/actions/attest) action, not the legacy wrapper.

The workflow grants write/OIDC permissions only to a separate main-push attestation job. Pull
request test jobs retain read-only permissions and never receive the attestation authority.

## Remaining trust boundary

Before a successful attested public run, the proof establishes only local integrity and
deterministic re-execution. After such a run, the attestation identifies the GitHub workflow,
repository, commit, and triggering event that produced the manifest. Reviewers must still inspect
the referenced workflow and source commit; an attestation proves provenance, not that the code is
correct.
