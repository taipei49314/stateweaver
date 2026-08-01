# StateWeaver CLI

This package verifies the local, synthetic StateWeaver foundation entirely in process. It has no
network client, subprocess, arbitrary-command, or arbitrary-target execution capability.

## Usage

After installation, run:

```console
stateweaver --json doctor
stateweaver --json foundation verify
stateweaver foundation collect-evidence --help
stateweaver foundation verify-evidence --help
```

The command writes one compact JSON object to standard output. It verifies five clean-root
vulnerable replays, runs the identical typed action plan in patched mode, and exercises the
synthetic lab's negative controls. Its exit status is zero only when every acceptance condition
for these replay-differential scenarios holds; it does not claim to verify every StateWeaver
subsystem.

`--json doctor` reports the CLI version, `offline-in-process` mode, `auth_required: false`, and
whether each required local component is importable. Both successful commands write exactly one
JSON object to standard output. A successful verification or doctor invocation exits `0`; an
acceptance failure exits `1`; invalid command-line arguments exit `2`. JSON output never includes
credentials because this CLI has no authentication or network capability. A runtime verification
error has the stable JSON shape `{"accepted":false,"error":{"code":"verification_error"}}`
and exits `1`.

`foundation collect-evidence` runs that same local differential once, binds four named JUnit XML
inputs (`contracts`, `policy`, `lab`, and `replay`), writes an immutable proof directory, and then
self-verifies its hashes and causal links. `foundation verify-evidence` never executes bundle
content; it independently re-runs the installed, fixed local foundation under the process-local
network guard and requires the resulting semantic hash, installed source/Oracle digests, and stable
runtime dependency-byte fingerprint to match the bundle. Neither command accepts a target,
credential, or arbitrary command.
Collection requires `--started-at` with an absolute timestamp captured immediately before the
first normative JUnit command, so the retained run window covers both the tests and differential.
This establishes local hash, causal, installed-runtime, and deterministic re-execution coherence;
it does not authenticate a bundle producer or prove that a fully malicious producer executed the
named JUnit cases. Public CI artifacts require a separate external attestation.

The repository workspace includes this package, so the same commands can be run from the
repository root as `uv run stateweaver ...` after the locked workspace sync.

## Development checks

```console
uv run pytest apps/cli/tests
uv run ruff check apps/cli
uv run mypy apps/cli/src
```
