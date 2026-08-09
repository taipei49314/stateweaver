# StateWeaver fixed Docker Compose adapter

This package is a local-only M2 adapter boundary for one repository-owned synthetic Compose
definition. It accepts no command, environment, image, Compose path, credential, or target address
from a caller. At runner construction, the production boundary resolves Docker (and Windows
`docker-compose`) once from the operator-controlled host `PATH`, rejects missing, relative,
non-file, or non-executable results, and thereafter invokes the resolved absolute path from the
fixed fixture directory with `shell=False`. Host `PATH` and the resolved installation directories
are therefore explicit construction-time trust inputs; later caller changes to `PATH` or cwd cannot
redirect an admitted argv. The child receives only a derived executable path, the fixed local Linux
engine endpoint, and required Windows system variables; user Docker configuration variables are not
forwarded. The Compose network is internal. Health parsing accepts only Compose v2's one-row array
or Compose v5's one-row object and then applies the same strict identity checks.

Each fixed child runs in an isolated process group with a 60-second deadline and a one-MiB cap on
each output stream. Any read, write, wait, cancellation, timeout, or overflow failure aborts the
tree and reaps the direct child while preserving the authoritative exception. POSIX aborts apply a
fixed grace interval and then signal the process group with `SIGKILL` even when its leader already
exited. Windows aborts invoke the absolute `%SystemRoot%\\System32\\taskkill.exe /T /F` through a
closed argv before reaping the leader. The hosted observation also rejects surviving Docker/Compose
clients, fixed-project or fixture-path processes, and `swm2` Docker resources.

The lifecycle and namespace boundary is covered with a deterministic stateful process emulator. The
fixed in-container bridge exports a canonical archive for six synthetic components, binds each
component hash to the inspected image identity, stages a complete generation before one atomic
generation-pointer switch, and re-exports after fork or restore for byte-level identity checking.
Tests also cover four disjoint logical siblings, forged manifests and handles, cancellation cleanup,
mutable-image-tag races, strict process replies, and wheel resource packaging. A short synchronous
registry critical section reserves identities and protects immutable records; a separate lifecycle
gate per live world serializes same-world snapshot/restore/destroy while allowing unrelated worlds
to enter fixed runner operations concurrently. Issued environment and snapshot identities have
fixed process-lifetime caps, and compensating `down` gets its own two-second boundary. A cancelled
destructive operation retains exact ownership so a caller can retry restore or destroy; it never
silently revives or reassigns the project.

The repository owns the fixture Dockerfile and pins its base by digest. From the repository root,
the only intended image bootstrap is:

```powershell
docker build --tag stateweaver-synthetic-demo:local adapters/environments/docker_compose/src/stateweaver/adapters/docker_compose
```

During 2026-08-09 development, that image build and the following explicit four-sibling test were
observed on a local Docker Desktop host:

```powershell
$env:STATEWEAVER_RUN_DOCKER_INTEGRATION = "1"
uv run pytest -o 'addopts=--strict-config --strict-markers -ra' tests/integration/worlds/test_live_docker_compose.py -m docker_integration -q
```

This was an ephemeral operator-local diagnostic. No immutable exact-SHA log, artifact inventory,
or qualification receipt from it is retained in this repository. The 2026-08-09 baseline GitHub
run failed before the compatibility fixes and is retained as failure evidence; an exact-merged-SHA
rerun is required. The adapter proves a synthetic archive protocol, not live PostgreSQL, Redis,
queue, browser-session, filesystem-provider, or controlled-clock capture.
All six capabilities therefore remain truthfully advertised as `PARTIAL`.

The default suite requires four emulator siblings to overlap at runner barriers. During the
ephemeral diagnostic, the explicit `docker_integration` test was observed to complete four local
Compose siblings and leave zero `swm2` containers, networks, and volumes. That observation is not
qualification evidence; the manual GitHub workflow must pass again on the exact merged SHA before
it can be cited as hosted synthetic evidence.

M2 is not certified until a Docker-equipped clean host builds the fixture and retains a successful
run proving real mutation, snapshot/restore, four genuinely parallel sibling Compose projects, and
zero cross-world contamination. Even that synthetic observation would not replace the architecture's
real PostgreSQL, Redis, queue, browser, filesystem-provider, and clock requirements.
