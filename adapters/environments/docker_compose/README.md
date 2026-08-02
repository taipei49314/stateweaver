# StateWeaver fixed Docker Compose adapter

This package is a local-only M2 adapter boundary for one repository-owned synthetic Compose
definition. It accepts no command, environment, image, Compose path, credential, or target address
from a caller. The production runner admits only a closed Docker argv grammar, fixes the Docker
endpoint to the local engine, uses `shell=False`, and the Compose network is internal.

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

That command has not been executed in the retained local verification because Docker is unavailable;
on a clean host it may need to fetch the pinned base image. The emulator proves the archive protocol,
not live PostgreSQL, Redis, queue, browser-session, filesystem-provider, or controlled-clock capture.
All six capabilities therefore remain truthfully advertised as `PARTIAL`.

The default suite now requires four emulator siblings to overlap at runner barriers. An explicit
`docker_integration` test and manual GitHub workflow encode the corresponding live-host observation,
but neither has been executed or retained here. Their existence, collection, or deselection is not
evidence.

M2 is not certified until a Docker-equipped clean host builds the fixture and retains a successful
run proving real mutation, snapshot/restore, four genuinely parallel sibling Compose projects, and
zero cross-world contamination. Even that synthetic observation would not replace the architecture's
real PostgreSQL, Redis, queue, browser, filesystem-provider, and clock requirements.
