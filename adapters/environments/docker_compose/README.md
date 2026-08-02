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
mutable-image-tag races, strict process replies, and wheel resource packaging.

The repository owns the fixture Dockerfile and pins its base by digest. From the repository root,
the only intended image bootstrap is:

```powershell
docker build --tag stateweaver-synthetic-demo:local adapters/environments/docker_compose/src/stateweaver/adapters/docker_compose
```

That command has not been executed in the retained local verification because Docker is unavailable;
on a clean host it may need to fetch the pinned base image. The emulator proves the archive protocol,
not live PostgreSQL, Redis, queue, browser-session, filesystem-provider, or controlled-clock capture.
All six capabilities therefore remain truthfully advertised as `PARTIAL`.

M2 is not certified until a Docker-equipped clean host builds the fixture and proves real mutation,
snapshot/restore, four genuinely parallel sibling Compose projects, and zero cross-world
contamination. The adapter currently serializes lifecycle calls with one lock, and no live
integration suite is retained yet; unit tests do not simulate either claim.
