# StateWeaver fixed Docker Compose adapter

This package is a local-only M2 adapter boundary for one repository-owned synthetic Compose
definition. It accepts no command, environment, image, Compose path, credential, or target address
from a caller. The production runner admits only a closed Docker argv grammar, fixes the Docker
endpoint to the local engine, uses `shell=False`, and the Compose network is internal.

The lifecycle and namespace boundary is implemented and covered with a deterministic fake process
runner, including four disjoint sibling projects, fail-closed process results, cleanup, and wheel
resource packaging. The current snapshot projection records adapter-observed health and target
identity; it does **not** yet capture and restore real database, cache, queue, session, filesystem,
or clock bytes. Those capabilities are therefore truthfully advertised as `PARTIAL`.

M2 is not certified until a repository-built synthetic image and a Docker-equipped clean host prove
real state mutation, snapshot/restore, four concurrent siblings, and zero cross-world contamination.
No such materialized result is simulated by this package's unit tests.
