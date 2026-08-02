# StateWeaver Worlds

M2's dependency-light world lifecycle core. It defines immutable manifests and
ports, plus a fail-closed `WorldManager`; it deliberately does **not** implement
or claim completion of Docker Compose. A deterministic in-memory adapter is
supplied only as a conformance-test harness.

The manager pins adapter identity, version, and capabilities, validates parent
lineage, rejects pruned worlds, bounds every awaited adapter call, and never puts
secret values in a snapshot manifest. Restore revalidates copied manifests before
crossing the adapter boundary, and every materialized `WorldNode` binds its snapshot
source to its exact live environment.

Run the focused suite from this directory with `pytest`.
