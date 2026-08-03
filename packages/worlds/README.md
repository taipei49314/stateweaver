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

Every mutating lifecycle method is awaitable. Operations targeting the same world are admitted
through a stable per-world gate and commit against a monotonic node revision, while operations on
different worlds remain independent. This prevents an adapter call that resumes late from
overwriting a newer lifecycle phase.

`WorldManager` is the sole lifecycle writer. Its private store issues one opaque writer capability;
callers receive the live `ReadOnlyWorldStore` catalog through `manager.worlds` (and the compatible
`manager.store` alias), with only `get`, `all`, and `canonical_world_id`. Direct phase writes and
metadata-only destruction therefore cannot bypass manager admission or adapter cleanup. Ghost
children enter through `create_ghost`, which derives parent identity and lineage without touching an
adapter. Every asynchronous command binds the manager to one event loop, and caller-supplied world
IDs are fully validated before any adapter call.

API boundary change: the former mutable `WorldStore` export and `manager.store.add/replace` surface
were removed in this pre-alpha contract. Use `manager.worlds` for queries and `WorldManager`
lifecycle commands for every write; `manager.store` remains only as a read-compatible alias.

Root preparation and child forks reserve their world identity before the first adapter call. A
returned environment must first claim a unique identifier and opaque ownership reference, then pass
isolation checks across all six namespace components before it can be snapshotted or published.
Cleanup releases that reservation only after destruction succeeds; cleanup failure retains a
quarantine entry so an uncertain environment cannot be reassigned. An ID/opaque collision is
rejected without destroying the ambiguous handle, while a uniquely owned namespace-overlap loser is
cleaned up without touching or blocking winner commits. Once published, a world cannot attach or
switch environments through a store replacement. Disjoint reservations still execute snapshots
concurrently.

Run the focused suite from this directory with `pytest`.
