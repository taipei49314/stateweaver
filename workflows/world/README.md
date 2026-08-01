# StateWeaver World Workflow

This package is the **implemented offline core** that applies `stateweaver-search`
promotion decisions to abstract typed allocation and capture callbacks. It has no
Docker, sockets, subprocesses, network clients, or target data access.

It performs hard reservation before allocation, rolls reservations back after a
failed or cancelled callback, rejects duplicate state fingerprints and reused
sibling identities, and records canonical promotion events. Scores only rank
already eligible candidates; policy, capability, evidence, and oracle gates
remain mandatory.

Real materialized-world workflow certification is **pending**. The tests use only
deterministic in-memory fakes and do not establish a Docker or external-service
integration claim.
