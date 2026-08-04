# StateWeaver World Workflow

This package is the **implemented offline core** that applies `stateweaver-search`
promotion decisions to abstract typed allocation and capture callbacks. It has no
Docker, sockets, subprocesses, network clients, or target data access.

It performs hard reservation before allocation, rolls reservations back after a
failed or cancelled callback, rejects duplicate state fingerprints and reused
sibling identities, and records canonical promotion events. Scores only rank
already eligible candidates; policy, capability, evidence, and oracle gates
remain mandatory.

The package also provides a pure `compile_observed_promotion` boundary. It reconstructs every
public model before use, requires an evidence-bound `OBSERVED` fragment set from a committed
Simulated-to-Materialized promotion, and replays the deterministic search from the recorded input
ledger, policy, and complete batch. It binds the capture-supplied exact compiler root, policy and
approval decision, allocation world, expected observations, terminal goal, fragment guards/effects,
and compiler output before emitting a content-bound admission receipt. The compiler is not allowed
to silently discard an admitted fragment. This boundary performs no execution or I/O, and the
resulting replay plan still requires fresh policy authorization.

Real materialized-world workflow certification is **pending**. The tests use only
deterministic in-memory fakes and do not establish a Docker or external-service
integration claim.
