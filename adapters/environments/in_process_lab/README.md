# StateWeaver in-process lab replay adapter

This distribution implements the replay environment and oracle ports for the
repository's deterministic multi-tenant SaaS lab. It never opens a socket. A
registered `ActionEnvelope` resolves to one of the lab's closed `TypedLabAction`
variants and is executed exactly once through the repository FastAPI app's in-memory
ASGI HTTP lifecycle. The app and replay service are bound to the same `LabState`.

The adapter intentionally has no generic URL, request-body, header, command,
filesystem, subprocess, or outbound-network execution path. Every action must:

- resolve through both a fixed action ID and the canonical typed-parameter artifact digest;
- match an exact lab route, method, synthetic identity handle, and status set;
- carry an `ALLOW` policy decision bound to the canonical envelope hash; and
- retain the registered idempotency key.

Policy and budget reservation, before/after capture, the actual ASGI request, response and
evidence correlation, and idempotency commit share one environment lock. Route, status and
timing metadata come from that ASGI lifecycle; no second service execution is used to create an
observation.

From ASGI task creation until the immutable execution receipt is committed, synchronous public
state reads fail closed so they cannot expose evidence or captures from a partially completed
handler. A timed-out or otherwise uncommitted task quarantines the run until it has settled and an
explicit cleanup or reset succeeds. Each committed lifecycle has one stable execution ID and
content digest, and an environment-owned claim ledger permits at most one trusted runtime
observation issuance for that execution, including across controller instances.

Changing a clock interval, role, principal, queue delay, recipient, document, or actor changes
the content handle and therefore the replay plan hash. Unknown actions, artifacts, policy decisions, modes, target versions, adapter
versions, and capture shapes fail closed. Captures come only from
`DeterministicLabService.capture_layers()` and contain seven redacted semantic
layers. Browser artifacts contain opaque session handles and identity hashes,
never fixture bearer values.

This adapter is exclusively for the local synthetic lab. It is not a general
HTTP client and cannot be repointed at a remote target.
