# StateWeaver in-process lab replay adapter

This distribution implements the replay environment and oracle ports for the
repository's deterministic multi-tenant SaaS lab. It never opens a socket. A
registered `ActionEnvelope` is translated directly into one of the lab's closed
`TypedLabAction` variants and executed in memory.

The adapter intentionally has no generic URL, request-body, header, command,
filesystem, subprocess, or outbound-network execution path. Every action must:

- resolve through both a fixed action ID and the canonical typed-parameter artifact digest;
- match an exact lab route, method, synthetic identity handle, and status set;
- carry an `ALLOW` policy decision bound to the canonical envelope hash; and
- retain the registered idempotency key.

Changing a clock interval, role, principal, queue delay, recipient, document, or actor changes
the content handle and therefore the replay plan hash. Unknown actions, artifacts, policy decisions, modes, target versions, adapter
versions, and capture shapes fail closed. Captures come only from
`DeterministicLabService.capture_layers()` and contain seven redacted semantic
layers. Browser artifacts contain opaque session handles and identity hashes,
never fixture bearer values.

This adapter is exclusively for the local synthetic lab. It is not a general
HTTP client and cannot be repointed at a remote target.
