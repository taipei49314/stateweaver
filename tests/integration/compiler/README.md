# Clean-room compiler integration proof

This directory tests an offline synthetic state machine only. Its in-memory
adapter accepts a closed set of compiler-produced, freshly policy-authorized
`TimeAdvanceAction` envelopes and applies only their typed `SET` effects. It
has no network, socket, Docker, subprocess, HTTP client, or product-data path.

The proof establishes deterministic behaviour for one synthetic three-step
chain. It is implementation evidence, not M5 release certification and not a
claim about any product target or materialized environment.
