# Runtime observation integration

These tests execute a typed action against the repository-owned ASGI lab without opening a socket.
The production observation controller, rather than the test caller, issues the trace, captures
redacted runtime state, derives deltas, and binds the receipt. Tests exercise canonical round trips,
trace/capture substitution, ordering, and secret-like attribute rejection.

This is a process-local M3 primitive. It is not an external OTel collector receipt, a materialized
M4 world, an executed M5 observed chain, or milestone certification.
