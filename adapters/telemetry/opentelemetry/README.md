# StateWeaver OpenTelemetry Adapter

This adapter contains a pure offline OTLP JSON decoder and a bounded process-local
runtime observation controller. It does not include an external OpenTelemetry collector,
network listener, socket, subprocess, or remote target integration.

The accepted OTLP JSON subset contains `resourceSpans -> scopeSpans -> spans`,
scalar attributes, W3C trace/span IDs, nanosecond timestamps, and optional
resource/scope metadata. Unknown fields and secret-like attributes are rejected.

For one synthetic user flow, the adapter requires a unique connected parent DAG,
one HTTP server root span, a localhost `HttpRequestAction`, a matching method,
route template, path and expected status, and an evidence record bound to the
trace root. The evidence SHA-256 digest binds the canonical decoded semantic
trace, so OTLP array order is irrelevant while semantic tampering is rejected.
The legacy decoder retains caller-supplied `StateDelta` objects and `FidelityProfile` in the
emitted `TelemetryFlow`; such a flow is typed synthetic input and cannot establish an observed
runtime claim by itself.

`RuntimeObservationController` is the stronger process-local path. The caller supplies only an
existing `ActionEnvelope`, route identity, and closed observed paths. Its constructor accepts only
the exact repository `InProcessLabEnvironment`; the environment binds the import-time-fixed
repository FastAPI app and replay service to the same `LabState`. Policy and budget reservation,
before/after capture, and one socket-free ASGI HTTP lifecycle run under the environment lock before
the idempotency receipt is committed. The controller derives the server span's route, status and
timing from that actual lifecycle and constructs a content-bound receipt. The receipt and span bind
the environment-issued execution ID, execution digest, and one-time observation-claim digest.
Public state reads remain unavailable while an ASGI task is executing or quarantined after an
uncommitted outcome, and a second controller cannot issue a fresh trace for the same cached
execution. The controller rejects
cross-controller swaps, trust-provider substitution, tampered or reversed captures, trace mutation,
and secret-like attributes. It does not yet wire the receipt into M4 materialized worlds or M5
clean-root execution and is not external telemetry or M3 certification.
