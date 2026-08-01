# StateWeaver OpenTelemetry Adapter

This adapter is a pure, offline OTLP JSON decoder and causal validator. It does
not include an OpenTelemetry SDK, collector, exporter, network listener, socket,
or subprocess integration.

The accepted OTLP JSON subset contains `resourceSpans -> scopeSpans -> spans`,
scalar attributes, W3C trace/span IDs, nanosecond timestamps, and optional
resource/scope metadata. Unknown fields and secret-like attributes are rejected.

For one synthetic user flow, the adapter requires a unique connected parent DAG,
one HTTP server root span, a localhost `HttpRequestAction`, a matching method,
route template, path and expected status, and an evidence record bound to the
trace root. The evidence SHA-256 digest binds the canonical decoded semantic
trace, so OTLP array order is irrelevant while semantic tampering is rejected.
Caller-supplied `StateDelta` objects and `FidelityProfile` are retained in the
emitted `TelemetryFlow`.

The adapter only converts already-collected local evidence. It never executes the
typed action represented by the trace.
