# Observed search-to-chain integration

This integration test closes one local horizontal implementation seam across M3, M4, and M5.
Three requests execute through FastAPI `TestClient` without opening a socket. Caller-constructed
synthetic OTLP JSON and matching state-delta evidence produce the same three `OBSERVED` fragments
that are carried by one candidate through the deterministic 24 -> 4 -> 2 -> 1 search workflow.
The final in-memory Materialized-tier promotion record is then admitted into the chain compiler
without recreating or substituting those fragments.

The test proves typed data continuity, deterministic beam reduction, reservation/capture-reference
closure, exact capture-root and compiler input/output binding, a minimal three-fragment chain, and a
replay plan that requires reauthorization. Its winning hypothesis, state, and score are synthetic
fixtures rather than Twin-derived ranking inputs. It does not prove a live materialized provider,
application-emitted telemetry, runtime-derived state-delta learning, external telemetry provenance,
execution of the compiled plan, a clean-root Oracle result for this observed chain, retained release
evidence, or M3/M4/M5 certification.

```powershell
uv run pytest tests/integration/pipeline workflows/world/tests/test_chain.py -q
```
