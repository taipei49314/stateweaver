# Contributing

StateWeaver values reproducibility and evidence over feature count. A contribution is complete when
another person can reproduce its behavior from a clean root and inspect the evidence behind its
claim.

## Set up

```bash
uv sync --all-packages --group dev --locked
uv run pytest
```

## Before opening a pull request

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy packages adapters apps labs workflows benchmarks tests
uv run pytest --cov --cov-report=term-missing
uv lock --check --offline
```

For changes under `apps/web/`, also run `npm ci`, `npm run format:check`, `npm run lint`,
`npm run typecheck`, `npm test`, and `npm run build` from that directory.

Add focused unit tests and, where state is involved, at least one deterministic replay or property
test. New adapters also require conformance tests for cleanup, idempotency, isolation, redaction,
egress enforcement, timeout cancellation, root replay, fingerprint stability, and version pinning.

## Adding an intentional vulnerability

Intentional weaknesses may exist only under `labs/`. They must:

1. require a non-trivial, documented state chain rather than a single unauthenticated request;
2. use only synthetic identities and data;
3. have a deterministic machine-checkable oracle;
4. include negative controls and a patched implementation;
5. run in-process or on localhost with bounded resources and no Internet egress;
6. never be copied into platform or adapter code.

Read [AGENTS.md](AGENTS.md) for the binding engineering and authorization boundary.

## Commit style

Prefer small commits with an imperative subject, such as `Add strict action envelope contract` or
`Verify patched replay blocks stale-session chain`. Do not commit generated evidence bundles,
secrets, local environment files, or benchmark results that CI cannot reproduce.
