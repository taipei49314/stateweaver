## What changed

<!-- Describe the state transition this change introduces, not only the files edited. -->

## Evidence

- [ ] Tests added or updated
- [ ] `uv run ruff format --check .`
- [ ] `uv run ruff check .`
- [ ] `uv run mypy packages adapters apps labs`
- [ ] `uv run pytest`

## Security boundary

- [ ] Work is limited to synthetic/authorized scope
- [ ] No real secrets or target data are included
- [ ] No raw shell, arbitrary URL, scope expansion, or default-allow action was added
- [ ] Intentional lab weakness has a patched mode and deterministic negative control

## Reproducibility

<!-- Name the root seed, replay plan, oracle, and expected vulnerable/patched verdict if relevant. -->
