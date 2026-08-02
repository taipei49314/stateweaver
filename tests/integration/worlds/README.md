# M2 live Docker observation

This directory contains an opt-in test for the repository-owned synthetic Compose fixture. The
default test suite deselects `docker_integration`; an explicit environment opt-in and marker are
both required:

```powershell
docker build --tag stateweaver-synthetic-demo:local adapters/environments/docker_compose/src/stateweaver/adapters/docker_compose
$env:STATEWEAVER_RUN_DOCKER_INTEGRATION = "1"
uv run pytest -o 'addopts=--strict-config --strict-markers -ra' tests/integration/worlds/test_live_docker_compose.py -m docker_integration -q
```

The test fails rather than skips when explicitly selected without the opt-in. It requires four
distinct child `up` subprocesses to overlap, writes only canonical state through the fixed bridge
import grammar, verifies sibling/root isolation, restores each child from its own baseline, and
destroys only the exact project handles it created.

The code, a deselection, or an unrun workflow is not evidence. A successful Docker-host run is only
a live synthetic observation with its retained JUnit/runtime artifact. It is not PostgreSQL, Redis,
Celery, Playwright, or M2 certification.
