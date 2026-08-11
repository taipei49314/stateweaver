# M2 live Docker observations

This directory contains opt-in tests for the repository-owned synthetic and real-provider Compose
fixtures. The default suite deselects `docker_integration`; each gate requires an explicit
environment opt-in:

```powershell
docker build --tag stateweaver-synthetic-demo:local adapters/environments/docker_compose/src/stateweaver/adapters/docker_compose
$env:STATEWEAVER_RUN_DOCKER_INTEGRATION = "1"
uv run pytest -o 'addopts=--strict-config --strict-markers -ra' tests/integration/worlds/test_live_docker_compose.py -m docker_integration -q

docker compose --file adapters/environments/docker_compose/src/stateweaver/adapters/docker_compose/real_compose.yaml pull postgres redis rabbitmq selenium
docker build --tag stateweaver-real-provider-bridge:local --file adapters/environments/docker_compose/src/stateweaver/adapters/docker_compose/RealDockerfile adapters/environments/docker_compose/src/stateweaver/adapters/docker_compose
$env:STATEWEAVER_RUN_REAL_DOCKER_INTEGRATION = "1"
uv run pytest -o 'addopts=--strict-config --strict-markers -ra' tests/integration/worlds/test_live_real_providers.py -m docker_integration -q
```

Both tests fail rather than skip when explicitly selected without their opt-in. The real-provider
gate captures, mutates, fingerprints, and restores actual PostgreSQL, Redis, RabbitMQ,
Chromium cookie/localStorage, filesystem, and controlled-clock state across four overlapping
worlds. It verifies four unique per-provider mutation digests, exact baseline recovery, distinct
namespaces, and empty project state after cleanup.

Code, a deselection, or an unrun workflow is not evidence. M2 qualification requires retained
exact-SHA hosted artifacts and cleanup inventories admitted by the acceptance verifier.
