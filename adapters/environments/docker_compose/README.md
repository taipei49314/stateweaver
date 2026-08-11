# StateWeaver fixed Docker Compose adapters

This package contains two local-only M2 boundaries: the retained synthetic diagnostic and a
repository-owned real-provider lab. The real path materializes PostgreSQL, Redis, RabbitMQ,
Chromium/WebDriver session state, filesystem state, and a controlled clock behind one fixed bridge.
Neither adapter accepts a caller command, environment, image, Compose path, credential, target
address, shell fragment, or arbitrary URL.

At construction, the runner resolves Docker (and Windows `docker-compose`) once from the
operator-controlled host `PATH`, rejects missing, relative, non-file, or non-executable results, and
then invokes the resolved absolute path from the fixed fixture directory with `shell=False`. The
child receives only a derived executable path, the fixed local Linux engine endpoint, and required
Windows system variables. User Docker configuration variables are not forwarded. Both Compose
networks are internal and publish no host port.

Every child runs in an isolated process group with a one-MiB cap on each output stream. Commands use
a 60-second deadline; only the exact real-provider `compose up --detach --wait --no-build` argv uses
a fixed 180-second startup deadline. Read, write, wait, cancellation, timeout, and overflow failures
abort the process tree and reap the direct child. Compensating `down` has a 70-second outer boundary
around the runner's own fixed deadline, so failed creation or restore cannot silently strand
provider volumes or networks.

The synthetic adapter retains its canonical six-component JSON archive and advertises those
capabilities as `PARTIAL`. `RealDockerComposeEnvironmentAdapter` captures and restores six actual
provider boundaries and advertises them as `SUPPORTED`. Its archive binds the inspected bridge image
ID plus four digest-pinned provider references, validates a closed v2 schema, re-exports after every
import, and rejects forged handles, targets, manifests, lineage, mutable bridge-image swaps, and
unexpected process replies. RabbitMQ capture uses an authoritative non-consuming `/get` readback,
not eventually consistent management depth counters. Browser state is proven through a real
headless Chromium cookie and localStorage roundtrip.

The repository owns both fixture Dockerfiles and pins every external base/provider image by digest.
From the repository root:

```powershell
docker build --tag stateweaver-synthetic-demo:local adapters/environments/docker_compose/src/stateweaver/adapters/docker_compose
docker compose --file adapters/environments/docker_compose/src/stateweaver/adapters/docker_compose/real_compose.yaml pull postgres redis rabbitmq selenium
docker build --tag stateweaver-real-provider-bridge:local --file adapters/environments/docker_compose/src/stateweaver/adapters/docker_compose/RealDockerfile adapters/environments/docker_compose/src/stateweaver/adapters/docker_compose

$env:STATEWEAVER_RUN_DOCKER_INTEGRATION = "1"
uv run pytest -o 'addopts=--strict-config --strict-markers -ra' tests/integration/worlds/test_live_docker_compose.py -m docker_integration -q

$env:STATEWEAVER_RUN_REAL_DOCKER_INTEGRATION = "1"
uv run pytest -o 'addopts=--strict-config --strict-markers -ra' tests/integration/worlds/test_live_real_providers.py -m docker_integration -q
```

On 2026-08-11 the current development tree completed all four real-provider paths locally (`4 passed
in 437.75s`) and returned the complete `swm2` container/network/volume inventory to empty after the
success, startup-timeout, cancellation, and partial-failure cases. The success path proved four
overlapping forks and restores, four unique mutations across every provider, and exact baseline
digest recovery. This remains an ephemeral implementation observation, not exact-merged-SHA
qualification evidence. M2 stays uncertified until the hosted workflow passes on the merged commit,
retains JUnit, image identities, source hashes, and cleanup inventories, and the acceptance verifier
admits those exact bytes.
