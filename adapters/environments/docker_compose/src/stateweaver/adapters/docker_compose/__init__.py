"""Fixed-scope Docker Compose environment adapters for local M2 worlds."""

from .adapter import DockerComposeEnvironmentAdapter, RealDockerComposeEnvironmentAdapter
from .errors import ComposeAdapterError, ComposeUnavailableError
from .materialization import (
    M4MaterializedStateBinding,
    M5MaterializedProviderRunReceipt,
    M5MaterializedProviderRunRequest,
    M5MaterializedProviderStep,
    M5ProviderDigest,
    MaterializedCandidateRequest,
    MaterializedProviderReceipt,
    ProviderStateChange,
)
from .materialized_lab_runtime import (
    ApplicationImageBinding,
    ApplicationRouteTrace,
    CheckpointWitness,
    MaterializedLabDockerRuntime,
    MaterializedLabRunReceipt,
    MaterializedLabRunRequest,
    MaterializedLabStepReceipt,
    ProviderCheckpointWitness,
)
from .runner import ProcessResult, ProcessRunner

__all__ = [
    "ApplicationImageBinding",
    "ApplicationRouteTrace",
    "CheckpointWitness",
    "ComposeAdapterError",
    "ComposeUnavailableError",
    "DockerComposeEnvironmentAdapter",
    "M4MaterializedStateBinding",
    "M5MaterializedProviderRunReceipt",
    "M5MaterializedProviderRunRequest",
    "M5MaterializedProviderStep",
    "M5ProviderDigest",
    "MaterializedCandidateRequest",
    "MaterializedLabDockerRuntime",
    "MaterializedLabRunReceipt",
    "MaterializedLabRunRequest",
    "MaterializedLabStepReceipt",
    "MaterializedProviderReceipt",
    "ProcessResult",
    "ProcessRunner",
    "ProviderCheckpointWitness",
    "ProviderStateChange",
    "RealDockerComposeEnvironmentAdapter",
]
