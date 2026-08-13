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
    MaterializedLabDockerRuntime,
    MaterializedLabRunReceipt,
    MaterializedLabRunRequest,
)
from .runner import ProcessResult, ProcessRunner

__all__ = [
    "ApplicationImageBinding",
    "ApplicationRouteTrace",
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
    "MaterializedProviderReceipt",
    "ProcessResult",
    "ProcessRunner",
    "ProviderStateChange",
    "RealDockerComposeEnvironmentAdapter",
]
