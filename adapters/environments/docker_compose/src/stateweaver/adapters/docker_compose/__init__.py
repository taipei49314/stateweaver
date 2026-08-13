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
from .runner import ProcessResult, ProcessRunner

__all__ = [
    "ComposeAdapterError",
    "ComposeUnavailableError",
    "DockerComposeEnvironmentAdapter",
    "M4MaterializedStateBinding",
    "M5MaterializedProviderRunReceipt",
    "M5MaterializedProviderRunRequest",
    "M5MaterializedProviderStep",
    "M5ProviderDigest",
    "MaterializedCandidateRequest",
    "MaterializedProviderReceipt",
    "ProcessResult",
    "ProcessRunner",
    "ProviderStateChange",
    "RealDockerComposeEnvironmentAdapter",
]
