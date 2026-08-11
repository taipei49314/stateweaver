"""Fixed-scope Docker Compose environment adapters for local M2 worlds."""

from .adapter import DockerComposeEnvironmentAdapter, RealDockerComposeEnvironmentAdapter
from .errors import ComposeAdapterError, ComposeUnavailableError
from .materialization import (
    MaterializedCandidateRequest,
    MaterializedProviderReceipt,
    ProviderStateChange,
)
from .runner import ProcessResult, ProcessRunner

__all__ = [
    "ComposeAdapterError",
    "ComposeUnavailableError",
    "DockerComposeEnvironmentAdapter",
    "MaterializedCandidateRequest",
    "MaterializedProviderReceipt",
    "ProcessResult",
    "ProcessRunner",
    "ProviderStateChange",
    "RealDockerComposeEnvironmentAdapter",
]
