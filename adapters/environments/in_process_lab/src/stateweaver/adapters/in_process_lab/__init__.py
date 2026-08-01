"""Public API for the fail-closed synthetic in-process lab adapter."""

from .environment import (
    ADAPTER_NAME,
    ADAPTER_VERSION,
    CANONICAL_RANDOM_SEED,
    InProcessLabEnvironment,
)
from .errors import (
    AdapterConfigurationError,
    InProcessLabAdapterError,
    LabCaptureRejectedError,
    LabEvidenceRejectedError,
    LabExecutionRejectedError,
    LabIdempotencyConflictError,
    LabIdentityRejectedError,
    LabPolicyDeniedError,
    LabTargetRejectedError,
    UnknownLabActionError,
)
from .oracle import ORACLE_ID, ORACLE_VERSION, InProcessLabReplayOracle
from .registry import (
    FixedLabActionRegistry,
    LabAction,
    LabHttpActionSpec,
    PolicyAuthorization,
    lab_action_artifact,
    lab_http_action_spec,
)

__all__ = [
    "ADAPTER_NAME",
    "ADAPTER_VERSION",
    "CANONICAL_RANDOM_SEED",
    "ORACLE_ID",
    "ORACLE_VERSION",
    "AdapterConfigurationError",
    "FixedLabActionRegistry",
    "InProcessLabAdapterError",
    "InProcessLabEnvironment",
    "InProcessLabReplayOracle",
    "LabAction",
    "LabCaptureRejectedError",
    "LabEvidenceRejectedError",
    "LabExecutionRejectedError",
    "LabHttpActionSpec",
    "LabIdempotencyConflictError",
    "LabIdentityRejectedError",
    "LabPolicyDeniedError",
    "LabTargetRejectedError",
    "PolicyAuthorization",
    "UnknownLabActionError",
    "lab_action_artifact",
    "lab_http_action_spec",
]
