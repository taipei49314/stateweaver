"""Public API for the fail-closed synthetic in-process lab adapter."""

from stateweaver.policy import PolicyAuthorization

from .environment import (
    ADAPTER_NAME,
    ADAPTER_VERSION,
    CANONICAL_RANDOM_SEED,
    InProcessLabEnvironment,
    InProcessLabRuntimeExecution,
    state_capture_from_lab_checkpoint,
)
from .errors import (
    AdapterConfigurationError,
    InProcessLabAdapterError,
    LabCaptureRejectedError,
    LabEvidenceRejectedError,
    LabExecutionRejectedError,
    LabExecutionTimeoutError,
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
    "InProcessLabRuntimeExecution",
    "LabAction",
    "LabCaptureRejectedError",
    "LabEvidenceRejectedError",
    "LabExecutionRejectedError",
    "LabExecutionTimeoutError",
    "LabHttpActionSpec",
    "LabIdempotencyConflictError",
    "LabIdentityRejectedError",
    "LabPolicyDeniedError",
    "LabTargetRejectedError",
    "PolicyAuthorization",
    "UnknownLabActionError",
    "lab_action_artifact",
    "lab_http_action_spec",
    "state_capture_from_lab_checkpoint",
]
