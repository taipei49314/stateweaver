"""Stable, non-sensitive adapter failures.

Exception messages are intentionally constant. ReplayKernel records only their
types, but callers using this adapter directly must not receive supplied target
or action content in an error string either.
"""

from __future__ import annotations


class InProcessLabAdapterError(RuntimeError):
    """Base class for fail-closed adapter failures."""


class AdapterConfigurationError(InProcessLabAdapterError):
    """The adapter or registry was not pinned to a supported configuration."""


class UnknownLabActionError(InProcessLabAdapterError):
    """No fixed typed lab action was registered for an envelope."""


class LabTargetRejectedError(InProcessLabAdapterError):
    """An envelope did not match its fixed in-process HTTP description."""


class LabIdentityRejectedError(InProcessLabAdapterError):
    """An envelope did not carry the fixed synthetic identity handle."""


class LabPolicyDeniedError(InProcessLabAdapterError):
    """The server-owned policy authorization was absent, denied, or mismatched."""


class LabIdempotencyConflictError(InProcessLabAdapterError):
    """An idempotency key was reused for different envelope semantics."""


class LabCaptureRejectedError(InProcessLabAdapterError):
    """A state capture was incomplete, unredacted, or inconsistent."""


class LabExecutionRejectedError(InProcessLabAdapterError):
    """The synthetic lab returned an outcome outside the registered contract."""


class LabExecutionTimeoutError(LabExecutionRejectedError):
    """The repository ASGI lifecycle exceeded its action-envelope deadline."""


class LabEvidenceRejectedError(InProcessLabAdapterError):
    """Execution evidence was missing, duplicated, or causally inconsistent."""
