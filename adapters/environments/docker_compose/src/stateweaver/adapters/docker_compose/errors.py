"""Value-safe failures for the fixed synthetic Docker Compose boundary."""


class ComposeAdapterError(RuntimeError):
    """The adapter rejected an unavailable or malformed local-only lifecycle operation."""


class ComposeUnavailableError(ComposeAdapterError):
    """Docker Compose is absent or did not identify a usable local daemon."""
