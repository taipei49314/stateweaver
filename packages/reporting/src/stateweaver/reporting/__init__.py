"""Deterministic reporting for non-authoritative Reality publication candidates."""

from .reality import (
    PublicationArtifactRole,
    RealityPublication,
    RealityPublicationError,
    RealityPublicationManifest,
    RealityPublicationManifestEntry,
    RealityPublicationVerificationResult,
    build_reality_publication,
    verify_reality_publication,
)

__all__ = [
    "PublicationArtifactRole",
    "RealityPublication",
    "RealityPublicationError",
    "RealityPublicationManifest",
    "RealityPublicationManifestEntry",
    "RealityPublicationVerificationResult",
    "build_reality_publication",
    "verify_reality_publication",
]
