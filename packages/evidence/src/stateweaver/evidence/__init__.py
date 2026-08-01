"""Offline collection and verification of M0/M1 acceptance evidence."""

from ._io import semantic_sha256
from .collector import (
    ACCEPTANCE_TEST_COMMAND,
    AcceptanceEvidenceError,
    CollectionInput,
    CollectionResult,
    collect_acceptance_evidence,
    collect_from_json_file,
)
from .verify import ExpectedProvenance, VerificationResult, verify_acceptance_evidence

__all__ = [
    "ACCEPTANCE_TEST_COMMAND",
    "AcceptanceEvidenceError",
    "CollectionInput",
    "CollectionResult",
    "ExpectedProvenance",
    "VerificationResult",
    "collect_acceptance_evidence",
    "collect_from_json_file",
    "semantic_sha256",
    "verify_acceptance_evidence",
]
