"""Public, synthetic fixture identifiers. None of these values is a secret."""

from __future__ import annotations

from enum import StrEnum
from types import MappingProxyType
from typing import Final, Literal


class FixtureBearer(StrEnum):
    TENANT_A_OLD_EDITOR = "fixture_session_a_old"
    TENANT_A_FRESH_VIEWER = "fixture_session_a_fresh"
    TENANT_B_VIEWER = "fixture_session_b_viewer"
    LAB_ADMIN = "fixture_session_admin"


class FixtureSessionId(StrEnum):
    TENANT_A_OLD = "session-a-old"
    TENANT_A_FRESH = "session-a-fresh"
    TENANT_B_VIEWER = "session-b-viewer"
    LAB_ADMIN = "session-lab-admin"


BEARER_TO_SESSION = MappingProxyType(
    {
        FixtureBearer.TENANT_A_OLD_EDITOR.value: FixtureSessionId.TENANT_A_OLD,
        FixtureBearer.TENANT_A_FRESH_VIEWER.value: FixtureSessionId.TENANT_A_FRESH,
        FixtureBearer.TENANT_B_VIEWER.value: FixtureSessionId.TENANT_B_VIEWER,
        FixtureBearer.LAB_ADMIN.value: FixtureSessionId.LAB_ADMIN,
    }
)

CANONICAL_SEED: Final[Literal["m0-canonical-v1"]] = "m0-canonical-v1"
SYNTHETIC_TENANT_A_BODY: Final = "SYNTHETIC_TENANT_A_DOCUMENT"
SYNTHETIC_TENANT_B_MARKER: Final = "SYNTHETIC_TENANT_B_MARKER_7F3A"
SYNTHETIC_MOCK_PLACEHOLDER: Final = "MOCK_ONLY_NOT_RUNTIME_DATA"
