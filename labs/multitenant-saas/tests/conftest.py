from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from stateweaver_lab import create_app
from stateweaver_lab.fixtures import FixtureBearer


def bearer_headers(bearer: FixtureBearer) -> dict[str, str]:
    return {"Authorization": f"Bearer {bearer.value}"}


@pytest.fixture
def vulnerable_client() -> Iterator[TestClient]:
    with TestClient(create_app("vulnerable")) as client:
        yield client


@pytest.fixture
def patched_client() -> Iterator[TestClient]:
    with TestClient(create_app("patched")) as client:
        yield client
