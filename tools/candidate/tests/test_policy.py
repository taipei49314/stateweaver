"""Truthfulness checks for the public candidate gate narrative."""

from __future__ import annotations

from ..policy import (
    CONTROLLED_GATES,
    LIMITATIONS,
    QUALIFICATION_AND_IMPLEMENTATION_GAPS,
)


def test_m5_actual_asgi_admission_is_not_reported_as_pending() -> None:
    controlled = {item["gate_id"]: item for item in CONTROLLED_GATES}
    pending = {item["gate_id"]: item for item in QUALIFICATION_AND_IMPLEMENTATION_GAPS}

    assert controlled["SW-M5-MATERIALIZED-REPLAY"]["status"] == "PASS"
    assert "SW-M5-MATERIALIZED-REPLAY" not in pending
    assert all("materialized-provider M5 exit" not in statement for statement in LIMITATIONS)


def test_m6_m8_repository_slices_do_not_launder_external_qualification() -> None:
    pending = {item["gate_id"]: item for item in QUALIFICATION_AND_IMPLEMENTATION_GAPS}
    assert pending["SW-M6-PRODUCTION-PRODUCER"]["status"] == "PENDING_IMPLEMENTATION"
    assert pending["SW-M7-EQUAL-WORK-PROTOCOL"]["status"] == "PENDING_IMPLEMENTATION"
    assert pending["SW-M8-PUBLIC-JOURNEY"]["status"] == "PENDING_IMPLEMENTATION"
    assert "immutable-object closure" in pending["SW-M6-PRODUCTION-PRODUCER"]["reason"]
    assert "host-measured" in pending["SW-M7-EQUAL-WORK-PROTOCOL"]["reason"]
    assert "Chromium" in pending["SW-M8-PUBLIC-JOURNEY"]["reason"]
