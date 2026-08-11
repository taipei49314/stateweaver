"""Opt-in M3→M4 qualification against fixed real-provider Docker worlds."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from stateweaver.cli.materialized_search_qualification import (
    MaterializedSearchQualificationReceipt,
    qualify_materialized_search,
)
from stateweaver.contracts import canonical_json_bytes

_OPT_IN = "STATEWEAVER_RUN_REAL_DOCKER_INTEGRATION"


@pytest.mark.docker_integration
def test_observed_search_materializes_only_four_two_one_and_reclaims_every_world() -> None:
    if os.environ.get(_OPT_IN) != "1":
        pytest.fail(f"explicit M4 Docker selection requires {_OPT_IN}=1")
    marker = os.environ.get("STATEWEAVER_M4_REPOSITORY_MARKER", "4" * 40)

    receipt = qualify_materialized_search(marker)

    assert receipt.ghost_evaluation_count == 24
    assert receipt.promotion_counts == (4, 2, 1)
    assert receipt.materialized_world_count == 7
    assert receipt.peak_live_allocations == 4
    assert not receipt.residual_allocation_ids
    assert len(receipt.released_allocation_ids) == 7
    assert all(item.changed_provider_count == 6 for item in receipt.provider_receipts)
    assert receipt.final_ledger.usage().materialized_worlds == 1
    assert len(receipt.winner.transition_fragments) == 3
    assert receipt.winner.transition_fragments[-1] == receipt.winner_transition
    assert (
        MaterializedSearchQualificationReceipt.model_validate_json(canonical_json_bytes(receipt))
        == receipt
    )

    output = Path("artifacts/m4-live/materialized-search-receipt.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical_json_bytes(receipt) + b"\n")
