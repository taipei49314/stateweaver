"""Focused M4 materialized-state lineage contract regressions."""

from __future__ import annotations

from copy import deepcopy

import pytest
from stateweaver.adapters.docker_compose import (
    M4MaterializedStateBinding,
    MaterializedCandidateRequest,
    MaterializedProviderReceipt,
)
from stateweaver.contracts import WorldTier, sha256_digest
from stateweaver.worlds import AdapterPin, SnapshotManifest, TargetSpec

_PROVIDERS = ("cache", "clock", "database", "filesystem", "queue", "session")
_PIN = AdapterPin(adapter="docker-compose-real-providers", version="0.1.0")


def _receipt() -> MaterializedProviderReceipt:
    before = {
        provider: sha256_digest({"provider": provider, "phase": "before"})
        for provider in _PROVIDERS
    }
    after = {
        provider: sha256_digest({"provider": provider, "phase": "after"}) for provider in _PROVIDERS
    }
    snapshot = SnapshotManifest(
        snapshot_id="snapshot:" + "1" * 32,
        root_snapshot_id="root:m4-lineage",
        source_environment_id="environment:" + "2" * 32,
        target=TargetSpec(target_id="real-provider-demo", target_version="1.0.0"),
        adapter=_PIN,
        content_hashes=before,
        state_fingerprint=SnapshotManifest.derive_state_fingerprint(before),
    )
    request = MaterializedCandidateRequest(
        allocation_id="allocation.m4.replay.aaaaaaaaaaaaaaaa.01",
        candidate_id="candidate.m4.aaaaaaaaaaaaaaaa.01",
        source_tier=WorldTier.GHOST,
        target_tier=WorldTier.REPLAY,
        candidate_fingerprint=sha256_digest({"candidate": 1}),
        observed_transition_digest=sha256_digest({"transition": "m3"}),
        evidence_ref="evidence.m3.observed",
        oracle_ref="oracle.m4.provider-delta.aaaaaaaaaaaaaaaa.01",
        ordinal=1,
    )
    binding = M4MaterializedStateBinding.create(
        adapter_pin=_PIN,
        bridge_image_id="sha256:" + "3" * 64,
        provider_image_refs=("provider-a@sha256:" + "4" * 64,),
        source_snapshot=snapshot,
        after_archive_digest=sha256_digest({"archive": "after"}),
        provider_state_digest=sha256_digest(after),
    )
    return MaterializedProviderReceipt.create(
        request=request,
        environment_id="environment:" + "5" * 32,
        before=before,
        after=after,
        elapsed_ns=1,
        state_binding=binding,
    )


def test_rehashed_provider_state_substitution_is_rejected_by_its_lineage() -> None:
    receipt = _receipt()
    substituted = deepcopy(receipt.model_dump(mode="python"))
    substituted["state_binding"]["provider_state_digest"] = sha256_digest({"forged": True})
    substituted["state_binding"]["binding_digest"] = sha256_digest(
        {
            key: value
            for key, value in substituted["state_binding"].items()
            if key != "binding_digest"
        }
    )
    substituted["receipt_digest"] = sha256_digest(
        {key: value for key, value in substituted.items() if key != "receipt_digest"}
    )

    with pytest.raises(ValueError, match="state binding"):
        MaterializedProviderReceipt.model_validate(substituted)


def test_rehashed_snapshot_or_image_substitution_requires_a_new_trusted_m4_receipt() -> None:
    receipt = _receipt()
    substituted = deepcopy(receipt.model_dump(mode="python"))
    substituted["state_binding"]["bridge_image_id"] = "sha256:" + "6" * 64
    substituted["state_binding"]["source_snapshot_state_fingerprint"] = sha256_digest(
        {"forged": "snapshot"}
    )
    substituted["state_binding"]["binding_digest"] = sha256_digest(
        {
            key: value
            for key, value in substituted["state_binding"].items()
            if key != "binding_digest"
        }
    )
    substituted["receipt_digest"] = sha256_digest(
        {key: value for key, value in substituted.items() if key != "receipt_digest"}
    )

    with pytest.raises(ValueError, match="image binding"):
        MaterializedProviderReceipt.model_validate(substituted)
