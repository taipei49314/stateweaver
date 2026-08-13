"""The actual-ASGI M5 composite is closed under substitution and rehashing."""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

import pytest
import stateweaver.adapters.docker_compose.materialized_lab_runtime as runtime
from pydantic import ValidationError
from stateweaver.adapters.docker_compose import MaterializedLabRunReceipt
from stateweaver.adapters.docker_compose.real_provider_bridge import (
    ProviderCheckpointCapture,
    ProviderCheckpointObservation,
)
from stateweaver.adapters.docker_compose.runner import ProcessResult
from stateweaver.contracts import canonical_json_bytes, sha256_digest
from stateweaver_lab import LabStateCheckpoint
from test_m5_plan import MARKER, _m4_receipt  # type: ignore[import-not-found]

from stateweaver.cli.materialized_chain_qualification import (
    ActualMaterializedChainQualificationReceipt,
    qualify_actual_materialized_chain,
    write_materialized_chain_qualification,
)
from stateweaver.cli.observed_chain_qualification import qualify_observed_chain


class _MemoryCheckpointStore:
    def __init__(self) -> None:
        self._staged: dict[str, ProviderCheckpointCapture] = {}
        self._active: str | None = None

    @staticmethod
    def _capture(checkpoint: LabStateCheckpoint) -> ProviderCheckpointCapture:
        raw = checkpoint.canonical_bytes()
        observations = tuple(
            ProviderCheckpointObservation(
                provider=provider,
                generation=checkpoint.generation,
                checkpoint_digest=checkpoint.checkpoint_digest,
                storage_digest="sha256:" + sha256(raw).hexdigest(),
            )
            for provider in runtime._PROVIDERS
        )
        return ProviderCheckpointCapture(
            generation=checkpoint.generation,
            checkpoint_digest=checkpoint.checkpoint_digest,
            checkpoint_bytes=raw,
            observations=observations,
        )

    def stage(self, raw: bytes) -> ProviderCheckpointCapture:
        capture = self._capture(LabStateCheckpoint.from_canonical_bytes(raw))
        self._staged[capture.generation] = capture
        return capture

    def load_active(self) -> ProviderCheckpointCapture:
        assert self._active is not None
        return self._staged[self._active]

    def compare_and_swap(
        self, expected: str | None, next_generation: str
    ) -> ProviderCheckpointCapture:
        assert self._active == expected
        self._active = next_generation
        return self.load_active()


@dataclass
class _ActualApplicationAdapter:
    monkeypatch: pytest.MonkeyPatch
    run_count: int = 0

    async def run_m5_materialized_application(
        self, request: runtime.MaterializedLabRunRequest
    ) -> MaterializedLabRunReceipt:
        self.run_count += 1
        store = _MemoryCheckpointStore()
        self.monkeypatch.setattr(runtime, "RealProviderLabStateStore", lambda: store)
        output = await runtime._execute_in_container(request)
        binding_values: dict[str, object] = {
            "application_container_id": f"{self.run_count:064x}",
            "application_image_id": "sha256:" + "1" * 64,
            "application_source_revision": request.repository_marker,
            "bridge_container_id": f"{self.run_count + 100:064x}",
            "bridge_image_id": "sha256:" + "2" * 64,
            "image_identity_provenance": "EXECUTED_COMPOSE_CONTAINERS",
            "provider_image_refs": runtime._PROVIDER_IMAGE_REFS,
            "provider_image_set_digest": sha256_digest(runtime._PROVIDER_IMAGE_REFS),
            "provider_image_provenance": "PINNED_MANIFEST_REFS_NOT_RUNTIME_IMAGE_IDS",
        }
        binding = runtime.ApplicationImageBinding.model_validate(
            {**binding_values, "binding_digest": runtime._digest(binding_values)}
        )
        return runtime._parse_runtime_result(
            ProcessResult(
                returncode=0,
                stdout=json.dumps(runtime._json_compatible(output)),
            ),
            request,
            binding,
        )


@pytest.fixture(scope="module")
def actual_receipt(
    tmp_path_factory: pytest.TempPathFactory,
) -> ActualMaterializedChainQualificationReceipt:
    root = tmp_path_factory.mktemp("actual-materialized-chain")
    m4 = _m4_receipt()
    m4_path = root / "materialized-search-receipt.json"
    m4_path.write_bytes(canonical_json_bytes(m4) + b"\n")
    process = qualify_observed_chain(m4_receipt_path=m4_path, repository_marker=MARKER)
    process_path = root / "observed-chain-receipt.json"
    process_path.write_bytes(canonical_json_bytes(process) + b"\n")
    patcher = pytest.MonkeyPatch()
    try:
        return qualify_actual_materialized_chain(
            m4_receipt_path=m4_path,
            process_receipt_path=process_path,
            repository_marker=MARKER,
            adapter=_ActualApplicationAdapter(patcher),
        )
    finally:
        patcher.undo()


def _rehash(values: dict[str, object]) -> dict[str, object]:
    values["receipt_digest"] = sha256_digest(
        runtime._json_compatible(
            {key: value for key, value in values.items() if key != "receipt_digest"}
        )
    )
    return values


def _rehash_run_witness(witness: dict[str, object]) -> dict[str, object]:
    retained = witness["materialized_run_receipt"]
    assert isinstance(retained, dict)
    receipt = dict(retained)
    receipt["receipt_digest"] = runtime._digest(
        {key: value for key, value in receipt.items() if key != "receipt_digest"}
    )
    witness["materialized_run_receipt"] = receipt
    witness["materialized_run_receipt_digest"] = receipt["receipt_digest"]
    return witness


def test_actual_composite_retains_all_ten_exact_scenarios_and_canonical_file(
    actual_receipt: ActualMaterializedChainQualificationReceipt,
    tmp_path: Path,
) -> None:
    assert actual_receipt.status == "M5_MATERIALIZED_ACTUAL_ASGI_QUALIFIED"
    assert len(actual_receipt.clean_root_runs) == 5
    assert actual_receipt.patched_run.materialized_run_receipt.steps[-1].oracle.verdict == (
        "NOT_VIOLATED"
    )
    assert tuple(item.name for item in actual_receipt.negative_controls) == (
        "masked_response",
        "mock_only_response",
        "fresh_session",
        "same_tenant_document",
    )
    assert len(set(actual_receipt.vulnerable_deterministic_signatures)) == 1
    assert actual_receipt.cleanup_count == 10
    assert actual_receipt.all_cleanups_passed and actual_receipt.all_projects_destroyed
    retained_runs = (
        *(item.materialized_run_receipt for item in actual_receipt.clean_root_runs),
        actual_receipt.patched_run.materialized_run_receipt,
        *(item.materialized_run_receipt for item in actual_receipt.negative_controls),
    )
    assert len({item.image_binding.application_container_id for item in retained_runs}) == 10
    assert len({item.image_binding.bridge_container_id for item in retained_runs}) == 10
    assert all(
        item.image_binding.application_container_id != item.image_binding.bridge_container_id
        for item in retained_runs
    )
    for retained in retained_runs:
        request = retained.request
        assert request.action_bytes == tuple(canonical_json_bytes(item) for item in request.actions)
        assert request.policy_request_bytes == tuple(
            canonical_json_bytes(item) for item in request.policy_requests
        )
        assert request.policy_authorization_bytes == tuple(
            canonical_json_bytes(item) for item in request.policy_authorizations
        )

    output = tmp_path / "materialized-chain-replay.json"
    write_materialized_chain_qualification(output, actual_receipt)
    assert (
        output.read_bytes()
        == canonical_json_bytes(runtime._json_compatible(actual_receipt)) + b"\n"
    )


@pytest.mark.parametrize(
    "substitution",
    ("swap_run", "initial_checkpoint", "m4_lineage", "oracle", "control", "source_marker"),
)
def test_actual_composite_rejects_substitution_even_when_rehashed(
    actual_receipt: ActualMaterializedChainQualificationReceipt,
    substitution: str,
) -> None:
    values = actual_receipt.model_dump(mode="python")
    if substitution == "swap_run":
        runs = list(values["clean_root_runs"])
        runs[0], runs[1] = runs[1], runs[0]
        values["clean_root_runs"] = tuple(runs)
    elif substitution == "initial_checkpoint":
        values["initial_checkpoint_bytes_digest"] = sha256_digest("substituted-checkpoint")
    elif substitution == "m4_lineage":
        values["m4_winner_state_binding_digest"] = sha256_digest("substituted-lineage")
    elif substitution == "oracle":
        patched = dict(values["patched_run"])
        patched["expected_oracle_outcome"] = "VIOLATED"
        values["patched_run"] = patched
    elif substitution == "control":
        controls = list(values["negative_controls"])
        controls[0], controls[1] = controls[1], controls[0]
        values["negative_controls"] = tuple(controls)
    else:
        values["repository_marker"] = "f" * 40

    with pytest.raises((ValidationError, ValueError)):
        ActualMaterializedChainQualificationReceipt.model_validate(_rehash(values))


@pytest.mark.parametrize("container_field", ("application_container_id", "bridge_container_id"))
def test_actual_composite_rejects_reused_container_id_even_when_every_digest_is_rehashed(
    actual_receipt: ActualMaterializedChainQualificationReceipt,
    container_field: str,
) -> None:
    values = actual_receipt.model_dump(mode="python")
    runs = list(values["clean_root_runs"])
    source_receipt = runs[0]["materialized_run_receipt"]
    target = dict(runs[1])
    target_receipt = dict(target["materialized_run_receipt"])
    target_binding = dict(target_receipt["image_binding"])
    target_binding[container_field] = source_receipt["image_binding"][container_field]
    target_binding["binding_digest"] = runtime._digest(
        {key: value for key, value in target_binding.items() if key != "binding_digest"}
    )
    target_receipt["image_binding"] = target_binding
    target["materialized_run_receipt"] = target_receipt
    runs[1] = _rehash_run_witness(target)
    values["clean_root_runs"] = tuple(runs)

    with pytest.raises((ValidationError, ValueError), match="incoherent"):
        ActualMaterializedChainQualificationReceipt.model_validate(_rehash(values))


def test_actual_composite_rejects_swapped_project_bindings_even_when_rehashed(
    actual_receipt: ActualMaterializedChainQualificationReceipt,
) -> None:
    values = actual_receipt.model_dump(mode="python")
    runs = list(values["clean_root_runs"])
    first = dict(runs[0])
    second = dict(runs[1])
    first_receipt = dict(first["materialized_run_receipt"])
    second_receipt = dict(second["materialized_run_receipt"])
    first_receipt["image_binding"], second_receipt["image_binding"] = (
        second_receipt["image_binding"],
        first_receipt["image_binding"],
    )
    first["materialized_run_receipt"] = first_receipt
    second["materialized_run_receipt"] = second_receipt
    runs[0] = _rehash_run_witness(first)
    runs[1] = _rehash_run_witness(second)
    values["clean_root_runs"] = tuple(runs)

    with pytest.raises((ValidationError, ValueError), match="incoherent"):
        ActualMaterializedChainQualificationReceipt.model_validate(_rehash(values))
