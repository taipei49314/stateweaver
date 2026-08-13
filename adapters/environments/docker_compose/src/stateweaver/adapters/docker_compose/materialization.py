"""Closed M4 mutation and six-provider observation contracts."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from stateweaver.contracts import (
    ActionEnvelope,
    ContractId,
    HttpRequestAction,
    Sha256Digest,
    WorldTier,
    sha256_digest,
)
from stateweaver.worlds import AdapterPin, SnapshotManifest

ProviderName = Literal["cache", "clock", "database", "filesystem", "queue", "session"]
_PROVIDERS: tuple[ProviderName, ...] = (
    "cache",
    "clock",
    "database",
    "filesystem",
    "queue",
    "session",
)
_NEXT_TIER = {
    WorldTier.GHOST: WorldTier.REPLAY,
    WorldTier.REPLAY: WorldTier.SIMULATED,
    WorldTier.SIMULATED: WorldTier.MATERIALIZED,
}
_TICK_OFFSET = {
    WorldTier.REPLAY: 100,
    WorldTier.SIMULATED: 200,
    WorldTier.MATERIALIZED: 300,
}
_M5_PRIMARY_ROUTES: tuple[tuple[str, str, str], ...] = (
    ("POST", "/v1/lab/session/retain", "identity:test_user_a"),
    ("POST", "/v1/lab/authorization-cache/prime", "identity:test_user_a"),
    ("POST", "/v1/lab/admin/role-downgrade", "identity:test_admin"),
    ("POST", "/v1/lab/admin/queue/defer", "identity:test_admin"),
    ("POST", "/v1/lab/references/publish", "identity:test_user_b"),
    ("POST", "/v1/lab/references/claim", "identity:test_user_a"),
    ("POST", "/v1/lab/admin/clock/advance", "identity:test_admin"),
    ("GET", "/v1/lab/documents/doc-b-protected", "identity:test_user_a"),
)
_M5_SCENARIO_ROUTES: dict[str, tuple[tuple[str, str, str], ...]] = {
    "primary_vulnerable": _M5_PRIMARY_ROUTES,
    "primary_patched": _M5_PRIMARY_ROUTES,
    "masked_response": (("GET", "/v1/lab/decoys/masked/doc-b-protected", "identity:test_user_a"),),
    "mock_only_response": (
        ("GET", "/v1/lab/decoys/mock-policy/doc-b-protected", "identity:test_user_a"),
    ),
    "fresh_session": _M5_PRIMARY_ROUTES,
    "same_tenant_document": (("GET", "/v1/lab/documents/doc-a-owned", "identity:test_user_a"),),
}
_M5_SCENARIO_BOUNDARIES: dict[str, tuple[str, int]] = {
    "primary_vulnerable": ("VIOLATED", 200),
    "primary_patched": ("SATISFIED", 403),
    "masked_response": ("SATISFIED", 200),
    "mock_only_response": ("INCONCLUSIVE", 200),
    "fresh_session": ("SATISFIED", 403),
    "same_tenant_document": ("SATISFIED", 200),
}


class _MaterializationModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class MaterializedCandidateRequest(_MaterializationModel):
    """No-command request for one pre-admitted observed candidate."""

    allocation_id: ContractId
    candidate_id: ContractId
    source_tier: WorldTier
    target_tier: WorldTier
    candidate_fingerprint: Sha256Digest
    observed_transition_digest: Sha256Digest
    evidence_ref: ContractId
    oracle_ref: ContractId
    ordinal: Annotated[int, Field(ge=0, lt=24)]

    @model_validator(mode="after")
    def tier_step_is_exact(self) -> MaterializedCandidateRequest:
        if self.source_tier is WorldTier.MATERIALIZED:
            raise ValueError("materialized candidates cannot be promoted again")
        if _NEXT_TIER[self.source_tier] is not self.target_tier:
            raise ValueError("materialization request must advance exactly one tier")
        return self

    @property
    def marker(self) -> str:
        digest = sha256_digest(self).removeprefix("sha256:")
        return f"m4-{digest[:24]}"

    @property
    def tick(self) -> int:
        return _TICK_OFFSET[self.target_tier] + self.ordinal + 1


class ProviderStateChange(_MaterializationModel):
    provider: ProviderName
    before_sha256: Sha256Digest
    after_sha256: Sha256Digest

    @model_validator(mode="after")
    def provider_changed(self) -> ProviderStateChange:
        if self.before_sha256 == self.after_sha256:
            raise ValueError("materialized provider did not change")
        return self


class M4MaterializedStateBinding(_MaterializationModel):
    """Content-derived provenance for one M4 six-provider materialization.

    The current M4 world has no application container.  ``application_image_binding``
    therefore records that bounded fact explicitly instead of assigning the bridge
    image to an application that was not run.
    """

    schema_version: Literal["stateweaver-m4-materialized-state-binding-v1"]
    adapter_pin: AdapterPin
    bridge_image_id: Sha256Digest
    provider_image_refs: tuple[str, ...]
    provider_image_set_digest: Sha256Digest
    source_snapshot: SnapshotManifest
    source_snapshot_id: str
    source_snapshot_manifest_digest: Sha256Digest
    source_snapshot_state_fingerprint: Sha256Digest
    after_archive_digest: Sha256Digest
    provider_state_digest: Sha256Digest
    application_image_binding: Literal["UNOBSERVED"]
    application_image_lineage_status: Literal["PENDING_APPLICATION_EXECUTION"]
    binding_digest: Sha256Digest

    @model_validator(mode="after")
    def binding_is_content_derived(self) -> M4MaterializedStateBinding:
        if (
            not self.source_snapshot_id
            or len(set(self.provider_image_refs)) != len(self.provider_image_refs)
            or tuple(sorted(self.provider_image_refs)) != self.provider_image_refs
            or self.provider_image_set_digest != sha256_digest(self.provider_image_refs)
            or self.source_snapshot.adapter != self.adapter_pin
            or self.source_snapshot_id != self.source_snapshot.snapshot_id
            or self.source_snapshot_manifest_digest != sha256_digest(self.source_snapshot)
            or self.source_snapshot_state_fingerprint != self.source_snapshot.state_fingerprint
        ):
            raise ValueError("M4 materialized image binding is invalid")
        expected = sha256_digest(self.model_dump(mode="python", exclude={"binding_digest"}))
        if self.binding_digest != expected:
            raise ValueError("M4 materialized state binding digest is invalid")
        return self

    @classmethod
    def create(
        cls,
        *,
        adapter_pin: AdapterPin,
        bridge_image_id: str,
        provider_image_refs: tuple[str, ...],
        source_snapshot: SnapshotManifest,
        after_archive_digest: str,
        provider_state_digest: str,
    ) -> M4MaterializedStateBinding:
        if source_snapshot.adapter != adapter_pin:
            raise ValueError("M4 source snapshot adapter does not match materialization")
        refs = tuple(sorted(provider_image_refs))
        values: dict[str, object] = {
            "schema_version": "stateweaver-m4-materialized-state-binding-v1",
            "adapter_pin": adapter_pin,
            "bridge_image_id": bridge_image_id,
            "provider_image_refs": refs,
            "provider_image_set_digest": sha256_digest(refs),
            "source_snapshot": source_snapshot,
            "source_snapshot_id": source_snapshot.snapshot_id,
            "source_snapshot_manifest_digest": sha256_digest(source_snapshot),
            "source_snapshot_state_fingerprint": source_snapshot.state_fingerprint,
            "after_archive_digest": after_archive_digest,
            "provider_state_digest": provider_state_digest,
            "application_image_binding": "UNOBSERVED",
            "application_image_lineage_status": "PENDING_APPLICATION_EXECUTION",
        }
        return cls.model_validate({**values, "binding_digest": sha256_digest(values)})


class MaterializedProviderReceipt(_MaterializationModel):
    """Atomic before/mutate/after observation from one real-provider sibling."""

    schema_version: Literal["stateweaver-m4-provider-materialization-v1"]
    request: MaterializedCandidateRequest
    request_digest: Sha256Digest
    environment_id: ContractId
    marker: str
    tick: Annotated[int, Field(ge=1, le=324)]
    providers: tuple[ProviderStateChange, ...]
    changed_provider_count: Literal[6]
    elapsed_ns: Annotated[int, Field(ge=0)]
    provider_state_digest: Sha256Digest
    state_binding: M4MaterializedStateBinding
    oracle_passed: Literal[True]
    receipt_digest: Sha256Digest

    @model_validator(mode="after")
    def receipt_is_content_bound(self) -> MaterializedProviderReceipt:
        if self.request_digest != sha256_digest(self.request):
            raise ValueError("materialization request digest is invalid")
        if self.marker != self.request.marker or self.tick != self.request.tick:
            raise ValueError("materialization marker is not request-derived")
        if tuple(item.provider for item in self.providers) != _PROVIDERS:
            raise ValueError("materialization receipt must cover every provider exactly once")
        after = {item.provider: item.after_sha256 for item in self.providers}
        if self.provider_state_digest != sha256_digest(after):
            raise ValueError("materialized provider state digest is invalid")
        if self.state_binding.provider_state_digest != self.provider_state_digest:
            raise ValueError("materialized provider state binding does not match receipt")
        expected = sha256_digest(self.model_dump(mode="python", exclude={"receipt_digest"}))
        if self.receipt_digest != expected:
            raise ValueError("materialization receipt digest is invalid")
        return self

    @classmethod
    def create(
        cls,
        *,
        request: MaterializedCandidateRequest,
        environment_id: ContractId,
        before: dict[str, str],
        after: dict[str, str],
        elapsed_ns: int,
        state_binding: M4MaterializedStateBinding,
    ) -> MaterializedProviderReceipt:
        if tuple(sorted(before)) != _PROVIDERS or tuple(sorted(after)) != _PROVIDERS:
            raise ValueError("materialization capture does not cover the fixed providers")
        providers = tuple(
            ProviderStateChange(
                provider=provider,
                before_sha256=before[provider],
                after_sha256=after[provider],
            )
            for provider in _PROVIDERS
        )
        provider_state_digest = sha256_digest(
            {item.provider: item.after_sha256 for item in providers}
        )
        if state_binding.provider_state_digest != provider_state_digest:
            raise ValueError("materialized state binding does not match provider state")
        values: dict[str, object] = {
            "schema_version": "stateweaver-m4-provider-materialization-v1",
            "request": request,
            "request_digest": sha256_digest(request),
            "environment_id": environment_id,
            "marker": request.marker,
            "tick": request.tick,
            "providers": providers,
            "changed_provider_count": 6,
            "elapsed_ns": elapsed_ns,
            "provider_state_digest": provider_state_digest,
            "state_binding": state_binding,
            "oracle_passed": True,
        }
        return cls.model_validate({**values, "receipt_digest": sha256_digest(values)})


class M5ProviderDigest(_MaterializationModel):
    """One provider hash captured during a closed M5 Docker replay step."""

    provider: ProviderName
    sha256: Sha256Digest


class M5MaterializedProviderRunRequest(_MaterializationModel):
    """One Docker-backed M5 replay attempt; it deliberately accepts no command data."""

    repository_marker: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    m4_provider_receipt: MaterializedProviderReceipt
    m4_receipt_sha256: Sha256Digest
    m4_receipt_digest: Sha256Digest
    process_receipt_sha256: Sha256Digest
    process_receipt_digest: Sha256Digest
    plan_id: ContractId
    root_seed_id: ContractId
    root_digest: Sha256Digest
    plan_digest: Sha256Digest
    run_id: ContractId
    scenario: Literal[
        "primary_vulnerable",
        "primary_patched",
        "masked_response",
        "mock_only_response",
        "fresh_session",
        "same_tenant_document",
    ]
    mode: Literal["vulnerable", "patched"]
    actions: tuple[ActionEnvelope, ...]
    expected_oracle_outcome: Literal["VIOLATED", "SATISFIED", "INCONCLUSIVE"]
    expected_response_status: Annotated[int, Field(ge=100, le=599)]
    expected_failed_step_id: ContractId | None = None
    expected_failure_code: Literal["ORACLE_EXPECTATION_MISMATCH"] | None = None

    @model_validator(mode="after")
    def run_is_closed(self) -> M5MaterializedProviderRunRequest:
        expected_routes = _M5_SCENARIO_ROUTES[self.scenario]
        if len(self.actions) != len(expected_routes):
            raise ValueError("M5 materialized replay does not match its closed scenario length")
        if tuple(item.sequence for item in self.actions) != tuple(range(1, len(self.actions) + 1)):
            raise ValueError("M5 materialized actions must have an exact sequence")
        if len({item.action_id for item in self.actions}) != len(self.actions):
            raise ValueError("M5 materialized action IDs must be unique")
        if any(
            not isinstance(item.action, HttpRequestAction)
            or item.action.target is None
            or item.action.method is None
            or item.action.target.scheme != "http"
            or item.action.target.host != "localhost"
            or item.action.target.port != 80
            or item.action.body_artifact is None
            or not item.action.body_artifact.startswith("artifact:lab-action/")
            or item.action.query
            or item.action.headers
            or item.action.template_ref is not None
            or item.requested_by.type.value != "workflow"
            or not item.requested_by.role
            or not item.policy_decision_ref
            or not item.idempotency_key
            for item in self.actions
        ):
            raise ValueError("M5 materialized replay contains an inadmissible action")
        actual_routes = tuple(
            (item.action.method.value, item.action.target.path, item.action.identity_handle)
            for item in self.actions
            if isinstance(item.action, HttpRequestAction)
            and item.action.method is not None
            and item.action.target is not None
        )
        if actual_routes != expected_routes:
            raise ValueError("M5 materialized replay does not match its closed scenario routes")
        final_step = f"step.{len(self.actions):02d}"
        if (self.expected_failed_step_id is None) != (self.expected_failure_code is None):
            raise ValueError("M5 expected failure boundary is incomplete")
        if self.expected_failed_step_id is not None and self.expected_failed_step_id != final_step:
            raise ValueError("M5 failure must be at the exact terminal step")
        if (self.scenario == "primary_patched") != (self.mode == "patched"):
            raise ValueError("M5 scenario and mode disagree")
        if (self.expected_oracle_outcome, self.expected_response_status) != _M5_SCENARIO_BOUNDARIES[
            self.scenario
        ]:
            raise ValueError("M5 scenario does not retain its oracle boundary")
        if self.mode == "patched" and self.expected_failure_code is None:
            raise ValueError("patched M5 replay must retain its terminal mismatch boundary")
        if self.mode == "vulnerable" and self.expected_failure_code is not None:
            raise ValueError("vulnerable M5 replay must not manufacture a failure")
        return self


class M5MaterializedProviderStep(_MaterializationModel):
    """A bridge-executed action and real six-provider before/after state witness."""

    step_id: ContractId
    action: ActionEnvelope
    action_digest: Sha256Digest
    response_status: Annotated[int, Field(ge=100, le=599)]
    oracle_outcome: Literal["VIOLATED", "SATISFIED", "INCONCLUSIVE"]
    before: tuple[M5ProviderDigest, ...]
    after: tuple[M5ProviderDigest, ...]

    @model_validator(mode="after")
    def step_is_content_bound(self) -> M5MaterializedProviderStep:
        if (
            self.action_digest != sha256_digest(self.action)
            or tuple(item.provider for item in self.before) != _PROVIDERS
            or tuple(item.provider for item in self.after) != _PROVIDERS
            or self.before == self.after
        ):
            raise ValueError("M5 materialized provider step is invalid")
        return self


class M5MaterializedProviderRunReceipt(_MaterializationModel):
    """Audited provider-side counterpart of one process-local M5 replay attempt."""

    schema_version: Literal["stateweaver-m5-materialized-provider-run-v1"]
    status: Literal["M5_MATERIALIZED_PROVIDER_RUN_QUALIFIED"]
    request: M5MaterializedProviderRunRequest
    request_digest: Sha256Digest
    steps: tuple[M5MaterializedProviderStep, ...]
    final_provider_state: tuple[M5ProviderDigest, ...]
    restored_provider_state: tuple[M5ProviderDigest, ...]
    cleanup_status: Literal["PASS"]
    destroyed: Literal[True]
    receipt_digest: Sha256Digest

    @model_validator(mode="after")
    def receipt_is_closed(self) -> M5MaterializedProviderRunReceipt:
        baseline = tuple(
            M5ProviderDigest(provider=item.provider, sha256=item.after_sha256)
            for item in self.request.m4_provider_receipt.providers
        )
        if (
            self.request_digest != sha256_digest(self.request)
            or len(self.steps) != len(self.request.actions)
            or tuple(item.step_id for item in self.steps)
            != tuple(f"step.{index:02d}" for index in range(1, len(self.steps) + 1))
            or tuple(item.action for item in self.steps) != self.request.actions
            or self.steps[0].before != baseline
            or any(
                previous.after != following.before
                for previous, following in zip(self.steps, self.steps[1:], strict=False)
            )
            or self.final_provider_state != self.steps[-1].after
            or self.restored_provider_state != baseline
        ):
            raise ValueError("M5 materialized provider run is incoherent")
        expected = sha256_digest(self.model_dump(mode="python", exclude={"receipt_digest"}))
        if self.receipt_digest != expected:
            raise ValueError("M5 materialized provider run digest is invalid")
        return self


__all__ = [
    "M4MaterializedStateBinding",
    "M5MaterializedProviderRunReceipt",
    "M5MaterializedProviderRunRequest",
    "M5MaterializedProviderStep",
    "M5ProviderDigest",
    "MaterializedCandidateRequest",
    "MaterializedProviderReceipt",
    "ProviderStateChange",
]
