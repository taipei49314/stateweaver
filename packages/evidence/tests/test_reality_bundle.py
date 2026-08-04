"""Adversarial tests for immutable-byte Reality pre-receipt resolution."""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from typing import Any, cast

import pytest
from evidence_test_fixtures import plan as fixture_plan
from evidence_test_fixtures import scenario
from pydantic import ValidationError
from reality_bundle_fixtures import (
    _build_bundle,
    _Bundle,
    _entry,
    _model_from_json,
    _oracles,
    _reissue_receipt,
    _remint_bundle,
    _tagged_sha256,
    _trace,
)
from stateweaver.contracts import (
    FidelityLevel,
    FidelityProfile,
    Finding,
    FindingStatus,
    NegativeControl,
    NegativeControlKind,
    OracleOutcome,
    PatchedVersionReplay,
    RealityReplayAttempt,
    canonical_json_bytes,
    sha256_digest,
)
from stateweaver.evidence import (
    RealityAdapterComponent,
    RealityAdapterLock,
    RealityArtifactRole,
    RealityBundleVerificationResult,
    RealityControlDelta,
    RealityControlDeltaDimension,
    RealityDeltaChange,
    RealityManifestEntry,
    RealityTraceArtifact,
    RealityTraceFact,
    RealityTraceLane,
    verify_reality_pre_receipt_bundle,
)
from stateweaver.replay import ReplayPlan, ReplayRunResult, RootSeed, canonical_sha256


class _ReadOnceMapping(Mapping[str, bytes]):
    """Return poisoned bytes on a second lookup so repeated reads cannot pass silently."""

    def __init__(self, values: Mapping[str, bytes]) -> None:
        self._values = dict(values)
        self.reads = dict.fromkeys(values, 0)

    def __getitem__(self, key: str) -> bytes:
        self.reads[key] += 1
        if self.reads[key] > 1:
            return b'{"poisoned":"second-read"}'
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)


@pytest.fixture
def bundle() -> _Bundle:
    return _build_bundle()


def _verify(
    bundle: _Bundle, *, artifacts: Mapping[str, bytes] | None = None
) -> RealityBundleVerificationResult:
    return verify_reality_pre_receipt_bundle(
        receipt_json=bundle.receipt_json,
        manifest_json=bundle.manifest_json,
        artifacts=bundle.artifacts if artifacts is None else artifacts,
    )


def _fidelity() -> FidelityProfile:
    return FidelityProfile(
        code=FidelityLevel.EXACT,
        identity=FidelityLevel.EXACT,
        database=FidelityLevel.EXACT,
        cache=FidelityLevel.OBSERVED,
        queue=FidelityLevel.PARTIAL,
        timing=FidelityLevel.OBSERVED,
    )


def test_valid_synthetic_bundle_is_a_non_promotable_candidate(bundle: _Bundle) -> None:
    result = _verify(bundle)

    assert result.valid
    assert result.errors == ()
    assert result.receipt_hash == bundle.receipt.receipt_hash
    assert result.pre_receipt_manifest_sha256 == _tagged_sha256(bundle.manifest_json)
    assert result.snapshot_sha256 is not None
    assert result.profile == "source-backed-synthetic-v2"
    assert result.event_semantics_verified is True
    assert result.control_delta_derivation_verified is True
    assert result.control_kind_semantics_verified is False
    assert result.primary_semantic_trace_hash is not None
    assert result.promotable is False
    assert result.authoritative is False


def test_control_delta_v2_is_the_exact_artifact_projection(bundle: _Bundle) -> None:
    delta_entry = next(
        entry
        for entry in bundle.manifest.entries
        if entry.role is RealityArtifactRole.CONTROL_DELTA
    )
    primary_root_entry = next(
        entry for entry in bundle.manifest.entries if entry.role is RealityArtifactRole.ROOT
    )
    control_root_entry = next(
        entry for entry in bundle.manifest.entries if entry.role is RealityArtifactRole.CONTROL_ROOT
    )
    delta = RealityControlDelta.model_validate_json(bundle.artifacts[delta_entry.path])
    control = bundle.receipt.negative_controls[0]

    assert delta.schema_version == "reality-control-delta-v2"
    assert delta.projection_scope == "artifact-causal-projection"
    assert delta.kind_semantics_attested is False
    assert delta.primary_plan_sha256 == bundle.receipt.plan_hash
    assert delta.control_plan_sha256 == control.plan_hash
    assert delta.primary_root_sha256 == primary_root_entry.sha256
    assert delta.control_root_sha256 == control_root_entry.sha256
    assert delta.primary_result_signature == bundle.receipt.attempts[0].semantic_signature
    assert delta.control_result_signature == control.semantic_signature
    assert tuple(change.dimension for change in delta.changes) == (
        RealityControlDeltaDimension.PLAN_ARTIFACT,
        RealityControlDeltaDimension.RESULT_SEMANTICS,
    )


def test_control_delta_rejects_an_internally_omitted_source_change(bundle: _Bundle) -> None:
    delta_entry = next(
        entry
        for entry in bundle.manifest.entries
        if entry.role is RealityArtifactRole.CONTROL_DELTA
    )
    delta = RealityControlDelta.model_validate_json(bundle.artifacts[delta_entry.path])

    with pytest.raises(ValidationError, match="exact source projection"):
        RealityControlDelta.model_validate(
            {
                **delta.model_dump(mode="python"),
                "changes": (delta.changes[0],),
            }
        )


def test_control_delta_wire_defaults_cannot_be_omitted_and_reminted(bundle: _Bundle) -> None:
    delta_entry = next(
        entry
        for entry in bundle.manifest.entries
        if entry.role is RealityArtifactRole.CONTROL_DELTA
    )
    control = bundle.receipt.negative_controls[0]
    delta_payload = json.loads(bundle.artifacts[delta_entry.path])
    assert isinstance(delta_payload, dict)
    delta_payload.pop("projection_scope")
    abbreviated_delta = canonical_json_bytes(delta_payload)
    artifacts = {**bundle.artifacts, delta_entry.path: abbreviated_delta}
    forged_control = NegativeControl.model_validate(
        {
            **control.model_dump(mode="python"),
            "control_delta_sha256": _tagged_sha256(abbreviated_delta),
        }
    )
    substituted = _remint_bundle(bundle, artifacts=artifacts, controls=(forged_control,))

    result = _verify(substituted)

    assert not result.valid
    assert result.errors == ("control-delta-derivation-mismatch",)


def test_legacy_control_delta_is_rejected_after_full_bundle_remint(bundle: _Bundle) -> None:
    delta_entry = next(
        entry
        for entry in bundle.manifest.entries
        if entry.role is RealityArtifactRole.CONTROL_DELTA
    )
    control = bundle.receipt.negative_controls[0]
    legacy_delta = canonical_json_bytes(
        {
            "schema_version": "1.0",
            "control_name": control.name,
            "kind": control.kind,
            "changes": [
                {
                    "state_path": "session.prerequisite",
                    "before_sha256": sha256_digest({"present": True}),
                    "after_sha256": sha256_digest({"present": False}),
                }
            ],
        }
    )
    artifacts = {**bundle.artifacts, delta_entry.path: legacy_delta}
    forged_control = NegativeControl.model_validate(
        {
            **control.model_dump(mode="python"),
            "control_delta_sha256": _tagged_sha256(legacy_delta),
        }
    )
    substituted = _remint_bundle(bundle, artifacts=artifacts, controls=(forged_control,))

    result = _verify(substituted)

    assert not result.valid
    assert result.errors == ("artifact-schema-invalid",)


def test_coherently_reminted_delta_claim_cannot_replace_derived_sources(
    bundle: _Bundle,
) -> None:
    delta_entry = next(
        entry
        for entry in bundle.manifest.entries
        if entry.role is RealityArtifactRole.CONTROL_DELTA
    )
    delta = RealityControlDelta.model_validate_json(bundle.artifacts[delta_entry.path])
    control = bundle.receipt.negative_controls[0]
    forged_plan_sha256 = sha256_digest({"forged": "control-plan"})
    forged_changes = tuple(
        RealityDeltaChange(
            dimension=change.dimension,
            primary_sha256=change.primary_sha256,
            control_sha256=(
                forged_plan_sha256
                if change.dimension is RealityControlDeltaDimension.PLAN_ARTIFACT
                else change.control_sha256
            ),
        )
        for change in delta.changes
    )
    forged_delta = RealityControlDelta.model_validate(
        {
            **delta.model_dump(mode="python"),
            "control_plan_sha256": forged_plan_sha256,
            "changes": forged_changes,
        }
    )
    forged_delta_json = forged_delta.canonical_bytes()
    artifacts = {**bundle.artifacts, delta_entry.path: forged_delta_json}
    forged_control = NegativeControl.model_validate(
        {
            **control.model_dump(mode="python"),
            "control_delta_sha256": _tagged_sha256(forged_delta_json),
        }
    )
    substituted = _remint_bundle(bundle, artifacts=artifacts, controls=(forged_control,))

    result = _verify(substituted)

    assert not result.valid
    assert result.errors == ("control-delta-derivation-mismatch",)


def test_missing_control_root_fails_exact_role_closure(bundle: _Bundle) -> None:
    root_entry = next(
        entry for entry in bundle.manifest.entries if entry.role is RealityArtifactRole.CONTROL_ROOT
    )
    artifacts = {path: value for path, value in bundle.artifacts.items() if path != root_entry.path}
    entries = tuple(entry for entry in bundle.manifest.entries if entry.path != root_entry.path)
    substituted = _remint_bundle(bundle, artifacts=artifacts, entries=entries)

    result = _verify(substituted)

    assert not result.valid
    assert result.errors == ("manifest-role-closure-invalid",)


def test_control_root_default_omission_cannot_escape_exact_artifact_derivation(
    bundle: _Bundle,
) -> None:
    root_entry = next(
        entry for entry in bundle.manifest.entries if entry.role is RealityArtifactRole.CONTROL_ROOT
    )
    root_payload = cast(dict[str, Any], json.loads(bundle.artifacts[root_entry.path]))
    capture = cast(dict[str, Any], root_payload["capture"])
    capture_artifacts = cast(list[dict[str, Any]], capture["artifacts"])
    assert capture_artifacts[0].pop("schema_version") == "1.0"
    abbreviated_root = canonical_json_bytes(root_payload)
    artifacts = {**bundle.artifacts, root_entry.path: abbreviated_root}
    substituted = _remint_bundle(bundle, artifacts=artifacts)

    result = _verify(substituted)

    assert not result.valid
    assert result.errors == ("control-delta-derivation-mismatch",)


def test_control_plan_default_omission_cannot_escape_exact_artifact_derivation(
    bundle: _Bundle,
) -> None:
    plan_entry = next(
        entry for entry in bundle.manifest.entries if entry.role is RealityArtifactRole.CONTROL_PLAN
    )
    control = bundle.receipt.negative_controls[0]
    plan_payload = cast(dict[str, Any], json.loads(bundle.artifacts[plan_entry.path]))
    assert plan_payload.pop("schema_version") == "1.0"
    abbreviated_plan = canonical_json_bytes(plan_payload)
    artifacts = {**bundle.artifacts, plan_entry.path: abbreviated_plan}
    forged_control = NegativeControl.model_validate(
        {
            **control.model_dump(mode="python"),
            "plan_hash": _tagged_sha256(abbreviated_plan),
        }
    )
    substituted = _remint_bundle(bundle, artifacts=artifacts, controls=(forged_control,))

    result = _verify(substituted)

    assert not result.valid
    assert result.errors == ("control-delta-derivation-mismatch",)


def test_control_root_random_seed_substitution_fails_after_delta_and_bundle_remint(
    bundle: _Bundle,
) -> None:
    primary_plan_entry = next(
        entry for entry in bundle.manifest.entries if entry.role is RealityArtifactRole.PLAN
    )
    primary_root_entry = next(
        entry for entry in bundle.manifest.entries if entry.role is RealityArtifactRole.ROOT
    )
    primary_result_entry = next(
        entry
        for entry in bundle.manifest.entries
        if entry.role is RealityArtifactRole.PRIMARY_RESULT
        and entry.run_id == bundle.receipt.attempts[0].replay_run_id
    )
    control_root_entry = next(
        entry for entry in bundle.manifest.entries if entry.role is RealityArtifactRole.CONTROL_ROOT
    )
    control_plan_entry = next(
        entry for entry in bundle.manifest.entries if entry.role is RealityArtifactRole.CONTROL_PLAN
    )
    control_result_entry = next(
        entry
        for entry in bundle.manifest.entries
        if entry.role is RealityArtifactRole.CONTROL_RESULT
    )
    delta_entry = next(
        entry
        for entry in bundle.manifest.entries
        if entry.role is RealityArtifactRole.CONTROL_DELTA
    )
    primary_result = ReplayRunResult.model_validate_json(
        bundle.artifacts[primary_result_entry.path]
    )
    control_root = RootSeed.model_validate_json(bundle.artifacts[control_root_entry.path])
    forged_root = RootSeed.model_validate(
        {**control_root.model_dump(mode="python"), "random_seed": control_root.random_seed + 1}
    )
    control_result = ReplayRunResult.model_validate_json(
        bundle.artifacts[control_result_entry.path]
    )
    control = bundle.receipt.negative_controls[0]
    forged_root_json = canonical_json_bytes(forged_root)
    forged_delta = RealityControlDelta.derive(
        control_name=control.name,
        kind=control.kind,
        primary_plan_sha256=primary_plan_entry.sha256,
        primary_root_sha256=primary_root_entry.sha256,
        primary_result=primary_result,
        control_plan_sha256=control_plan_entry.sha256,
        control_root_sha256=_tagged_sha256(forged_root_json),
        control_result=control_result,
    )
    forged_delta_json = forged_delta.canonical_bytes()
    artifacts = {
        **bundle.artifacts,
        control_root_entry.path: forged_root_json,
        delta_entry.path: forged_delta_json,
    }
    forged_control = NegativeControl.model_validate(
        {
            **control.model_dump(mode="python"),
            "control_delta_sha256": _tagged_sha256(forged_delta_json),
        }
    )
    substituted = _remint_bundle(bundle, artifacts=artifacts, controls=(forged_control,))

    result = _verify(substituted)

    assert not result.valid
    assert result.errors == ("control-root-logical-root-mismatch",)


def test_delta_kind_mismatch_is_rejected_after_receipt_and_manifest_remint(
    bundle: _Bundle,
) -> None:
    delta_entry = next(
        entry
        for entry in bundle.manifest.entries
        if entry.role is RealityArtifactRole.CONTROL_DELTA
    )
    delta = RealityControlDelta.model_validate_json(bundle.artifacts[delta_entry.path])
    control = bundle.receipt.negative_controls[0]
    forged_delta = RealityControlDelta.model_validate(
        {**delta.model_dump(mode="python"), "kind": NegativeControlKind.SAME_TENANT}
    )
    forged_delta_json = forged_delta.canonical_bytes()
    artifacts = {**bundle.artifacts, delta_entry.path: forged_delta_json}
    forged_control = NegativeControl.model_validate(
        {
            **control.model_dump(mode="python"),
            "control_delta_sha256": _tagged_sha256(forged_delta_json),
        }
    )
    substituted = _remint_bundle(bundle, artifacts=artifacts, controls=(forged_control,))

    result = _verify(substituted)

    assert not result.valid
    assert result.errors == ("control-binding-mismatch",)


def test_coherent_kind_relabel_stays_explicitly_outside_the_trust_boundary(
    bundle: _Bundle,
) -> None:
    delta_entry = next(
        entry
        for entry in bundle.manifest.entries
        if entry.role is RealityArtifactRole.CONTROL_DELTA
    )
    delta = RealityControlDelta.model_validate_json(bundle.artifacts[delta_entry.path])
    control = bundle.receipt.negative_controls[0]
    relabeled_delta = RealityControlDelta.model_validate(
        {**delta.model_dump(mode="python"), "kind": NegativeControlKind.SAME_TENANT}
    )
    relabeled_delta_json = relabeled_delta.canonical_bytes()
    artifacts = {**bundle.artifacts, delta_entry.path: relabeled_delta_json}
    relabeled_control = NegativeControl.model_validate(
        {
            **control.model_dump(mode="python"),
            "kind": NegativeControlKind.SAME_TENANT,
            "control_delta_sha256": _tagged_sha256(relabeled_delta_json),
        }
    )
    substituted = _remint_bundle(bundle, artifacts=artifacts, controls=(relabeled_control,))

    result = _verify(substituted)

    assert result.valid
    assert result.control_delta_derivation_verified is True
    assert result.control_kind_semantics_verified is False
    assert result.authoritative is False
    assert result.promotable is False


def test_candidate_cannot_promote_a_finding(bundle: _Bundle) -> None:
    result = _verify(bundle)
    assert result.valid and not result.promotable

    with pytest.raises(ValidationError, match="broker-verified artifact attestation"):
        Finding(
            finding_id="finding.synthetic.primary",
            title="Synthetic cross-tenant document disclosure candidate",
            status=FindingStatus.PATCH_VERIFIED,
            chain_id=bundle.receipt.chain_id,
            oracle_result_ids=tuple(
                oracle.oracle_result_id for oracle in bundle.receipt.oracle_results
            ),
            fidelity=_fidelity(),
            reality_replay=bundle.receipt,
        )


def test_artifact_mapping_is_snapshotted_with_one_read_per_path(bundle: _Bundle) -> None:
    artifacts = _ReadOnceMapping(bundle.artifacts)

    result = _verify(bundle, artifacts=artifacts)

    assert result.valid
    assert artifacts.reads == dict.fromkeys(bundle.artifacts, 1)


def test_digest_mutation_is_rejected_before_parsing(bundle: _Bundle) -> None:
    artifacts = dict(bundle.artifacts)
    result_entry = next(
        entry
        for entry in bundle.manifest.entries
        if entry.role is RealityArtifactRole.PRIMARY_RESULT
    )
    artifacts[result_entry.path] += b" "

    result = _verify(bundle, artifacts=artifacts)

    assert not result.valid
    assert result.errors == ("artifact-digest-mismatch",)


@pytest.mark.parametrize(
    "role",
    (
        RealityArtifactRole.PRIMARY_TRACE,
        RealityArtifactRole.CONTROL_TRACE,
        RealityArtifactRole.PATCH_TRACE,
    ),
)
def test_logical_trace_hash_substitution_is_rejected_after_coherent_rehash(
    bundle: _Bundle, role: RealityArtifactRole
) -> None:
    trace_entry = next(entry for entry in bundle.manifest.entries if entry.role is role)
    trace = RealityTraceArtifact.model_validate_json(bundle.artifacts[trace_entry.path])
    substitute = RealityTraceArtifact.create(
        lane=trace.lane,
        run_id=trace.run_id,
        plan_id=trace.plan_id,
        replay_trace_hash=sha256_digest({"substituted_role": role.value}),
        events=trace.events,
    )
    artifacts = {
        **bundle.artifacts,
        trace_entry.path: canonical_json_bytes(substitute),
    }
    substituted = _remint_bundle(bundle, artifacts=artifacts)

    result = _verify(substituted)

    assert not result.valid
    assert result.errors == ("replay-causal-binding-mismatch",)


@pytest.mark.parametrize(
    ("role", "lane"),
    (
        (RealityArtifactRole.PRIMARY_TRACE, RealityTraceLane.PRIMARY),
        (RealityArtifactRole.CONTROL_TRACE, RealityTraceLane.CONTROL),
        (RealityArtifactRole.PATCH_TRACE, RealityTraceLane.PATCH),
    ),
)
def test_trace_events_are_exact_replay_semantic_reconstructions(
    bundle: _Bundle,
    role: RealityArtifactRole,
    lane: RealityTraceLane,
) -> None:
    trace_entry = next(entry for entry in bundle.manifest.entries if entry.role is role)
    result_roles = {
        RealityArtifactRole.PRIMARY_TRACE: RealityArtifactRole.PRIMARY_RESULT,
        RealityArtifactRole.CONTROL_TRACE: RealityArtifactRole.CONTROL_RESULT,
        RealityArtifactRole.PATCH_TRACE: RealityArtifactRole.PATCH_RESULT,
    }
    result_entry = next(
        entry
        for entry in bundle.manifest.entries
        if entry.role is result_roles[role] and entry.run_id == trace_entry.run_id
    )
    trace = RealityTraceArtifact.model_validate_json(bundle.artifacts[trace_entry.path])
    replay_result = ReplayRunResult.model_validate_json(bundle.artifacts[result_entry.path])

    assert trace.schema_version == "2.0"
    assert trace.lane is lane
    assert trace == RealityTraceArtifact.from_replay_result(replay_result, lane=lane)
    assert trace.events[0].event_type.value == "replay.started"
    assert trace.events[-1].event_type.value == (
        "patch.replay.completed" if lane is RealityTraceLane.PATCH else "replay.completed"
    )
    assert tuple(event.sequence for event in trace.events) == tuple(range(len(trace.events)))


@pytest.mark.parametrize(
    "role",
    (
        RealityArtifactRole.PRIMARY_TRACE,
        RealityArtifactRole.CONTROL_TRACE,
        RealityArtifactRole.PATCH_TRACE,
    ),
)
def test_trace_event_payload_substitution_is_rejected_after_full_rehash(
    bundle: _Bundle, role: RealityArtifactRole
) -> None:
    trace_entry = next(entry for entry in bundle.manifest.entries if entry.role is role)
    trace = RealityTraceArtifact.model_validate_json(bundle.artifacts[trace_entry.path])
    event = trace.events[0]
    facts = tuple(
        RealityTraceFact(
            name=fact.name,
            value="sha256:" + "f" * 64 if fact.name == "root_fingerprint" else fact.value,
        )
        for fact in event.payload
    )
    forged_event = event.create(
        event_type=event.event_type,
        run_id=event.run_id,
        plan_id=event.plan_id,
        sequence=event.sequence,
        trace_id=event.trace_id,
        step_id=event.step_id,
        payload=facts,
    )
    events = (forged_event, *trace.events[1:])
    forged_trace = RealityTraceArtifact.create(
        lane=trace.lane,
        run_id=trace.run_id,
        plan_id=trace.plan_id,
        replay_trace_hash=trace.replay_trace_hash,
        events=events,
    )
    artifacts = {
        **bundle.artifacts,
        trace_entry.path: canonical_json_bytes(forged_trace),
    }
    substituted = _remint_bundle(bundle, artifacts=artifacts)

    result = _verify(substituted)

    assert not result.valid
    assert result.errors == ("replay-trace-semantics-mismatch",)


def test_primary_trace_cannot_be_relabeled_as_a_control_lane_after_full_rehash(
    bundle: _Bundle,
) -> None:
    trace_entry = next(
        entry
        for entry in bundle.manifest.entries
        if entry.role is RealityArtifactRole.PRIMARY_TRACE
    )
    trace = RealityTraceArtifact.model_validate_json(bundle.artifacts[trace_entry.path])
    forged_trace = RealityTraceArtifact.create(
        lane=RealityTraceLane.CONTROL,
        run_id=trace.run_id,
        plan_id=trace.plan_id,
        replay_trace_hash=trace.replay_trace_hash,
        events=trace.events,
    )
    artifacts = {
        **bundle.artifacts,
        trace_entry.path: canonical_json_bytes(forged_trace),
    }
    substituted = _remint_bundle(bundle, artifacts=artifacts)

    result = _verify(substituted)

    assert not result.valid
    assert result.errors == ("replay-trace-semantics-mismatch",)


def test_trace_event_omission_fails_closed_before_bundle_remint(bundle: _Bundle) -> None:
    trace_entry = next(
        entry
        for entry in bundle.manifest.entries
        if entry.role is RealityArtifactRole.PRIMARY_TRACE
    )
    trace = RealityTraceArtifact.model_validate_json(bundle.artifacts[trace_entry.path])
    events = tuple(
        event.model_copy(update={"sequence": sequence})
        for sequence, event in enumerate((*trace.events[:1], *trace.events[2:]))
    )
    reminted_events = tuple(
        event.create(
            event_type=event.event_type,
            run_id=event.run_id,
            plan_id=event.plan_id,
            sequence=event.sequence,
            trace_id=event.trace_id,
            step_id=event.step_id,
            payload=event.payload,
        )
        for event in events
    )
    with pytest.raises(ValidationError, match="at least 3 items"):
        RealityTraceArtifact.create(
            lane=trace.lane,
            run_id=trace.run_id,
            plan_id=trace.plan_id,
            replay_trace_hash=trace.replay_trace_hash,
            events=reminted_events,
        )


def test_legacy_v1_trace_profile_is_rejected_even_when_manifest_is_reminted(
    bundle: _Bundle,
) -> None:
    trace_entry = next(
        entry
        for entry in bundle.manifest.entries
        if entry.role is RealityArtifactRole.PRIMARY_TRACE
    )
    trace = RealityTraceArtifact.model_validate_json(bundle.artifacts[trace_entry.path])
    legacy_trace = canonical_json_bytes(
        {
            "schema_version": "1.0",
            "replay_trace_hash": trace.replay_trace_hash,
            "events": [
                {
                    "event_id": "event.legacy.1",
                    "kind": "synthetic.replay",
                    "attributes_sha256": trace.replay_trace_hash,
                }
            ],
        }
    )
    artifacts = {**bundle.artifacts, trace_entry.path: legacy_trace}
    substituted = _remint_bundle(bundle, artifacts=artifacts)

    result = _verify(substituted)

    assert not result.valid
    assert result.errors == ("artifact-schema-invalid",)


def test_manifest_profile_downgrade_is_rejected_with_a_reissued_receipt(
    bundle: _Bundle,
) -> None:
    manifest_payload = bundle.manifest.model_dump(mode="json")
    manifest_payload["schema_version"] = "reality-pre-receipt-v1"
    manifest_payload["profile"] = "source-backed-synthetic-v1"
    manifest_json = canonical_json_bytes(manifest_payload)
    receipt = _reissue_receipt(bundle.receipt, manifest_json=manifest_json)

    result = verify_reality_pre_receipt_bundle(
        receipt_json=receipt.canonical_bytes(),
        manifest_json=manifest_json,
        artifacts=bundle.artifacts,
    )

    assert not result.valid
    assert result.errors == ("artifact-schema-invalid",)


def test_adapter_lock_substitution_is_rejected_after_manifest_rehash(bundle: _Bundle) -> None:
    adapter_entry = next(
        entry for entry in bundle.manifest.entries if entry.role is RealityArtifactRole.ADAPTER_LOCK
    )
    adapter = RealityAdapterLock.model_validate_json(bundle.artifacts[adapter_entry.path])
    component = adapter.entries[0]
    substituted_adapter = RealityAdapterLock(
        entries=(
            RealityAdapterComponent(
                adapter_id=component.adapter_id,
                version=component.version,
                source_sha256=sha256_digest({"substituted": component.adapter_id}),
            ),
        )
    )
    artifacts = {
        **bundle.artifacts,
        adapter_entry.path: canonical_json_bytes(substituted_adapter),
    }
    substituted = _remint_bundle(bundle, artifacts=artifacts)

    result = _verify(substituted)

    assert not result.valid
    assert result.errors == ("receipt-artifact-digest-mismatch",)


def test_artifact_json_uses_compact_contract_canonical_dialect(bundle: _Bundle) -> None:
    chain_entry = next(
        entry for entry in bundle.manifest.entries if entry.role is RealityArtifactRole.CHAIN
    )
    artifacts = {
        **bundle.artifacts,
        chain_entry.path: bundle.artifacts[chain_entry.path] + b"\n",
    }
    substituted = _remint_bundle(bundle, artifacts=artifacts)

    result = _verify(substituted)

    assert not result.valid
    assert result.errors == ("artifact-json-not-canonical",)


@pytest.mark.parametrize(
    "role",
    (
        RealityArtifactRole.PRIMARY_RESULT,
        RealityArtifactRole.CONTROL_RESULT,
        RealityArtifactRole.PATCH_RESULT,
    ),
)
def test_typed_result_run_id_substitution_is_rejected_for_each_replay_kind(
    bundle: _Bundle, role: RealityArtifactRole
) -> None:
    result_entry = next(entry for entry in bundle.manifest.entries if entry.role is role)
    replay_result = ReplayRunResult.model_validate_json(bundle.artifacts[result_entry.path])
    substitute = ReplayRunResult.model_validate(
        {
            **replay_result.model_dump(mode="python"),
            "run_id": f"run.substituted.{role.value}",
        }
    )
    artifacts = {
        **bundle.artifacts,
        result_entry.path: canonical_json_bytes(substitute),
    }
    digest = _tagged_sha256(artifacts[result_entry.path])
    if role is RealityArtifactRole.PRIMARY_RESULT:
        attempts = tuple(
            RealityReplayAttempt.model_validate(
                {
                    **attempt.model_dump(mode="python"),
                    "replay_result_sha256": (
                        digest
                        if attempt.replay_run_id == result_entry.run_id
                        else attempt.replay_result_sha256
                    ),
                }
            )
            for attempt in bundle.receipt.attempts
        )
        substituted = _remint_bundle(bundle, artifacts=artifacts, attempts=attempts)
    elif role is RealityArtifactRole.CONTROL_RESULT:
        controls = tuple(
            NegativeControl.model_validate(
                {
                    **control.model_dump(mode="python"),
                    "replay_result_sha256": (
                        digest
                        if control.replay_run_id == result_entry.run_id
                        else control.replay_result_sha256
                    ),
                }
            )
            for control in bundle.receipt.negative_controls
        )
        substituted = _remint_bundle(bundle, artifacts=artifacts, controls=controls)
    else:
        patch = bundle.receipt.patched_version
        assert patch is not None
        substituted_patch = PatchedVersionReplay.model_validate(
            {
                **patch.model_dump(mode="python"),
                "replay_result_sha256": digest,
            }
        )
        substituted = _remint_bundle(
            bundle,
            artifacts=artifacts,
            patched_version=substituted_patch,
            replace_patch=True,
        )

    result = _verify(substituted)

    assert not result.valid
    assert result.errors == ("replay-causal-binding-mismatch",)


@pytest.mark.parametrize("boundary", ("receipt", "oracle-vector"))
def test_noncanonical_json_is_rejected_at_claim_and_vector_boundaries(
    bundle: _Bundle, boundary: str
) -> None:
    if boundary == "receipt":
        result = verify_reality_pre_receipt_bundle(
            receipt_json=bundle.receipt_json + b"\n",
            manifest_json=bundle.manifest_json,
            artifacts=bundle.artifacts,
        )
    else:
        oracle_entry = next(
            entry
            for entry in bundle.manifest.entries
            if entry.role is RealityArtifactRole.PRIMARY_ORACLES
        )
        artifacts = {
            **bundle.artifacts,
            oracle_entry.path: bundle.artifacts[oracle_entry.path] + b"\n",
        }
        substituted = _remint_bundle(bundle, artifacts=artifacts)
        result = _verify(substituted)

    assert not result.valid
    assert result.errors == ("artifact-json-not-canonical",)


def test_primary_run_swap_is_rejected_after_coherent_rehash(bundle: _Bundle) -> None:
    result_entries = tuple(
        entry
        for entry in bundle.manifest.entries
        if entry.role is RealityArtifactRole.PRIMARY_RESULT
    )
    first_entry, second_entry = result_entries
    artifacts = dict(bundle.artifacts)
    artifacts[first_entry.path], artifacts[second_entry.path] = (
        artifacts[second_entry.path],
        artifacts[first_entry.path],
    )
    swapped_attempts = tuple(
        RealityReplayAttempt.model_validate(
            {
                **attempt.model_dump(mode="python"),
                "replay_result_sha256": _tagged_sha256(
                    artifacts[
                        next(
                            entry.path
                            for entry in result_entries
                            if entry.run_id == attempt.replay_run_id
                        )
                    ]
                ),
            }
        )
        for attempt in bundle.receipt.attempts
    )
    swapped = _remint_bundle(bundle, artifacts=artifacts, attempts=swapped_attempts)

    result = _verify(swapped)

    assert not result.valid
    assert result.errors == ("replay-causal-binding-mismatch",)


def test_manifest_role_closure_rejects_substitution(bundle: _Bundle) -> None:
    entries = tuple(
        RealityManifestEntry.model_validate(
            {
                **entry.model_dump(mode="python"),
                "role": (
                    RealityArtifactRole.EVIDENCE_INDEX
                    if entry.role is RealityArtifactRole.CHAIN
                    else entry.role
                ),
            }
        )
        for entry in bundle.manifest.entries
    )
    substituted = _remint_bundle(bundle, entries=entries)

    result = _verify(substituted)

    assert not result.valid
    assert result.errors == ("manifest-role-closure-invalid",)


def test_manifest_requires_exact_artifact_coverage(bundle: _Bundle) -> None:
    artifacts = {**bundle.artifacts, "extra/untracked.json": canonical_json_bytes({"x": 1})}

    result = _verify(bundle, artifacts=artifacts)

    assert not result.valid
    assert result.errors == ("artifact-coverage-mismatch",)


@pytest.mark.parametrize(
    "forbidden_path",
    (
        "meta/pre-manifest.json",
        "claims/receipt.json",
        "claims/finding.json",
        "meta/report.json",
        "meta/attestation.json",
    ),
)
def test_pre_receipt_manifest_rejects_recursive_or_post_receipt_artifacts(
    bundle: _Bundle, forbidden_path: str
) -> None:
    content = canonical_json_bytes({"kind": "forbidden"})
    artifacts = {**bundle.artifacts, forbidden_path: content}
    entries = (
        *bundle.manifest.entries,
        _entry(role=RealityArtifactRole.CHAIN, path=forbidden_path, content=content),
    )
    recursive = _remint_bundle(bundle, artifacts=artifacts, entries=entries)

    result = _verify(recursive)

    assert not result.valid
    assert result.errors == ("artifact-path-invalid",)


@pytest.mark.parametrize(
    "unsafe_path",
    (
        "../escape.json",
        "/absolute.json",
        "c:/boot.ini",
        "runs\\escape.json",
        "runs/%2e%2e/escape.json",
        "Runs/case.json",
        "runs/nonascii-é.json",
        "runs/file.json:stream",
    ),
)
def test_artifact_snapshot_rejects_noncanonical_or_traversal_paths(
    bundle: _Bundle, unsafe_path: str
) -> None:
    artifacts = {**bundle.artifacts, unsafe_path: canonical_json_bytes({"x": 1})}

    result = _verify(bundle, artifacts=artifacts)

    assert not result.valid
    assert result.errors == ("artifact-path-invalid",)


def test_noncanonical_manifest_json_is_rejected(bundle: _Bundle) -> None:
    payload = json.loads(bundle.manifest_json.decode("utf-8"))
    noncanonical = json.dumps(payload, indent=2).encode("utf-8")

    result = verify_reality_pre_receipt_bundle(
        receipt_json=bundle.receipt_json,
        manifest_json=noncanonical,
        artifacts=bundle.artifacts,
    )

    assert not result.valid
    assert result.errors == ("artifact-json-not-canonical",)


@pytest.mark.parametrize("model_field", ("receipt", "manifest"))
def test_model_instances_cannot_cross_the_serialized_claim_boundary(
    bundle: _Bundle, model_field: str
) -> None:
    receipt_json: object = bundle.receipt_json
    manifest_json: object = bundle.manifest_json
    if model_field == "receipt":
        receipt_json = bundle.receipt
    else:
        manifest_json = bundle.manifest

    result = verify_reality_pre_receipt_bundle(
        receipt_json=receipt_json,  # type: ignore[arg-type]
        manifest_json=manifest_json,  # type: ignore[arg-type]
        artifacts=bundle.artifacts,
    )

    assert not result.valid
    assert result.errors == ("serialized-input-required",)


def test_artifact_model_instance_is_rejected_instead_of_trusted(bundle: _Bundle) -> None:
    result_entry = next(
        entry
        for entry in bundle.manifest.entries
        if entry.role is RealityArtifactRole.PRIMARY_RESULT
    )
    artifacts: dict[str, object] = dict(bundle.artifacts)
    artifacts[result_entry.path] = ReplayRunResult.model_validate_json(
        bundle.artifacts[result_entry.path]
    )

    result = verify_reality_pre_receipt_bundle(
        receipt_json=bundle.receipt_json,
        manifest_json=bundle.manifest_json,
        artifacts=artifacts,  # type: ignore[arg-type]
    )

    assert not result.valid
    assert result.errors == ("artifact-snapshot-invalid",)


def test_control_result_must_execute_the_retained_plan_envelope_exactly(
    bundle: _Bundle,
) -> None:
    control = bundle.receipt.negative_controls[0]
    plan_entry = next(
        entry for entry in bundle.manifest.entries if entry.role is RealityArtifactRole.CONTROL_PLAN
    )
    result_entry = next(
        entry
        for entry in bundle.manifest.entries
        if entry.role is RealityArtifactRole.CONTROL_RESULT
    )
    log_entry = next(
        entry
        for entry in bundle.manifest.entries
        if entry.role is RealityArtifactRole.CONTROL_ACTION_LOG
    )
    trace_entry = next(
        entry
        for entry in bundle.manifest.entries
        if entry.role is RealityArtifactRole.CONTROL_TRACE
    )
    root_entry = next(
        entry for entry in bundle.manifest.entries if entry.role is RealityArtifactRole.CONTROL_ROOT
    )
    retained_plan = ReplayPlan.model_validate_json(bundle.artifacts[plan_entry.path])
    retained_action = retained_plan.steps[0].action
    substituted_plan = fixture_plan(
        plan_id=retained_plan.plan_id,
        action_id=retained_action.action_id,
        decision_ref=retained_action.policy_decision_ref,
        outcome=OracleOutcome.SATISFIED,
        path="/v1/lab/substituted-plan-envelope",
        expected_statuses=(200, 403),
    )
    primary_root = RootSeed.model_validate_json(bundle.artifacts[root_entry.path])
    raw_substitute = scenario(
        name="substituted_control",
        run_id=control.replay_run_id,
        replay_plan=substituted_plan,
        root_seed=primary_root,
        oracle_outcome=OracleOutcome.SATISFIED,
        response_status=403,
    )
    substitute = _model_from_json(ReplayRunResult, raw_substitute["replay_result"])
    assert _oracles(substitute) == control.oracle_results
    artifacts = dict(bundle.artifacts)
    artifacts[result_entry.path] = canonical_json_bytes(substitute)
    artifacts[log_entry.path] = canonical_json_bytes(substitute.action_log)
    artifacts[trace_entry.path] = canonical_json_bytes(
        _trace(substitute, lane=RealityTraceLane.CONTROL)
    )
    forged_control = NegativeControl.model_validate(
        {
            **control.model_dump(mode="python"),
            "replay_result_sha256": _tagged_sha256(artifacts[result_entry.path]),
            "action_log_sha256": _tagged_sha256(artifacts[log_entry.path]),
            "trace_hash": substitute.trace_hash,
            "semantic_signature": substitute.deterministic_signature(),
        }
    )
    substituted = _remint_bundle(bundle, artifacts=artifacts, controls=(forged_control,))

    result = _verify(substituted)

    assert not result.valid
    assert result.errors == ("replay-plan-execution-mismatch",)


def test_patched_root_random_seed_must_match_the_primary_logical_root(
    bundle: _Bundle,
) -> None:
    root_entry = next(
        entry for entry in bundle.manifest.entries if entry.role is RealityArtifactRole.PATCH_ROOT
    )
    root = RootSeed.model_validate_json(bundle.artifacts[root_entry.path])
    substituted_root = RootSeed.model_validate(
        {**root.model_dump(mode="python"), "random_seed": root.random_seed + 1}
    )
    artifacts = {
        **bundle.artifacts,
        root_entry.path: canonical_json_bytes(substituted_root),
    }
    substituted = _remint_bundle(bundle, artifacts=artifacts)

    result = _verify(substituted)

    assert not result.valid
    assert result.errors == ("patch-binding-mismatch",)


def test_patched_block_cannot_be_claimed_from_an_unrelated_failure_code(
    bundle: _Bundle,
) -> None:
    patch = bundle.receipt.patched_version
    assert patch is not None
    result_entry = next(
        entry for entry in bundle.manifest.entries if entry.role is RealityArtifactRole.PATCH_RESULT
    )
    trace_entry = next(
        entry for entry in bundle.manifest.entries if entry.role is RealityArtifactRole.PATCH_TRACE
    )
    replay_result = ReplayRunResult.model_validate_json(bundle.artifacts[result_entry.path])
    failed_step = replay_result.steps[0]
    substituted_step = type(failed_step).model_validate(
        {**failed_step.model_dump(mode="python"), "failure_code": "EXECUTE_TIMEOUT"}
    )
    substituted_steps = (substituted_step, *replay_result.steps[1:])
    trace_hash = canonical_sha256(
        {
            "plan_id": replay_result.plan_id,
            "status": replay_result.status,
            "root_fingerprint": replay_result.root_fingerprint,
            "final_fingerprint": replay_result.final_fingerprint,
            "steps": substituted_steps,
            "action_log": replay_result.action_log,
            "failed_step_id": replay_result.failed_step_id,
        }
    )
    substitute = ReplayRunResult.model_validate(
        {
            **replay_result.model_dump(mode="python"),
            "steps": substituted_steps,
            "trace_hash": trace_hash,
        }
    )
    artifacts = dict(bundle.artifacts)
    artifacts[result_entry.path] = canonical_json_bytes(substitute)
    artifacts[trace_entry.path] = canonical_json_bytes(
        _trace(substitute, lane=RealityTraceLane.PATCH)
    )
    forged_patch = PatchedVersionReplay.model_validate(
        {
            **patch.model_dump(mode="python"),
            "replay_result_sha256": _tagged_sha256(artifacts[result_entry.path]),
            "trace_hash": substitute.trace_hash,
            "semantic_signature": substitute.deterministic_signature(),
            "failure_code": "EXECUTE_TIMEOUT",
        }
    )
    substituted = _remint_bundle(
        bundle,
        artifacts=artifacts,
        patched_version=forged_patch,
        replace_patch=True,
    )

    result = _verify(substituted)

    assert not result.valid
    assert result.errors == ("patch-binding-mismatch",)


def test_control_result_substitution_is_rejected(bundle: _Bundle) -> None:
    control = bundle.receipt.negative_controls[0]
    plan_entry = next(
        entry for entry in bundle.manifest.entries if entry.role is RealityArtifactRole.CONTROL_PLAN
    )
    result_entry = next(
        entry
        for entry in bundle.manifest.entries
        if entry.role is RealityArtifactRole.CONTROL_RESULT
    )
    trace_entry = next(
        entry
        for entry in bundle.manifest.entries
        if entry.role is RealityArtifactRole.CONTROL_TRACE
    )
    root_entry = next(
        entry for entry in bundle.manifest.entries if entry.role is RealityArtifactRole.CONTROL_ROOT
    )
    control_plan = ReplayPlan.model_validate_json(bundle.artifacts[plan_entry.path])
    primary_root = RootSeed.model_validate_json(bundle.artifacts[root_entry.path])
    raw_substitute = scenario(
        name="substituted_control",
        run_id=control.replay_run_id,
        replay_plan=control_plan,
        root_seed=primary_root,
        oracle_outcome=OracleOutcome.VIOLATED,
        response_status=200,
    )
    substitute = _model_from_json(ReplayRunResult, raw_substitute["replay_result"])
    artifacts = dict(bundle.artifacts)
    artifacts[result_entry.path] = canonical_json_bytes(substitute)
    artifacts[trace_entry.path] = canonical_json_bytes(
        _trace(substitute, lane=RealityTraceLane.CONTROL)
    )
    forged_control = NegativeControl.model_validate(
        {
            **control.model_dump(mode="python"),
            "replay_result_sha256": _tagged_sha256(artifacts[result_entry.path]),
            "trace_hash": substitute.trace_hash,
            "semantic_signature": substitute.deterministic_signature(),
        }
    )
    substituted = _remint_bundle(bundle, artifacts=artifacts, controls=(forged_control,))

    result = _verify(substituted)

    assert not result.valid
    assert result.errors == ("replay-causal-binding-mismatch",)


def test_patch_result_substitution_is_rejected(bundle: _Bundle) -> None:
    patch = bundle.receipt.patched_version
    assert patch is not None
    plan_entry = next(
        entry for entry in bundle.manifest.entries if entry.role is RealityArtifactRole.PLAN
    )
    root_entry = next(
        entry for entry in bundle.manifest.entries if entry.role is RealityArtifactRole.PATCH_ROOT
    )
    result_entry = next(
        entry for entry in bundle.manifest.entries if entry.role is RealityArtifactRole.PATCH_RESULT
    )
    trace_entry = next(
        entry for entry in bundle.manifest.entries if entry.role is RealityArtifactRole.PATCH_TRACE
    )
    replay_plan = ReplayPlan.model_validate_json(bundle.artifacts[plan_entry.path])
    patch_root = RootSeed.model_validate_json(bundle.artifacts[root_entry.path])
    raw_substitute = scenario(
        name="substituted_patch",
        run_id=patch.replay_run_id,
        replay_plan=replay_plan,
        root_seed=patch_root,
        oracle_outcome=OracleOutcome.SATISFIED,
        response_status=200,
        failed=False,
    )
    substitute = _model_from_json(ReplayRunResult, raw_substitute["replay_result"])
    artifacts = dict(bundle.artifacts)
    artifacts[result_entry.path] = canonical_json_bytes(substitute)
    artifacts[trace_entry.path] = canonical_json_bytes(
        _trace(substitute, lane=RealityTraceLane.PATCH)
    )
    forged_patch = PatchedVersionReplay.model_validate(
        {
            **patch.model_dump(mode="python"),
            "replay_result_sha256": _tagged_sha256(artifacts[result_entry.path]),
            "trace_hash": substitute.trace_hash,
            "semantic_signature": substitute.deterministic_signature(),
        }
    )
    substituted = _remint_bundle(
        bundle,
        artifacts=artifacts,
        patched_version=forged_patch,
        replace_patch=True,
    )

    result = _verify(substituted)

    assert not result.valid
    assert result.errors == ("patch-binding-mismatch",)
