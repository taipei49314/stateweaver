from __future__ import annotations

from datetime import UTC, datetime, timedelta
from math import nan

import pytest
from pydantic import TypeAdapter, ValidationError
from stateweaver.contracts import (
    Action,
    ActionEnvelope,
    ActionTarget,
    AdapterVersionPin,
    ClockMode,
    EffectOperation,
    Entity,
    EntityKind,
    EnvironmentMode,
    EstimatedCost,
    EventEnvelope,
    EventType,
    EvidenceKind,
    EvidenceProducer,
    EvidenceRecord,
    ExpectedEffect,
    Fact,
    FidelityLevel,
    FidelityProfile,
    HttpMethod,
    HttpRequestAction,
    Hypothesis,
    HypothesisStatus,
    OracleOutcome,
    OracleResult,
    OracleType,
    PredictedBoundary,
    Provenance,
    ProvenanceKind,
    QueueOrder,
    QueueReorderAction,
    Relation,
    RelationKind,
    RequestedBy,
    RequesterType,
    RiskClass,
    ScopeAction,
    ScopeActions,
    ScopeIdentities,
    ScopeLimits,
    ScopeManifest,
    ScopeMetadata,
    ScopeSpec,
    ScopeTargets,
    ScopeValidity,
    SnapshotReferences,
    StateCondition,
    StateEffect,
    Taint,
    TargetSelector,
    TargetVersionPin,
    TransitionFragment,
    WorldCapabilities,
    WorldClock,
    WorldLineage,
    WorldManifest,
    WorldStatus,
    WorldTier,
    sha256_digest,
    validate_scope_authorization,
    validate_world_parent,
)
from stateweaver.contracts.enums import ComparisonOperator

NOW = datetime(2026, 8, 1, 8, 0, tzinfo=UTC)
DIGEST = "sha256:" + "a" * 64


def scope_manifest() -> ScopeManifest:
    return ScopeManifest(
        metadata=ScopeMetadata(name="local-saas-lab"),
        spec=ScopeSpec(
            environmentMode=EnvironmentMode.SOURCE_BACKED,
            targets=ScopeTargets(
                include=(TargetSelector(host="app.local", ports=(443,), paths=("/api/**",)),),
                exclude=(TargetSelector(paths=("/admin/destructive/**",)),),
            ),
            identities=ScopeIdentities(allowed=("test_user_a", "test_user_b")),
            actions=ScopeActions(
                allow=(ScopeAction.HTTP_REQUEST, ScopeAction.SESSION_ROTATION),
                requireApproval=(ScopeAction.QUEUE_REORDER,),
                deny=(
                    ScopeAction.DENIAL_OF_SERVICE,
                    ScopeAction.PERSISTENCE,
                    ScopeAction.CREDENTIAL_EXFILTRATION,
                    ScopeAction.DESTRUCTIVE_DATA_DELETE,
                ),
            ),
            limits=ScopeLimits(
                requestsPerSecond=2.0,
                concurrentMaterializedWorlds=2,
                maxWriteRequests=30,
            ),
            validity=ScopeValidity(expiresAt=NOW + timedelta(days=30)),
        ),
    )


def request_action() -> HttpRequestAction:
    return HttpRequestAction(
        method=HttpMethod.GET,
        target=ActionTarget(scheme="https", host="app.local", port=443, path="/api/documents/17"),
        identity_handle="identity:test_user_a",
        expected_statuses=(200, 403),
    )


def action_envelope(**overrides: object) -> ActionEnvelope:
    values: dict[str, object] = {
        "action_id": "act_091",
        "experiment_id": "exp_01",
        "world_id": "world_23",
        "scope_action": ScopeAction.HTTP_REQUEST,
        "action": request_action(),
        "expected_effects": (
            ExpectedEffect(path="request.count", operation=EffectOperation.INCREMENT, value=1),
        ),
        "risk_class": RiskClass.READ_ONLY,
        "idempotency_key": DIGEST,
        "requested_by": RequestedBy(type=RequesterType.MODEL, role="hypothesis_generator"),
        "policy_decision_ref": "decision_882",
    }
    values.update(overrides)
    return ActionEnvelope.model_validate(values)


def fidelity() -> FidelityProfile:
    return FidelityProfile(
        code=FidelityLevel.EXACT,
        identity=FidelityLevel.EXACT,
        database=FidelityLevel.EXACT,
        cache=FidelityLevel.OBSERVED,
        queue=FidelityLevel.PARTIAL,
        timing=FidelityLevel.PARTIAL,
    )


def test_closed_schema_rejects_unknown_fields() -> None:
    payload = scope_manifest().model_dump()
    payload["unexpected"] = True

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ScopeManifest.model_validate(payload)

    assert ScopeManifest.model_json_schema()["additionalProperties"] is False


def test_strict_boundary_rejects_numeric_string_coercion() -> None:
    with pytest.raises(ValidationError):
        ScopeLimits(
            requestsPerSecond="2",  # type: ignore[arg-type]
            concurrentMaterializedWorlds=2,
            maxWriteRequests=30,
        )


def test_contracts_are_frozen() -> None:
    manifest = scope_manifest()
    with pytest.raises(ValidationError, match="Instance is frozen"):
        manifest.kind = "Changed"  # type: ignore[assignment]


def test_scope_action_sets_are_disjoint_and_default_deny() -> None:
    with pytest.raises(ValidationError, match="must be disjoint"):
        ScopeActions(
            allow=(ScopeAction.HTTP_REQUEST,),
            deny=(ScopeAction.HTTP_REQUEST,),
        )

    assert (
        scope_manifest().authorization_requirement(ScopeAction.FILE_UPLOAD_TEST).value
        == "unspecified"
    )


def test_action_envelope_round_trip_is_wire_stable() -> None:
    envelope = action_envelope()
    wire = envelope.model_dump_json(by_alias=True)
    restored = ActionEnvelope.model_validate_json(wire)

    assert restored == envelope
    assert restored.model_dump_json(by_alias=True) == wire
    assert restored.action_type == "http.request"


def test_shell_action_is_not_part_of_closed_union() -> None:
    with pytest.raises(ValidationError, match="union_tag_invalid"):
        TypeAdapter(Action).validate_python({"type": "shell.exec", "command": "whoami"})


def test_envelope_requires_policy_and_coherent_risk_metadata() -> None:
    payload = action_envelope().model_dump()
    del payload["policy_decision_ref"]
    with pytest.raises(ValidationError, match="Field required"):
        ActionEnvelope.model_validate(payload)

    with pytest.raises(ValidationError, match="approval reference"):
        action_envelope(risk_class=RiskClass.ELEVATED_REVERSIBLE)

    with pytest.raises(ValidationError, match="requires scope action"):
        action_envelope(scope_action=ScopeAction.BROWSER_INTERACTION)


def test_scope_approval_rule_is_machine_checkable() -> None:
    reorder = QueueReorderAction(
        queue_ref="queue:email",
        job_ref="job:authorization_invalidation",
        order=QueueOrder.FRONT,
    )
    envelope = action_envelope(
        action=reorder,
        scope_action=ScopeAction.QUEUE_REORDER,
        risk_class=RiskClass.REVERSIBLE_STATE_CHANGE,
    )
    with pytest.raises(ValueError, match="requires an approval"):
        validate_scope_authorization(scope_manifest(), envelope, at=NOW)

    approved = action_envelope(
        action=reorder,
        scope_action=ScopeAction.QUEUE_REORDER,
        risk_class=RiskClass.REVERSIBLE_STATE_CHANGE,
        approval_ref="approval_901",
    )
    validate_scope_authorization(scope_manifest(), approved, at=NOW)


def test_fact_and_observed_transition_require_provenance() -> None:
    with pytest.raises(ValidationError, match="observed provenance requires evidence"):
        Provenance(kind=ProvenanceKind.OBSERVED)

    fact = Fact(
        fact_id="fact_001",
        subject="session:s_17",
        predicate="issued_role",
        object="role:editor",
        valid_from=NOW,
        provenance=Provenance(kind=ProvenanceKind.OBSERVED, evidence_ids=("ev_trace_17",)),
        confidence=0.97,
        taint=Taint.TRUSTED_RUNTIME,
    )
    entity = Entity(entity_id="session:s_17", kind=EntityKind.SESSION)
    assert fact.subject == entity.entity_id

    with pytest.raises(ValidationError, match="runtime evidence"):
        TransitionFragment(
            transition_id="tr_stale_auth_cache",
            name="stale authorization cache",
            source=ProvenanceKind.OBSERVED,
            preconditions=(
                StateCondition(
                    path="principal.role", operator=ComparisonOperator.EQ, value="viewer"
                ),
            ),
            action=HttpRequestAction(template_ref="req_read_document"),
            effects=(
                StateEffect(
                    path="capability.foreign_read",
                    operation=EffectOperation.SET,
                    value=True,
                ),
            ),
            observables=(
                StateCondition(path="response.status", operator=ComparisonOperator.EQ, value=200),
            ),
            fidelity=fidelity(),
        )


def test_hypothesis_round_trip_preserves_search_budget() -> None:
    hypothesis = Hypothesis(
        hypothesis_id="hyp_44",
        claim="role downgrade may leave a stale cached authorization decision",
        required_facts=(
            "role_changed",
            "existing_session_preserved",
            "cache_generation_lags_policy",
        ),
        predicted_boundary=PredictedBoundary(type=OracleType.TENANT_ISOLATION),
        novelty_score=0.83,
        information_gain=0.76,
        estimated_cost=EstimatedCost(
            llm_calls=1,
            target_requests=8,
            materialized_worlds=1,
        ),
        suggested_mutations=(
            "role.downgrade",
            "cache.delay_invalidation",
            "session.reuse",
        ),
        status=HypothesisStatus.PROPOSED,
    )

    restored = Hypothesis.model_validate_json(hypothesis.model_dump_json())
    assert restored == hypothesis
    assert restored.estimated_cost.target_requests == 8


def test_world_manifest_pins_target_and_adapters() -> None:
    world = WorldManifest(
        world_id="world_023",
        parent_world_id="world_004",
        root_snapshot_id="snap_root_01",
        tier=WorldTier.MATERIALIZED,
        hypothesis_id="hyp_cache_role_mismatch",
        state_fingerprint=DIGEST,
        seed=982341,
        clock=WorldClock(mode=ClockMode.CONTROLLED, epoch=NOW),
        capabilities=WorldCapabilities(postgres_restore=True, timing_control=FidelityLevel.PARTIAL),
        snapshots=SnapshotReferences(postgres="pg_22"),
        target_version=TargetVersionPin(
            target_id="target_lab", version="vulnerable", image_digest=DIGEST
        ),
        adapter_versions=(AdapterVersionPin(adapter="postgres", version="0.1.0"),),
        lineage=WorldLineage(transitions=("tr_01",)),
        status=WorldStatus.ACTIVE,
    )
    assert world.target_version.version == "vulnerable"

    payload = world.model_dump()
    payload["adapter_versions"] = ()
    with pytest.raises(ValidationError, match="pinned adapter"):
        WorldManifest.model_validate(payload)


def test_world_tier_status_and_lineage_are_coherent() -> None:
    world = WorldManifest(
        world_id="world_023",
        parent_world_id="world_004",
        root_snapshot_id="snap_root_01",
        tier=WorldTier.MATERIALIZED,
        hypothesis_id="hyp_cache_role_mismatch",
        state_fingerprint=DIGEST,
        seed=982341,
        clock=WorldClock(mode=ClockMode.CONTROLLED, epoch=NOW),
        capabilities=WorldCapabilities(postgres_restore=True),
        snapshots=SnapshotReferences(postgres="pg_22"),
        target_version=TargetVersionPin(
            target_id="target_lab", version="vulnerable", image_digest=DIGEST
        ),
        adapter_versions=(AdapterVersionPin(adapter="postgres", version="0.1.0"),),
        lineage=WorldLineage(transitions=("tr_01",)),
        status=WorldStatus.ACTIVE,
    )
    payload = world.model_dump()
    with pytest.raises(ValidationError, match="not valid for tier"):
        WorldManifest.model_validate(
            {**payload, "tier": WorldTier.GHOST, "status": WorldStatus.VERIFIED}
        )
    with pytest.raises(ValidationError, match="not valid for tier"):
        WorldManifest.model_validate({**payload, "status": WorldStatus.GHOST})
    with pytest.raises(ValidationError, match="require a parent"):
        WorldManifest.model_validate(
            {
                **payload,
                "tier": WorldTier.REPLAY,
                "status": WorldStatus.REPLAY,
                "parent_world_id": None,
            }
        )
    root = WorldManifest.model_validate(
        {
            **payload,
            "tier": WorldTier.GHOST,
            "status": WorldStatus.PRUNED,
            "parent_world_id": None,
        }
    )
    assert root.lineage.transitions == ("tr_01",)
    with pytest.raises(ValidationError, match="require a hypothesis"):
        WorldManifest.model_validate(
            {
                **payload,
                "tier": WorldTier.GHOST,
                "status": WorldStatus.GHOST,
                "hypothesis_id": None,
                "lineage": WorldLineage(),
            }
        )
    reordered = WorldManifest.model_validate(
        {
            **payload,
            "adapter_versions": (
                AdapterVersionPin(adapter="redis", version="0.1.0"),
                AdapterVersionPin(adapter="postgres", version="0.1.0"),
            ),
        }
    )
    ordered = WorldManifest.model_validate(
        {
            **payload,
            "adapter_versions": tuple(reversed(reordered.adapter_versions)),
        }
    )
    assert reordered.adapter_versions == ordered.adapter_versions
    assert reordered.canonical_bytes() == ordered.canonical_bytes()

    parent = WorldManifest.model_validate(
        {
            **payload,
            "world_id": "world_004",
            "parent_world_id": None,
            "tier": WorldTier.GHOST,
            "status": WorldStatus.GHOST,
            "snapshots": SnapshotReferences(),
            "lineage": WorldLineage(),
        }
    )
    validate_world_parent(world, parent)
    with pytest.raises(ValueError, match="root snapshot"):
        validate_world_parent(
            world, parent.model_copy(update={"root_snapshot_id": "snap_other_01"})
        )
    with pytest.raises(ValueError, match="extend"):
        validate_world_parent(
            world.model_copy(update={"lineage": WorldLineage(transitions=("tr_other",))}),
            parent.model_copy(update={"lineage": WorldLineage(transitions=("tr_parent",))}),
        )


@pytest.mark.parametrize(
    ("tier", "status"),
    [
        (WorldTier.GHOST, WorldStatus.PROPOSED),
        (WorldTier.GHOST, WorldStatus.GHOST),
        (WorldTier.GHOST, WorldStatus.PRUNED),
        (WorldTier.GHOST, WorldStatus.REJECTED),
        (WorldTier.REPLAY, WorldStatus.REPLAY),
        (WorldTier.REPLAY, WorldStatus.PRUNED),
        (WorldTier.REPLAY, WorldStatus.REJECTED),
        (WorldTier.SIMULATED, WorldStatus.SIMULATED),
        (WorldTier.SIMULATED, WorldStatus.PRUNED),
        (WorldTier.SIMULATED, WorldStatus.REJECTED),
        (WorldTier.MATERIALIZED, WorldStatus.MATERIALIZING),
        (WorldTier.MATERIALIZED, WorldStatus.ACTIVE),
        (WorldTier.MATERIALIZED, WorldStatus.BLOCKED),
        (WorldTier.MATERIALIZED, WorldStatus.FROZEN),
        (WorldTier.MATERIALIZED, WorldStatus.FRAGMENT_EXTRACTED),
        (WorldTier.MATERIALIZED, WorldStatus.COMPOSITION_CANDIDATE),
        (WorldTier.MATERIALIZED, WorldStatus.REPLAYED),
        (WorldTier.MATERIALIZED, WorldStatus.VERIFIED),
        (WorldTier.MATERIALIZED, WorldStatus.REJECTED),
    ],
)
def test_world_tier_status_mapping_accepts_only_lifecycle_pairs(
    tier: WorldTier, status: WorldStatus
) -> None:
    world = WorldManifest(
        world_id="world_lifecycle_01",
        parent_world_id=None if tier is WorldTier.GHOST else "world_parent_01",
        root_snapshot_id="snap_root_01",
        tier=tier,
        hypothesis_id="hyp_lifecycle_01",
        state_fingerprint=DIGEST,
        seed=1,
        clock=WorldClock(mode=ClockMode.CONTROLLED, epoch=NOW),
        capabilities=WorldCapabilities(),
        snapshots=SnapshotReferences(postgres="pg_01")
        if tier is WorldTier.MATERIALIZED
        else SnapshotReferences(),
        target_version=TargetVersionPin(
            target_id="target_lab", version="vulnerable", image_digest=DIGEST
        ),
        adapter_versions=(AdapterVersionPin(adapter="lab", version="0.1.0"),),
        lineage=WorldLineage(),
        status=status,
    )
    assert world.status is status


def test_evidence_requires_digest_and_rejects_traversal() -> None:
    evidence = EvidenceRecord(
        evidence_id="ev_http_812",
        kind=EvidenceKind.HTTP_EXCHANGE,
        artifact_uri="s3://artifacts/exp_1/world_23/http_812.json",
        sha256=DIGEST,
        produced_by=EvidenceProducer(adapter="playwright-http", version="0.1.0"),
        redaction_policy_version="policy_07",
        taint=Taint.UNTRUSTED_TARGET_CONTENT,
        created_at=NOW,
    )
    assert evidence.sha256 == DIGEST

    payload = evidence.model_dump()
    payload["artifact_uri"] = "s3://artifacts/world/../secret"
    with pytest.raises(ValidationError, match="traversal"):
        EvidenceRecord.model_validate(payload)


def test_event_payload_hash_is_verified() -> None:
    actor = RequestedBy(type=RequesterType.WORKFLOW, role="experiment_orchestrator")
    event = EventEnvelope.create(
        event_type=EventType.ACTION_AUTHORIZED,
        experiment_id="exp_01",
        run_id="run_01",
        world_id="world_23",
        actor=actor,
        trace_id="a" * 32,
        timestamp=NOW,
        payload={"action_id": "act_091", "authorized": True},
    )
    assert event.payload_hash == sha256_digest(event.payload)
    assert EventEnvelope.model_validate_json(event.model_dump_json()) == event

    with pytest.raises(TypeError):
        event.payload["authorized"] = False  # type: ignore[index]

    with pytest.raises(ValidationError, match="payload_hash"):
        EventEnvelope.model_validate({**event.model_dump(), "payload": {"authorized": False}})


@pytest.mark.parametrize("effect_type", [StateEffect, ExpectedEffect])
def test_effect_operation_value_matrix_is_shared(
    effect_type: type[StateEffect | ExpectedEffect],
) -> None:
    with pytest.raises(ValidationError, match="set and add"):
        effect_type(path="session.generation", operation=EffectOperation.SET)
    with pytest.raises(ValidationError, match="set and add"):
        effect_type(path="session.roles", operation=EffectOperation.ADD)
    with pytest.raises(ValidationError, match="integer or float"):
        effect_type(path="session.generation", operation=EffectOperation.INCREMENT, value=True)
    with pytest.raises(ValidationError, match="finite"):
        effect_type(
            path="session.generation", operation=EffectOperation.DECREMENT, value=float("inf")
        )

    assert effect_type(path="session.roles", operation=EffectOperation.REMOVE).value is None
    assert effect_type(
        path="session.roles", operation=EffectOperation.REMOVE, value="role:viewer"
    ).value


def test_provenance_and_taint_preserve_target_content_distinction() -> None:
    observed = Provenance(kind=ProvenanceKind.OBSERVED, evidence_ids=("ev_http_812",))
    fact = Fact(
        fact_id="fact_target_body",
        subject="session:s_17",
        predicate="response_body",
        object="untrusted",
        valid_from=NOW,
        provenance=observed,
        confidence=0.8,
        taint=Taint.UNTRUSTED_TARGET_CONTENT,
    )
    assert fact.taint is Taint.UNTRUSTED_TARGET_CONTENT

    relation = Relation(
        relation_id="rel_target_content",
        subject="session:s_17",
        predicate=RelationKind.REFERENCES,
        object="resource:doc_17",
        provenance=observed,
        taint=Taint.UNTRUSTED_TARGET_CONTENT,
    )
    assert relation.taint is Taint.UNTRUSTED_TARGET_CONTENT

    with pytest.raises(ValidationError, match="model-generated"):
        Fact(
            fact_id="fact_hypothesis",
            subject="session:s_17",
            predicate="may_escalate",
            object=True,
            valid_from=NOW,
            provenance=Provenance(kind=ProvenanceKind.HYPOTHESIZED),
            confidence=0.2,
            taint=Taint.TRUSTED_RUNTIME,
        )
    declared = Fact(
        fact_id="fact_declared_source",
        subject="session:s_17",
        predicate="source_declared",
        object=True,
        valid_from=NOW,
        provenance=Provenance(kind=ProvenanceKind.DECLARED),
        confidence=1.0,
        taint=Taint.TRUSTED_SOURCE,
    )
    assert declared.taint is Taint.TRUSTED_SOURCE
    with pytest.raises(ValidationError, match="trusted source"):
        Fact(
            fact_id="fact_bad_declared_source",
            subject="session:s_17",
            predicate="source_declared",
            object=True,
            valid_from=NOW,
            provenance=Provenance(kind=ProvenanceKind.DECLARED),
            confidence=1.0,
            taint=Taint.TRUSTED_RUNTIME,
        )
    with pytest.raises(ValidationError, match="cannot claim evidence"):
        Provenance(kind=ProvenanceKind.UNKNOWN, evidence_ids=("ev_http_812",))
    with pytest.raises(ValidationError, match="supporting evidence"):
        Provenance(kind=ProvenanceKind.INFERRED)


def test_unknown_transition_cannot_claim_evidence_or_fidelity() -> None:
    values: dict[str, object] = {
        "transition_id": "tr_unknown_01",
        "name": "unknown transition",
        "source": ProvenanceKind.UNKNOWN,
        "preconditions": (
            StateCondition(path="principal.role", operator=ComparisonOperator.EQ, value="viewer"),
        ),
        "action": HttpRequestAction(template_ref="req_read_document"),
        "effects": (
            StateEffect(path="capability.read", operation=EffectOperation.SET, value=True),
        ),
        "observables": (
            StateCondition(path="response.status", operator=ComparisonOperator.EQ, value=200),
        ),
        "fidelity": FidelityProfile(),
    }
    assert TransitionFragment.model_validate(values).source is ProvenanceKind.UNKNOWN
    with pytest.raises(ValidationError, match="cannot claim evidence"):
        TransitionFragment.model_validate({**values, "evidence_ids": ("ev_http_812",)})
    with pytest.raises(ValidationError, match="cannot claim fidelity"):
        TransitionFragment.model_validate(
            {**values, "fidelity": FidelityProfile(code=FidelityLevel.PARTIAL)}
        )
    with pytest.raises(ValidationError, match="mocked transitions require supporting evidence"):
        TransitionFragment.model_validate({**values, "source": ProvenanceKind.MOCKED})
    with pytest.raises(ValidationError, match="mocked transitions cannot claim"):
        TransitionFragment.model_validate(
            {
                **values,
                "source": ProvenanceKind.MOCKED,
                "evidence_ids": ("ev_mock_812",),
                "fidelity": FidelityProfile(code=FidelityLevel.OBSERVED),
            }
        )
    with pytest.raises(ValidationError, match="declared transitions require supporting evidence"):
        TransitionFragment.model_validate({**values, "source": ProvenanceKind.DECLARED})


def test_scope_is_canonical_and_valid_at_inclusive_boundaries() -> None:
    first = scope_manifest()
    second = ScopeManifest(
        metadata=ScopeMetadata(name="local-saas-lab"),
        spec=ScopeSpec(
            environmentMode=EnvironmentMode.SOURCE_BACKED,
            targets=ScopeTargets(
                include=(
                    TargetSelector(host="api.local", ports=(443, 80), paths=("/z", "/a")),
                    TargetSelector(host="app.local", ports=(443,), paths=("/api/**",)),
                )
            ),
            identities=ScopeIdentities(allowed=("test_user_b", "test_user_a")),
            actions=ScopeActions(
                allow=(ScopeAction.SESSION_ROTATION, ScopeAction.HTTP_REQUEST),
                requireApproval=(ScopeAction.QUEUE_REORDER,),
            ),
            limits=ScopeLimits(
                requestsPerSecond=2.0,
                concurrentMaterializedWorlds=2,
                maxWriteRequests=30,
            ),
            validity=ScopeValidity(notBefore=NOW, expiresAt=NOW + timedelta(days=1)),
        ),
    )
    reversed_second = second.model_copy(
        update={
            "spec": second.spec.model_copy(
                update={
                    "targets": ScopeTargets(include=tuple(reversed(second.spec.targets.include))),
                    "actions": ScopeActions(
                        allow=tuple(reversed(second.spec.actions.allow)),
                        requireApproval=second.spec.actions.require_approval,
                    ),
                }
            )
        }
    )
    assert second.canonical_bytes() == reversed_second.canonical_bytes()
    assert second.is_valid_at(NOW)
    assert second.is_valid_at(NOW + timedelta(days=1))
    assert not second.is_valid_at(NOW - timedelta(microseconds=1))
    assert first.authorization_requirement(ScopeAction.HTTP_REQUEST).value == "allowed"
    with pytest.raises(ValidationError, match="allow or require approval"):
        ScopeActions(deny=(ScopeAction.HTTP_REQUEST,))


def test_oracle_results_fail_closed_for_deterministic_and_nonfinite_observations() -> None:
    values: dict[str, object] = {
        "oracle_result_id": "oracle_88",
        "oracle_type": OracleType.AUTHORIZATION,
        "world_id": "world_23",
        "invariant": "request.actor == session.actor",
        "result": OracleOutcome.INCONCLUSIVE,
        "observed": {},
        "evidence_ids": (),
        "deterministic": True,
    }
    with pytest.raises(ValidationError, match="machine observations and evidence"):
        OracleResult.model_validate(values)
    with pytest.raises(ValidationError, match="finite"):
        OracleResult.model_validate(
            {
                **values,
                "deterministic": False,
                "observed": {"observed_value": nan},
            }
        )
    with pytest.raises(ValidationError, match="mocked oracle"):
        OracleResult.model_validate(
            {
                **values,
                "observed": {"result": "inconclusive"},
                "evidence_ids": ("ev_http_812",),
                "provenance": ProvenanceKind.MOCKED,
            }
        )
