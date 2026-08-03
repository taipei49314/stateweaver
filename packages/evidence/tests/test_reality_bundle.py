"""Adversarial tests for immutable-byte Reality pre-receipt resolution."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any, cast

import pytest
from evidence_test_fixtures import foundation, scenario
from pydantic import BaseModel, ValidationError
from stateweaver.contracts import (
    FidelityLevel,
    FidelityProfile,
    Finding,
    FindingStatus,
    NegativeControl,
    NegativeControlKind,
    OracleOutcome,
    OracleResult,
    PatchedVersionReplay,
    ProvenanceKind,
    RealityAnchorMode,
    RealityReplayAttempt,
    RealityReplayReceipt,
    ReplayOutcome,
    ScopeManifest,
    canonical_json_bytes,
    sha256_digest,
)
from stateweaver.evidence import (
    RealityAdapterComponent,
    RealityAdapterLock,
    RealityArtifactRole,
    RealityBundleVerificationResult,
    RealityChainBinding,
    RealityControlDelta,
    RealityDeltaChange,
    RealityEvidenceFact,
    RealityEvidenceIndex,
    RealityEvidenceItem,
    RealityEvidenceManifestV1,
    RealityManifestEntry,
    RealityScopeArtifact,
    RealityTargetLock,
    RealityTraceArtifact,
    RealityTraceEvent,
    verify_reality_pre_receipt_bundle,
)
from stateweaver.replay import ReplayPlan, ReplayRunResult, RootSeed


@dataclass(frozen=True)
class _Bundle:
    receipt: RealityReplayReceipt
    receipt_json: bytes
    manifest: RealityEvidenceManifestV1
    manifest_json: bytes
    artifacts: dict[str, bytes]


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


def _tagged_sha256(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def _model_from_json[ModelT: BaseModel](model_type: type[ModelT], value: object) -> ModelT:
    return model_type.model_validate_json(canonical_json_bytes(value))


def _oracles(result: ReplayRunResult) -> tuple[OracleResult, ...]:
    return tuple(oracle for step in result.steps for oracle in step.oracle_results)


def _evidence_ids(oracles: tuple[OracleResult, ...]) -> tuple[str, ...]:
    return tuple(sorted({evidence_id for oracle in oracles for evidence_id in oracle.evidence_ids}))


def _trace(result: ReplayRunResult, *, event_id: str) -> RealityTraceArtifact:
    return RealityTraceArtifact(
        replay_trace_hash=result.trace_hash,
        events=(
            RealityTraceEvent(
                event_id=event_id,
                kind="synthetic.replay",
                attributes_sha256=result.trace_hash,
            ),
        ),
    )


def _entry(
    *,
    role: RealityArtifactRole,
    path: str,
    content: bytes,
    run_id: str | None = None,
    control_name: str | None = None,
) -> RealityManifestEntry:
    return RealityManifestEntry(
        role=role,
        path=path,
        sha256=_tagged_sha256(content),
        run_id=run_id,
        control_name=control_name,
    )


def _reissue_receipt(
    receipt: RealityReplayReceipt,
    *,
    manifest_json: bytes,
    attempts: tuple[RealityReplayAttempt, ...] | None = None,
    controls: tuple[NegativeControl, ...] | None = None,
    patched_version: PatchedVersionReplay | None = None,
    replace_patch: bool = False,
) -> RealityReplayReceipt:
    return RealityReplayReceipt.create(
        anchor_mode=receipt.anchor_mode,
        scope_id=receipt.scope_id,
        scope_manifest_sha256=receipt.scope_manifest_sha256,
        target_id=receipt.target_id,
        target_version=receipt.target_version,
        target_lock_sha256=receipt.target_lock_sha256,
        adapter_lock_sha256=receipt.adapter_lock_sha256,
        chain_id=receipt.chain_id,
        plan_id=receipt.plan_id,
        plan_hash=receipt.plan_hash,
        root_seed_id=receipt.root_seed_id,
        root_fingerprint=receipt.root_fingerprint,
        attempts=receipt.attempts if attempts is None else attempts,
        oracle_results=receipt.oracle_results,
        negative_controls=receipt.negative_controls if controls is None else controls,
        patched_version=(patched_version if replace_patch else receipt.patched_version),
        pre_receipt_evidence_manifest_sha256=_tagged_sha256(manifest_json),
    )


def _remint_bundle(
    bundle: _Bundle,
    *,
    artifacts: dict[str, bytes] | None = None,
    entries: tuple[RealityManifestEntry, ...] | None = None,
    attempts: tuple[RealityReplayAttempt, ...] | None = None,
    controls: tuple[NegativeControl, ...] | None = None,
    patched_version: PatchedVersionReplay | None = None,
    replace_patch: bool = False,
) -> _Bundle:
    next_artifacts = dict(bundle.artifacts if artifacts is None else artifacts)
    source_entries = bundle.manifest.entries if entries is None else entries
    next_entries = tuple(
        sorted(
            (
                RealityManifestEntry.model_validate(
                    {
                        **entry.model_dump(mode="python"),
                        "sha256": _tagged_sha256(next_artifacts[entry.path]),
                    }
                )
                for entry in source_entries
            ),
            key=lambda entry: entry.path,
        )
    )
    manifest = RealityEvidenceManifestV1(entries=next_entries)
    manifest_json = manifest.canonical_bytes()
    receipt = _reissue_receipt(
        bundle.receipt,
        manifest_json=manifest_json,
        attempts=attempts,
        controls=controls,
        patched_version=patched_version,
        replace_patch=replace_patch,
    )
    return _Bundle(
        receipt=receipt,
        receipt_json=receipt.canonical_bytes(),
        manifest=manifest,
        manifest_json=manifest_json,
        artifacts=next_artifacts,
    )


def _build_bundle() -> _Bundle:
    proof = cast(dict[str, Any], foundation())
    vulnerable = cast(dict[str, Any], proof["vulnerable"])
    attempt_sources = cast(list[dict[str, object]], vulnerable["attempts"])[0:2]
    control_source = cast(list[dict[str, object]], proof["negative_controls"])[0]
    patch_summary = cast(dict[str, Any], proof["patched"])
    patch_source = cast(dict[str, object], patch_summary["proof"])

    scope = _model_from_json(ScopeManifest, proof["scope_manifest"])
    plan = _model_from_json(ReplayPlan, proof["canonical_plan"])
    primary_root = _model_from_json(RootSeed, proof["root_state"])
    control_plan = _model_from_json(ReplayPlan, control_source["plan"])
    patch_root = _model_from_json(RootSeed, patch_source["root_seed"])
    primary_results = tuple(
        _model_from_json(ReplayRunResult, source["replay_result"]) for source in attempt_sources
    )
    control_result = _model_from_json(ReplayRunResult, control_source["replay_result"])
    patch_result = _model_from_json(ReplayRunResult, patch_source["replay_result"])
    primary_oracles = _oracles(primary_results[0])
    control_oracles = _oracles(control_result)
    patch_oracles = _oracles(patch_result)
    assert all(_oracles(result) == primary_oracles for result in primary_results)
    assert all(oracle.provenance is ProvenanceKind.OBSERVED for oracle in control_oracles)

    artifacts: dict[str, bytes] = {}
    entries: list[RealityManifestEntry] = []

    def add(
        path: str,
        role: RealityArtifactRole,
        value: object,
        *,
        run_id: str | None = None,
        control_name: str | None = None,
    ) -> str:
        content = canonical_json_bytes(value)
        artifacts[path] = content
        entries.append(
            _entry(
                role=role,
                path=path,
                content=content,
                run_id=run_id,
                control_name=control_name,
            )
        )
        return _tagged_sha256(content)

    scope_hash = add(
        "scope/scope.json",
        RealityArtifactRole.SCOPE,
        RealityScopeArtifact(scope_id="scope.synthetic.lab", manifest=scope),
    )
    target_hash = add(
        "locks/target.json",
        RealityArtifactRole.TARGET_LOCK,
        RealityTargetLock(
            target_id="target.synthetic.lab",
            target_version="lab-vulnerable",
            source_sha256=sha256_digest({"target": "lab-vulnerable"}),
        ),
    )
    adapter_lock = RealityAdapterLock(
        entries=(
            RealityAdapterComponent(
                adapter_id="fixture",
                version="1.0.0",
                source_sha256=sha256_digest({"adapter": "fixture", "version": "1.0.0"}),
            ),
        )
    )
    adapter_hash = add("locks/adapter.json", RealityArtifactRole.ADAPTER_LOCK, adapter_lock)
    add("roots/primary.json", RealityArtifactRole.ROOT, primary_root)
    plan_hash = add("plans/primary.json", RealityArtifactRole.PLAN, plan)
    add(
        "chains/primary.json",
        RealityArtifactRole.CHAIN,
        RealityChainBinding(
            chain_id="chain.synthetic.primary",
            plan_id=plan.plan_id,
            plan_hash=plan_hash,
        ),
    )
    primary_oracle_hash = add(
        "oracles/primary.json", RealityArtifactRole.PRIMARY_ORACLES, primary_oracles
    )

    attempts: list[RealityReplayAttempt] = []
    for index, result in enumerate(primary_results, start=1):
        run_path = f"runs/primary-{index}"
        result_hash = add(
            f"{run_path}/result.json",
            RealityArtifactRole.PRIMARY_RESULT,
            result,
            run_id=result.run_id,
        )
        action_log_hash = add(
            f"{run_path}/action-log.json",
            RealityArtifactRole.PRIMARY_ACTION_LOG,
            result.action_log,
            run_id=result.run_id,
        )
        add(
            f"{run_path}/trace.json",
            RealityArtifactRole.PRIMARY_TRACE,
            _trace(result, event_id=f"event.primary.{index}"),
            run_id=result.run_id,
        )
        attempts.append(
            RealityReplayAttempt(
                replay_run_id=result.run_id,
                replay_outcome=ReplayOutcome.REPRODUCED,
                scope_manifest_sha256=scope_hash,
                target_id="target.synthetic.lab",
                target_version="lab-vulnerable",
                target_lock_sha256=target_hash,
                adapter_lock_sha256=adapter_hash,
                plan_id=plan.plan_id,
                plan_hash=plan_hash,
                root_seed_id=primary_root.root_seed_id,
                root_fingerprint=primary_root.capture.fingerprint,
                replay_result_sha256=result_hash,
                action_log_sha256=action_log_hash,
                trace_hash=result.trace_hash,
                semantic_signature=result.deterministic_signature(),
                oracle_results_hash=primary_oracle_hash,
                evidence_ids=_evidence_ids(primary_oracles),
            )
        )

    control_name = cast(str, control_source["name"])
    control_path = "controls/removed-precondition"
    control_plan_hash = add(
        f"{control_path}/plan.json",
        RealityArtifactRole.CONTROL_PLAN,
        control_plan,
        run_id=control_result.run_id,
        control_name=control_name,
    )
    control_result_hash = add(
        f"{control_path}/result.json",
        RealityArtifactRole.CONTROL_RESULT,
        control_result,
        run_id=control_result.run_id,
        control_name=control_name,
    )
    control_action_log_hash = add(
        f"{control_path}/action-log.json",
        RealityArtifactRole.CONTROL_ACTION_LOG,
        control_result.action_log,
        run_id=control_result.run_id,
        control_name=control_name,
    )
    add(
        f"{control_path}/trace.json",
        RealityArtifactRole.CONTROL_TRACE,
        _trace(control_result, event_id="event.control.1"),
        run_id=control_result.run_id,
        control_name=control_name,
    )
    control_oracle_hash = add(
        f"{control_path}/oracles.json",
        RealityArtifactRole.CONTROL_ORACLES,
        control_oracles,
        run_id=control_result.run_id,
        control_name=control_name,
    )
    control_delta = RealityControlDelta(
        control_name=control_name,
        kind=NegativeControlKind.REMOVED_PRECONDITION,
        changes=(
            RealityDeltaChange(
                state_path="session.prerequisite",
                before_sha256=sha256_digest({"present": True}),
                after_sha256=sha256_digest({"present": False}),
            ),
        ),
    )
    control_delta_hash = add(
        f"{control_path}/delta.json",
        RealityArtifactRole.CONTROL_DELTA,
        control_delta,
        run_id=control_result.run_id,
        control_name=control_name,
    )
    control = NegativeControl(
        name=control_name,
        kind=NegativeControlKind.REMOVED_PRECONDITION,
        target_id="target.synthetic.lab",
        target_version="lab-vulnerable",
        target_lock_sha256=target_hash,
        adapter_lock_sha256=adapter_hash,
        plan_id=control_plan.plan_id,
        plan_hash=control_plan_hash,
        root_seed_id=primary_root.root_seed_id,
        root_fingerprint=primary_root.capture.fingerprint,
        replay_run_id=control_result.run_id,
        replay_result_sha256=control_result_hash,
        action_log_sha256=control_action_log_hash,
        control_delta_sha256=control_delta_hash,
        trace_hash=control_result.trace_hash,
        semantic_signature=control_result.deterministic_signature(),
        result=ReplayOutcome.NOT_REPRODUCED,
        oracle_results=control_oracles,
        oracle_results_hash=control_oracle_hash,
        evidence_ids=_evidence_ids(control_oracles),
    )

    patch_target_hash = add(
        "patch/target-lock.json",
        RealityArtifactRole.PATCH_TARGET_LOCK,
        RealityTargetLock(
            target_id="target.synthetic.lab",
            target_version="lab-patched",
            source_sha256=sha256_digest({"target": "lab-patched"}),
        ),
        run_id=patch_result.run_id,
    )
    add(
        "patch/root.json",
        RealityArtifactRole.PATCH_ROOT,
        patch_root,
        run_id=patch_result.run_id,
    )
    patch_result_hash = add(
        "patch/result.json",
        RealityArtifactRole.PATCH_RESULT,
        patch_result,
        run_id=patch_result.run_id,
    )
    patch_action_log_hash = add(
        "patch/action-log.json",
        RealityArtifactRole.PATCH_ACTION_LOG,
        patch_result.action_log,
        run_id=patch_result.run_id,
    )
    add(
        "patch/trace.json",
        RealityArtifactRole.PATCH_TRACE,
        _trace(patch_result, event_id="event.patch.1"),
        run_id=patch_result.run_id,
    )
    patch_oracle_hash = add(
        "patch/oracles.json",
        RealityArtifactRole.PATCH_ORACLES,
        patch_oracles,
        run_id=patch_result.run_id,
    )
    failed_step = next(step for step in patch_result.steps if step.step_id == "step.00")
    assert failed_step.failure_code is not None
    patched = PatchedVersionReplay(
        target_id="target.synthetic.lab",
        target_version="lab-patched",
        target_lock_sha256=patch_target_hash,
        adapter_lock_sha256=adapter_hash,
        plan_id=plan.plan_id,
        plan_hash=plan_hash,
        root_seed_id=patch_root.root_seed_id,
        root_fingerprint=patch_root.capture.fingerprint,
        replay_run_id=patch_result.run_id,
        replay_result_sha256=patch_result_hash,
        action_log_sha256=patch_action_log_hash,
        trace_hash=patch_result.trace_hash,
        semantic_signature=patch_result.deterministic_signature(),
        replay_result=ReplayOutcome.BLOCKED_BY_FIX,
        oracle_results=patch_oracles,
        oracle_results_hash=patch_oracle_hash,
        evidence_ids=_evidence_ids(patch_oracles),
        failed_step_id=patch_result.failed_step_id or "step.00",
        failure_code=failed_step.failure_code,
    )

    all_evidence_ids = sorted(
        {
            *_evidence_ids(primary_oracles),
            *_evidence_ids(control_oracles),
            *_evidence_ids(patch_oracles),
        }
    )
    evidence_items: list[RealityEvidenceItem] = []
    for evidence_id in all_evidence_ids:
        facts = (
            RealityEvidenceFact(name="mode", value="synthetic"),
            RealityEvidenceFact(name="source", value="in-process"),
        )
        evidence_items.append(
            RealityEvidenceItem(
                evidence_id=evidence_id,
                provenance=ProvenanceKind.OBSERVED,
                facts=facts,
                payload_sha256=sha256_digest(facts),
            )
        )
    add(
        "evidence/index.json",
        RealityArtifactRole.EVIDENCE_INDEX,
        RealityEvidenceIndex(items=tuple(evidence_items)),
    )

    manifest = RealityEvidenceManifestV1(entries=tuple(sorted(entries, key=lambda item: item.path)))
    manifest_json = manifest.canonical_bytes()
    receipt = RealityReplayReceipt.create(
        anchor_mode=RealityAnchorMode.SOURCE_BACKED,
        scope_id="scope.synthetic.lab",
        scope_manifest_sha256=scope_hash,
        target_id="target.synthetic.lab",
        target_version="lab-vulnerable",
        target_lock_sha256=target_hash,
        adapter_lock_sha256=adapter_hash,
        chain_id="chain.synthetic.primary",
        plan_id=plan.plan_id,
        plan_hash=plan_hash,
        root_seed_id=primary_root.root_seed_id,
        root_fingerprint=primary_root.capture.fingerprint,
        attempts=tuple(attempts),
        oracle_results=primary_oracles,
        negative_controls=(control,),
        patched_version=patched,
        pre_receipt_evidence_manifest_sha256=_tagged_sha256(manifest_json),
    )
    return _Bundle(
        receipt=receipt,
        receipt_json=receipt.canonical_bytes(),
        manifest=manifest,
        manifest_json=manifest_json,
        artifacts=artifacts,
    )


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
    assert result.promotable is False
    assert result.authoritative is False


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
    substitute = RealityTraceArtifact(
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
        entry for entry in bundle.manifest.entries if entry.role is RealityArtifactRole.ROOT
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
        _trace(substitute, event_id="event.control.substitute")
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
        _trace(substitute, event_id="event.patch.substitute")
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
