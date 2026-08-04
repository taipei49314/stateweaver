"""Deterministic synthetic fixtures for Reality pre-receipt bundle tests."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, cast

from evidence_test_fixtures import foundation
from pydantic import BaseModel
from stateweaver.contracts import (
    NegativeControl,
    NegativeControlKind,
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
    RealityChainBinding,
    RealityControlDelta,
    RealityEvidenceFact,
    RealityEvidenceIndex,
    RealityEvidenceItem,
    RealityEvidenceManifestV2,
    RealityManifestEntry,
    RealityScopeArtifact,
    RealityTargetLock,
    RealityTraceArtifact,
    RealityTraceLane,
)
from stateweaver.replay import ReplayPlan, ReplayRunResult, RootSeed


@dataclass(frozen=True)
class _Bundle:
    receipt: RealityReplayReceipt
    receipt_json: bytes
    manifest: RealityEvidenceManifestV2
    manifest_json: bytes
    artifacts: dict[str, bytes]


def _tagged_sha256(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def _model_from_json[ModelT: BaseModel](model_type: type[ModelT], value: object) -> ModelT:
    return model_type.model_validate_json(canonical_json_bytes(value))


def _oracles(result: ReplayRunResult) -> tuple[OracleResult, ...]:
    return tuple(oracle for step in result.steps for oracle in step.oracle_results)


def _evidence_ids(oracles: tuple[OracleResult, ...]) -> tuple[str, ...]:
    return tuple(sorted({evidence_id for oracle in oracles for evidence_id in oracle.evidence_ids}))


def _trace(result: ReplayRunResult, *, lane: RealityTraceLane) -> RealityTraceArtifact:
    return RealityTraceArtifact.from_replay_result(result, lane=lane)


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
    manifest = RealityEvidenceManifestV2(entries=next_entries)
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
    control_root = _model_from_json(RootSeed, control_source["root_seed"])
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
    primary_root_hash = add("roots/primary.json", RealityArtifactRole.ROOT, primary_root)
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
            _trace(result, lane=RealityTraceLane.PRIMARY),
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
    control_root_hash = add(
        f"{control_path}/root.json",
        RealityArtifactRole.CONTROL_ROOT,
        control_root,
        run_id=control_result.run_id,
        control_name=control_name,
    )
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
        _trace(control_result, lane=RealityTraceLane.CONTROL),
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
    control_delta = RealityControlDelta.derive(
        control_name=control_name,
        kind=NegativeControlKind.REMOVED_PRECONDITION,
        primary_plan_sha256=plan_hash,
        primary_root_sha256=primary_root_hash,
        primary_result=primary_results[0],
        control_plan_sha256=control_plan_hash,
        control_root_sha256=control_root_hash,
        control_result=control_result,
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
        root_seed_id=control_root.root_seed_id,
        root_fingerprint=control_root.capture.fingerprint,
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
        _trace(patch_result, lane=RealityTraceLane.PATCH),
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

    manifest = RealityEvidenceManifestV2(entries=tuple(sorted(entries, key=lambda item: item.path)))
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
