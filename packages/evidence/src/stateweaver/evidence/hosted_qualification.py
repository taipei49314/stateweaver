"""Typed M2-M4 admission with an exact retained M5 receipt."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, ClassVar, Final, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)
from stateweaver.contracts import ContractId, Sha256Digest, sha256_digest

from ._io import EvidenceInputError, canonical_json_bytes
from .runtime_observation import (
    OBSERVED_FRAGMENT_QUALIFICATION_PATH,
    RUNTIME_OBSERVATION_QUALIFICATION_PATH,
    RuntimeObservationQualificationReceipt,
    observed_fragment_qualification_payload,
    runtime_observation_admissions,
)

HOSTED_QUALIFICATION_ADMISSION_PATH = "qualification/hosted/docker-compose-admission.json"
M2_LIVE_PROVIDER_QUALIFICATION_PATH = "qualification/m2/live-provider-receipt.json"
M2_EXIT_QUALIFICATION_PATH = "qualification/m2/m2-exit-receipt.json"
M2_GITHUB_HOSTED_QUALIFICATION_PATH = "qualification/m2/github-hosted-receipt.json"
M2_FOUR_WAY_QUALIFICATION_PATH = "qualification/m2/four-way-receipt.json"
M2_REAL_PROVIDER_QUALIFICATION_PATH = "qualification/m2/real-provider-receipt.json"
M2_CLEANUP_QUALIFICATION_PATH = "qualification/m2/cleanup-receipt.json"
M4_MATERIALIZED_QUALIFICATION_PATH = "qualification/m4/materialized-search-receipt.json"
M5_OBSERVED_CHAIN_QUALIFICATION_PATH = "qualification/m5/observed-chain-receipt.json"
M5_MATERIALIZED_PROVIDER_QUALIFICATION_PATH = "qualification/m5/materialized-provider-receipt.json"
_MAX_HOSTED_PRODUCER_BYTES: Final = 8 * 1_048_576
_MAX_HOSTED_ADMISSION_BYTES: Final = 16 * 1_048_576

HOSTED_QUALIFICATION_DERIVED_PATHS: Final = (
    M2_LIVE_PROVIDER_QUALIFICATION_PATH,
    M2_EXIT_QUALIFICATION_PATH,
    M2_GITHUB_HOSTED_QUALIFICATION_PATH,
    M2_FOUR_WAY_QUALIFICATION_PATH,
    M2_REAL_PROVIDER_QUALIFICATION_PATH,
    M2_CLEANUP_QUALIFICATION_PATH,
    RUNTIME_OBSERVATION_QUALIFICATION_PATH,
    OBSERVED_FRAGMENT_QUALIFICATION_PATH,
    M4_MATERIALIZED_QUALIFICATION_PATH,
    M5_OBSERVED_CHAIN_QUALIFICATION_PATH,
    M5_MATERIALIZED_PROVIDER_QUALIFICATION_PATH,
    HOSTED_QUALIFICATION_ADMISSION_PATH,
)

_REPOSITORY_URL = "https://github.com/taipei49314/stateweaver"
_SOURCE_REF = "refs/heads/main"
_WORKFLOW_PATH = ".github/workflows/docker-compose-live.yml"
_SIGNER_WORKFLOW = "github.com/taipei49314/stateweaver/.github/workflows/docker-compose-live.yml"
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_RUN_URL_RE = re.compile(
    r"^https://github\.com/taipei49314/stateweaver/actions/runs/(?P<run_id>[1-9][0-9]*)$"
)
type ProviderName = Literal["cache", "clock", "database", "filesystem", "queue", "session"]
_PROVIDERS: tuple[ProviderName, ...] = (
    "cache",
    "clock",
    "database",
    "filesystem",
    "queue",
    "session",
)


class HostedQualificationError(ValueError):
    """Value-safe rejection of an untrusted hosted admission."""


class _HostedModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)


class HostedArtifactEntry(_HostedModel):
    """One byte-identified file retained by the hosted qualification workflow."""

    path: Annotated[
        str,
        StringConstraints(
            pattern=r"^(?:m2-live|m4-live|m5-clean-root)/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
        ),
    ]
    role: Annotated[
        str,
        StringConstraints(pattern=r"^[a-z][a-z0-9-]{1,63}$"),
    ]
    sha256: Sha256Digest
    size: Annotated[int, Field(ge=0, le=4 * 1_048_576)]


class HostedJunitBinding(_HostedModel):
    """Passing, skip-free JUnit identities extracted from one retained report."""

    artifact_path: str
    artifact_sha256: Sha256Digest
    errors: Literal[0]
    failures: Literal[0]
    skipped: Literal[0]
    tests: Annotated[int, Field(ge=1, le=128)]
    testcase_identities: tuple[str, ...]

    @model_validator(mode="after")
    def _validate_identities(self) -> HostedJunitBinding:
        if (
            len(self.testcase_identities) != self.tests
            or tuple(sorted(set(self.testcase_identities))) != self.testcase_identities
            or any("::" not in identity for identity in self.testcase_identities)
        ):
            raise ValueError("hosted JUnit identities are invalid")
        return self


class M2ProviderWorld(_HostedModel):
    baseline: Mapping[ProviderName, Sha256Digest]
    mutated: Mapping[ProviderName, Sha256Digest]
    restored: Mapping[ProviderName, Sha256Digest]

    @model_validator(mode="after")
    def _validate_world(self) -> M2ProviderWorld:
        if any(
            tuple(sorted(value)) != _PROVIDERS
            for value in (self.baseline, self.mutated, self.restored)
        ):
            raise ValueError("M2 provider world coverage is invalid")
        if self.baseline != self.restored or any(
            self.baseline[name] == self.mutated[name] for name in _PROVIDERS
        ):
            raise ValueError("M2 provider restore is invalid")
        return self


class M2RealProviderObservation(_HostedModel):
    schema_version: Literal["stateweaver-m2-real-provider-observation-v1"]
    adapter: Literal["docker-compose-real-providers@0.1.0"]
    target: Literal["real-provider-demo@1.0.0"]
    providers: tuple[ProviderName, ...]
    siblings: Literal[4]
    overlap: Mapping[str, int]
    worlds: tuple[M2ProviderWorld, ...]
    cleanup: Mapping[str, object]
    status: Literal["PASS"]

    @model_validator(mode="after")
    def _validate_observation(self) -> M2RealProviderObservation:
        if self.providers != _PROVIDERS or len(self.worlds) != 4:
            raise ValueError("M2 real-provider observation coverage is invalid")
        if self.overlap != {"fork_max_in_flight": 4, "restore_max_in_flight": 4}:
            raise ValueError("M2 real-provider overlap is invalid")
        if self.cleanup != {"adapter_owned_worlds": 0, "status": "PASS"}:
            raise ValueError("M2 real-provider cleanup is invalid")
        for name in _PROVIDERS:
            if len({world.mutated[name] for world in self.worlds}) != 4:
                raise ValueError("M2 sibling provider state is not isolated")
        return self


class M2CleanupCase(_HostedModel):
    schema_version: Literal["stateweaver-m2-cleanup-case-v1"]
    case: Literal["success", "timeout", "cancellation", "partial-failure"]
    containers_after: Literal[0]
    networks_after: Literal[0]
    volumes_after: Literal[0]
    status: Literal["PASS"]


class HostedInventoryBinding(_HostedModel):
    """Digest equality and zero-residue results derived from workflow inventories."""

    containers_before_sha256: Sha256Digest
    containers_after_sha256: Sha256Digest
    networks_before_sha256: Sha256Digest
    networks_after_sha256: Sha256Digest
    volumes_before_sha256: Sha256Digest
    volumes_after_sha256: Sha256Digest
    dirty_before_bytes: Literal[0]
    dirty_after_bytes: Literal[0]
    managed_processes_before_bytes: Literal[0]
    managed_processes_after_bytes: Literal[0]
    residual_containers_bytes: Literal[0]
    residual_networks_bytes: Literal[0]
    residual_volumes_bytes: Literal[0]

    @model_validator(mode="after")
    def _validate_equal_inventories(self) -> HostedInventoryBinding:
        if (
            self.containers_before_sha256 != self.containers_after_sha256
            or self.networks_before_sha256 != self.networks_after_sha256
            or self.volumes_before_sha256 != self.volumes_after_sha256
        ):
            raise ValueError("hosted cleanup inventory differs from its baseline")
        return self


class M2HostedProjection(_HostedModel):
    synthetic_junit: HostedJunitBinding
    real_provider_junit: HostedJunitBinding
    real_provider: M2RealProviderObservation
    cleanup_cases: tuple[M2CleanupCase, ...]
    inventory: HostedInventoryBinding

    @model_validator(mode="after")
    def _validate_projection(self) -> M2HostedProjection:
        if tuple(item.case for item in self.cleanup_cases) != (
            "success",
            "timeout",
            "cancellation",
            "partial-failure",
        ):
            raise ValueError("M2 cleanup cases are incomplete or out of order")
        return self


class M4HostedProjection(_HostedModel):
    m3_qualification: RuntimeObservationQualificationReceipt
    m3_semantic_digest: Sha256Digest
    observed_chain_digest: Sha256Digest
    observed_transition_digest: Sha256Digest
    ghost_evaluation_count: Literal[24]
    promotion_counts: tuple[Literal[4], Literal[2], Literal[1]]
    materialized_world_count: Literal[7]
    peak_live_allocations: Literal[4]
    provider_receipt_digests: tuple[Sha256Digest, ...]
    released_allocation_ids: tuple[ContractId, ...]
    residual_allocation_ids: tuple[ContractId, ...]
    winner_candidate_id: ContractId
    receipt_digest: Sha256Digest

    @model_validator(mode="after")
    def _validate_projection(self) -> M4HostedProjection:
        if self.residual_allocation_ids:
            raise ValueError("M4 hosted projection retained residual allocations")
        if len(self.provider_receipt_digests) != 7 or len(self.released_allocation_ids) != 7:
            raise ValueError("M4 hosted projection does not cover seven materialized worlds")
        if (
            len(set(self.provider_receipt_digests)) != 7
            or len(set(self.released_allocation_ids)) != 7
        ):
            raise ValueError("M4 hosted projection contains duplicate materialization evidence")
        if self.m3_semantic_digest != self.m3_qualification.semantic_digest:
            raise ValueError("M4 hosted projection is not bound to its M3 qualification")
        return self


class M5HostedProjection(_HostedModel):
    """The materialized-provider M5 receipt projected into a hosted admission.

    The process-local M5 receipt is deliberately not sufficient: this projection only
    exists after the Docker-backed receipt has cross-bound it byte-for-byte.
    """

    m4_receipt_sha256: Sha256Digest
    m4_receipt_digest: Sha256Digest
    process_receipt_sha256: Sha256Digest
    process_receipt_digest: Sha256Digest
    materialized_receipt_digest: Sha256Digest
    provider_runtime: Literal["docker-compose-real-providers@0.1.0"]
    observed_chain_digest: Sha256Digest
    compiler_chain_fingerprint: Sha256Digest
    fragment_ids: tuple[ContractId, ...]
    replay_plan_digest: Sha256Digest
    clean_root_run_ids: tuple[str, ...]
    clean_root_result_digests: tuple[Sha256Digest, ...]
    patched_result_digest: Sha256Digest
    patched_failed_step_id: Literal["step.08"]
    patched_failure_code: Literal["ORACLE_EXPECTATION_MISMATCH"]
    negative_control_names: tuple[
        Literal[
            "masked_response",
            "mock_only_response",
            "fresh_session",
            "same_tenant_document",
        ],
        ...,
    ]
    negative_controls_digest: Sha256Digest
    cleanup_count: Literal[10]
    receipt_digest: Sha256Digest

    @model_validator(mode="after")
    def _validate_projection(self) -> M5HostedProjection:
        if (
            len(self.fragment_ids) != 8
            or len(set(self.fragment_ids)) != 8
            or self.clean_root_run_ids
            != tuple(f"run.m5.clean-root-{index:02d}" for index in range(1, 6))
            or len(self.clean_root_result_digests) != 5
            or self.negative_control_names
            != (
                "masked_response",
                "mock_only_response",
                "fresh_session",
                "same_tenant_document",
            )
        ):
            raise ValueError("M5 hosted projection is incomplete")
        return self


def _validate_materialized_m5_run(
    value: object,
    *,
    expected_plan: Mapping[str, object],
    expected_root: Mapping[str, object],
    expected_run_id: str,
    expected_status: str,
    expected_outcome: str,
    expected_response_status: int,
) -> tuple[str, str]:
    """Require one Docker-backed run to retain every action and provider boundary."""

    if not isinstance(value, Mapping):
        raise ValueError("hosted materialized M5 run is invalid")
    try:
        run_id = value["run_id"]
        root = value["root"]
        root_digest = value["root_digest"]
        result = value["result"]
        action_log = value["action_log"]
        steps = value["steps"]
        result_digest = value["result_digest"]
        action_log_digest = value["action_log_digest"]
    except KeyError:
        raise ValueError("hosted materialized M5 run is incomplete") from None
    plan_steps = expected_plan.get("steps")
    if (
        run_id != expected_run_id
        or not isinstance(root, Mapping)
        or root != expected_root
        or root_digest != sha256_digest(root)
        or not isinstance(result, Mapping)
        or not isinstance(action_log, list)
        or not isinstance(steps, list)
        or not isinstance(plan_steps, list)
        or not plan_steps
        or len(action_log) != len(plan_steps)
        or len(steps) != len(plan_steps)
        or result.get("status") != expected_status
        or not isinstance(result_digest, str)
        or not isinstance(action_log_digest, str)
        or result_digest != sha256_digest(result)
        or action_log_digest != sha256_digest(action_log)
    ):
        raise ValueError("hosted materialized M5 run does not retain its result")
    for expected, action, step in zip(plan_steps, action_log, steps, strict=True):
        if (
            not isinstance(expected, Mapping)
            or not isinstance(action, Mapping)
            or not isinstance(step, Mapping)
            or action.get("step_id") != expected.get("step_id")
            or action.get("action") != expected.get("action")
            or step.get("action") != expected.get("action")
            or step.get("action_digest") != sha256_digest(expected.get("action"))
            or type(step.get("response_status")) is not int
        ):
            raise ValueError("hosted materialized M5 action log is invalid")
        captures = step.get("provider_captures")
        if not isinstance(captures, Mapping) or tuple(sorted(captures)) != _PROVIDERS:
            raise ValueError("hosted materialized M5 provider capture is incomplete")
        for provider in _PROVIDERS:
            capture = captures[provider]
            if (
                not isinstance(capture, Mapping)
                or not isinstance(capture.get("before"), str)
                or not isinstance(capture.get("after"), str)
                or capture["before"] == capture["after"]
            ):
                raise ValueError("hosted materialized M5 provider capture is invalid")
    terminal = steps[-1]
    if (
        terminal.get("oracle_outcome") != expected_outcome
        or terminal.get("response_status") != expected_response_status
    ):
        raise ValueError("hosted materialized M5 terminal boundary is invalid")
    return result_digest, action_log_digest


class HostedDockerQualificationReceipt(_HostedModel):
    """Producer receipt emitted only after the hosted Docker cleanup gate succeeds."""

    schema_version: Literal["stateweaver-hosted-docker-qualification-v2"]
    status: Literal["HOSTED_M2_M4_QUALIFIED_M5_RETAINED"]
    repository_url: Literal["https://github.com/taipei49314/stateweaver"]
    repository_marker: str
    tree_sha: str
    source_ref: Literal["refs/heads/main"]
    workflow_path: Literal[".github/workflows/docker-compose-live.yml"]
    workflow_run_id: Annotated[int, Field(gt=0)]
    workflow_run_attempt: Annotated[int, Field(gt=0)]
    workflow_run_url: str
    runner_environment: Literal["github-hosted"]
    runner_os: Literal["Linux"]
    runner_arch: Literal["X64"]
    artifact_manifest: tuple[HostedArtifactEntry, ...]
    m2: M2HostedProjection
    m4_junit: HostedJunitBinding
    m4_receipt_json: Annotated[str, StringConstraints(min_length=2, max_length=2 * 1_048_576)]
    m4_receipt_sha256: Sha256Digest
    m4: M4HostedProjection
    m5_receipt_json: Annotated[str, StringConstraints(min_length=2, max_length=4 * 1_048_576)]
    m5_receipt_sha256: Sha256Digest
    m5_materialized_receipt_json: Annotated[
        str, StringConstraints(min_length=2, max_length=4 * 1_048_576)
    ]
    m5_materialized_receipt_sha256: Sha256Digest
    m5: M5HostedProjection
    release_eligible: Literal[False]
    limitations: tuple[str, ...]
    receipt_digest: Sha256Digest

    @model_validator(mode="after")
    def _validate_receipt(self) -> HostedDockerQualificationReceipt:
        match = _RUN_URL_RE.fullmatch(self.workflow_run_url)
        if (
            _SHA_RE.fullmatch(self.repository_marker) is None
            or _SHA_RE.fullmatch(self.tree_sha) is None
            or match is None
            or int(match.group("run_id")) != self.workflow_run_id
        ):
            raise ValueError("hosted workflow identity is invalid")
        manifest_paths = tuple(item.path for item in self.artifact_manifest)
        if manifest_paths != tuple(sorted(set(manifest_paths))) or not manifest_paths:
            raise ValueError("hosted artifact manifest must be sorted, unique, and nonempty")
        try:
            raw: object = json.loads(self.m4_receipt_json)
            if (
                not isinstance(raw, dict)
                or canonical_json_bytes(raw).decode("utf-8") != self.m4_receipt_json
            ):
                raise ValueError("hosted M4 receipt is not canonical")
        except (json.JSONDecodeError, EvidenceInputError, UnicodeError, ValueError, RecursionError):
            raise ValueError("hosted M4 receipt is invalid") from None
        byte_digest = f"sha256:{hashlib.sha256(self.m4_receipt_json.encode()).hexdigest()}"
        if byte_digest != self.m4_receipt_sha256:
            raise ValueError("hosted M4 receipt byte digest is invalid")
        projection = self.m4
        provider_receipts = raw.get("provider_receipts")
        winner = raw.get("winner")
        if not isinstance(provider_receipts, list) or not isinstance(winner, dict):
            raise ValueError("hosted M4 receipt shape is invalid")
        try:
            expected_provider_digests = tuple(item["receipt_digest"] for item in provider_receipts)
        except (KeyError, TypeError):
            raise ValueError("hosted M4 provider receipt projection is invalid") from None
        if (
            raw.get("repository_marker") != self.repository_marker
            or raw.get("m3_qualification") != projection.m3_qualification.model_dump(mode="json")
            or raw.get("m3_semantic_digest") != projection.m3_semantic_digest
            or raw.get("observed_chain_digest") != projection.observed_chain_digest
            or raw.get("observed_transition_digest") != projection.observed_transition_digest
            or raw.get("ghost_evaluation_count") != projection.ghost_evaluation_count
            or tuple(raw.get("promotion_counts", ())) != projection.promotion_counts
            or raw.get("materialized_world_count") != projection.materialized_world_count
            or raw.get("peak_live_allocations") != projection.peak_live_allocations
            or expected_provider_digests != projection.provider_receipt_digests
            or tuple(raw.get("released_allocation_ids", ())) != projection.released_allocation_ids
            or tuple(raw.get("residual_allocation_ids", ())) != projection.residual_allocation_ids
            or winner.get("candidate_id") != projection.winner_candidate_id
            or raw.get("receipt_digest") != projection.receipt_digest
        ):
            raise ValueError("hosted M4 receipt does not match its projection")
        unsigned_m4 = {key: value for key, value in raw.items() if key != "receipt_digest"}
        if projection.receipt_digest != sha256_digest(unsigned_m4):
            raise ValueError("hosted M4 receipt semantic digest is invalid")
        try:
            raw_m5: object = json.loads(self.m5_receipt_json)
            if (
                not isinstance(raw_m5, dict)
                or canonical_json_bytes(raw_m5).decode("utf-8") != self.m5_receipt_json
            ):
                raise ValueError("hosted M5 receipt is not canonical")
        except (json.JSONDecodeError, EvidenceInputError, UnicodeError, ValueError, RecursionError):
            raise ValueError("hosted M5 receipt is invalid") from None
        m5_byte_digest = f"sha256:{hashlib.sha256(self.m5_receipt_json.encode()).hexdigest()}"
        try:
            raw_materialized: object = json.loads(self.m5_materialized_receipt_json)
            if (
                not isinstance(raw_materialized, dict)
                or canonical_json_bytes(raw_materialized).decode("utf-8")
                != self.m5_materialized_receipt_json
            ):
                raise ValueError("hosted materialized M5 receipt is not canonical")
        except (json.JSONDecodeError, EvidenceInputError, UnicodeError, ValueError, RecursionError):
            raise ValueError("hosted materialized M5 receipt is invalid") from None
        materialized_byte_digest = (
            f"sha256:{hashlib.sha256(self.m5_materialized_receipt_json.encode()).hexdigest()}"
        )
        m5 = self.m5
        compiler = raw_m5.get("compiler_admission")
        compiled_chain = compiler.get("compiled_chain") if isinstance(compiler, dict) else None
        runs = raw_m5.get("runs")
        patched = raw_m5.get("patched_run")
        controls = raw_m5.get("negative_controls")
        if (
            not isinstance(compiler, dict)
            or not isinstance(compiled_chain, dict)
            or not isinstance(runs, list)
            or not isinstance(patched, dict)
            or not isinstance(controls, list)
        ):
            raise ValueError("hosted M5 receipt shape is invalid")
        try:
            process_run_ids = tuple(item["run_id"] for item in runs)
            control_names = tuple(item["name"] for item in controls)
            patched_steps = patched["steps"]
            patched_failure = patched_steps[-1]["failure_code"]
        except (IndexError, KeyError, TypeError):
            raise ValueError("hosted M5 projection is invalid") from None
        materialized_runs = raw_materialized.get("clean_root_runs")
        materialized_controls = raw_materialized.get("negative_controls")
        materialized_patched = raw_materialized.get("patched_run")
        cleanup = raw_materialized.get("cleanup")
        if (
            not isinstance(materialized_runs, list)
            or not isinstance(materialized_controls, list)
            or not isinstance(materialized_patched, dict)
            or not isinstance(cleanup, dict)
        ):
            raise ValueError("hosted materialized M5 receipt shape is invalid")
        try:
            materialized_run_ids = tuple(item["run_id"] for item in materialized_runs)
            materialized_result_digests = tuple(item["result_digest"] for item in materialized_runs)
            materialized_control_names = tuple(item["name"] for item in materialized_controls)
        except (KeyError, TypeError):
            raise ValueError("hosted materialized M5 projection is invalid") from None
        replay_plan = raw_m5.get("replay_plan")
        if not isinstance(replay_plan, Mapping):
            raise ValueError("hosted M5 replay plan is invalid")
        if raw_materialized.get("plan") != replay_plan:
            raise ValueError("hosted materialized M5 plan is not exact")
        for run, expected_run_id in zip(materialized_runs, process_run_ids, strict=True):
            _validate_materialized_m5_run(
                run,
                expected_plan=replay_plan,
                expected_root=raw_m5["clean_root"],
                expected_run_id=expected_run_id,
                expected_status="succeeded",
                expected_outcome="VIOLATED",
                expected_response_status=200,
            )
        _validate_materialized_m5_run(
            materialized_patched,
            expected_plan=replay_plan,
            expected_root=raw_m5["patched_root"],
            expected_run_id="run.m5.patched-01",
            expected_status="failed",
            expected_outcome="SATISFIED",
            expected_response_status=403,
        )
        expected_controls = tuple(item.get("name") for item in controls)
        if materialized_control_names != expected_controls:
            raise ValueError("hosted materialized M5 controls are substituted")
        for control_index, (materialized_control, process_control) in enumerate(
            zip(materialized_controls, controls, strict=True)
        ):
            if not isinstance(process_control, Mapping) or not isinstance(
                materialized_control, Mapping
            ):
                raise ValueError("hosted materialized M5 control is invalid")
            expected_result = process_control.get("result")
            if not isinstance(expected_result, Mapping):
                raise ValueError("hosted process M5 control is invalid")
            process_steps = expected_result.get("steps")
            if not isinstance(process_steps, list) or not process_steps:
                raise ValueError("hosted process M5 control result is invalid")
            process_terminal = process_steps[-1]
            observations = (
                process_terminal.get("observations")
                if isinstance(process_terminal, Mapping)
                else None
            )
            status = None
            if isinstance(observations, list) and observations:
                payload = (
                    observations[-1].get("payload")
                    if isinstance(observations[-1], Mapping)
                    else None
                )
                status = payload.get("response_status") if isinstance(payload, Mapping) else None
            process_plan = process_control.get("plan")
            if (
                not isinstance(process_plan, Mapping)
                or materialized_control.get("plan") != process_plan
            ):
                raise ValueError("hosted materialized M5 control plan is not exact")
            _validate_materialized_m5_run(
                materialized_control,
                expected_plan=process_plan,
                expected_root=process_control["root"],
                expected_run_id=f"run.m5.control-{materialized_control_names[control_index]}",
                expected_status="succeeded",
                expected_outcome=str(process_control.get("expected_outcome")),
                expected_response_status=status if type(status) is int else -1,
            )
        if (
            m5_byte_digest != self.m5_receipt_sha256
            or materialized_byte_digest != self.m5_materialized_receipt_sha256
            or raw_m5.get("schema_version") != "stateweaver-m5-observed-chain-qualification-v2"
            or raw_m5.get("status") != "VULNERABLE_PATCHED_CONTROLS_QUALIFIED"
            or raw_m5.get("repository_marker") != self.repository_marker
            or raw_m5.get("m4_receipt_json") != self.m4_receipt_json
            or raw_m5.get("m4_receipt_sha256") != m5.m4_receipt_sha256
            or raw_m5.get("m4_receipt_digest") != m5.m4_receipt_digest
            or raw_m5.get("observed_chain_digest") != m5.observed_chain_digest
            or compiler.get("chain_fingerprint") != m5.compiler_chain_fingerprint
            or tuple(compiled_chain.get("fragment_ids", ())) != m5.fragment_ids
            or raw_m5.get("replay_plan_digest") != m5.replay_plan_digest
            or process_run_ids != m5.clean_root_run_ids
            or patched.get("failed_step_id") != m5.patched_failed_step_id
            or patched_failure != m5.patched_failure_code
            or control_names != m5.negative_control_names
            or raw_m5.get("negative_controls_digest") != m5.negative_controls_digest
            or raw_m5.get("cleanup_count") != m5.cleanup_count
            or raw_m5.get("network_denied_attempts") != 0
            or raw_m5.get("release_eligible") is not False
            or raw_m5.get("receipt_digest") != m5.receipt_digest
            or raw_materialized.get("schema_version")
            != "stateweaver-m5-materialized-provider-qualification-v1"
            or raw_materialized.get("status") != "M5_MATERIALIZED_PROVIDER_WITNESS_RETAINED"
            or raw_materialized.get("repository_marker") != self.repository_marker
            or raw_materialized.get("provider_runtime") != m5.provider_runtime
            or tuple(raw_materialized.get("provider_names", ())) != _PROVIDERS
            or raw_materialized.get("m4_receipt_json") != self.m4_receipt_json
            or raw_materialized.get("m4_receipt_sha256") != m5.m4_receipt_sha256
            or raw_materialized.get("m4_receipt_digest") != m5.m4_receipt_digest
            or raw_materialized.get("m4_winner_provider_state_digest")
            != next(
                (
                    item.get("provider_state_digest")
                    for item in provider_receipts
                    if isinstance(item, Mapping)
                    and isinstance(item.get("request"), Mapping)
                    and item["request"].get("candidate_id") == projection.winner_candidate_id
                    and item["request"].get("target_tier") == "materialized"
                ),
                None,
            )
            or raw_materialized.get("process_receipt_json") != self.m5_receipt_json
            or raw_materialized.get("process_receipt_sha256") != m5.process_receipt_sha256
            or raw_materialized.get("process_receipt_digest") != m5.process_receipt_digest
            or raw_materialized.get("plan_digest") != m5.replay_plan_digest
            or materialized_run_ids != m5.clean_root_run_ids
            or materialized_result_digests != m5.clean_root_result_digests
            or materialized_patched.get("result_digest") != m5.patched_result_digest
            or not isinstance(materialized_patched.get("result"), Mapping)
            or materialized_patched["result"].get("failed_step_id") != m5.patched_failed_step_id
            or not isinstance(materialized_patched["result"].get("steps"), list)
            or not materialized_patched["result"]["steps"]
            or materialized_patched["result"]["steps"][-1].get("failure_code")
            != m5.patched_failure_code
            or materialized_control_names != m5.negative_control_names
            or raw_materialized.get("cleanup_count") != m5.cleanup_count
            or cleanup.get("status") != "PASS"
            or cleanup.get("destroyed") is not True
            or cleanup.get("residual_containers") != 0
            or cleanup.get("residual_networks") != 0
            or cleanup.get("residual_volumes") != 0
            or raw_materialized.get("receipt_digest") != m5.materialized_receipt_digest
        ):
            raise ValueError("hosted M5 receipt does not match its projection")
        unsigned_m5 = {key: value for key, value in raw_m5.items() if key != "receipt_digest"}
        if m5.receipt_digest != sha256_digest(unsigned_m5):
            raise ValueError("hosted M5 receipt semantic digest is invalid")
        unsigned_materialized = {
            key: value for key, value in raw_materialized.items() if key != "receipt_digest"
        }
        if m5.materialized_receipt_digest != sha256_digest(unsigned_materialized):
            raise ValueError("hosted materialized M5 receipt semantic digest is invalid")
        expected = sha256_digest(self.model_dump(mode="python", exclude={"receipt_digest"}))
        if self.receipt_digest != expected:
            raise ValueError("hosted Docker qualification receipt digest is invalid")
        return self


class HostedAttestationVerification(_HostedModel):
    """Exact constrained verification outcome retained by the consumer workflow."""

    verifier: Literal["gh-attestation"]
    repository: Literal["taipei49314/stateweaver"]
    signer_workflow: Literal[
        "github.com/taipei49314/stateweaver/.github/workflows/docker-compose-live.yml"
    ]
    signer_digest: str
    source_digest: str
    source_ref: Literal["refs/heads/main"]
    deny_self_hosted_runners: Literal[True]
    subject_sha256: Sha256Digest
    attestation_bundle_sha256: Sha256Digest
    exit_code: Literal[0]

    @model_validator(mode="after")
    def _validate_sha_fields(self) -> HostedAttestationVerification:
        if (
            _SHA_RE.fullmatch(self.signer_digest) is None
            or _SHA_RE.fullmatch(self.source_digest) is None
            or self.signer_digest != self.source_digest
        ):
            raise ValueError("hosted attestation source identity is invalid")
        return self


class HostedQualificationAdmissionReceipt(_HostedModel):
    """Consumer-side admission retained in the acceptance proof."""

    schema_version: Literal["stateweaver-hosted-qualification-admission-v2"]
    status: Literal["HOSTED_QUALIFICATION_ADMITTED"]
    qualification_receipt_json: Annotated[
        str, StringConstraints(min_length=2, max_length=_MAX_HOSTED_PRODUCER_BYTES)
    ]
    qualification_receipt_sha256: Sha256Digest
    attestation: HostedAttestationVerification
    release_eligible: Literal[False]
    limitations: tuple[str, ...]
    admission_digest: Sha256Digest

    @model_validator(mode="after")
    def _validate_admission(self) -> HostedQualificationAdmissionReceipt:
        try:
            raw: object = json.loads(self.qualification_receipt_json)
            receipt = HostedDockerQualificationReceipt.model_validate_json(
                self.qualification_receipt_json
            )
            if canonical_json_bytes(raw).decode("utf-8") != self.qualification_receipt_json:
                raise ValueError("hosted qualification receipt is not canonical")
        except (
            json.JSONDecodeError,
            ValidationError,
            EvidenceInputError,
            ValueError,
            RecursionError,
        ):
            raise ValueError("hosted qualification receipt is invalid") from None
        receipt_bytes = self.qualification_receipt_json.encode()
        receipt_sha = f"sha256:{hashlib.sha256(receipt_bytes).hexdigest()}"
        if (
            receipt_sha != self.qualification_receipt_sha256
            or self.attestation.subject_sha256 != receipt_sha
            or self.attestation.source_digest != receipt.repository_marker
        ):
            raise ValueError("hosted qualification attestation does not bind the receipt")
        expected = sha256_digest(self.model_dump(mode="python", exclude={"admission_digest"}))
        if self.admission_digest != expected:
            raise ValueError("hosted qualification admission digest is invalid")
        return self

    @property
    def qualification(self) -> HostedDockerQualificationReceipt:
        return HostedDockerQualificationReceipt.model_validate_json(self.qualification_receipt_json)


def validate_hosted_qualification_admission(
    value: Mapping[str, object], *, expected_repository_marker: str
) -> HostedQualificationAdmissionReceipt:
    """Validate one admission and independently require the current exact Git SHA."""

    try:
        receipt = HostedQualificationAdmissionReceipt.model_validate_json(
            canonical_json_bytes(value)
        )
    except (ValidationError, TypeError, ValueError, RecursionError):
        raise HostedQualificationError("hosted qualification admission is invalid") from None
    if receipt.qualification.repository_marker != expected_repository_marker:
        raise HostedQualificationError("hosted qualification repository marker is invalid")
    return receipt


def load_hosted_qualification_admission(
    path: Path, *, expected_repository_marker: str
) -> HostedQualificationAdmissionReceipt:
    """Load one bounded canonical hosted admission without following a final symlink."""

    if path.is_symlink():
        raise HostedQualificationError("hosted qualification admission is invalid")
    try:
        size = path.stat().st_size
        content = path.read_bytes()
    except OSError:
        raise HostedQualificationError("hosted qualification admission is invalid") from None
    if size != len(content) or not 1 <= size <= _MAX_HOSTED_ADMISSION_BYTES:
        raise HostedQualificationError("hosted qualification admission is invalid")
    try:
        parsed: object = json.loads(content.decode("utf-8"))
        if not isinstance(parsed, Mapping) or canonical_json_bytes(parsed) != content:
            raise HostedQualificationError("hosted qualification admission is invalid")
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        EvidenceInputError,
        ValueError,
        RecursionError,
    ):
        raise HostedQualificationError("hosted qualification admission is invalid") from None
    return validate_hosted_qualification_admission(
        parsed,
        expected_repository_marker=expected_repository_marker,
    )


def load_hosted_docker_qualification(
    path: Path, *, expected_repository_marker: str
) -> HostedDockerQualificationReceipt:
    """Load one canonical producer receipt retained by the hosted Docker workflow."""

    if path.is_symlink():
        raise HostedQualificationError("hosted Docker qualification receipt is invalid")
    try:
        size = path.stat().st_size
        content = path.read_bytes()
    except OSError:
        raise HostedQualificationError("hosted Docker qualification receipt is invalid") from None
    if size != len(content) or not 1 <= size <= _MAX_HOSTED_PRODUCER_BYTES:
        raise HostedQualificationError("hosted Docker qualification receipt is invalid")
    try:
        parsed: object = json.loads(content.decode("utf-8"))
        if canonical_json_bytes(parsed) != content:
            raise HostedQualificationError("hosted Docker qualification receipt is invalid")
        receipt = HostedDockerQualificationReceipt.model_validate_json(content)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValidationError,
        EvidenceInputError,
        ValueError,
        RecursionError,
    ):
        raise HostedQualificationError("hosted Docker qualification receipt is invalid") from None
    if receipt.repository_marker != expected_repository_marker:
        raise HostedQualificationError("hosted Docker qualification source does not match")
    return receipt


def hosted_qualification_test_identities(
    admission: HostedQualificationAdmissionReceipt,
) -> tuple[str, ...]:
    """Return only JUnit identities covered by the admitted hosted receipt."""

    qualification = admission.qualification
    return tuple(
        sorted(
            {
                *qualification.m2.synthetic_junit.testcase_identities,
                *qualification.m2.real_provider_junit.testcase_identities,
                *qualification.m4_junit.testcase_identities,
            }
        )
    )


def hosted_qualification_admissions(
    admission: HostedQualificationAdmissionReceipt,
) -> dict[str, str]:
    """Return only the exact M2-M4 registry rows proven by this hosted run."""

    digest = admission.admission_digest
    admitted = dict.fromkeys(
        (
            "M2-W01",
            "M2-W02",
            "M2-W03",
            "M2-W04",
            "M2-W05",
            "M2-X01",
            "SW-M2-4WAY",
            "SW-M2-PROVIDERS",
            "SW-M2-CLEANUP",
            "M4-X01",
            "SW-M4-MATERIALIZED",
        ),
        digest,
    )
    admitted.update(runtime_observation_admissions(admission.qualification.m4.m3_qualification))
    return admitted


def hosted_qualification_payloads(
    admission: HostedQualificationAdmissionReceipt,
) -> dict[str, object]:
    """Derive all registry evidence paths from the one validated admission."""

    qualification = admission.qualification
    m2 = qualification.m2
    common = {
        "repository_marker": qualification.repository_marker,
        "workflow_run_id": qualification.workflow_run_id,
        "workflow_run_attempt": qualification.workflow_run_attempt,
        "workflow_run_url": qualification.workflow_run_url,
        "admission_digest": admission.admission_digest,
        "release_eligible": False,
    }
    runtime = qualification.m4.m3_qualification
    raw_m4 = json.loads(qualification.m4_receipt_json)
    raw_m5 = json.loads(qualification.m5_receipt_json)
    raw_materialized_m5 = json.loads(qualification.m5_materialized_receipt_json)
    return {
        M2_LIVE_PROVIDER_QUALIFICATION_PATH: {
            "schema_version": "stateweaver-m2-live-provider-qualification-v1",
            "status": "HOSTED_SYNTHETIC_COMPOSE_QUALIFIED",
            **common,
            "junit": m2.synthetic_junit.model_dump(mode="json"),
        },
        M2_EXIT_QUALIFICATION_PATH: {
            "schema_version": "stateweaver-m2-exit-qualification-v1",
            "status": "M2_HOSTED_EXIT_QUALIFIED",
            **common,
            "four_way_overlap": True,
            "real_provider_count": 6,
            "cleanup_cases": [item.case for item in m2.cleanup_cases],
        },
        M2_GITHUB_HOSTED_QUALIFICATION_PATH: {
            "schema_version": "stateweaver-m2-hosted-workflow-v1",
            "status": "GITHUB_HOSTED_QUALIFIED",
            **common,
            "workflow_path": qualification.workflow_path,
            "runner_os": qualification.runner_os,
            "runner_arch": qualification.runner_arch,
            "limitation": (
                "A separate retained clean-host receipt is still required for SW-M2-LIVE."
            ),
        },
        M2_FOUR_WAY_QUALIFICATION_PATH: {
            "schema_version": "stateweaver-m2-four-way-qualification-v1",
            "status": "FOUR_WAY_ISOLATION_QUALIFIED",
            **common,
            "siblings": m2.real_provider.siblings,
            "overlap": dict(m2.real_provider.overlap),
            "junit": m2.real_provider_junit.model_dump(mode="json"),
        },
        M2_REAL_PROVIDER_QUALIFICATION_PATH: {
            "schema_version": "stateweaver-m2-provider-qualification-v1",
            "status": "SIX_REAL_PROVIDERS_QUALIFIED",
            **common,
            "observation": m2.real_provider.model_dump(mode="json"),
        },
        M2_CLEANUP_QUALIFICATION_PATH: {
            "schema_version": "stateweaver-m2-cleanup-qualification-v1",
            "status": "FAILURE_PATH_CLEANUP_QUALIFIED",
            **common,
            "cases": [item.model_dump(mode="json") for item in m2.cleanup_cases],
            "inventory": m2.inventory.model_dump(mode="json"),
        },
        RUNTIME_OBSERVATION_QUALIFICATION_PATH: runtime.model_dump(mode="json"),
        OBSERVED_FRAGMENT_QUALIFICATION_PATH: observed_fragment_qualification_payload(runtime),
        M4_MATERIALIZED_QUALIFICATION_PATH: raw_m4,
        M5_OBSERVED_CHAIN_QUALIFICATION_PATH: raw_m5,
        M5_MATERIALIZED_PROVIDER_QUALIFICATION_PATH: raw_materialized_m5,
        HOSTED_QUALIFICATION_ADMISSION_PATH: admission.model_dump(mode="json"),
    }


__all__ = [
    "HOSTED_QUALIFICATION_ADMISSION_PATH",
    "HOSTED_QUALIFICATION_DERIVED_PATHS",
    "HostedArtifactEntry",
    "HostedAttestationVerification",
    "HostedDockerQualificationReceipt",
    "HostedInventoryBinding",
    "HostedJunitBinding",
    "HostedQualificationAdmissionReceipt",
    "HostedQualificationError",
    "M2CleanupCase",
    "M2HostedProjection",
    "M2ProviderWorld",
    "M2RealProviderObservation",
    "M4HostedProjection",
    "M5HostedProjection",
    "hosted_qualification_admissions",
    "hosted_qualification_payloads",
    "hosted_qualification_test_identities",
    "load_hosted_docker_qualification",
    "load_hosted_qualification_admission",
    "validate_hosted_qualification_admission",
]
