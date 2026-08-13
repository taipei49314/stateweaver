"""Typed hosted M2-M5 admission over exact retained qualification bytes."""

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
M5_MATERIALIZED_CHAIN_QUALIFICATION_PATH = "qualification/m5/materialized-chain-replay.json"
_MAX_HOSTED_PRODUCER_BYTES: Final = 48 * 1_048_576
_MAX_HOSTED_ADMISSION_BYTES: Final = 64 * 1_048_576
_MAX_HOSTED_ARTIFACT_TOTAL_BYTES: Final = 256 * 1_048_576

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
    M5_MATERIALIZED_CHAIN_QUALIFICATION_PATH,
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
_M5_PROVIDERS: Final = (
    "postgres",
    "redis",
    "rabbitmq",
    "browser_session",
    "filesystem",
    "clock",
)
_M5_CONTROL_NAMES: Final = (
    "masked_response",
    "mock_only_response",
    "fresh_session",
    "same_tenant_document",
)
_HOSTED_LIMITATIONS: Final = (
    "This admission proves repository-controlled GitHub-hosted M2 through M5 execution "
    "for one exact SHA.",
    "A separate clean host and external M6-M8 trust remain pending.",
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
    size: Annotated[int, Field(ge=0, le=64 * 1_048_576)]


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
    """The independently checked actual-ASGI M5 composite projection."""

    m4_receipt_sha256: Sha256Digest
    m4_receipt_digest: Sha256Digest
    process_receipt_sha256: Sha256Digest
    process_receipt_digest: Sha256Digest
    actual_receipt_digest: Sha256Digest
    runtime: Literal["docker-compose-fastapi-asgi-six-provider@0.1.0"]
    m4_winner_state_binding_digest: Sha256Digest
    m4_source_snapshot_digest: Sha256Digest
    m4_after_archive_digest: Sha256Digest
    m4_provider_state_digest: Sha256Digest
    execution_plan_digest: Sha256Digest
    primary_plan_digest: Sha256Digest
    application_image_binding_digest: Sha256Digest
    clean_root_run_ids: tuple[str, ...]
    clean_root_materialized_receipt_digests: tuple[Sha256Digest, ...]
    vulnerable_deterministic_signatures: tuple[Sha256Digest, ...]
    initial_checkpoint_bytes_digest: Sha256Digest
    patched_run_id: Literal["run.m5.patched-01"]
    patched_materialized_receipt_digest: Sha256Digest
    negative_control_names: tuple[
        Literal[
            "masked_response",
            "mock_only_response",
            "fresh_session",
            "same_tenant_document",
        ],
        ...,
    ]
    negative_control_materialized_receipt_digests: tuple[Sha256Digest, ...]
    cleanup_count: Literal[10]
    receipt_digest: Sha256Digest

    @model_validator(mode="after")
    def _validate_projection(self) -> M5HostedProjection:
        if (
            self.clean_root_run_ids
            != tuple(f"run.m5.clean-root-{index:02d}" for index in range(1, 6))
            or len(self.clean_root_materialized_receipt_digests) != 5
            or len(self.vulnerable_deterministic_signatures) != 5
            or len(set(self.vulnerable_deterministic_signatures)) != 1
            or self.negative_control_names != _M5_CONTROL_NAMES
            or len(self.negative_control_materialized_receipt_digests) != 4
        ):
            raise ValueError("M5 hosted projection is incomplete")
        return self


def _mapping(value: object, message: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(message)
    return value


def _sequence(value: object, message: str) -> tuple[object, ...]:
    if not isinstance(value, list):
        raise ValueError(message)
    return tuple(value)


def _exact_keys(value: Mapping[str, object], keys: set[str], message: str) -> None:
    if set(value) != keys:
        raise ValueError(message)


def _raw_digest(value: str | bytes) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _semantic_digest(value: Mapping[str, object], digest_key: str) -> str:
    unsigned = {key: item for key, item in value.items() if key != digest_key}
    return sha256_digest(unsigned)


def _normalized_wire_value(value: object) -> object:
    if isinstance(value, dict):
        return {
            re.sub(r"(?<!^)(?=[A-Z])", "_", key).lower(): _normalized_wire_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_normalized_wire_value(item) for item in value]
    if isinstance(value, str) and value.endswith("+00:00"):
        return value[:-6] + "Z"
    return value


def _validate_checkpoint(value: object) -> tuple[str, str, str]:
    checkpoint = _mapping(value, "hosted M5 checkpoint is invalid")
    _exact_keys(
        checkpoint,
        {
            "generation",
            "checkpoint_digest",
            "checkpoint_bytes",
            "checkpoint_bytes_digest",
            "observations",
        },
        "hosted M5 checkpoint shape is invalid",
    )
    raw = checkpoint.get("checkpoint_bytes")
    generation = checkpoint.get("generation")
    checkpoint_digest = checkpoint.get("checkpoint_digest")
    if (
        not isinstance(raw, str)
        or not isinstance(generation, str)
        or not isinstance(checkpoint_digest, str)
    ):
        raise ValueError("hosted M5 checkpoint values are invalid")
    if len(raw.encode("utf-8")) > 131_072 or checkpoint.get(
        "checkpoint_bytes_digest"
    ) != _raw_digest(raw):
        raise ValueError("hosted M5 checkpoint bytes are invalid")
    try:
        embedded = json.loads(raw)
    except (json.JSONDecodeError, UnicodeError, ValueError, RecursionError):
        raise ValueError("hosted M5 checkpoint bytes are invalid") from None
    if (
        not isinstance(embedded, dict)
        or json.dumps(
            embedded,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        != raw
    ):
        raise ValueError("hosted M5 checkpoint bytes are not canonical")
    _exact_keys(
        embedded,
        {
            "schema_version",
            "generation",
            "mode",
            "seed",
            "state",
            "state_fingerprint",
            "checkpoint_digest",
        },
        "hosted M5 checkpoint payload is invalid",
    )
    generation_payload = {
        key: embedded[key]
        for key in ("schema_version", "mode", "seed", "state", "state_fingerprint")
    }
    unsigned_checkpoint = {
        key: embedded[key]
        for key in (
            "schema_version",
            "generation",
            "mode",
            "seed",
            "state",
            "state_fingerprint",
        )
    }
    if (
        embedded.get("schema_version") != "stateweaver-lab-checkpoint-v1"
        or embedded.get("seed") != "m0-canonical-v1"
        or embedded.get("mode") not in {"vulnerable", "patched"}
        or embedded.get("generation") != generation
        or hashlib.sha256(
            json.dumps(
                generation_payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        != generation
        or sha256_digest(unsigned_checkpoint) != checkpoint_digest
        or embedded.get("checkpoint_digest") != checkpoint_digest
    ):
        raise ValueError("hosted M5 checkpoint seal is invalid")
    observations = _sequence(
        checkpoint.get("observations"), "hosted M5 checkpoint providers are invalid"
    )
    if (
        tuple(
            _mapping(item, "hosted M5 checkpoint provider is invalid").get("provider")
            for item in observations
        )
        != _M5_PROVIDERS
    ):
        raise ValueError("hosted M5 checkpoint provider set is invalid")
    for item in observations:
        observation = _mapping(item, "hosted M5 checkpoint provider is invalid")
        _exact_keys(
            observation,
            {"provider", "generation", "checkpoint_digest", "storage_digest"},
            "hosted M5 checkpoint provider shape is invalid",
        )
        if (
            observation.get("generation") != generation
            or observation.get("checkpoint_digest") != checkpoint_digest
            or observation.get("storage_digest") != checkpoint.get("checkpoint_bytes_digest")
        ):
            raise ValueError("hosted M5 checkpoint provider is not exact")
    return generation, checkpoint_digest, raw


def _validate_actual_m5_run(
    value: object,
    *,
    expected_plan: object,
    expected_root: object,
    expected_process_result: object,
    expected_run_id: str,
    expected_scenario: str,
    expected_mode: str,
    expected_outcome: str,
    expected_verdict: str,
    expected_response_status: int,
) -> tuple[str, str, str, str, str, str]:
    """Independently validate one actual application run from raw JSON."""

    witness = _mapping(value, "hosted actual M5 run is invalid")
    _exact_keys(
        witness,
        {
            "run_id",
            "process_result_digest",
            "root",
            "root_digest",
            "plan",
            "plan_digest",
            "expected_oracle_outcome",
            "expected_response_status",
            "materialized_run_receipt",
            "materialized_run_receipt_digest",
        },
        "hosted actual M5 run shape is invalid",
    )
    plan = _mapping(expected_plan, "hosted actual M5 plan is invalid")
    plan_steps = _sequence(plan.get("steps"), "hosted actual M5 plan steps are invalid")
    receipt = _mapping(
        witness.get("materialized_run_receipt"), "hosted actual M5 receipt is invalid"
    )
    _exact_keys(
        receipt,
        {
            "schema_version",
            "status",
            "request",
            "request_digest",
            "image_binding",
            "execution_backend",
            "application_schema_digest",
            "checkpoint_visibility",
            "initial_checkpoint",
            "steps",
            "final_checkpoint",
            "cleanup_status",
            "destroyed",
            "receipt_digest",
        },
        "hosted actual M5 receipt shape is invalid",
    )
    request = _mapping(receipt.get("request"), "hosted actual M5 request is invalid")
    actions = _sequence(request.get("actions"), "hosted actual M5 actions are invalid")
    lab_actions = _sequence(request.get("lab_actions"), "hosted actual M5 lab actions are invalid")
    authorizations = _sequence(
        request.get("policy_authorizations"), "hosted actual M5 authorizations are invalid"
    )
    policy_requests = _sequence(
        request.get("policy_requests"), "hosted actual M5 policy requests are invalid"
    )
    steps = _sequence(receipt.get("steps"), "hosted actual M5 steps are invalid")
    plan_actions = tuple(
        _mapping(item, "hosted actual M5 plan step is invalid").get("action") for item in plan_steps
    )
    if (
        witness.get("run_id") != expected_run_id
        or witness.get("root") != expected_root
        or witness.get("root_digest") != sha256_digest(expected_root)
        or witness.get("plan") != expected_plan
        or witness.get("plan_digest") != sha256_digest(expected_plan)
        or witness.get("process_result_digest") != sha256_digest(expected_process_result)
        or witness.get("expected_oracle_outcome") != expected_outcome
        or witness.get("expected_response_status") != expected_response_status
        or receipt.get("schema_version") != "stateweaver-m5-materialized-application-run-v2"
        or receipt.get("status") != "M5_MATERIALIZED_APPLICATION_SCENARIO_EXECUTED"
        or receipt.get("execution_backend") != "fastapi-asgi"
        or receipt.get("checkpoint_visibility") != "SIX_IMMUTABLE_SHARDS_POSTGRES_CAS"
        or receipt.get("cleanup_status") != "PASS"
        or receipt.get("destroyed") is not True
        or receipt.get("receipt_digest") != _semantic_digest(receipt, "receipt_digest")
        or receipt.get("receipt_digest") != witness.get("materialized_run_receipt_digest")
        or request.get("run_id") != expected_run_id
        or request.get("scenario") != expected_scenario
        or request.get("mode") != expected_mode
        or request.get("root_digest") != witness.get("root_digest")
        or request.get("plan_digest") != witness.get("plan_digest")
        or request.get("plan_id") != plan.get("plan_id")
        or receipt.get("request_digest") != sha256_digest(request)
        or actions != plan_actions
        or not plan_steps
        or len(steps) != len(plan_steps)
        or len(lab_actions) != len(plan_steps)
        or len(authorizations) != len(plan_steps)
        or len(policy_requests) != len(plan_steps)
    ):
        raise ValueError("hosted actual M5 run is not exact")
    retained_byte_groups: dict[str, tuple[object, ...]] = {}
    for key, exact in (
        ("action_bytes", actions),
        ("lab_action_bytes", lab_actions),
        ("policy_authorization_bytes", authorizations),
        ("policy_request_bytes", policy_requests),
    ):
        retained = _sequence(request.get(key), "hosted actual M5 retained bytes are invalid")
        retained_byte_groups[key] = retained
        for raw_bytes, item in zip(retained, exact, strict=True):
            if not isinstance(raw_bytes, str):
                raise ValueError("hosted actual M5 retained bytes are not exact")
            try:
                decoded = json.loads(raw_bytes)
            except (json.JSONDecodeError, UnicodeError, ValueError, RecursionError):
                raise ValueError("hosted actual M5 retained bytes are not exact") from None
            canonical = json.dumps(
                decoded,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            if canonical != raw_bytes or _normalized_wire_value(decoded) != _normalized_wire_value(
                item
            ):
                raise ValueError(f"hosted actual M5 retained {key} bytes are not exact")
    initial = _validate_checkpoint(receipt.get("initial_checkpoint"))
    previous_after = initial
    for index, (expected, action, item) in enumerate(
        zip(plan_steps, actions, steps, strict=True),
        start=1,
    ):
        step = _mapping(item, "hosted actual M5 step is invalid")
        _exact_keys(
            step,
            {
                "step_id",
                "before",
                "trace",
                "after",
                "evidence_digest",
                "appended_evidence",
                "oracle",
                "oracle_digest",
                "visibility_commit",
                "step_digest",
            },
            "hosted actual M5 step shape is invalid",
        )
        trace = _mapping(step.get("trace"), "hosted actual M5 trace is invalid")
        before = _validate_checkpoint(step.get("before"))
        after = _validate_checkpoint(step.get("after"))
        if (
            _mapping(expected, "hosted actual M5 plan step is invalid").get("step_id")
            != f"step.{index:02d}"
            or step.get("step_id") != f"step.{index:02d}"
            or before != previous_after
            or step.get("visibility_commit") != "POSTGRES_CAS"
            or step.get("oracle_digest") != sha256_digest(step.get("oracle"))
            or step.get("step_digest") != _semantic_digest(step, "step_digest")
            or trace.get("action_id")
            != _mapping(action, "hosted actual M5 action is invalid").get("action_id")
            or trace.get("action_digest")
            != _raw_digest(str(retained_byte_groups["action_bytes"][index - 1]))
            or trace.get("lab_action_digest")
            != _raw_digest(str(retained_byte_groups["lab_action_bytes"][index - 1]))
            or trace.get("policy_authorization_digest")
            != _raw_digest(str(retained_byte_groups["policy_authorization_bytes"][index - 1]))
            or trace.get("policy_request_digest")
            != _raw_digest(str(retained_byte_groups["policy_request_bytes"][index - 1]))
            or trace.get("response_status") not in (200, 403)
            or trace.get("response_body_digest") != _raw_digest(str(trace.get("response_body", "")))
            or trace.get("observation_digest") != _semantic_digest(trace, "observation_digest")
        ):
            raise ValueError("hosted actual M5 step is not content bound")
        previous_after = after
    terminal = _mapping(steps[-1], "hosted actual M5 terminal step is invalid")
    terminal_trace = _mapping(terminal.get("trace"), "hosted actual M5 terminal trace is invalid")
    terminal_oracle = _mapping(
        terminal.get("oracle"), "hosted actual M5 terminal oracle is invalid"
    )
    if (
        terminal_oracle.get("verdict") != expected_verdict
        or terminal_trace.get("response_status") != expected_response_status
        or previous_after != _validate_checkpoint(receipt.get("final_checkpoint"))
    ):
        raise ValueError("hosted actual M5 terminal boundary is invalid")
    image = _mapping(receipt.get("image_binding"), "hosted actual M5 image binding is invalid")
    if image.get("binding_digest") != _semantic_digest(image, "binding_digest"):
        raise ValueError("hosted actual M5 image binding is invalid")
    return (
        str(receipt["receipt_digest"]),
        str(image.get("application_container_id")),
        str(image.get("bridge_container_id")),
        str(image.get("application_image_id")),
        str(image.get("bridge_image_id")),
        initial[2],
    )


def _actual_signature(witness: Mapping[str, object]) -> str:
    receipt = _mapping(
        witness.get("materialized_run_receipt"), "hosted actual M5 receipt is invalid"
    )
    request = dict(_mapping(receipt.get("request"), "hosted actual M5 request is invalid"))
    request.pop("run_id", None)
    steps = _sequence(receipt.get("steps"), "hosted actual M5 steps are invalid")
    projected_steps: list[dict[str, object]] = []
    for item in steps:
        step = _mapping(item, "hosted actual M5 step is invalid")
        trace = _mapping(step.get("trace"), "hosted actual M5 trace is invalid")
        projected_steps.append(
            {
                "step_id": step.get("step_id"),
                "before": step.get("before"),
                "route": trace.get("route"),
                "method": trace.get("method"),
                "response_status": trace.get("response_status"),
                "response_body_digest": trace.get("response_body_digest"),
                "response_evidence_id": trace.get("response_evidence_id"),
                "response_action_id": trace.get("response_action_id"),
                "after": step.get("after"),
                "evidence_digest": step.get("evidence_digest"),
                "appended_evidence": step.get("appended_evidence"),
                "oracle": step.get("oracle"),
                "oracle_digest": step.get("oracle_digest"),
                "visibility_commit": step.get("visibility_commit"),
            }
        )
    return sha256_digest(
        {
            "request": request,
            "application_schema_digest": receipt.get("application_schema_digest"),
            "initial_checkpoint": receipt.get("initial_checkpoint"),
            "steps": projected_steps,
            "final_checkpoint": receipt.get("final_checkpoint"),
        }
    )


def _validate_actual_m5_composite(
    value: object,
    *,
    raw_m4: Mapping[str, object],
    raw_process: Mapping[str, object],
    m4_receipt_json: str,
    process_receipt_json: str,
    projection: M5HostedProjection,
    repository_marker: str,
) -> None:
    actual = _mapping(value, "hosted actual M5 composite is invalid")
    _exact_keys(
        actual,
        {
            "schema_version",
            "status",
            "repository_marker",
            "runtime",
            "m4_receipt_json",
            "m4_receipt_sha256",
            "m4_receipt_digest",
            "m4_winner_state_binding_digest",
            "m4_source_snapshot_digest",
            "m4_after_archive_digest",
            "m4_provider_state_digest",
            "process_receipt_json",
            "process_receipt_sha256",
            "process_receipt_digest",
            "execution_plan_digest",
            "primary_plan",
            "primary_plan_digest",
            "application_image_binding",
            "clean_root_runs",
            "vulnerable_deterministic_signatures",
            "initial_checkpoint_bytes_digest",
            "patched_run",
            "negative_controls",
            "cleanup_count",
            "all_cleanups_passed",
            "all_projects_destroyed",
            "receipt_digest",
        },
        "hosted actual M5 composite shape is invalid",
    )
    lineage = _mapping(
        raw_m4.get("winner_materialized_state"), "hosted actual M5 lineage is invalid"
    )
    primary_plan = actual.get("primary_plan")
    process_plan = raw_process.get("replay_plan")
    process_runs = _sequence(raw_process.get("runs"), "hosted process M5 runs are invalid")
    runs = _sequence(actual.get("clean_root_runs"), "hosted actual M5 runs are invalid")
    controls = _sequence(actual.get("negative_controls"), "hosted actual M5 controls are invalid")
    process_controls = _sequence(
        raw_process.get("negative_controls"), "hosted process M5 controls are invalid"
    )
    retained_signatures = _sequence(
        actual.get("vulnerable_deterministic_signatures"),
        "hosted actual M5 signatures are invalid",
    )
    if (
        actual.get("schema_version") != "stateweaver-m5-materialized-actual-asgi-qualification-v1"
        or actual.get("status") != "M5_MATERIALIZED_ACTUAL_ASGI_QUALIFIED"
        or actual.get("repository_marker") != repository_marker
        or actual.get("runtime") != "docker-compose-fastapi-asgi-six-provider@0.1.0"
        or actual.get("m4_receipt_json") != m4_receipt_json
        or actual.get("m4_receipt_sha256") != _raw_digest(m4_receipt_json)
        or actual.get("m4_receipt_digest") != raw_m4.get("receipt_digest")
        or actual.get("process_receipt_json") != process_receipt_json
        or actual.get("process_receipt_sha256") != _raw_digest(process_receipt_json)
        or actual.get("process_receipt_digest") != raw_process.get("receipt_digest")
        or actual.get("primary_plan") != process_plan
        or actual.get("primary_plan_digest") != sha256_digest(primary_plan)
        or lineage.get("binding_digest") != _semantic_digest(lineage, "binding_digest")
        or actual.get("m4_winner_state_binding_digest") != lineage.get("binding_digest")
        or actual.get("m4_source_snapshot_digest") != lineage.get("source_snapshot_manifest_digest")
        or actual.get("m4_after_archive_digest") != lineage.get("after_archive_digest")
        or actual.get("m4_provider_state_digest") != lineage.get("provider_state_digest")
        or len(runs) != 5
        or len(process_runs) != 5
        or len(controls) != 4
        or len(process_controls) != 4
        or actual.get("cleanup_count") != 10
        or actual.get("all_cleanups_passed") is not True
        or actual.get("all_projects_destroyed") is not True
        or actual.get("receipt_digest") != _semantic_digest(actual, "receipt_digest")
    ):
        raise ValueError("hosted actual M5 composite is not exact")
    receipt_digests: list[str] = []
    app_containers: list[str] = []
    bridge_containers: list[str] = []
    image_common: list[str] = []
    initial_raw: list[str] = []
    for index, (run, result) in enumerate(zip(runs, process_runs, strict=True), start=1):
        retained = _validate_actual_m5_run(
            run,
            expected_plan=primary_plan,
            expected_root=raw_process.get("clean_root"),
            expected_process_result=result,
            expected_run_id=f"run.m5.clean-root-{index:02d}",
            expected_scenario="primary_vulnerable",
            expected_mode="vulnerable",
            expected_outcome="VIOLATED",
            expected_verdict="VIOLATED",
            expected_response_status=200,
        )
        receipt_digests.append(retained[0])
        app_containers.append(retained[1])
        bridge_containers.append(retained[2])
        initial_raw.append(retained[5])
        image = _mapping(
            _mapping(run, "hosted actual M5 run is invalid").get("materialized_run_receipt"),
            "hosted actual M5 receipt is invalid",
        ).get("image_binding")
        binding = _mapping(image, "hosted actual M5 image binding is invalid")
        image_common.append(
            sha256_digest(
                tuple(
                    binding.get(key)
                    for key in (
                        "application_image_id",
                        "bridge_image_id",
                        "application_source_revision",
                        "image_identity_provenance",
                        "provider_image_refs",
                        "provider_image_set_digest",
                        "provider_image_provenance",
                    )
                )
            )
        )
    patched = _validate_actual_m5_run(
        actual.get("patched_run"),
        expected_plan=primary_plan,
        expected_root=raw_process.get("patched_root"),
        expected_process_result=raw_process.get("patched_run"),
        expected_run_id="run.m5.patched-01",
        expected_scenario="primary_patched",
        expected_mode="patched",
        expected_outcome="SATISFIED",
        expected_verdict="NOT_VIOLATED",
        expected_response_status=403,
    )
    receipt_digests.append(patched[0])
    app_containers.append(patched[1])
    bridge_containers.append(patched[2])
    control_receipts: list[str] = []
    expected_statuses = (200, 200, 403, 200)
    for name, status, control, process_control in zip(
        _M5_CONTROL_NAMES, expected_statuses, controls, process_controls, strict=True
    ):
        raw_control = _mapping(control, "hosted actual M5 control is invalid")
        retained_process_control = _mapping(process_control, "hosted process M5 control is invalid")
        if raw_control.get("name") != name or retained_process_control.get("name") != name:
            raise ValueError("hosted actual M5 control order is invalid")
        retained = _validate_actual_m5_run(
            {key: item for key, item in raw_control.items() if key != "name"},
            expected_plan=retained_process_control.get("plan"),
            expected_root=retained_process_control.get("root"),
            expected_process_result=retained_process_control.get("result"),
            expected_run_id=f"run.m5.control-{name}",
            expected_scenario=name,
            expected_mode="vulnerable",
            expected_outcome=str(retained_process_control.get("expected_outcome")),
            expected_verdict="NOT_VIOLATED",
            expected_response_status=status,
        )
        control_receipts.append(retained[0])
        receipt_digests.append(retained[0])
        app_containers.append(retained[1])
        bridge_containers.append(retained[2])
        image = _mapping(
            _mapping(
                raw_control.get("materialized_run_receipt"), "hosted actual M5 receipt is invalid"
            ).get("image_binding"),
            "hosted actual M5 image binding is invalid",
        )
        image_common.append(
            sha256_digest(
                tuple(
                    image.get(key)
                    for key in (
                        "application_image_id",
                        "bridge_image_id",
                        "application_source_revision",
                        "image_identity_provenance",
                        "provider_image_refs",
                        "provider_image_set_digest",
                        "provider_image_provenance",
                    )
                )
            )
        )
    patched_witness = _mapping(actual.get("patched_run"), "hosted actual M5 patch is invalid")
    patched_image = _mapping(
        _mapping(
            patched_witness.get("materialized_run_receipt"), "hosted actual M5 receipt is invalid"
        ).get("image_binding"),
        "hosted actual M5 image binding is invalid",
    )
    image_common.insert(
        5,
        sha256_digest(
            tuple(
                patched_image.get(key)
                for key in (
                    "application_image_id",
                    "bridge_image_id",
                    "application_source_revision",
                    "image_identity_provenance",
                    "provider_image_refs",
                    "provider_image_set_digest",
                    "provider_image_provenance",
                )
            )
        ),
    )
    all_container_ids = (*app_containers, *bridge_containers)
    signatures = tuple(
        _actual_signature(_mapping(item, "hosted actual M5 run is invalid")) for item in runs
    )
    representative_image = _mapping(
        actual.get("application_image_binding"), "hosted actual M5 image binding is invalid"
    )
    if (
        actual.get("application_image_binding")
        != _mapping(
            _mapping(
                _mapping(runs[0], "hosted actual M5 run is invalid").get(
                    "materialized_run_receipt"
                ),
                "hosted actual M5 receipt is invalid",
            ).get("image_binding"),
            "hosted actual M5 image binding is invalid",
        )
        or representative_image.get("application_source_revision") != repository_marker
        or representative_image.get("binding_digest") != projection.application_image_binding_digest
        or len(set(image_common)) != 1
        or len(set(all_container_ids)) != 20
        or tuple(initial_raw).count(initial_raw[0]) != 5
        or actual.get("initial_checkpoint_bytes_digest") != _raw_digest(initial_raw[0])
        or retained_signatures != signatures
        or len(set(signatures)) != 1
        or tuple(receipt_digests[:5]) != projection.clean_root_materialized_receipt_digests
        or patched[0] != projection.patched_materialized_receipt_digest
        or tuple(control_receipts) != projection.negative_control_materialized_receipt_digests
    ):
        raise ValueError("hosted actual M5 execution identities are invalid")


class HostedDockerQualificationReceipt(_HostedModel):
    """Producer receipt emitted only after the hosted Docker cleanup gate succeeds."""

    schema_version: Literal["stateweaver-hosted-docker-qualification-v3"]
    status: Literal["HOSTED_M2_M5_QUALIFIED"]
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
    m5_actual_receipt_json: Annotated[
        str, StringConstraints(min_length=2, max_length=32 * 1_048_576)
    ]
    m5_actual_receipt_sha256: Sha256Digest
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
        if (
            manifest_paths != tuple(sorted(set(manifest_paths)))
            or not manifest_paths
            or sum(item.size for item in self.artifact_manifest) > _MAX_HOSTED_ARTIFACT_TOTAL_BYTES
        ):
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
            raw_actual: object = json.loads(self.m5_actual_receipt_json)
            if (
                not isinstance(raw_m5, dict)
                or not isinstance(raw_actual, dict)
                or canonical_json_bytes(raw_m5).decode("utf-8") != self.m5_receipt_json
                or canonical_json_bytes(raw_actual).decode("utf-8") != self.m5_actual_receipt_json
            ):
                raise ValueError("hosted M5 receipts are not canonical")
        except (json.JSONDecodeError, EvidenceInputError, UnicodeError, ValueError, RecursionError):
            raise ValueError("hosted M5 receipts are invalid") from None
        m5 = self.m5
        if (
            _raw_digest(self.m5_receipt_json) != self.m5_receipt_sha256
            or _raw_digest(self.m5_actual_receipt_json) != self.m5_actual_receipt_sha256
            or raw_m5.get("schema_version") != "stateweaver-m5-observed-chain-qualification-v2"
            or raw_m5.get("status") != "VULNERABLE_PATCHED_CONTROLS_QUALIFIED"
            or raw_m5.get("repository_marker") != self.repository_marker
            or raw_m5.get("m4_receipt_json") != self.m4_receipt_json
            or raw_m5.get("m4_receipt_sha256") != m5.m4_receipt_sha256
            or raw_m5.get("m4_receipt_digest") != m5.m4_receipt_digest
            or raw_m5.get("receipt_digest") != m5.process_receipt_digest
            or raw_m5.get("receipt_digest") != _semantic_digest(raw_m5, "receipt_digest")
            or raw_actual.get("receipt_digest") != m5.actual_receipt_digest
            or raw_actual.get("runtime") != m5.runtime
            or raw_actual.get("m4_winner_state_binding_digest") != m5.m4_winner_state_binding_digest
            or raw_actual.get("m4_source_snapshot_digest") != m5.m4_source_snapshot_digest
            or raw_actual.get("m4_after_archive_digest") != m5.m4_after_archive_digest
            or raw_actual.get("m4_provider_state_digest") != m5.m4_provider_state_digest
            or raw_actual.get("execution_plan_digest") != m5.execution_plan_digest
            or raw_actual.get("primary_plan_digest") != m5.primary_plan_digest
            or raw_actual.get("initial_checkpoint_bytes_digest")
            != m5.initial_checkpoint_bytes_digest
            or tuple(raw_actual.get("vulnerable_deterministic_signatures", ()))
            != m5.vulnerable_deterministic_signatures
        ):
            raise ValueError("hosted M5 receipts do not match their projection")
        _validate_actual_m5_composite(
            raw_actual,
            raw_m4=raw,
            raw_process=raw_m5,
            m4_receipt_json=self.m4_receipt_json,
            process_receipt_json=self.m5_receipt_json,
            projection=m5,
            repository_marker=self.repository_marker,
        )
        expected = sha256_digest(self.model_dump(mode="python", exclude={"receipt_digest"}))
        if self.limitations != _HOSTED_LIMITATIONS or self.receipt_digest != expected:
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

    schema_version: Literal["stateweaver-hosted-qualification-admission-v3"]
    status: Literal["HOSTED_M2_M5_ADMITTED"]
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
        if self.limitations != _HOSTED_LIMITATIONS or self.admission_digest != expected:
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
    """Return only the exact M2-M5 registry rows proven by this hosted run."""

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
            "M5-X01",
            "SW-M5-CHAIN",
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
    raw_actual_m5 = json.loads(qualification.m5_actual_receipt_json)
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
        M5_MATERIALIZED_CHAIN_QUALIFICATION_PATH: raw_actual_m5,
        HOSTED_QUALIFICATION_ADMISSION_PATH: admission.model_dump(mode="json"),
    }


__all__ = [
    "HOSTED_QUALIFICATION_ADMISSION_PATH",
    "HOSTED_QUALIFICATION_DERIVED_PATHS",
    "M5_MATERIALIZED_CHAIN_QUALIFICATION_PATH",
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
