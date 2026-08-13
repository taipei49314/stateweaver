"""Fail-closed measured subprocess boundary for internal M7 experiments.

This module deliberately launches only the package's fixed worker.  It does not
accept commands, shell fragments, provider configuration, URLs, or filesystem
paths from benchmark inputs.
"""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from enum import StrEnum
from hashlib import sha256
from importlib import import_module
from pathlib import Path
from typing import Annotated, Literal, Protocol, cast

from pydantic import Field, model_validator
from stateweaver.contracts import Sha256Digest, canonical_json_bytes, sha256_digest
from stateweaver.contracts.base import ContractModel

from .generator import generate_dataset
from .models import (
    AblationFeature,
    AblationSpec,
    BudgetLimits,
    DatasetSplit,
    GeneratorConfig,
    SystemBenchmarkReport,
)
from .systems import BenchmarkSystem, LinearBaseline, StateWeaverTieredSystem


class MeasuredRunKind(StrEnum):
    LINEAR = "linear"
    FULL = "full"
    ABLATION = "ablation"


class MeasuredRunOutcome(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    CPU_BUDGET_EXCEEDED = "CPU_BUDGET_EXCEEDED"
    MEMORY_BUDGET_EXCEEDED = "MEMORY_BUDGET_EXCEEDED"
    WALL_BUDGET_EXCEEDED = "WALL_BUDGET_EXCEEDED"
    OUTPUT_LIMIT_EXCEEDED = "OUTPUT_LIMIT_EXCEEDED"
    PROCESS_MEASUREMENT_UNAVAILABLE = "PROCESS_MEASUREMENT_UNAVAILABLE"
    WORKER_FAILED = "WORKER_FAILED"
    PROTOCOL_REJECTED = "PROTOCOL_REJECTED"
    TAMPER_REJECTED = "TAMPER_REJECTED"


class MeasuredBudget(ContractModel):
    """One closed resource envelope applied identically to every matched run."""

    max_cpu_milliseconds: Annotated[int, Field(ge=50, le=3_600_000)]
    max_peak_rss_bytes: Annotated[int, Field(ge=16 * 1024 * 1024, le=16 * 1024**3)]
    max_wall_milliseconds: Annotated[int, Field(ge=50, le=3_600_000)]
    max_requests: Annotated[int, Field(ge=0, le=1_000_000)]
    max_tokens: Annotated[int, Field(ge=0, le=1_000_000_000)]
    max_cost_microusd: Annotated[int, Field(ge=0, le=10**12)]
    max_output_bytes: Annotated[int, Field(ge=512, le=16 * 1024 * 1024)] = 2 * 1024 * 1024


class MeasuredUsage(ContractModel):
    cpu_milliseconds: Annotated[int, Field(ge=0)]
    peak_rss_bytes: Annotated[int, Field(ge=0)]
    wall_milliseconds: Annotated[int, Field(ge=0)]
    requests: Annotated[int, Field(ge=0)] = 0
    tokens: Annotated[int, Field(ge=0)] = 0
    cost_microusd: Annotated[int, Field(ge=0)] = 0

    def fits(self, budget: MeasuredBudget) -> bool:
        return (
            self.cpu_milliseconds <= budget.max_cpu_milliseconds
            and self.peak_rss_bytes <= budget.max_peak_rss_bytes
            and self.wall_milliseconds <= budget.max_wall_milliseconds
            and self.requests <= budget.max_requests
            and self.tokens <= budget.max_tokens
            and self.cost_microusd <= budget.max_cost_microusd
        )


class MeasuredRunRequest(ContractModel):
    schema_version: Literal["m7-measured-request-v1"] = "m7-measured-request-v1"
    run_id: Sha256Digest
    kind: MeasuredRunKind
    generator_config: GeneratorConfig
    split: DatasetSplit
    logical_budget: BudgetLimits
    measured_budget: MeasuredBudget
    ablation: AblationFeature | None = None
    tiered_seed: Annotated[int, Field(ge=0, le=2**31 - 1)] = 0
    beam_width: Annotated[int, Field(ge=1, le=16)] = 3

    @model_validator(mode="after")
    def shape_and_identifier_are_closed(self) -> MeasuredRunRequest:
        if (self.kind is MeasuredRunKind.ABLATION) != (self.ablation is not None):
            raise ValueError("exactly an ablation run requires one ablation feature")
        if self.run_id != self.expected_run_id():
            raise ValueError("measured run ID must bind the complete immutable request")
        return self

    def expected_run_id(self) -> str:
        return sha256_digest(self._identity_payload())

    def _identity_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "generator_config": self.generator_config,
            "split": self.split,
            "logical_budget": self.logical_budget,
            "measured_budget": self.measured_budget,
            "ablation": self.ablation,
            "tiered_seed": self.tiered_seed,
            "beam_width": self.beam_width,
        }


def build_measured_run_request(
    *,
    kind: MeasuredRunKind,
    generator_config: GeneratorConfig,
    split: DatasetSplit,
    logical_budget: BudgetLimits,
    measured_budget: MeasuredBudget,
    ablation: AblationFeature | None,
    tiered_seed: int,
    beam_width: int,
) -> MeasuredRunRequest:
    payload: dict[str, object] = {
        "schema_version": "m7-measured-request-v1",
        "kind": kind,
        "generator_config": generator_config,
        "split": split,
        "logical_budget": logical_budget,
        "measured_budget": measured_budget,
        "ablation": ablation,
        "tiered_seed": tiered_seed,
        "beam_width": beam_width,
    }
    return MeasuredRunRequest.model_validate({"run_id": sha256_digest(payload), **payload})


class MeasuredExperimentPlan(ContractModel):
    schema_version: Literal["m7-measured-plan-v1"] = "m7-measured-plan-v1"
    dataset_posture: Literal["producer-visible-synthetic"] = "producer-visible-synthetic"
    protected_holdout: Literal[False] = False
    independent_evaluator: Literal[False] = False
    plan_digest: Sha256Digest
    generator_config: GeneratorConfig
    split: DatasetSplit
    logical_budget: BudgetLimits
    measured_budget: MeasuredBudget
    runs: tuple[MeasuredRunRequest, ...]

    @model_validator(mode="after")
    def matrix_and_budgets_are_closed(self) -> MeasuredExperimentPlan:
        if len(self.runs) != 2 + len(AblationFeature):
            raise ValueError("measured plan must retain the primary pair and every ablation")
        if tuple(item.kind for item in self.runs[:2]) != (
            MeasuredRunKind.LINEAR,
            MeasuredRunKind.FULL,
        ):
            raise ValueError("measured plan must begin with the linear/full matched pair")
        ablations = tuple(item.ablation for item in self.runs[2:])
        if tuple(sorted(ablations, key=lambda item: item.value if item else "")) != tuple(
            sorted(AblationFeature, key=lambda item: item.value)
        ):
            raise ValueError("measured plan must retain every ablation exactly once")
        if any(item.measured_budget != self.measured_budget for item in self.runs):
            raise ValueError("every measured run must receive the same measured budget")
        if any(item.logical_budget != self.logical_budget for item in self.runs):
            raise ValueError("every measured run must receive the same logical budget")
        if any(
            item.generator_config != self.generator_config or item.split is not self.split
            for item in self.runs
        ):
            raise ValueError("every measured run must receive the same dataset and split")
        if len({(item.tiered_seed, item.beam_width) for item in self.runs}) != 1:
            raise ValueError("full and ablation runs must share one solver configuration basis")
        run_ids = tuple(item.run_id for item in self.runs)
        if len(run_ids) != len(set(run_ids)):
            raise ValueError("measured run IDs must be unique")
        if self.plan_digest != self.expected_plan_digest():
            raise ValueError("measured plan digest must bind the complete run matrix")
        return self

    def expected_plan_digest(self) -> str:
        return sha256_digest(
            {
                "schema_version": self.schema_version,
                "dataset_posture": self.dataset_posture,
                "protected_holdout": self.protected_holdout,
                "independent_evaluator": self.independent_evaluator,
                "generator_config": self.generator_config,
                "split": self.split,
                "logical_budget": self.logical_budget,
                "measured_budget": self.measured_budget,
                "runs": self.runs,
            }
        )


def build_measured_experiment_plan(
    *,
    generator_config: GeneratorConfig,
    split: DatasetSplit,
    logical_budget: BudgetLimits,
    measured_budget: MeasuredBudget,
    tiered_seed: int,
    beam_width: int,
) -> MeasuredExperimentPlan:
    runs = (
        build_measured_run_request(
            kind=MeasuredRunKind.LINEAR,
            generator_config=generator_config,
            split=split,
            logical_budget=logical_budget,
            measured_budget=measured_budget,
            ablation=None,
            tiered_seed=tiered_seed,
            beam_width=beam_width,
        ),
        build_measured_run_request(
            kind=MeasuredRunKind.FULL,
            generator_config=generator_config,
            split=split,
            logical_budget=logical_budget,
            measured_budget=measured_budget,
            ablation=None,
            tiered_seed=tiered_seed,
            beam_width=beam_width,
        ),
        *(
            build_measured_run_request(
                kind=MeasuredRunKind.ABLATION,
                generator_config=generator_config,
                split=split,
                logical_budget=logical_budget,
                measured_budget=measured_budget,
                ablation=feature,
                tiered_seed=tiered_seed,
                beam_width=beam_width,
            )
            for feature in sorted(AblationFeature, key=lambda item: item.value)
        ),
    )
    payload = {
        "schema_version": "m7-measured-plan-v1",
        "dataset_posture": "producer-visible-synthetic",
        "protected_holdout": False,
        "independent_evaluator": False,
        "generator_config": generator_config,
        "split": split,
        "logical_budget": logical_budget,
        "measured_budget": measured_budget,
        "runs": runs,
    }
    return MeasuredExperimentPlan.model_validate({"plan_digest": sha256_digest(payload), **payload})


class MeasuredRunRecord(ContractModel):
    schema_version: Literal["m7-measured-record-v1"] = "m7-measured-record-v1"
    request: MeasuredRunRequest
    request_digest: Sha256Digest
    outcome: MeasuredRunOutcome
    usage: MeasuredUsage
    worker_pid: Annotated[int, Field(ge=1)]
    exit_code: int | None
    stdout_digest: Sha256Digest
    stdout_bytes: Annotated[int, Field(ge=0)]
    stdout_truncated: bool
    stderr_digest: Sha256Digest
    stderr_bytes: Annotated[int, Field(ge=0)]
    stderr_truncated: bool
    report: SystemBenchmarkReport | None

    @model_validator(mode="after")
    def record_is_bound_and_fail_closed(self) -> MeasuredRunRecord:
        if self.request_digest != sha256_digest(self.request):
            raise ValueError("measured record must bind its exact request")
        succeeded = self.outcome is MeasuredRunOutcome.SUCCEEDED
        if succeeded != (self.report is not None):
            raise ValueError("only a successful measured run may retain a benchmark report")
        if succeeded and (
            self.exit_code != 0
            or self.stdout_truncated
            or self.stderr_truncated
            or self.stderr_bytes != 0
            or not self.usage.fits(self.request.measured_budget)
        ):
            raise ValueError("successful measured records must satisfy every closed boundary")
        return self


class MeasuredExperimentReceipt(ContractModel):
    schema_version: Literal["m7-measured-receipt-v1"] = "m7-measured-receipt-v1"
    plan: MeasuredExperimentPlan
    records: tuple[MeasuredRunRecord, ...]
    all_runs_retained: Literal[True] = True
    external_qualification_satisfied: Literal[False] = False

    @model_validator(mode="after")
    def every_planned_run_is_retained(self) -> MeasuredExperimentReceipt:
        if tuple(item.request for item in self.records) != self.plan.runs:
            raise ValueError("measured receipt must retain every planned run in canonical order")
        return self

    @property
    def receipt_digest(self) -> str:
        return sha256_digest(self)


class _WorkerEnvelope(ContractModel):
    schema_version: Literal["m7-worker-v1"] = "m7-worker-v1"
    request_digest: Sha256Digest
    report: SystemBenchmarkReport
    report_digest: Sha256Digest
    requests: Literal[0] = 0
    tokens: Literal[0] = 0
    cost_microusd: Literal[0] = 0

    @model_validator(mode="after")
    def report_digest_is_exact(self) -> _WorkerEnvelope:
        if self.report_digest != self.report.report_digest:
            raise ValueError("worker report digest does not bind its report")
        return self


class _CapturedOutput:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.stdout_bytes = 0
        self.stderr_bytes = 0
        self.stdout_truncated = False
        self.stderr_truncated = False
        self.overflow = threading.Event()
        self._lock = threading.Lock()

    def read(self, stream: object, *, stderr: bool) -> None:
        target = self.stderr if stderr else self.stdout
        while True:
            chunk = stream.read(8192)  # type: ignore[attr-defined]
            if not chunk:
                return
            with self._lock:
                if stderr:
                    self.stderr_bytes += len(chunk)
                else:
                    self.stdout_bytes += len(chunk)
                remaining = max(0, self.limit - len(self.stdout) - len(self.stderr))
                target.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    if stderr:
                        self.stderr_truncated = True
                    else:
                        self.stdout_truncated = True
                    self.overflow.set()
                    return


def _raw_digest(value: bytes | bytearray) -> str:
    return f"sha256:{sha256(value).hexdigest()}"


class _ProcessSample(ContractModel):
    cpu_milliseconds: int
    rss_bytes: int


class _ResourceModule(Protocol):
    RLIMIT_CPU: int
    RLIMIT_AS: int

    def setrlimit(self, resource: int, limits: tuple[int, int]) -> None: ...


class MeasuredSubprocessRunner:
    """Run the fixed internal benchmark worker with host-enforced resource limits."""

    _poll_seconds = 0.005

    def sanitized_environment(self) -> dict[str, str]:
        """Return a fixed allowlist; provider credentials are never read or inherited."""

        environment = {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONNOUSERSITE": "1",
        }
        for name in ("SYSTEMROOT", "WINDIR", "PATH"):
            value = os.environ.get(name)
            if value:
                environment[name] = value
        if os.name != "nt":
            environment["LANG"] = "C.UTF-8"
            environment["LC_ALL"] = "C.UTF-8"
        return environment

    def run_plan(self, plan: MeasuredExperimentPlan) -> MeasuredExperimentReceipt:
        records = tuple(self.run(request) for request in plan.runs)
        return MeasuredExperimentReceipt(plan=plan, records=records)

    def run(self, request: MeasuredRunRequest) -> MeasuredRunRecord:
        request = MeasuredRunRequest.model_validate(request.model_dump(mode="python"))
        budget = request.measured_budget
        command = self._fixed_worker_command()
        started_ns = time.monotonic_ns()
        with tempfile.TemporaryDirectory(prefix="statechainbench-m7-") as workdir:
            process = self._start_process(command, workdir=workdir, budget=budget)
            worker_pid = process.pid
            captured = _CapturedOutput(budget.max_output_bytes)
            assert process.stdout is not None
            assert process.stderr is not None
            readers = (
                threading.Thread(
                    target=captured.read,
                    args=(process.stdout,),
                    kwargs={"stderr": False},
                    daemon=True,
                ),
                threading.Thread(
                    target=captured.read,
                    args=(process.stderr,),
                    kwargs={"stderr": True},
                    daemon=True,
                ),
            )
            for reader in readers:
                reader.start()
            assert process.stdin is not None
            process.stdin.write(canonical_json_bytes(request))
            process.stdin.close()

            outcome: MeasuredRunOutcome | None = None
            peak_cpu = 0
            peak_rss = 0
            sampled = False
            while process.poll() is None:
                sample = self._sample_process(process.pid)
                if sample is not None:
                    sampled = True
                    peak_cpu = max(peak_cpu, sample.cpu_milliseconds)
                    peak_rss = max(peak_rss, sample.rss_bytes)
                wall = (time.monotonic_ns() - started_ns) // 1_000_000
                if captured.overflow.is_set():
                    outcome = MeasuredRunOutcome.OUTPUT_LIMIT_EXCEEDED
                elif peak_cpu > budget.max_cpu_milliseconds:
                    outcome = MeasuredRunOutcome.CPU_BUDGET_EXCEEDED
                elif peak_rss > budget.max_peak_rss_bytes:
                    outcome = MeasuredRunOutcome.MEMORY_BUDGET_EXCEEDED
                elif wall > budget.max_wall_milliseconds:
                    outcome = MeasuredRunOutcome.WALL_BUDGET_EXCEEDED
                if outcome is not None:
                    process.kill()
                    break
                time.sleep(self._poll_seconds)
            process.wait()
            for reader in readers:
                reader.join(timeout=1)

        wall_ms = (time.monotonic_ns() - started_ns) // 1_000_000
        usage = MeasuredUsage(
            cpu_milliseconds=peak_cpu,
            peak_rss_bytes=peak_rss,
            wall_milliseconds=wall_ms,
            requests=0,
            tokens=0,
            cost_microusd=0,
        )
        if outcome is None:
            if captured.overflow.is_set():
                outcome = MeasuredRunOutcome.OUTPUT_LIMIT_EXCEEDED
            elif not sampled:
                outcome = MeasuredRunOutcome.PROCESS_MEASUREMENT_UNAVAILABLE
            elif usage.cpu_milliseconds > budget.max_cpu_milliseconds:
                outcome = MeasuredRunOutcome.CPU_BUDGET_EXCEEDED
            elif usage.peak_rss_bytes > budget.max_peak_rss_bytes:
                outcome = MeasuredRunOutcome.MEMORY_BUDGET_EXCEEDED
            elif usage.wall_milliseconds > budget.max_wall_milliseconds:
                outcome = MeasuredRunOutcome.WALL_BUDGET_EXCEEDED
        report: SystemBenchmarkReport | None = None
        if outcome is None:
            outcome, report = self._admit_worker_output(
                request=request,
                exit_code=process.returncode,
                stdout=bytes(captured.stdout),
                stderr=bytes(captured.stderr),
            )
        return MeasuredRunRecord(
            request=request,
            request_digest=sha256_digest(request),
            outcome=outcome,
            usage=usage,
            worker_pid=worker_pid,
            exit_code=process.returncode,
            stdout_digest=_raw_digest(captured.stdout),
            stdout_bytes=captured.stdout_bytes,
            stdout_truncated=captured.stdout_truncated,
            stderr_digest=_raw_digest(captured.stderr),
            stderr_bytes=captured.stderr_bytes,
            stderr_truncated=captured.stderr_truncated,
            report=report,
        )

    def _start_process(
        self,
        command: Sequence[str],
        *,
        workdir: str,
        budget: MeasuredBudget,
    ) -> subprocess.Popen[bytes]:
        if os.name == "nt":
            return subprocess.Popen(
                tuple(command),
                shell=False,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=workdir,
                env=self.sanitized_environment(),
                close_fds=True,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
            )
        return subprocess.Popen(
            tuple(command),
            shell=False,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=workdir,
            env=self.sanitized_environment(),
            close_fds=True,
            start_new_session=True,
            preexec_fn=self._posix_limits(budget),
        )

    @staticmethod
    def _posix_limits(budget: MeasuredBudget) -> Callable[[], None]:
        def set_limits() -> None:
            import math

            resource = cast(_ResourceModule, import_module("resource"))
            cpu_seconds = max(1, math.ceil(budget.max_cpu_milliseconds / 1000))
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
            resource.setrlimit(
                resource.RLIMIT_AS,
                (budget.max_peak_rss_bytes, budget.max_peak_rss_bytes),
            )

        return set_limits

    def _fixed_worker_command(self) -> tuple[str, ...]:
        benchmark_src = Path(__file__).resolve().parents[1]
        repository = Path(__file__).resolve().parents[4]
        import_roots = (
            benchmark_src,
            repository / "packages" / "contracts" / "src",
            repository / "packages" / "search" / "src",
            Path(sys.prefix) / "Lib" / "site-packages",
        )
        bootstrap = (
            "import sys;"
            f"sys.path[:0]={[str(item) for item in import_roots]!r};"
            "from statechainbench.measured_worker import main;"
            "raise SystemExit(main())"
        )
        executable = str(getattr(sys, "_base_executable", sys.executable))
        return (executable, "-I", "-c", bootstrap)

    @staticmethod
    def _sample_process(pid: int) -> _ProcessSample | None:
        if os.name == "nt":
            return _sample_windows_process(pid)
        return _sample_procfs_process(pid)

    @staticmethod
    def _admit_worker_output(
        *,
        request: MeasuredRunRequest,
        exit_code: int,
        stdout: bytes,
        stderr: bytes,
    ) -> tuple[MeasuredRunOutcome, SystemBenchmarkReport | None]:
        if exit_code != 0:
            return MeasuredRunOutcome.WORKER_FAILED, None
        if stderr:
            return MeasuredRunOutcome.PROTOCOL_REJECTED, None
        try:
            raw = json.loads(stdout.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return MeasuredRunOutcome.PROTOCOL_REJECTED, None
        if not isinstance(raw, Mapping):
            return MeasuredRunOutcome.PROTOCOL_REJECTED, None
        expected_request_digest = sha256_digest(request)
        if raw.get("request_digest") != expected_request_digest:
            return MeasuredRunOutcome.TAMPER_REJECTED, None
        report_payload = raw.get("report")
        if not isinstance(report_payload, Mapping):
            return MeasuredRunOutcome.PROTOCOL_REJECTED, None
        try:
            envelope = _WorkerEnvelope.model_validate_json(stdout)
        except ValueError:
            return MeasuredRunOutcome.TAMPER_REJECTED, None
        if not _report_matches_request(envelope.report, request):
            return MeasuredRunOutcome.TAMPER_REJECTED, None
        return MeasuredRunOutcome.SUCCEEDED, envelope.report


def _report_matches_request(report: SystemBenchmarkReport, request: MeasuredRunRequest) -> bool:
    dataset = generate_dataset(request.generator_config)
    system: BenchmarkSystem
    if request.kind is MeasuredRunKind.LINEAR:
        system = LinearBaseline()
    else:
        disabled = () if request.ablation is None else (request.ablation,)
        system = StateWeaverTieredSystem(
            seed=request.tiered_seed,
            beam_width=request.beam_width,
            ablation=AblationSpec(disabled=disabled),
        )
    return (
        report.dataset_digest == dataset.dataset_digest
        and report.evaluator_digest == dataset.evaluator_digest
        and report.generator_config_digest == request.generator_config.config_digest
        and report.system_id == system.system_id
        and report.system_config_digest == system.system_config_digest
        and tuple(item.challenge_id for item in report.raw_results)
        == tuple(descriptor.public.challenge_id for descriptor in dataset.for_split(request.split))
        and tuple(item.challenge_digest for item in report.raw_results)
        == tuple(descriptor.challenge_digest for descriptor in dataset.for_split(request.split))
        and all(
            item.split is request.split and item.budget == request.logical_budget
            for item in report.raw_results
        )
    )


def _sample_procfs_process(pid: int) -> _ProcessSample | None:
    stat_path = Path(f"/proc/{pid}/stat")
    try:
        stat = stat_path.read_text(encoding="ascii")
        fields = stat[stat.rfind(")") + 2 :].split()
        cpu_ticks = int(fields[11]) + int(fields[12])
        rss_pages = int(fields[21])
        sysconf = cast(Callable[[str], int], getattr(os, "sysconf"))  # noqa: B009
        ticks_per_second = sysconf("SC_CLK_TCK")
        page_size = sysconf("SC_PAGE_SIZE")
    except (FileNotFoundError, OSError, ValueError, IndexError):
        return None
    return _ProcessSample(
        cpu_milliseconds=(cpu_ticks * 1000) // ticks_per_second,
        rss_bytes=max(0, rss_pages * page_size),
    )


class _FileTime(ctypes.Structure):
    _fields_ = (("low", ctypes.c_uint32), ("high", ctypes.c_uint32))


class _ProcessMemoryCounters(ctypes.Structure):
    _fields_ = (
        ("cb", ctypes.c_uint32),
        ("page_fault_count", ctypes.c_uint32),
        ("peak_working_set_size", ctypes.c_size_t),
        ("working_set_size", ctypes.c_size_t),
        ("quota_peak_paged_pool_usage", ctypes.c_size_t),
        ("quota_paged_pool_usage", ctypes.c_size_t),
        ("quota_peak_non_paged_pool_usage", ctypes.c_size_t),
        ("quota_non_paged_pool_usage", ctypes.c_size_t),
        ("pagefile_usage", ctypes.c_size_t),
        ("peak_pagefile_usage", ctypes.c_size_t),
    )


def _filetime_value(value: _FileTime) -> int:
    return (int(value.high) << 32) | int(value.low)


def _sample_windows_process(pid: int) -> _ProcessSample | None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = (ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32)
    open_process.restype = ctypes.c_void_p
    handle = open_process(0x0400 | 0x0010, False, pid)
    if not handle:
        return None
    try:
        get_process_times = kernel32.GetProcessTimes
        get_process_times.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(_FileTime),
            ctypes.POINTER(_FileTime),
            ctypes.POINTER(_FileTime),
            ctypes.POINTER(_FileTime),
        )
        get_process_times.restype = ctypes.c_int
        get_process_memory = psapi.GetProcessMemoryInfo
        get_process_memory.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(_ProcessMemoryCounters),
            ctypes.c_uint32,
        )
        get_process_memory.restype = ctypes.c_int
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = (ctypes.c_void_p,)
        close_handle.restype = ctypes.c_int
        creation = _FileTime()
        exit_time = _FileTime()
        kernel = _FileTime()
        user = _FileTime()
        if not get_process_times(
            handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            return None
        counters = _ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        if not get_process_memory(
            handle,
            ctypes.byref(counters),
            counters.cb,
        ):
            return None
        return _ProcessSample(
            cpu_milliseconds=(_filetime_value(kernel) + _filetime_value(user)) // 10_000,
            rss_bytes=int(counters.peak_working_set_size),
        )
    finally:
        close_handle(handle)
