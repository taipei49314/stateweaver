from __future__ import annotations

import os
import sys
from collections.abc import Sequence
from io import BytesIO
from typing import TextIO, cast

import pytest
from pydantic import ValidationError
from stateweaver.contracts import sha256_digest

from statechainbench.measured import (
    MeasuredBudget,
    MeasuredExperimentPlan,
    MeasuredRunKind,
    MeasuredRunOutcome,
    MeasuredRunRequest,
    MeasuredSubprocessRunner,
    _ProcessSample,
    build_measured_experiment_plan,
    build_measured_run_request,
)
from statechainbench.measured_worker import main as worker_main
from statechainbench.models import (
    AblationFeature,
    BudgetLimits,
    DatasetSplit,
    GeneratorConfig,
)


def _measured_budget(**updates: int) -> MeasuredBudget:
    values = {
        "max_cpu_milliseconds": 5_000,
        "max_peak_rss_bytes": 512 * 1024 * 1024,
        "max_wall_milliseconds": 10_000,
        "max_requests": 0,
        "max_tokens": 0,
        "max_cost_microusd": 0,
        "max_output_bytes": 2 * 1024 * 1024,
    }
    values.update(updates)
    return MeasuredBudget(**values)


def _logical_budget() -> BudgetLimits:
    return BudgetLimits(
        max_action_cost=128,
        max_world_cost=32,
        max_latency_units=512,
    )


def _python_executable() -> str:
    return str(getattr(sys, "_base_executable", sys.executable))


def _request(kind: MeasuredRunKind = MeasuredRunKind.LINEAR) -> MeasuredRunRequest:
    return build_measured_run_request(
        kind=kind,
        generator_config=GeneratorConfig(seed=703, variants_per_family=1),
        split=DatasetSplit.TRAIN,
        logical_budget=_logical_budget(),
        measured_budget=_measured_budget(),
        ablation=(AblationFeature.SEMANTIC_TWIN if kind is MeasuredRunKind.ABLATION else None),
        tiered_seed=17,
        beam_width=3,
    )


class _BinaryStream:
    def __init__(self, value: bytes = b"") -> None:
        self.buffer = BytesIO(value)


def test_measured_contracts_are_strict_frozen_content_bound_and_closed() -> None:
    request = _request()
    dumped = request.model_dump(mode="python")

    with pytest.raises(ValidationError, match="Extra inputs"):
        MeasuredRunRequest.model_validate({**dumped, "shell": "ignored"})
    with pytest.raises(ValidationError, match="frozen"):
        request.run_id = sha256_digest({"tampered": True})
    with pytest.raises(ValidationError, match="run ID"):
        MeasuredRunRequest.model_validate({**dumped, "run_id": sha256_digest("tampered")})
    with pytest.raises(ValidationError, match="ablation feature"):
        build_measured_run_request(
            kind=MeasuredRunKind.LINEAR,
            generator_config=request.generator_config,
            split=request.split,
            logical_budget=request.logical_budget,
            measured_budget=request.measured_budget,
            ablation=AblationFeature.CHAIN_COMPILER,
            tiered_seed=request.tiered_seed,
            beam_width=request.beam_width,
        )


def test_plan_closes_equal_measured_work_and_retains_every_ablation() -> None:
    plan = build_measured_experiment_plan(
        generator_config=GeneratorConfig(seed=704, variants_per_family=1),
        split=DatasetSplit.HOLDOUT,
        logical_budget=_logical_budget(),
        measured_budget=_measured_budget(),
        tiered_seed=19,
        beam_width=3,
    )

    assert {request.measured_budget for request in plan.runs} == {plan.measured_budget}
    assert {request.logical_budget for request in plan.runs} == {plan.logical_budget}
    assert [request.kind for request in plan.runs[:2]] == [
        MeasuredRunKind.LINEAR,
        MeasuredRunKind.FULL,
    ]
    assert {
        request.ablation for request in plan.runs if request.kind is MeasuredRunKind.ABLATION
    } == set(AblationFeature)
    assert len(plan.runs) == 2 + len(AblationFeature)
    assert plan.dataset_posture == "producer-visible-synthetic"
    assert plan.protected_holdout is False
    assert plan.independent_evaluator is False

    with pytest.raises(ValidationError, match="every ablation"):
        MeasuredExperimentPlan(
            plan_digest=plan.plan_digest,
            generator_config=plan.generator_config,
            split=plan.split,
            logical_budget=plan.logical_budget,
            measured_budget=plan.measured_budget,
            runs=plan.runs[:-1],
        )

    unequal = build_measured_run_request(
        kind=MeasuredRunKind.ABLATION,
        generator_config=plan.generator_config,
        split=plan.split,
        logical_budget=plan.logical_budget,
        measured_budget=_measured_budget(max_tokens=1),
        ablation=plan.runs[-1].ablation,
        tiered_seed=plan.runs[-1].tiered_seed,
        beam_width=plan.runs[-1].beam_width,
    )
    with pytest.raises(ValidationError, match="same measured budget"):
        MeasuredExperimentPlan(
            plan_digest=plan.plan_digest,
            generator_config=plan.generator_config,
            split=plan.split,
            logical_budget=plan.logical_budget,
            measured_budget=plan.measured_budget,
            runs=(*plan.runs[:-1], unequal),
        )


def test_plan_execution_retains_every_failed_primary_and_ablation_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = build_measured_experiment_plan(
        generator_config=GeneratorConfig(seed=705, variants_per_family=1),
        split=DatasetSplit.TRAIN,
        logical_budget=_logical_budget(),
        measured_budget=_measured_budget(),
        tiered_seed=23,
        beam_width=3,
    )
    runner = MeasuredSubprocessRunner()
    monkeypatch.setattr(
        runner,
        "_fixed_worker_command",
        lambda: (_python_executable(), "-c", "print('hostile non-json')"),
    )

    receipt = runner.run_plan(plan)

    assert tuple(record.request.run_id for record in receipt.records) == tuple(
        request.run_id for request in plan.runs
    )
    assert len(receipt.records) == len(plan.runs)
    assert {record.outcome for record in receipt.records} == {MeasuredRunOutcome.PROTOCOL_REJECTED}
    assert receipt.all_runs_retained is True
    assert receipt.external_qualification_satisfied is False


def test_fixed_worker_runs_in_a_separate_process_and_retains_host_measurements() -> None:
    record = MeasuredSubprocessRunner().run(_request())

    assert record.outcome is MeasuredRunOutcome.SUCCEEDED
    assert record.worker_pid != os.getpid()
    assert record.report is not None
    assert record.report.raw_results
    assert record.request_digest == sha256_digest(record.request)
    assert record.usage.cpu_milliseconds <= record.request.measured_budget.max_cpu_milliseconds
    assert record.usage.peak_rss_bytes <= record.request.measured_budget.max_peak_rss_bytes
    assert record.usage.wall_milliseconds <= record.request.measured_budget.max_wall_milliseconds
    assert record.usage.requests == record.usage.tokens == record.usage.cost_microusd == 0
    assert record.stdout_bytes > 0
    assert record.stderr_bytes == 0


def test_fixed_worker_protocol_emits_one_bound_envelope_and_suppresses_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request()
    stdin = _BinaryStream(request.canonical_bytes())
    stdout = _BinaryStream()
    monkeypatch.setattr(sys, "stdin", cast(TextIO, stdin))
    monkeypatch.setattr(sys, "stdout", cast(TextIO, stdout))

    assert worker_main() == 0
    payload = stdout.buffer.getvalue()
    assert sha256_digest(request).encode() in payload
    assert b'"report_digest":"sha256:' in payload

    bad_stdin = _BinaryStream(b"{not-json")
    bad_stdout = _BinaryStream()
    monkeypatch.setattr(sys, "stdin", cast(TextIO, bad_stdin))
    monkeypatch.setattr(sys, "stdout", cast(TextIO, bad_stdout))
    assert worker_main() == 2
    assert bad_stdout.buffer.getvalue() == b""


def test_provider_credentials_are_not_inherited_by_the_fixed_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-do-not-read")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "synthetic-do-not-read")
    runner = MeasuredSubprocessRunner()

    environment = runner.sanitized_environment()

    assert "OPENAI_API_KEY" not in environment
    assert "ANTHROPIC_API_KEY" not in environment
    assert set(environment) <= {
        "LANG",
        "LC_ALL",
        "PATH",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONHASHSEED",
        "PYTHONNOUSERSITE",
        "SYSTEMROOT",
        "WINDIR",
    }


@pytest.mark.parametrize(
    ("command", "budget", "expected"),
    (
        (
            (_python_executable(), "-c", "import time; time.sleep(1)"),
            _measured_budget(max_wall_milliseconds=100),
            MeasuredRunOutcome.WALL_BUDGET_EXCEEDED,
        ),
        (
            (_python_executable(), "-c", "import sys; sys.stdout.write('x' * 65536)"),
            _measured_budget(max_output_bytes=1024),
            MeasuredRunOutcome.OUTPUT_LIMIT_EXCEEDED,
        ),
        (
            (_python_executable(), "-c", "print('{not-json')"),
            _measured_budget(),
            MeasuredRunOutcome.PROTOCOL_REJECTED,
        ),
    ),
)
def test_hostile_timing_output_and_protocol_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    command: Sequence[str],
    budget: MeasuredBudget,
    expected: MeasuredRunOutcome,
) -> None:
    request = _request().model_copy(update={"measured_budget": budget})
    request = request.model_copy(update={"run_id": request.expected_run_id()})
    runner = MeasuredSubprocessRunner()
    monkeypatch.setattr(runner, "_fixed_worker_command", lambda: tuple(command))

    record = runner.run(request)

    assert record.outcome is expected
    assert record.report is None
    assert record.stdout_digest.startswith("sha256:")
    assert record.stderr_digest.startswith("sha256:")


def test_tampered_worker_envelope_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    request = _request()
    script = (
        "import json,sys; "
        "json.load(sys.stdin); "
        "print(json.dumps({'schema_version':'m7-worker-v1',"
        "'request_digest':'sha256:'+'0'*64,'report':None,'report_digest':None,"
        "'requests':0,'tokens':0,'cost_microusd':0}))"
    )
    runner = MeasuredSubprocessRunner()
    monkeypatch.setattr(
        runner,
        "_fixed_worker_command",
        lambda: (_python_executable(), "-c", script),
    )

    record = runner.run(request)

    assert record.outcome is MeasuredRunOutcome.TAMPER_REJECTED
    assert record.report is None


def test_host_measured_cpu_and_memory_excesses_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cpu_request = _request().model_copy(
        update={
            "measured_budget": _measured_budget(
                max_cpu_milliseconds=50,
                max_wall_milliseconds=1_000,
            )
        }
    )
    cpu_request = cpu_request.model_copy(update={"run_id": cpu_request.expected_run_id()})
    cpu_runner = MeasuredSubprocessRunner()
    monkeypatch.setattr(
        cpu_runner,
        "_fixed_worker_command",
        lambda: (_python_executable(), "-c", "while True: pass"),
    )
    cpu_record = cpu_runner.run(cpu_request)
    assert cpu_record.outcome is MeasuredRunOutcome.CPU_BUDGET_EXCEEDED
    assert cpu_record.usage.cpu_milliseconds > 50

    memory_request = _request().model_copy(
        update={"measured_budget": _measured_budget(max_peak_rss_bytes=64 * 1024 * 1024)}
    )
    memory_request = memory_request.model_copy(update={"run_id": memory_request.expected_run_id()})
    memory_runner = MeasuredSubprocessRunner()
    monkeypatch.setattr(
        memory_runner,
        "_fixed_worker_command",
        lambda: (_python_executable(), "-c", "import time; time.sleep(1)"),
    )
    monkeypatch.setattr(
        memory_runner,
        "_sample_process",
        lambda _pid: _ProcessSample(cpu_milliseconds=0, rss_bytes=65 * 1024 * 1024),
    )
    memory_record = memory_runner.run(memory_request)
    assert memory_record.outcome is MeasuredRunOutcome.MEMORY_BUDGET_EXCEEDED
    assert memory_record.usage.peak_rss_bytes > 64 * 1024 * 1024
