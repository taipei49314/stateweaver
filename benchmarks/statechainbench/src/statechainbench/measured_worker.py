"""Fixed stdin/stdout worker for the internal measured M7 runner."""

from __future__ import annotations

import sys

from stateweaver.contracts import canonical_json_bytes, sha256_digest

from .generator import generate_dataset
from .measured import MeasuredRunKind, MeasuredRunRequest
from .models import AblationSpec
from .runner import EqualBudgetRunner
from .systems import BenchmarkSystem, LinearBaseline, StateWeaverTieredSystem


def main() -> int:
    try:
        request = MeasuredRunRequest.model_validate_json(sys.stdin.buffer.read())
        dataset = generate_dataset(request.generator_config)
        runner = EqualBudgetRunner(dataset)
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
        report = runner.run(system, request.logical_budget, split=request.split)
        payload = {
            "schema_version": "m7-worker-v1",
            "request_digest": sha256_digest(request),
            "report": report,
            "report_digest": report.report_digest,
            "requests": 0,
            "tokens": 0,
            "cost_microusd": 0,
        }
        sys.stdout.buffer.write(canonical_json_bytes(payload))
        return 0
    except Exception:
        # The parent retains a typed failure.  Raw exceptions may contain
        # untrusted observations and are intentionally not emitted.
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
