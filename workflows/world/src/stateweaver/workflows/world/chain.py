"""Fail-closed admission from an observed promotion into the chain compiler."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from pydantic import ConfigDict, TypeAdapter, model_validator
from stateweaver.compiler import (
    ChainCompiler,
    CompilationError,
    CompiledChain,
    CompilerFragment,
    RootState,
    TerminalGoal,
)
from stateweaver.contracts import (
    ActionEnvelope,
    ActionGuard,
    ComparisonOperator,
    ContractId,
    ExpectedEffect,
    ProvenanceKind,
    Sha256Digest,
    WorldTier,
    canonical_json_bytes,
    sha256_digest,
)
from stateweaver.contracts.base import ContractModel
from stateweaver.search import (
    DecisionDisposition,
    PolicyGateOutcome,
    SearchBatch,
    SearchCandidate,
    TieredSearchController,
)

from .models import PromotionRecord, WorkflowResult

_CONTRACT_ID = TypeAdapter(ContractId)


@dataclass(eq=False)
class ObservedChainAdmissionError(ValueError):
    """Stable, value-safe reason why a promoted candidate was not compiled."""

    code: str
    fragment_id: str | None = None

    def __str__(self) -> str:
        suffix = "" if self.fragment_id is None else f" at {self.fragment_id}"
        return f"observed chain admission failed: {self.code}{suffix}"


class ObservedChainAdmission(ContractModel):
    """Content-bound receipt for one admitted observed transition chain."""

    model_config = ConfigDict(revalidate_instances="always")

    candidate_id: ContractId
    reservation_id: ContractId
    allocation_id: ContractId
    search_batch_fingerprint: Sha256Digest
    workflow_fingerprint: Sha256Digest
    candidate_fingerprint: Sha256Digest
    promotion_fingerprint: Sha256Digest
    compiler_input_fingerprint: Sha256Digest
    chain_fingerprint: Sha256Digest
    compiled_chain: CompiledChain
    admission_fingerprint: Sha256Digest

    @model_validator(mode="after")
    def receipt_is_content_bound(self) -> ObservedChainAdmission:
        try:
            closed_chain = CompiledChain.model_validate(
                self.compiled_chain.model_dump(mode="python")
            )
        except (AttributeError, TypeError, ValueError) as error:
            raise ValueError("compiled chain must pass closed-model validation") from error
        if closed_chain.world_id != self.allocation_id:
            raise ValueError("compiled chain must target the admitted allocation")
        if self.chain_fingerprint != sha256_digest(closed_chain):
            raise ValueError("chain fingerprint must bind the compiled chain")
        if self.admission_fingerprint != sha256_digest(self.admission_projection()):
            raise ValueError("admission fingerprint must bind the receipt semantics")
        return self

    def admission_projection(self) -> dict[str, object]:
        """Return the immutable semantics covered by ``admission_fingerprint``."""

        return {
            "candidate_id": self.candidate_id,
            "reservation_id": self.reservation_id,
            "allocation_id": self.allocation_id,
            "search_batch_fingerprint": self.search_batch_fingerprint,
            "workflow_fingerprint": self.workflow_fingerprint,
            "candidate_fingerprint": self.candidate_fingerprint,
            "promotion_fingerprint": self.promotion_fingerprint,
            "compiler_input_fingerprint": self.compiler_input_fingerprint,
            "chain_fingerprint": self.chain_fingerprint,
        }


def compile_observed_promotion(
    *,
    batch: SearchBatch,
    workflow: WorkflowResult,
    candidate_id: ContractId,
    chain_id: ContractId,
    fragments: Iterable[CompilerFragment],
    goal: TerminalGoal,
) -> ObservedChainAdmission:
    """Compile exactly the observed fragments admitted by a committed promotion.

    This is a pure composition boundary: it opens no target and executes no
    action. All public models are reconstructed before their content is trusted,
    then the search, promotion, evidence, policy, world, and compiler bindings
    are independently checked.
    """

    try:
        closed_chain_id = _CONTRACT_ID.validate_python(chain_id, strict=True)
        closed_batch = SearchBatch.model_validate(batch.model_dump(mode="python"))
        closed_workflow = WorkflowResult.model_validate(workflow.model_dump(mode="python"))
        closed_goal = TerminalGoal.model_validate(goal.model_dump(mode="python"))
        closed_fragments = tuple(
            sorted(
                (
                    CompilerFragment.model_validate(item.model_dump(mode="python"))
                    for item in fragments
                ),
                key=lambda item: item.fragment_id,
            )
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise ObservedChainAdmissionError("MALFORMED_INPUT") from error

    candidates = {item.candidate_id: item for item in closed_batch.candidates}
    closed_candidate = candidates.get(candidate_id)
    if closed_candidate is None:
        raise ObservedChainAdmissionError("CANDIDATE_NOT_IN_BATCH")
    closed_promotion = _validate_workflow(
        closed_batch,
        closed_workflow,
        closed_candidate,
    )
    closed_root = closed_promotion.capture.compiler_root
    _validate_promotion(closed_candidate, closed_promotion)
    _validate_gates(closed_candidate, closed_promotion)
    _validate_fragments(closed_candidate, closed_fragments, closed_goal)

    try:
        compiled = ChainCompiler().compile(
            chain_id=closed_chain_id,
            root=closed_root,
            fragments=closed_fragments,
            goal=closed_goal,
        )
    except CompilationError as error:
        raise ObservedChainAdmissionError(
            f"COMPILATION_{error.code}",
            error.fragment_id,
        ) from error
    except (TypeError, ValueError) as error:
        raise ObservedChainAdmissionError("COMPILATION_REJECTED") from error
    try:
        compiled = CompiledChain.model_validate(compiled.model_dump(mode="python"))
    except (AttributeError, TypeError, ValueError) as error:
        raise ObservedChainAdmissionError("MALFORMED_COMPILER_OUTPUT") from error
    candidate_fragment_ids = tuple(
        fragment.transition_id for fragment in closed_candidate.transition_fragments
    )
    if set(compiled.fragment_ids) != set(candidate_fragment_ids) or len(
        compiled.fragment_ids
    ) != len(candidate_fragment_ids):
        raise ObservedChainAdmissionError("CHAIN_DROPPED_OBSERVED_FRAGMENT")
    _validate_compiler_output(
        compiled,
        chain_id=closed_chain_id,
        root=closed_root,
        fragments=closed_fragments,
        goal=closed_goal,
    )

    candidate_fingerprint = sha256_digest(closed_candidate)
    promotion_fingerprint = sha256_digest(closed_promotion)
    search_batch_fingerprint = sha256_digest(closed_batch)
    workflow_fingerprint = sha256_digest(closed_workflow)
    compiler_input_fingerprint = sha256_digest(
        {
            "chain_id": closed_chain_id,
            "root": closed_root,
            "fragments": closed_fragments,
            "goal": closed_goal,
        }
    )
    chain_fingerprint = sha256_digest(compiled)
    projection: dict[str, object] = {
        "candidate_id": closed_candidate.candidate_id,
        "reservation_id": closed_promotion.reservation_id,
        "allocation_id": closed_promotion.allocation.allocation_id,
        "search_batch_fingerprint": search_batch_fingerprint,
        "workflow_fingerprint": workflow_fingerprint,
        "candidate_fingerprint": candidate_fingerprint,
        "promotion_fingerprint": promotion_fingerprint,
        "compiler_input_fingerprint": compiler_input_fingerprint,
        "chain_fingerprint": chain_fingerprint,
    }
    return ObservedChainAdmission(
        candidate_id=closed_candidate.candidate_id,
        reservation_id=closed_promotion.reservation_id,
        allocation_id=closed_promotion.allocation.allocation_id,
        search_batch_fingerprint=search_batch_fingerprint,
        workflow_fingerprint=workflow_fingerprint,
        candidate_fingerprint=candidate_fingerprint,
        promotion_fingerprint=promotion_fingerprint,
        compiler_input_fingerprint=compiler_input_fingerprint,
        chain_fingerprint=chain_fingerprint,
        compiled_chain=compiled,
        admission_fingerprint=sha256_digest(projection),
    )


def _validate_workflow(
    batch: SearchBatch,
    workflow: WorkflowResult,
    candidate: SearchCandidate,
) -> PromotionRecord:
    if workflow.search.input_fingerprint != sha256_digest(batch):
        raise ObservedChainAdmissionError("SEARCH_BATCH_FINGERPRINT_MISMATCH")
    expected_search = TieredSearchController(workflow.search_policy).advance(
        batch,
        workflow.input_ledger,
    )
    if workflow.search != expected_search:
        raise ObservedChainAdmissionError("SEARCH_RESULT_MISMATCH")
    batch_ids = {item.candidate_id for item in batch.candidates}
    decision_ids = {item.candidate_id for item in workflow.search.decisions}
    if batch_ids != decision_ids:
        raise ObservedChainAdmissionError("SEARCH_DECISION_COVERAGE_MISMATCH")
    if (
        workflow.search.source_tier is not candidate.tier
        or workflow.search.target_tier is not WorldTier.MATERIALIZED
    ):
        raise ObservedChainAdmissionError("SEARCH_TIER_MISMATCH")
    decisions = {item.candidate_id: item for item in workflow.search.decisions}
    decision = decisions[candidate.candidate_id]
    if (
        decision.disposition is not DecisionDisposition.PROMOTE
        or decision.reservation_id is None
        or candidate.candidate_id not in workflow.search.promoted_candidate_ids
    ):
        raise ObservedChainAdmissionError("CANDIDATE_NOT_PROMOTED")
    if (
        decision.source_tier is not candidate.tier
        or decision.target_tier is not WorldTier.MATERIALIZED
    ):
        raise ObservedChainAdmissionError("SEARCH_TIER_MISMATCH")
    provisional = {item.reservation_id: item for item in workflow.search.ledger.reservations}.get(
        decision.reservation_id
    )
    if (
        provisional is None
        or provisional.candidate_id != candidate.candidate_id
        or provisional.target_tier is not WorldTier.MATERIALIZED
        or provisional.cost != candidate.promotion_cost
    ):
        raise ObservedChainAdmissionError("SEARCH_RESERVATION_MISMATCH")
    promotions = {item.candidate_id: item for item in workflow.promotions}
    promotion = promotions.get(candidate.candidate_id)
    if promotion is None:
        raise ObservedChainAdmissionError("PROMOTION_NOT_COMMITTED")
    committed = {item.reservation_id: item for item in workflow.committed_ledger.reservations}.get(
        promotion.reservation_id
    )
    if (
        committed is None
        or committed.candidate_id != candidate.candidate_id
        or committed.target_tier is not WorldTier.MATERIALIZED
        or committed.cost != candidate.promotion_cost
    ):
        raise ObservedChainAdmissionError("COMMITTED_RESERVATION_MISMATCH")
    return promotion


def _validate_promotion(
    candidate: SearchCandidate,
    promotion: PromotionRecord,
) -> None:
    if candidate.tier is not WorldTier.SIMULATED:
        raise ObservedChainAdmissionError("SOURCE_TIER_NOT_SIMULATED")
    if promotion.target_tier is not WorldTier.MATERIALIZED:
        raise ObservedChainAdmissionError("TARGET_TIER_NOT_MATERIALIZED")
    if promotion.allocation.target_tier is not WorldTier.MATERIALIZED:
        raise ObservedChainAdmissionError("ALLOCATION_TIER_NOT_MATERIALIZED")
    if promotion.candidate_id != candidate.candidate_id:
        raise ObservedChainAdmissionError("CANDIDATE_PROMOTION_MISMATCH")
    if (
        promotion.allocation.state_fingerprint != candidate.state_fingerprint
        or promotion.capture.state_fingerprint != candidate.state_fingerprint
    ):
        raise ObservedChainAdmissionError("STATE_FINGERPRINT_MISMATCH")


def _validate_gates(candidate: SearchCandidate, promotion: PromotionRecord) -> None:
    gates = candidate.gates
    if not gates.in_scope:
        raise ObservedChainAdmissionError("OUT_OF_SCOPE")
    if gates.policy_outcome is PolicyGateOutcome.DENY:
        raise ObservedChainAdmissionError("POLICY_DENIED")
    if gates.policy_outcome is PolicyGateOutcome.REQUIRE_APPROVAL and gates.approval_ref is None:
        raise ObservedChainAdmissionError("APPROVAL_MISSING")
    if not gates.reversible and gates.approval_ref is None:
        raise ObservedChainAdmissionError("NON_REVERSIBLE_WITHOUT_APPROVAL")
    if not set(gates.required_capabilities) <= set(gates.available_capabilities):
        raise ObservedChainAdmissionError("CAPABILITY_MISSING")
    if not gates.snapshot_capable:
        raise ObservedChainAdmissionError("SNAPSHOT_MISSING")
    if not gates.action_plan_refs:
        raise ObservedChainAdmissionError("ACTION_PLAN_MISSING")
    if not gates.expected_observations:
        raise ObservedChainAdmissionError("EXPECTED_OBSERVATION_MISSING")
    if not gates.evidence_ids:
        raise ObservedChainAdmissionError("EVIDENCE_MISSING")
    if not gates.oracle_refs:
        raise ObservedChainAdmissionError("ORACLE_MISSING")
    if promotion.capture.evidence_ref not in gates.evidence_ids:
        raise ObservedChainAdmissionError("CAPTURE_EVIDENCE_MISMATCH")
    if promotion.capture.oracle_ref not in gates.oracle_refs:
        raise ObservedChainAdmissionError("CAPTURE_ORACLE_MISMATCH")


def _validate_fragments(
    candidate: SearchCandidate,
    fragments: tuple[CompilerFragment, ...],
    goal: TerminalGoal,
) -> None:
    observed = candidate.transition_fragments
    if not observed:
        raise ObservedChainAdmissionError("NO_OBSERVED_FRAGMENTS")
    evidence = set(candidate.gates.evidence_ids)
    expected = {canonical_json_bytes(item) for item in candidate.gates.expected_observations}
    for observed_fragment in observed:
        if observed_fragment.source is not ProvenanceKind.OBSERVED:
            raise ObservedChainAdmissionError(
                "FRAGMENT_NOT_OBSERVED", observed_fragment.transition_id
            )
        if (
            not observed_fragment.evidence_ids
            or not set(observed_fragment.evidence_ids) <= evidence
        ):
            raise ObservedChainAdmissionError(
                "FRAGMENT_EVIDENCE_MISMATCH", observed_fragment.transition_id
            )
        if any(
            canonical_json_bytes(item) not in expected for item in observed_fragment.observables
        ):
            raise ObservedChainAdmissionError(
                "FRAGMENT_OBSERVATION_MISMATCH",
                observed_fragment.transition_id,
            )

    if any(canonical_json_bytes(item) not in expected for item in goal.conditions):
        raise ObservedChainAdmissionError("GOAL_OBSERVATION_MISMATCH")

    candidate_by_id = {item.transition_id: item for item in observed}
    compiler_ids = tuple(item.fragment_id for item in fragments)
    if len(compiler_ids) != len(set(compiler_ids)):
        raise ObservedChainAdmissionError("DUPLICATE_COMPILER_FRAGMENT")
    if set(compiler_ids) != set(candidate_by_id):
        raise ObservedChainAdmissionError("COMPILER_FRAGMENT_SET_MISMATCH")
    for compiler_fragment in fragments:
        admitted = candidate_by_id[compiler_fragment.fragment_id]
        if canonical_json_bytes(compiler_fragment.fragment) != canonical_json_bytes(admitted):
            raise ObservedChainAdmissionError(
                "COMPILER_FRAGMENT_SUBSTITUTION", compiler_fragment.fragment_id
            )
        if compiler_fragment.envelope.policy_decision_ref != candidate.gates.policy_decision_ref:
            raise ObservedChainAdmissionError(
                "POLICY_DECISION_MISMATCH", compiler_fragment.fragment_id
            )
        if compiler_fragment.envelope.approval_ref != candidate.gates.approval_ref:
            raise ObservedChainAdmissionError("APPROVAL_MISMATCH", compiler_fragment.fragment_id)

        guards: list[ActionGuard] = []
        for condition in admitted.preconditions:
            if condition.operator is not ComparisonOperator.EQ or condition.reference is not None:
                raise ObservedChainAdmissionError(
                    "PRECONDITION_NOT_ENVELOPE_REPRESENTABLE",
                    compiler_fragment.fragment_id,
                )
            guards.append(ActionGuard(path=condition.path, expected=condition.value))
        expected_effects = tuple(
            ExpectedEffect(
                path=effect.path,
                operation=effect.operation,
                value=effect.value,
            )
            for effect in admitted.effects
        )
        if tuple(guards) != compiler_fragment.envelope.preconditions:
            raise ObservedChainAdmissionError(
                "ENVELOPE_PRECONDITION_MISMATCH",
                compiler_fragment.fragment_id,
            )
        if expected_effects != compiler_fragment.envelope.expected_effects:
            raise ObservedChainAdmissionError(
                "ENVELOPE_EFFECT_MISMATCH",
                compiler_fragment.fragment_id,
            )


def _validate_compiler_output(
    compiled: CompiledChain,
    *,
    chain_id: ContractId,
    root: RootState,
    fragments: tuple[CompilerFragment, ...],
    goal: TerminalGoal,
) -> None:
    by_id = {item.fragment_id: item for item in fragments}
    try:
        ordered = tuple(by_id[item] for item in compiled.fragment_ids)
    except KeyError as error:  # pragma: no cover - guarded by the set check above
        raise ObservedChainAdmissionError("COMPILER_OUTPUT_MISMATCH") from error
    expected_envelopes = tuple(
        ActionEnvelope.model_validate(
            {
                **item.envelope.model_dump(mode="python"),
                "sequence": index,
            }
        )
        for index, item in enumerate(ordered)
    )
    expected_semantic_hashes = tuple(sha256_digest(item) for item in ordered)
    if (
        compiled.chain_id != chain_id
        or compiled.root_seed_id != root.root_seed_id
        or compiled.world_id != root.world_id
        or compiled.root_state_hash != sha256_digest(root)
        or compiled.terminal_goal != goal
        or compiled.action_envelopes != expected_envelopes
        or compiled.fragment_semantic_hashes != expected_semantic_hashes
    ):
        raise ObservedChainAdmissionError("COMPILER_OUTPUT_MISMATCH")
