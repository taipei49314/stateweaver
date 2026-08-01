"""Hidden, machine-checkable oracle boundary for local synthetic challenges."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Protocol

from pydantic import ValidationError, field_validator
from stateweaver.contracts import Sha256Digest, sha256_digest
from stateweaver.contracts.base import ContractModel

from .models import (
    CandidateSubmission,
    OracleReason,
    OracleVerdict,
    PublicChallenge,
    StateCell,
    action_is_applicable,
    apply_action,
    state_fingerprint,
)


class HiddenOracle(Protocol):
    """Evaluation-only interface; no method exposes terminal constraints."""

    def evaluate(
        self, challenge: PublicChallenge, submission: CandidateSubmission
    ) -> OracleVerdict: ...


class _OracleSpec(ContractModel):
    challenge_id: str
    public_fingerprint: Sha256Digest
    terminal_state: tuple[StateCell, ...]

    @field_validator("terminal_state")
    @classmethod
    def terminal_state_is_canonical(cls, value: tuple[StateCell, ...]) -> tuple[StateCell, ...]:
        keys = [item.key for item in value]
        if not value or len(keys) != len(set(keys)):
            raise ValueError("hidden terminal state must be nonempty and unique")
        return tuple(sorted(value, key=lambda item: item.key))


class DeterministicHiddenOracle:
    """Immutable in-memory oracle used only by the equal-budget runner."""

    __slots__ = ("__registry",)

    def __init__(self, specs: tuple[_OracleSpec, ...]) -> None:
        validated = tuple(
            _OracleSpec.model_validate(item.model_dump(mode="python")) for item in specs
        )
        identifiers = [item.challenge_id for item in validated]
        if not validated or len(identifiers) != len(set(identifiers)):
            raise ValueError("hidden oracle registry must be nonempty and unique")
        self.__registry: Mapping[str, _OracleSpec] = MappingProxyType(
            {item.challenge_id: item for item in validated}
        )

    def evaluate(
        self, challenge: PublicChallenge, submission: CandidateSubmission
    ) -> OracleVerdict:
        challenge = PublicChallenge.model_validate(challenge.model_dump(mode="python"))
        try:
            submission = CandidateSubmission.model_validate(submission.model_dump(mode="python"))
        except ValidationError:
            return _verdict(
                challenge,
                valid=False,
                success=False,
                reason=OracleReason.DUPLICATE_ACTION,
                state=challenge.initial_mapping(),
                evaluated=0,
            )
        if submission.challenge_id != challenge.challenge_id:
            return _verdict(
                challenge,
                valid=False,
                success=False,
                reason=OracleReason.CHALLENGE_MISMATCH,
                state=challenge.initial_mapping(),
                evaluated=0,
            )
        spec = self.__registry.get(challenge.challenge_id)
        if spec is None or spec.public_fingerprint != challenge.fingerprint:
            return _verdict(
                challenge,
                valid=False,
                success=False,
                reason=OracleReason.PUBLIC_CHALLENGE_MISMATCH,
                state=challenge.initial_mapping(),
                evaluated=0,
            )
        if len(submission.action_tokens) > challenge.max_chain_length:
            return _verdict(
                challenge,
                valid=False,
                success=False,
                reason=OracleReason.CHAIN_TOO_LONG,
                state=challenge.initial_mapping(),
                evaluated=0,
            )

        actions = {item.token: item for item in challenge.actions}
        state = challenge.initial_mapping()
        evaluated = 0
        for token in submission.action_tokens:
            action = actions.get(token)
            if action is None:
                return _verdict(
                    challenge,
                    valid=False,
                    success=False,
                    reason=OracleReason.UNKNOWN_ACTION,
                    state=state,
                    evaluated=evaluated,
                )
            if not action_is_applicable(action, state):
                return _verdict(
                    challenge,
                    valid=False,
                    success=False,
                    reason=OracleReason.PRECONDITION_FAILED,
                    state=state,
                    evaluated=evaluated,
                )
            state = apply_action(action, state)
            evaluated += 1

        success = all(state.get(item.key) is item.value for item in spec.terminal_state)
        return _verdict(
            challenge,
            valid=True,
            success=success,
            reason=OracleReason.SUCCESS if success else OracleReason.GOAL_NOT_REACHED,
            state=state,
            evaluated=evaluated,
        )

    @property
    def _evaluator_digest(self) -> str:
        """Commit to the closed evaluator registry without exposing its contents."""

        return sha256_digest(
            tuple(sorted(self.__registry.values(), key=lambda item: item.challenge_id))
        )


def make_hidden_oracle(
    registrations: tuple[tuple[str, str, tuple[StateCell, ...]], ...],
) -> HiddenOracle:
    """Create an evaluator without returning or serializing its hidden registry."""

    return DeterministicHiddenOracle(
        tuple(
            _OracleSpec(
                challenge_id=challenge_id,
                public_fingerprint=public_fingerprint,
                terminal_state=terminal_state,
            )
            for challenge_id, public_fingerprint, terminal_state in registrations
        )
    )


def evaluator_digest(oracle: HiddenOracle) -> Sha256Digest:
    """Return a commitment to the evaluator without expanding its solver-facing API."""

    if type(oracle) is not DeterministicHiddenOracle:
        raise TypeError("StateChainBench requires its registered deterministic oracle")
    return oracle._evaluator_digest


def anchor_disabled_verdict(challenge: PublicChallenge) -> OracleVerdict:
    return _verdict(
        challenge,
        valid=False,
        success=False,
        reason=OracleReason.REALITY_ANCHOR_DISABLED,
        state=challenge.initial_mapping(),
        evaluated=0,
    )


def _verdict(
    challenge: PublicChallenge,
    *,
    valid: bool,
    success: bool,
    reason: OracleReason,
    state: dict[str, bool],
    evaluated: int,
) -> OracleVerdict:
    return OracleVerdict(
        challenge_id=challenge.challenge_id,
        valid=valid,
        success=success,
        reason=reason,
        final_state_fingerprint=state_fingerprint(state),
        evaluated_actions=evaluated,
    )
