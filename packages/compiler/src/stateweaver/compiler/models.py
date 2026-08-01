"""Closed compiler input/output contracts; no untyped command or target escape hatches."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator
from stateweaver.contracts import (
    ActionEnvelope,
    ArtifactHandle,
    ContractId,
    IdentityHandle,
    Sha256Digest,
    StateCondition,
    TransitionFragment,
    canonical_json_bytes,
    sha256_digest,
)
from stateweaver.replay import ReplayPlan, ReplayStep

SessionHandle = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=10,
        max_length=160,
        pattern=r"^session:[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
]


class CompilerModel(BaseModel):
    """The compiler's closed, immutable trust boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class TimeWindow(CompilerModel):
    """An inclusive controlled-clock window measured from the pinned root in milliseconds."""

    opens_at_ms: Annotated[int, Field(ge=0)] = 0
    closes_at_ms: Annotated[int, Field(ge=0)] = 86_400_000

    @model_validator(mode="after")
    def window_is_forward(self) -> TimeWindow:
        if self.closes_at_ms < self.opens_at_ms:
            raise ValueError("time window closes before it opens")
        return self


class FragmentBinding(CompilerModel):
    """Explicit synthetic identity/session/artifact binding for one typed action."""

    identity_handle: IdentityHandle | None = None
    session_handle: SessionHandle | None = None
    artifact_handle: ArtifactHandle | None = None

    @model_validator(mode="after")
    def session_requires_identity(self) -> FragmentBinding:
        if self.session_handle is not None and self.identity_handle is None:
            raise ValueError("a session binding requires an identity binding")
        return self


class CompilerFragment(CompilerModel):
    """A transition plus its already-authorized synthetic action envelope."""

    fragment: TransitionFragment
    envelope: ActionEnvelope
    world_id: ContractId
    binding: FragmentBinding = FragmentBinding()
    window: TimeWindow = TimeWindow()
    after: tuple[ContractId, ...] = ()
    cost: Annotated[int, Field(ge=1, le=100)] = 1

    @model_validator(mode="after")
    def transition_and_envelope_are_bound(self) -> CompilerFragment:
        if self.envelope.world_id != self.world_id:
            raise ValueError("fragment world_id must match the action envelope")
        if canonical_json_bytes(self.fragment.action) != canonical_json_bytes(self.envelope.action):
            raise ValueError("fragment action must equal its typed action envelope")
        if self.fragment.transition_id in self.after or len(self.after) != len(set(self.after)):
            raise ValueError("fragment ordering constraints are invalid")
        return self

    @property
    def fragment_id(self) -> str:
        return self.fragment.transition_id


class RootState(CompilerModel):
    """A common synthetic root; snapshot merging is intentionally not represented."""

    root_seed_id: ContractId
    world_id: ContractId
    conditions: tuple[StateCondition, ...] = ()
    clock_ms: Annotated[int, Field(ge=0)] = 0


class TerminalGoal(CompilerModel):
    """The machine-checkable conditions expected after the candidate chain."""

    goal_id: ContractId
    conditions: tuple[StateCondition, ...]

    @model_validator(mode="after")
    def goal_has_conditions(self) -> TerminalGoal:
        if not self.conditions:
            raise ValueError("terminal goal requires at least one condition")
        return self


class CompiledChain(CompilerModel):
    """Typed compiler intermediate which can be materialized as a ReplayPlan without execution."""

    chain_id: ContractId
    root_seed_id: ContractId
    world_id: ContractId
    fragment_ids: tuple[ContractId, ...]
    action_envelopes: tuple[ActionEnvelope, ...]
    root_state_hash: Sha256Digest
    fragment_semantic_hashes: tuple[Sha256Digest, ...]
    terminal_goal: TerminalGoal
    requires_policy_reauthorization: Literal[True] = True
    causal_hash: Sha256Digest

    @model_validator(mode="after")
    def chain_shape_is_consistent(self) -> CompiledChain:
        if (
            not self.fragment_ids
            or len(self.fragment_ids) != len(self.action_envelopes)
            or len(self.fragment_ids) != len(self.fragment_semantic_hashes)
        ):
            raise ValueError("compiled chain must contain aligned fragment and action steps")
        if len(self.fragment_ids) != len(set(self.fragment_ids)):
            raise ValueError("compiled chain fragment IDs must be unique")
        expected = sha256_digest(self.causal_projection())
        if self.causal_hash != expected:
            raise ValueError("causal_hash does not match compiled chain semantics")
        return self

    def causal_projection(self) -> dict[str, object]:
        return {
            "root_seed_id": self.root_seed_id,
            "world_id": self.world_id,
            "fragment_ids": self.fragment_ids,
            "action_envelopes": self.action_envelopes,
            "root_state_hash": self.root_state_hash,
            "fragment_semantic_hashes": self.fragment_semantic_hashes,
            "terminal_goal": self.terminal_goal,
            "requires_policy_reauthorization": self.requires_policy_reauthorization,
        }

    def to_replay_plan(self, *, plan_id: ContractId) -> ReplayPlan:
        """Produce a candidate plan whose resequenced actions require fresh authorization."""

        steps = tuple(
            ReplayStep(
                step_id=f"step.{index:02d}",
                action=envelope,
            )
            for index, envelope in enumerate(self.action_envelopes)
        )
        return ReplayPlan(plan_id=plan_id, root_seed_id=self.root_seed_id, steps=steps)
