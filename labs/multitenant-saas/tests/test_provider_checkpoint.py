"""Security and continuation tests for sealed lab provider checkpoints."""

from __future__ import annotations

import json

import pytest
from stateweaver_lab import (
    CheckpointConflictError,
    CheckpointError,
    CheckpointPoisonedError,
    DeterministicLabService,
    InMemoryLabStateStore,
)
from stateweaver_lab.fixtures import (
    SYNTHETIC_TENANT_A_BODY,
    SYNTHETIC_TENANT_B_MARKER,
    FixtureBearer,
)
from stateweaver_lab.models import (
    AdvanceClockLabAction,
    AdvanceClockRequest,
    ClaimReferenceLabAction,
    ClaimReferenceRequest,
    DeferQueueLabAction,
    DelayQueueRequest,
    DocumentId,
    DowngradeRoleLabAction,
    MaskedReadLabAction,
    MockPolicyLabAction,
    PrimeAuthorizationCacheLabAction,
    PrimeAuthorizationCacheRequest,
    PrincipalId,
    PublishReferenceLabAction,
    PublishReferenceRequest,
    QueueJobId,
    ReadDocumentLabAction,
    ReadDocumentRequest,
    ReferenceId,
    RetainSessionLabAction,
    Role,
    RoleDowngradeRequest,
)
from stateweaver_lab.provider_checkpoint import LabStateCheckpoint


def _actions(*, include_read: bool = True) -> tuple[object, ...]:
    actions: tuple[object, ...] = (
        RetainSessionLabAction(),
        PrimeAuthorizationCacheLabAction(
            payload=PrimeAuthorizationCacheRequest(document_id=DocumentId.TENANT_A_OWNED)
        ),
        DowngradeRoleLabAction(
            payload=RoleDowngradeRequest(
                principal_id=PrincipalId.A_EDITOR,
                new_role=Role.VIEWER,
                propagation="queued",
            )
        ),
        DeferQueueLabAction(
            payload=DelayQueueRequest(job_id=QueueJobId.ROLE_SYNC_A, delay_seconds=240)
        ),
        PublishReferenceLabAction(
            payload=PublishReferenceRequest(
                document_id=DocumentId.TENANT_B_PROTECTED,
                recipient_id=PrincipalId.A_EDITOR,
            )
        ),
        ClaimReferenceLabAction(payload=ClaimReferenceRequest(reference_id=ReferenceId.B_TO_A)),
        AdvanceClockLabAction(payload=AdvanceClockRequest(seconds=90)),
    )
    if not include_read:
        return actions
    return (
        *actions,
        ReadDocumentLabAction(
            actor=FixtureBearer.TENANT_A_OLD_EDITOR,
            payload=ReadDocumentRequest(document_id=DocumentId.TENANT_B_PROTECTED),
        ),
    )


@pytest.mark.parametrize("mode", ["vulnerable", "patched"])
def test_checkpoint_round_trips_every_action_boundary_and_exact_continuation(mode: str) -> None:
    original = DeterministicLabService.seed(mode)
    for action in _actions(include_read=False):
        original.execute(action)  # type: ignore[arg-type]
        checkpoint = original._state.export_checkpoint()
        restored = DeterministicLabService.seed(mode)
        restored._state = original._state.from_checkpoint(checkpoint)
        assert restored.capture() == original.capture()
        assert restored.capture_layers() == original.capture_layers()
        assert restored.evidence() == original.evidence()
        assert restored.oracle() == original.oracle()

    checkpoint = original._state.export_checkpoint()
    restored = DeterministicLabService.seed(mode)
    restored._state = original._state.from_checkpoint(checkpoint)
    final_action = _actions()[-1]
    if mode == "vulnerable":
        assert original.execute(final_action) == restored.execute(final_action)  # type: ignore[arg-type]
    else:
        with pytest.raises(Exception, match="tenant_boundary_enforced"):
            original.execute(final_action)  # type: ignore[arg-type]
        with pytest.raises(Exception, match="tenant_boundary_enforced"):
            restored.execute(final_action)  # type: ignore[arg-type]
    assert restored.oracle() == original.oracle()
    assert restored.evidence() == original.evidence()
    assert restored.capture() == original.capture()


def test_checkpoint_canonical_bytes_exclude_bearers_and_document_bodies() -> None:
    service = DeterministicLabService.seed("vulnerable")
    for action in _actions():
        service.execute(action)  # type: ignore[arg-type]
    raw = service._state.export_checkpoint().canonical_bytes().decode("ascii")
    for bearer in FixtureBearer:
        assert bearer.value not in raw
    assert SYNTHETIC_TENANT_A_BODY not in raw
    assert SYNTHETIC_TENANT_B_MARKER not in raw


@pytest.mark.parametrize(
    "action",
    [
        MaskedReadLabAction(
            actor=FixtureBearer.TENANT_A_OLD_EDITOR,
            payload=ReadDocumentRequest(document_id=DocumentId.TENANT_B_PROTECTED),
        ),
        MockPolicyLabAction(
            actor=FixtureBearer.TENANT_A_OLD_EDITOR,
            payload=ReadDocumentRequest(document_id=DocumentId.TENANT_B_PROTECTED),
        ),
    ],
)
def test_checkpoint_restores_negative_control_state_and_next_result(action: object) -> None:
    original = DeterministicLabService.seed("vulnerable")
    original.execute(action)  # type: ignore[arg-type]
    checkpoint = original._state.export_checkpoint()
    restored = DeterministicLabService.seed("vulnerable")
    restored._state = original._state.from_checkpoint(checkpoint)
    assert restored.evidence() == original.evidence()
    assert restored.oracle() == original.oracle()
    assert restored.execute(action) == original.execute(action)  # type: ignore[arg-type]


def test_checkpoint_rejects_mutation_even_when_attacker_rehashes_outer_digest() -> None:
    service = DeterministicLabService.seed("vulnerable")
    checkpoint = service._state.export_checkpoint()
    payload = json.loads(checkpoint.canonical_bytes())
    payload["state"]["policy_generation"] = 2
    payload["checkpoint_digest"] = checkpoint.checkpoint_digest
    with pytest.raises(CheckpointError, match=r"canonical|shape|digest"):
        LabStateCheckpoint.from_canonical_bytes(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        )
    altered_state = json.loads(json.dumps(checkpoint.state))
    altered_state["policy_generation"] = 2
    rehashed = LabStateCheckpoint.create(
        mode=checkpoint.mode,
        state=altered_state,
        state_fingerprint=checkpoint.state_fingerprint,
    )
    with pytest.raises(CheckpointError, match="fingerprint"):
        service._state.from_checkpoint(rehashed)


def test_checkpoint_rejects_noncanonical_duplicate_deep_and_oversized_input() -> None:
    service = DeterministicLabService.seed("vulnerable")
    raw = service._state.export_checkpoint().canonical_bytes()
    assert b'"generation"' in raw
    duplicate = raw.replace(b'"generation":', b'"generation":"wrong","generation":', 1)
    with pytest.raises(CheckpointError, match="duplicate"):
        LabStateCheckpoint.from_canonical_bytes(duplicate)
    with pytest.raises(CheckpointError, match="byte boundary"):
        LabStateCheckpoint.from_canonical_bytes(b"{" + (b" " * 131_073) + b"}")
    missing = json.loads(raw)
    del missing["state"]
    with pytest.raises(CheckpointError, match="shape"):
        LabStateCheckpoint.from_canonical_bytes(
            json.dumps(missing, sort_keys=True, separators=(",", ":")).encode()
        )
    payload = json.loads(raw)
    nested: object = {"x": 1}
    for _ in range(17):
        nested = {"x": nested}
    payload["state"]["extra"] = nested
    with pytest.raises(CheckpointError, match=r"nesting|shape"):
        LabStateCheckpoint.from_canonical_bytes(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        )


def test_store_stages_and_cas_restores_exact_active_generation() -> None:
    service = DeterministicLabService.seed("vulnerable")
    initial = service._state.export_checkpoint()
    store = InMemoryLabStateStore(initial)
    service.execute(_actions(include_read=False)[0])  # type: ignore[arg-type]
    next_checkpoint = service._state.export_checkpoint()
    store.stage(next_checkpoint)
    active = store.compare_and_swap(initial.generation, next_checkpoint.generation)
    assert active == next_checkpoint
    restored = store.restore_active()
    assert restored.state_digest() == service.capture()
    assert restored.capture_layers() == service.capture_layers()


def test_store_rejects_stale_cas_and_poisoned_partial_generation() -> None:
    service = DeterministicLabService.seed("vulnerable")
    initial = service._state.export_checkpoint()
    store = InMemoryLabStateStore(initial)
    with pytest.raises(CheckpointConflictError):
        store.compare_and_swap("0" * 64, initial.generation)
    with pytest.raises(CheckpointPoisonedError, match="missing"):
        store.compare_and_swap(initial.generation, "f" * 64)
    assert store.poisoned is True
    with pytest.raises(CheckpointPoisonedError):
        store.load_active()
