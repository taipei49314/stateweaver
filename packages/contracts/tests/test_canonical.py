from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from math import inf, nan
from string import ascii_lowercase, digits

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from stateweaver.contracts import (
    CanonicalSecurityState,
    FeatureFlagState,
    GenerationState,
    ResourceSecurityState,
    canonical_json_bytes,
    canonical_state_fingerprint,
    security_semantic_projection,
)


def state(*, reversed_input: bool = False, session_generation: int = 3) -> CanonicalSecurityState:
    principals: tuple[str, ...] = ("principal:bob", "principal:alice")
    capabilities: tuple[str, ...] = (
        "read_foreign_tenant_resource",
        "read_own_resource",
    )
    resources: tuple[ResourceSecurityState, ...] = (
        ResourceSecurityState(
            resource_ref="resource:document_b",
            owner_ref="tenant:b",
            visible_to=("principal:bob", "principal:alice"),
        ),
        ResourceSecurityState(resource_ref="resource:document_a", owner_ref="tenant:a"),
    )
    if not reversed_input:
        principals = tuple(reversed(principals))
        capabilities = tuple(reversed(capabilities))
        resources = tuple(reversed(resources))
    return CanonicalSecurityState(
        principals=principals,
        roles=("role:viewer", "role:editor"),
        tenants=("tenant:b", "tenant:a"),
        credentials=(GenerationState(ref="credential:alice", generation=1),),
        sessions=(GenerationState(ref="session:alice", generation=session_generation),),
        resources=resources,
        policy_generations=(GenerationState(ref="policy:tenant", generation=5),),
        cache_generations=(GenerationState(ref="cache:tenant", generation=4),),
        pending_jobs=("job:invalidate_b", "job:invalidate_a"),
        feature_flags=(
            FeatureFlagState(name="new_authz", enabled=False),
            FeatureFlagState(name="audit_v2", enabled=True),
        ),
        capabilities=capabilities,
        controlled_time_bucket=42,
    )


def test_canonical_fingerprint_is_input_order_independent() -> None:
    left = state(reversed_input=False)
    right = state(reversed_input=True)

    assert left.canonical_bytes() == right.canonical_bytes()
    assert canonical_state_fingerprint(left) == canonical_state_fingerprint(right)
    assert canonical_state_fingerprint(left).startswith("sha256:")


def test_security_relevant_change_changes_fingerprint() -> None:
    assert canonical_state_fingerprint(state(session_generation=3)) != canonical_state_fingerprint(
        state(session_generation=4)
    )


def test_canonical_json_normalizes_equal_instants_and_unordered_values() -> None:
    instant_utc = datetime(2026, 7, 29, 12, tzinfo=UTC)
    instant_offset = instant_utc.astimezone(timezone(timedelta(hours=8)))

    assert canonical_json_bytes(
        {"at": instant_utc, "values": frozenset({"b", "a"})}
    ) == canonical_json_bytes({"values": frozenset({"a", "b"}), "at": instant_offset})


@pytest.mark.parametrize(
    "value, message",
    [
        ({"at": datetime(2026, 7, 29, 12)}, "UTC offset"),  # noqa: DTZ001
        ({"number": nan}, "finite"),
        ({"number": [inf]}, "finite"),
        ({1: "non-string key"}, "keys must be strings"),
        ({"1": "string key", 1: "colliding key"}, "keys must be strings"),
    ],
)
def test_public_canonical_json_rejects_ambiguous_or_non_json_values(
    value: object, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        canonical_json_bytes(value)


def test_security_fingerprint_uses_explicit_semantic_projection() -> None:
    semantic = state()
    decorated = state()
    decorated = decorated.model_copy(
        update={
            "display_metadata": {"label": "Operator-friendly state"},
            "audit_metadata": {"last_viewed_by": "identity:test_user_a"},
        }
    )

    assert semantic.canonical_bytes() != decorated.canonical_bytes()
    assert semantic.fingerprint() == decorated.fingerprint()
    projection = security_semantic_projection(decorated)
    assert "display_metadata" not in projection
    assert "audit_metadata" not in projection


safe_token = st.builds(
    lambda head, tail: head + tail,
    st.sampled_from(tuple(ascii_lowercase)),
    st.text(alphabet=ascii_lowercase + digits + "_", min_size=0, max_size=10),
)


@settings(max_examples=150, deadline=None)
@given(
    principal_names=st.lists(safe_token, min_size=1, max_size=10, unique=True),
    tenant_names=st.lists(safe_token, min_size=1, max_size=8, unique=True),
    capabilities=st.lists(safe_token, min_size=0, max_size=10, unique=True),
    pending_jobs=st.lists(safe_token, min_size=0, max_size=10, unique=True),
    time_bucket=st.integers(min_value=0, max_value=2**31 - 1),
)
def test_fingerprint_property_is_permutation_invariant(
    principal_names: list[str],
    tenant_names: list[str],
    capabilities: list[str],
    pending_jobs: list[str],
    time_bucket: int,
) -> None:
    forward = CanonicalSecurityState(
        principals=tuple(f"principal:{name}" for name in principal_names),
        tenants=tuple(f"tenant:{name}" for name in tenant_names),
        capabilities=tuple(capabilities),
        pending_jobs=tuple(f"job:{name}" for name in pending_jobs),
        controlled_time_bucket=time_bucket,
    )
    reversed_input = CanonicalSecurityState(
        principals=tuple(f"principal:{name}" for name in reversed(principal_names)),
        tenants=tuple(f"tenant:{name}" for name in reversed(tenant_names)),
        capabilities=tuple(reversed(capabilities)),
        pending_jobs=tuple(f"job:{name}" for name in reversed(pending_jobs)),
        controlled_time_bucket=time_bucket,
    )

    assert forward.canonical_bytes() == reversed_input.canonical_bytes()
    assert forward.fingerprint() == reversed_input.fingerprint()


@settings(max_examples=150, deadline=None)
@given(
    generation=st.integers(min_value=0, max_value=2**31 - 2),
    delta=st.integers(min_value=1, max_value=10_000),
)
def test_fingerprint_property_detects_security_semantic_change(generation: int, delta: int) -> None:
    before = CanonicalSecurityState(
        sessions=(GenerationState(ref="session:alice", generation=generation),),
        controlled_time_bucket=1,
    )
    after = CanonicalSecurityState(
        sessions=(GenerationState(ref="session:alice", generation=generation + delta),),
        controlled_time_bucket=1,
    )

    assert before.fingerprint() != after.fingerprint()
