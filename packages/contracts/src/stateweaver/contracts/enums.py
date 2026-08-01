"""Wire-stable enum values shared by StateWeaver contracts."""

from __future__ import annotations

from enum import StrEnum


class EnvironmentMode(StrEnum):
    BLACK_BOX = "black-box"
    GRAY_BOX = "gray-box"
    SOURCE_BACKED = "source-backed"


class ScopeAction(StrEnum):
    PASSIVE_OBSERVATION = "passive_observation"
    HTTP_REQUEST = "http_request"
    BROWSER_INTERACTION = "browser_interaction"
    TEST_ACCOUNT_WRITE = "test_account_write"
    SESSION_ROTATION = "session_rotation"
    CACHE_DELAY = "cache_delay"
    QUEUE_REORDER = "queue_reorder"
    CONTROLLED_TIME = "controlled_time"
    CONCURRENCY_TEST = "concurrency_test"
    FILE_UPLOAD_TEST = "file_upload_test"
    DENIAL_OF_SERVICE = "denial_of_service"
    PERSISTENCE = "persistence"
    CREDENTIAL_EXFILTRATION = "credential_exfiltration"
    DESTRUCTIVE_DATA_DELETE = "destructive_data_delete"


class AuthorizationRequirement(StrEnum):
    ALLOWED = "allowed"
    APPROVAL_REQUIRED = "approval_required"
    DENIED = "denied"
    UNSPECIFIED = "unspecified"


class RiskClass(StrEnum):
    PASSIVE = "passive"
    READ_ONLY = "read_only"
    REVERSIBLE_STATE_CHANGE = "reversible_state_change"
    ELEVATED_REVERSIBLE = "elevated_reversible"


class RequesterType(StrEnum):
    HUMAN = "human"
    MODEL = "model"
    WORKFLOW = "workflow"
    ADAPTER = "adapter"


class HttpMethod(StrEnum):
    GET = "GET"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class QueueOrder(StrEnum):
    FRONT = "front"
    BACK = "back"
    BEFORE = "before"
    AFTER = "after"


class EntityKind(StrEnum):
    PRINCIPAL = "principal"
    ROLE = "role"
    TENANT = "tenant"
    CREDENTIAL = "credential"
    SESSION = "session"
    RESOURCE = "resource"
    POLICY = "policy"
    CACHE_ENTRY = "cache_entry"
    QUEUE_JOB = "queue_job"
    FEATURE_FLAG = "feature_flag"
    SERVICE = "service"
    ENDPOINT = "endpoint"
    EXTERNAL_DEPENDENCY = "external_dependency"


class RelationKind(StrEnum):
    MEMBER_OF = "member_of"
    ACTS_AS = "acts_as"
    OWNS = "owns"
    BELONGS_TO = "belongs_to"
    AUTHORIZED_BY = "authorized_by"
    CACHED_AS = "cached_as"
    ISSUED_FROM = "issued_from"
    REFERENCES = "references"
    PENDING_TRANSITION = "pending_transition"
    CONTROLLED_BY = "controlled_by"
    VISIBLE_TO = "visible_to"


class ProvenanceKind(StrEnum):
    HYPOTHESIZED = "hypothesized"
    INFERRED = "inferred"
    OBSERVED = "observed"
    MOCKED = "mocked"
    UNKNOWN = "unknown"
    DECLARED = "declared"


class Taint(StrEnum):
    TRUSTED_RUNTIME = "trusted_runtime"
    TRUSTED_SOURCE = "trusted_source"
    UNTRUSTED_TARGET_CONTENT = "untrusted_target_content"
    MODEL_GENERATED = "model_generated"


class ComparisonOperator(StrEnum):
    EQ = "eq"
    NE = "ne"
    LT = "lt"
    LE = "le"
    GT = "gt"
    GE = "ge"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"


class EffectOperation(StrEnum):
    SET = "set"
    ADD = "add"
    REMOVE = "remove"
    INCREMENT = "increment"
    DECREMENT = "decrement"


class FidelityLevel(StrEnum):
    EXACT = "exact"
    OBSERVED = "observed"
    PARTIAL = "partial"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


class WorldTier(StrEnum):
    GHOST = "ghost"
    REPLAY = "replay"
    SIMULATED = "simulated"
    MATERIALIZED = "materialized"


class WorldStatus(StrEnum):
    PROPOSED = "PROPOSED"
    GHOST = "GHOST"
    PRUNED = "PRUNED"
    REPLAY = "REPLAY"
    SIMULATED = "SIMULATED"
    MATERIALIZING = "MATERIALIZING"
    ACTIVE = "ACTIVE"
    BLOCKED = "BLOCKED"
    FROZEN = "FROZEN"
    FRAGMENT_EXTRACTED = "FRAGMENT_EXTRACTED"
    COMPOSITION_CANDIDATE = "COMPOSITION_CANDIDATE"
    REPLAYED = "REPLAYED"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"


class ClockMode(StrEnum):
    CONTROLLED = "controlled"
    WALL = "wall"


class OracleType(StrEnum):
    TENANT_ISOLATION = "tenant_isolation"
    AUTHORIZATION = "authorization"
    SESSION_REVOCATION = "session_revocation"
    WORKFLOW_INTEGRITY = "workflow_integrity"
    TRANSACTION_INTEGRITY = "transaction_integrity"
    CUSTOM_DETERMINISTIC = "custom_deterministic"


class OracleOutcome(StrEnum):
    SATISFIED = "SATISFIED"
    VIOLATED = "VIOLATED"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"


class HypothesisStatus(StrEnum):
    PROPOSED = "PROPOSED"
    CALIBRATING = "CALIBRATING"
    VALIDATED = "VALIDATED"
    REJECTED = "REJECTED"
    EXHAUSTED = "EXHAUSTED"


class FindingStatus(StrEnum):
    CANDIDATE = "CANDIDATE"
    CHAIN_COMPILED = "CHAIN_COMPILED"
    REALITY_REPLAYED = "REALITY_REPLAYED"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"


class ReplayOutcome(StrEnum):
    REPRODUCED = "REPRODUCED"
    BLOCKED_BY_FIX = "BLOCKED_BY_FIX"
    NOT_REPRODUCED = "NOT_REPRODUCED"
    INCONCLUSIVE = "INCONCLUSIVE"


class EvidenceKind(StrEnum):
    HTTP_EXCHANGE = "http_exchange"
    BROWSER_TRACE = "browser_trace"
    OTEL_TRACE = "otel_trace"
    DATABASE_DIFF = "database_diff"
    CACHE_DIFF = "cache_diff"
    QUEUE_DIFF = "queue_diff"
    SCREENSHOT = "screenshot"
    STATE_SNAPSHOT = "state_snapshot"
    ORACLE_REPORT = "oracle_report"


class EventType(StrEnum):
    EXPERIMENT_CREATED = "experiment.created"
    SCOPE_VALIDATED = "scope.validated"
    BASELINE_CAPTURE_STARTED = "baseline.capture.started"
    BASELINE_CAPTURE_COMPLETED = "baseline.capture.completed"
    TWIN_FACT_UPSERTED = "twin.fact.upserted"
    TWIN_TRANSITION_LEARNED = "twin.transition.learned"
    TWIN_DIVERGENCE_DETECTED = "twin.divergence.detected"
    HYPOTHESIS_PROPOSED = "hypothesis.proposed"
    WORLD_FORKED = "world.forked"
    WORLD_PROMOTED = "world.promoted"
    WORLD_PRUNED = "world.pruned"
    WORLD_MATERIALIZATION_STARTED = "world.materialization.started"
    WORLD_MATERIALIZATION_COMPLETED = "world.materialization.completed"
    ACTION_PROPOSED = "action.proposed"
    ACTION_AUTHORIZED = "action.authorized"
    ACTION_EXECUTED = "action.executed"
    OBSERVATION_CAPTURED = "observation.captured"
    ORACLE_VIOLATED = "oracle.violated"
    FRAGMENT_EXTRACTED = "fragment.extracted"
    CHAIN_COMPILED = "chain.compiled"
    REPLAY_STARTED = "replay.started"
    REPLAY_COMPLETED = "replay.completed"
    FINDING_VERIFIED = "finding.verified"
    FINDING_REJECTED = "finding.rejected"
    PATCH_REPLAY_COMPLETED = "patch.replay.completed"
