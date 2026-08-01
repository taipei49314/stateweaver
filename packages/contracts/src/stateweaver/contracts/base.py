"""Shared primitives for every public StateWeaver contract."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from types import MappingProxyType
from typing import Annotated, Any, ClassVar, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
)

from .enums import EffectOperation

type SchemaVersion = Literal["1.0"]
ContractId = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=3,
        max_length=128,
        pattern=r"^[a-z][a-z0-9]*(?:[._:-][a-z0-9][a-z0-9_-]*)+$",
    ),
]
Name = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
]
Sha256Digest = Annotated[
    str,
    StringConstraints(
        to_lower=True,
        pattern=r"^sha256:[0-9a-f]{64}$",
    ),
]
TraceId = Annotated[
    str,
    StringConstraints(to_lower=True, pattern=r"^[0-9a-f]{32}$"),
]
SpanId = Annotated[
    str,
    StringConstraints(to_lower=True, pattern=r"^[0-9a-f]{16}$"),
]
IdentityHandle = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=10,
        max_length=160,
        pattern=r"^identity:[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
]
ArtifactHandle = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=10,
        max_length=256,
        pattern=r"^artifact:[A-Za-z0-9][A-Za-z0-9._:/-]*$",
    ),
]


def _finite_json_scalar(value: str | int | float | bool | None) -> str | int | float | bool | None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("JSON floating-point values must be finite")
    return value


type JsonScalar = Annotated[
    str | int | float | bool | None,
    AfterValidator(_finite_json_scalar),
]


def validate_effect_operation_value(operation: EffectOperation, value: JsonScalar) -> None:
    """Enforce the operation/value matrix shared by planned and observed effects.

    ``REMOVE`` intentionally permits an omitted value: it represents removing a
    whole state path, while a supplied value can identify a collection member.
    """

    if operation in {EffectOperation.SET, EffectOperation.ADD} and value is None:
        raise ValueError("set and add effects require a value")
    if operation in {EffectOperation.INCREMENT, EffectOperation.DECREMENT}:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("increment and decrement effects require an integer or float value")
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("increment and decrement effects require a finite value")


class ContractModel(BaseModel):
    """Secure-by-default base: closed shape, frozen fields, stable validation."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        strict=True,
        str_strip_whitespace=True,
        validate_default=True,
    )

    def canonical_bytes(self) -> bytes:
        """Return deterministic UTF-8 JSON suitable for hashing and signatures."""

        return canonical_json_bytes(self)


class VersionedContract(ContractModel):
    schema_version: SchemaVersion = "1.0"


def _json_ready(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _json_ready(value.model_dump(mode="python", by_alias=True, exclude_none=False))
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("canonical JSON datetimes must include a UTC offset")
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, Mapping):
        converted: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("canonical JSON mapping keys must be strings")
            if key in converted:
                raise ValueError("canonical JSON mapping keys must not collide")
            converted[key] = _json_ready(item)
        return converted
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    if isinstance(value, (set, frozenset)):
        set_items = [_json_ready(item) for item in value]
        return sorted(
            set_items,
            key=lambda item: json.dumps(
                item,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
        )
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("canonical JSON floating-point values must be finite")
    return value


def freeze_json(value: Any) -> Any:
    """Recursively copy JSON into immutable mappings and tuples."""

    if isinstance(value, Mapping):
        frozen: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("JSON mapping keys must be strings")
            if key in frozen:
                raise ValueError("JSON mapping keys must not collide")
            frozen[key] = freeze_json(item)
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(freeze_json(item) for item in value)
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("JSON floating-point values must be finite")
    return value


def thaw_json(value: Any) -> Any:
    """Return ordinary JSON containers for Pydantic's wire serializer."""

    if isinstance(value, Mapping):
        return {str(key): thaw_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [thaw_json(item) for item in value]
    return value


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize JSON deterministically without depending on insertion order."""

    return json.dumps(
        _json_ready(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_digest(value: Any) -> str:
    """Hash the canonical representation and return a tagged digest."""

    return f"sha256:{sha256(canonical_json_bytes(value)).hexdigest()}"


class AwareTimestampMixin(ContractModel):
    """Mixin for contracts whose timestamps must be absolute, not local."""

    @field_validator("created_at", "timestamp", "expires_at", "epoch", check_fields=False)
    @classmethod
    def timestamp_must_have_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("timestamp must include a UTC offset")
        return value


def nonempty_unique_tuple(values: tuple[Any, ...], *, field_name: str) -> tuple[Any, ...]:
    if not values:
        raise ValueError(f"{field_name} must not be empty")
    if len(values) != len(set(values)):
        raise ValueError(f"{field_name} must not contain duplicates")
    return values


Probability = Annotated[float, Field(ge=0.0, le=1.0)]
PositiveInt = Annotated[int, Field(gt=0)]
NonNegativeInt = Annotated[int, Field(ge=0)]
