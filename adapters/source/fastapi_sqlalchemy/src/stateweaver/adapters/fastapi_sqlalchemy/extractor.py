"""Deterministic extraction from already-instantiated FastAPI and SQLAlchemy metadata."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from types import MappingProxyType
from typing import Annotated, ClassVar

from fastapi import FastAPI
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator
from sqlalchemy import Table
from stateweaver.contracts import (
    ContractId,
    HttpMethod,
    Provenance,
    ProvenanceKind,
    sha256_digest,
)
from stateweaver.twin import OpenApiIngestion, OrmResource, SourceRoute

_SUPPORTED_METHODS = MappingProxyType({method.value: method for method in HttpMethod})
_OPENAPI_OPERATION_FIELDS = frozenset({"operationId", "summary", "description"})
SafeName = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")]


class _FrozenModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid", frozen=True, strict=True, validate_default=True
    )


class SqlAlchemyResourceSpec(_FrozenModel):
    resource_id: ContractId
    tenant_field: SafeName
    owner_field: SafeName | None = None


class SourceExtractionSpec(_FrozenModel):
    service_id: ContractId
    evidence_id: ContractId
    include_path_prefixes: tuple[str, ...] = ("/",)
    policy_checks_by_operation: Mapping[SafeName, tuple[SafeName, ...]] = Field(
        default_factory=dict
    )

    @field_validator("include_path_prefixes")
    @classmethod
    def prefixes_are_local_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or len(value) != len(set(value)):
            raise ValueError("path prefixes must be nonempty and unique")
        if any(not item.startswith("/") or "//" in item or "?" in item for item in value):
            raise ValueError("path prefixes must be relative application paths")
        return tuple(sorted(value))

    @field_validator("policy_checks_by_operation")
    @classmethod
    def checks_are_closed(
        cls, value: Mapping[str, tuple[str, ...]]
    ) -> Mapping[str, tuple[str, ...]]:
        normalized: dict[str, tuple[str, ...]] = {}
        for operation, checks in sorted(value.items()):
            if not checks or len(checks) != len(set(checks)):
                raise ValueError("declared policy checks must be nonempty and unique")
            normalized[operation] = tuple(sorted(checks))
        return MappingProxyType(normalized)

    @field_serializer("policy_checks_by_operation")
    def serialize_checks(self, value: Mapping[str, tuple[str, ...]]) -> dict[str, tuple[str, ...]]:
        return dict(value)

    @property
    def provenance(self) -> Provenance:
        return Provenance(
            kind=ProvenanceKind.DECLARED,
            evidence_ids=(self.evidence_id,),
            adapter="fastapi_sqlalchemy",
            adapter_version="0.1.0",
        )


class SourceExtractionError(ValueError):
    """A deterministic rejection of unsupported or incoherent framework metadata."""


def extract_fastapi_routes(app: FastAPI, spec: SourceExtractionSpec) -> tuple[SourceRoute, ...]:
    """Project supported FastAPI routes without invoking a request or dependency."""

    routes: list[SourceRoute] = []
    observed_operations: set[str] = set()
    seen_shapes: set[tuple[str, tuple[HttpMethod, ...]]] = set()
    for route in app.routes:
        if not isinstance(route, APIRoute) or not any(
            route.path.startswith(prefix) for prefix in spec.include_path_prefixes
        ):
            continue
        methods = tuple(
            sorted(
                (
                    _SUPPORTED_METHODS[item]
                    for item in route.methods or ()
                    if item in _SUPPORTED_METHODS
                ),
                key=lambda item: item.value,
            )
        )
        if not methods:
            continue
        shape = (route.path, methods)
        if shape in seen_shapes:
            raise SourceExtractionError("duplicate FastAPI route shape")
        seen_shapes.add(shape)
        operation = route.operation_id or route.name
        if not operation:
            raise SourceExtractionError("FastAPI route requires a stable operation name")
        observed_operations.add(operation)
        suffix = sha256_digest((spec.service_id, route.path, methods)).removeprefix("sha256:")[:24]
        routes.append(
            SourceRoute(
                route_id=f"route.{suffix}",
                service_id=spec.service_id,
                path=route.path,
                methods=methods,
                operation_id=f"operation.{operation}",
                policy_checks=spec.policy_checks_by_operation.get(operation, ()),
                provenance=spec.provenance,
            )
        )
    unbound_checks = set(spec.policy_checks_by_operation) - observed_operations
    if unbound_checks:
        raise SourceExtractionError("policy check declaration references an unknown operation")
    if not routes:
        raise SourceExtractionError("no supported FastAPI routes matched the extraction scope")
    return tuple(sorted(routes, key=lambda item: item.route_id))


def extract_fastapi_openapi(app: FastAPI, spec: SourceExtractionSpec) -> OpenApiIngestion:
    """Produce a deliberately narrow OpenAPI projection accepted by the twin core."""

    raw = app.openapi()
    raw_paths = raw.get("paths")
    if not isinstance(raw_paths, Mapping):
        raise SourceExtractionError("FastAPI OpenAPI output has no paths mapping")
    paths: dict[str, object] = {}
    for path, operations in sorted(raw_paths.items()):
        if not isinstance(path, str) or not any(
            path.startswith(prefix) for prefix in spec.include_path_prefixes
        ):
            continue
        if not isinstance(operations, Mapping):
            raise SourceExtractionError("OpenAPI path operations must be a mapping")
        projected: dict[str, object] = {}
        for method, operation in sorted(operations.items()):
            if str(method).upper() not in _SUPPORTED_METHODS:
                continue
            if not isinstance(operation, Mapping):
                raise SourceExtractionError("OpenAPI operation must be a mapping")
            projected[str(method).lower()] = {
                key: operation[key]
                for key in sorted(_OPENAPI_OPERATION_FIELDS & set(operation))
                if isinstance(operation[key], str)
            }
        if projected:
            paths[path] = projected
    if not paths:
        raise SourceExtractionError("no OpenAPI paths matched the extraction scope")
    version = raw.get("openapi")
    if not isinstance(version, str):
        raise SourceExtractionError("OpenAPI version is missing")
    suffix = sha256_digest((spec.service_id, tuple(paths))).removeprefix("sha256:")[:24]
    return OpenApiIngestion(
        document_id=f"openapi.{suffix}",
        service_id=spec.service_id,
        document={"openapi": version, "paths": paths},
        provenance=spec.provenance,
    )


def extract_sqlalchemy_resources(
    tables: Iterable[Table],
    specs: Mapping[str, SqlAlchemyResourceSpec],
    extraction: SourceExtractionSpec,
) -> tuple[OrmResource, ...]:
    """Read table/column metadata only; engines and connections are never accepted."""

    resources: list[OrmResource] = []
    seen_tables: set[str] = set()
    for table in tables:
        if not isinstance(table, Table):
            raise SourceExtractionError("SQLAlchemy extraction accepts Table metadata only")
        if table.name in seen_tables:
            raise SourceExtractionError("duplicate SQLAlchemy table metadata")
        seen_tables.add(table.name)
        resource_spec = specs.get(table.name)
        if resource_spec is None:
            raise SourceExtractionError("every supplied table requires an extraction spec")
        columns = set(table.columns.keys())
        required = {resource_spec.tenant_field}
        if resource_spec.owner_field is not None:
            required.add(resource_spec.owner_field)
        if not required <= columns:
            raise SourceExtractionError("tenant or owner field is absent from SQLAlchemy metadata")
        resources.append(
            OrmResource(
                resource_id=resource_spec.resource_id,
                service_id=extraction.service_id,
                table_name=table.name,
                tenant_field=resource_spec.tenant_field,
                owner_field=resource_spec.owner_field,
                provenance=extraction.provenance,
            )
        )
    if set(specs) != seen_tables:
        raise SourceExtractionError("extraction specs must exactly match supplied tables")
    if not resources:
        raise SourceExtractionError("at least one SQLAlchemy table is required")
    return tuple(sorted(resources, key=lambda item: item.resource_id))
