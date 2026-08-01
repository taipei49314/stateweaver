from __future__ import annotations

import pytest
from sqlalchemy import Column, MetaData, String, Table
from stateweaver.adapters.fastapi_sqlalchemy import (
    SourceExtractionError,
    SourceExtractionSpec,
    SqlAlchemyResourceSpec,
    extract_fastapi_openapi,
    extract_fastapi_routes,
    extract_sqlalchemy_resources,
)
from stateweaver.contracts import HttpMethod, ProvenanceKind
from stateweaver_lab.app import create_app


def _spec() -> SourceExtractionSpec:
    return SourceExtractionSpec(
        service_id="service.synthetic.lab",
        evidence_id="evidence.source.lab",
        include_path_prefixes=("/v1/lab/",),
        policy_checks_by_operation={"read_document": ("principal.tenant",)},
    )


def test_extracts_real_fastapi_route_and_narrow_openapi_without_requesting_it() -> None:
    app = create_app("vulnerable")

    routes = extract_fastapi_routes(app, _spec())
    document = extract_fastapi_openapi(app, _spec())

    read = next(item for item in routes if item.operation_id == "operation.read_document")
    assert read.path == "/v1/lab/documents/{document_id}"
    assert read.methods == (HttpMethod.GET,)
    assert read.policy_checks == ("principal.tenant",)
    assert read.provenance.kind is ProvenanceKind.DECLARED
    assert document.provenance.evidence_ids == ("evidence.source.lab",)
    assert set(document.document) == {"openapi", "paths"}


def test_extracts_actual_sqlalchemy_table_metadata_without_engine_or_connection() -> None:
    metadata = MetaData()
    documents = Table(
        "documents",
        metadata,
        Column("document_id", String, primary_key=True),
        Column("tenant_id", String, nullable=False),
        Column("owner_id", String, nullable=False),
    )

    resources = extract_sqlalchemy_resources(
        (documents,),
        {
            "documents": SqlAlchemyResourceSpec(
                resource_id="resource.documents",
                tenant_field="tenant_id",
                owner_field="owner_id",
            )
        },
        _spec(),
    )

    assert resources[0].table_name == "documents"
    assert resources[0].tenant_field == "tenant_id"
    assert resources[0].owner_field == "owner_id"


def test_rejects_unbound_policy_claim_and_missing_tenant_column() -> None:
    app = create_app("patched")
    bad_spec = SourceExtractionSpec(
        service_id="service.synthetic.lab",
        evidence_id="evidence.source.lab",
        policy_checks_by_operation={"operation_does_not_exist": ("principal.tenant",)},
    )
    with pytest.raises(SourceExtractionError, match="unknown operation"):
        extract_fastapi_routes(app, bad_spec)

    table = Table("documents", MetaData(), Column("document_id", String))
    with pytest.raises(SourceExtractionError, match="absent"):
        extract_sqlalchemy_resources(
            (table,),
            {
                "documents": SqlAlchemyResourceSpec(
                    resource_id="resource.documents", tenant_field="tenant_id"
                )
            },
            _spec(),
        )


def test_output_is_deterministic_across_repeated_framework_extraction() -> None:
    app = create_app("vulnerable")
    assert extract_fastapi_routes(app, _spec()) == extract_fastapi_routes(app, _spec())
    assert extract_fastapi_openapi(app, _spec()) == extract_fastapi_openapi(app, _spec())
