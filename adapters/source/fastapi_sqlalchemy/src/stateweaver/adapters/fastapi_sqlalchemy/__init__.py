"""Offline framework metadata extraction for the Security Semantic Twin."""

from .extractor import (
    SourceExtractionError,
    SourceExtractionSpec,
    SqlAlchemyResourceSpec,
    extract_fastapi_openapi,
    extract_fastapi_routes,
    extract_sqlalchemy_resources,
)

__all__ = [
    "SourceExtractionError",
    "SourceExtractionSpec",
    "SqlAlchemyResourceSpec",
    "extract_fastapi_openapi",
    "extract_fastapi_routes",
    "extract_sqlalchemy_resources",
]
