"""End-to-end handoff for an in-memory, non-authoritative Reality publication."""

from __future__ import annotations

from reality_bundle_fixtures import _build_bundle
from stateweaver.reporting import (
    RealityPublicationManifest,
    build_reality_publication,
    verify_reality_publication,
)


def test_independent_consumer_reproduces_the_publication_candidate() -> None:
    pre_receipt = _build_bundle()
    produced = build_reality_publication(
        receipt_json=pre_receipt.receipt_json,
        pre_receipt_manifest_json=pre_receipt.manifest_json,
        pre_receipt_artifacts=pre_receipt.artifacts,
    )

    transported_manifest = bytes(produced.manifest_json)
    transported_payload = dict(reversed(tuple(produced.artifacts.items())))
    consumed = verify_reality_publication(
        manifest_json=transported_manifest,
        artifacts=transported_payload,
    )

    assert consumed.valid
    assert consumed.publication_sha256 == produced.publication_sha256
    assert consumed.pre_receipt_snapshot_sha256 == produced.pre_receipt_snapshot_sha256
    assert consumed.authoritative is False
    assert consumed.promotable is False
    assert consumed.attested is False
    manifest = RealityPublicationManifest.model_validate_json(transported_manifest)
    assert {entry.path for entry in manifest.entries} == set(transported_payload)
    report = transported_payload["reports/reality-publication-report.md"].decode()
    assert all(f"(../artifacts/{entry.path})" in report for entry in pre_receipt.manifest.entries)


def test_partial_publication_cannot_survive_the_handoff() -> None:
    pre_receipt = _build_bundle()
    produced = build_reality_publication(
        receipt_json=pre_receipt.receipt_json,
        pre_receipt_manifest_json=pre_receipt.manifest_json,
        pre_receipt_artifacts=pre_receipt.artifacts,
    )
    partial_payload = dict(produced.artifacts)
    partial_payload.pop("reports/reality-publication-report.md")

    consumed = verify_reality_publication(
        manifest_json=produced.manifest_json,
        artifacts=partial_payload,
    )

    assert not consumed.valid
    assert consumed.errors == ("publication-artifact-coverage-mismatch",)
    assert consumed.authoritative is False
    assert consumed.promotable is False
    assert consumed.attested is False
