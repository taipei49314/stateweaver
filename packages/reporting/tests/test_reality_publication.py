"""Adversarial tests for deterministic Reality publication candidates."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator, Mapping
from typing import cast

import pytest
from reality_bundle_fixtures import _build_bundle, _Bundle, _remint_bundle
from stateweaver.contracts import canonical_json_bytes, sha256_digest
from stateweaver.evidence import (
    RealityArtifactRole,
    RealityEvidenceFact,
    RealityEvidenceIndex,
    RealityEvidenceItem,
)
from stateweaver.reporting import (
    PublicationArtifactRole,
    RealityPublication,
    RealityPublicationError,
    RealityPublicationManifest,
    build_reality_publication,
    verify_reality_publication,
)


class _ReadOnceMapping(Mapping[str, bytes]):
    def __init__(self, values: Mapping[str, bytes]) -> None:
        self._values = dict(values)
        self.reads = dict.fromkeys(values, 0)

    def __getitem__(self, key: str) -> bytes:
        self.reads[key] += 1
        if self.reads[key] > 1:
            return b"poisoned-second-read"
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)


def _sha256(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


@pytest.fixture
def bundle() -> _Bundle:
    return _build_bundle()


@pytest.fixture
def publication(bundle: _Bundle) -> RealityPublication:
    return build_reality_publication(
        receipt_json=bundle.receipt_json,
        pre_receipt_manifest_json=bundle.manifest_json,
        pre_receipt_artifacts=bundle.artifacts,
    )


def _remint_manifest(
    publication: RealityPublication,
    *,
    path: str,
    content: bytes,
) -> bytes:
    manifest = RealityPublicationManifest.model_validate_json(publication.manifest_json)
    payload = manifest.model_dump(mode="json")
    entries = cast(list[dict[str, object]], payload["entries"])
    selected = next(entry for entry in entries if entry["path"] == path)
    selected["sha256"] = _sha256(content)
    role = selected["role"]
    if role == PublicationArtifactRole.REPORT.value:
        payload["report_sha256"] = _sha256(content)
    elif role == PublicationArtifactRole.RECEIPT.value:
        payload["receipt_sha256"] = _sha256(content)
    elif role == PublicationArtifactRole.PRE_RECEIPT_MANIFEST.value:
        payload["pre_receipt_manifest_sha256"] = _sha256(content)
    return RealityPublicationManifest.model_validate_json(
        canonical_json_bytes(payload)
    ).canonical_bytes()


def test_build_is_byte_deterministic_and_immutable(bundle: _Bundle) -> None:
    first = build_reality_publication(
        receipt_json=bundle.receipt_json,
        pre_receipt_manifest_json=bundle.manifest_json,
        pre_receipt_artifacts=bundle.artifacts,
    )
    reversed_artifacts = dict(reversed(tuple(bundle.artifacts.items())))
    second = build_reality_publication(
        receipt_json=bundle.receipt_json,
        pre_receipt_manifest_json=bundle.manifest_json,
        pre_receipt_artifacts=reversed_artifacts,
    )

    assert first.manifest_json == second.manifest_json
    assert dict(first.artifacts) == dict(second.artifacts)
    assert first.publication_sha256 == second.publication_sha256
    assert first.authoritative is False
    assert first.promotable is False
    assert first.attested is False
    assert first.control_kind_semantics_attested is False
    with pytest.raises(TypeError):
        cast(dict[str, bytes], first.artifacts)["unexpected"] = b"mutation"


def test_builder_snapshots_each_caller_artifact_once(bundle: _Bundle) -> None:
    source = _ReadOnceMapping(bundle.artifacts)

    publication = build_reality_publication(
        receipt_json=bundle.receipt_json,
        pre_receipt_manifest_json=bundle.manifest_json,
        pre_receipt_artifacts=source,
    )

    assert publication.publication_sha256.startswith("sha256:")
    assert set(source.reads.values()) == {1}


def test_manifest_closes_payload_without_self_inclusion(
    bundle: _Bundle,
    publication: RealityPublication,
) -> None:
    manifest = RealityPublicationManifest.model_validate_json(publication.manifest_json)

    assert {entry.path for entry in manifest.entries} == set(publication.artifacts)
    assert "artifact-manifest.json" not in publication.artifacts
    assert manifest.receipt_hash == bundle.receipt.receipt_hash
    assert manifest.authoritative is False
    assert manifest.promotable is False
    assert manifest.attested is False
    assert manifest.control_kind_semantics_attested is False
    source_entries = tuple(
        entry
        for entry in manifest.entries
        if entry.role is PublicationArtifactRole.PRE_RECEIPT_ARTIFACT
    )
    assert len(source_entries) == len(bundle.manifest.entries)
    assert tuple(entry.source_path for entry in source_entries) == tuple(
        entry.path for entry in bundle.manifest.entries
    )


def test_report_traces_every_pre_receipt_artifact(
    bundle: _Bundle,
    publication: RealityPublication,
) -> None:
    report = publication.artifacts["reports/reality-publication-report.md"].decode()

    for entry in bundle.manifest.entries:
        assert f"(../artifacts/{entry.path})" in report
        assert f"`{entry.sha256}`" in report
        assert f"`{entry.role.value}`" in report
    assert "| Authoritative | `false` |" in report
    assert "| Promotable | `false` |" in report
    assert "| Control-kind semantics attested | `false` |" in report
    assert "M6 certification" in report


def test_report_exposes_every_direct_primary_oracle_receipt_claim(
    bundle: _Bundle,
    publication: RealityPublication,
) -> None:
    report = publication.artifacts["reports/reality-publication-report.md"].decode()
    oracle_path = next(
        entry.path for entry in bundle.manifest.entries if entry.role.value == "primary-oracles"
    )
    oracle_row = next(line for line in report.splitlines() if f"{oracle_path}`]" in line)

    assert "manifest-exact + receipt-exact-digest" in oracle_row
    for index in range(len(bundle.receipt.attempts)):
        assert f"#/attempts/{index}/oracle_results_hash" in oracle_row

    control_oracle_path = next(
        entry.path for entry in bundle.manifest.entries if entry.role.value == "control-oracles"
    )
    control_row = next(line for line in report.splitlines() if f"{control_oracle_path}`]" in line)
    assert "#/negative_controls/0/oracle_results_hash" in control_row
    assert "#/attempts/" not in control_row


def test_verifier_rederives_the_complete_publication(
    publication: RealityPublication,
) -> None:
    source = _ReadOnceMapping(publication.artifacts)

    result = verify_reality_publication(
        manifest_json=publication.manifest_json,
        artifacts=source,
    )

    assert result.valid
    assert result.errors == ()
    assert result.publication_sha256 == publication.publication_sha256
    assert result.receipt_sha256 == publication.receipt_sha256
    assert result.pre_receipt_manifest_sha256 == publication.pre_receipt_manifest_sha256
    assert result.pre_receipt_snapshot_sha256 == publication.pre_receipt_snapshot_sha256
    assert result.report_sha256 == publication.report_sha256
    assert result.authoritative is False
    assert result.promotable is False
    assert result.attested is False
    assert result.control_kind_semantics_attested is False
    assert set(source.reads.values()) == {1}


def test_fully_coherent_producer_remint_stays_non_authoritative(bundle: _Bundle) -> None:
    evidence_entry = next(
        entry
        for entry in bundle.manifest.entries
        if entry.role is RealityArtifactRole.EVIDENCE_INDEX
    )
    evidence_index = RealityEvidenceIndex.model_validate_json(bundle.artifacts[evidence_entry.path])
    original_item = evidence_index.items[0]
    reminted_facts = tuple(
        RealityEvidenceFact(
            name=fact.name,
            value="producer-reminted" if fact.name == "source" else fact.value,
        )
        for fact in original_item.facts
    )
    reminted_item = RealityEvidenceItem(
        evidence_id=original_item.evidence_id,
        provenance=original_item.provenance,
        facts=reminted_facts,
        payload_sha256=sha256_digest(reminted_facts),
    )
    reminted_index = RealityEvidenceIndex(items=(reminted_item, *evidence_index.items[1:]))
    artifacts = dict(bundle.artifacts)
    artifacts[evidence_entry.path] = reminted_index.canonical_bytes()
    reminted_bundle = _remint_bundle(bundle, artifacts=artifacts)

    publication = build_reality_publication(
        receipt_json=reminted_bundle.receipt_json,
        pre_receipt_manifest_json=reminted_bundle.manifest_json,
        pre_receipt_artifacts=reminted_bundle.artifacts,
    )
    result = verify_reality_publication(
        manifest_json=publication.manifest_json,
        artifacts=publication.artifacts,
    )

    assert result.valid
    assert result.authoritative is False
    assert result.promotable is False
    assert result.attested is False
    assert result.control_kind_semantics_attested is False


def test_builder_rejects_an_invalid_pre_receipt_artifact(bundle: _Bundle) -> None:
    artifacts = dict(bundle.artifacts)
    path = next(iter(artifacts))
    artifacts[path] += b"tampered"

    with pytest.raises(RealityPublicationError) as raised:
        build_reality_publication(
            receipt_json=bundle.receipt_json,
            pre_receipt_manifest_json=bundle.manifest_json,
            pre_receipt_artifacts=artifacts,
        )

    assert raised.value.code == "pre-receipt-artifact-digest-mismatch"


def test_verifier_rejects_raw_payload_tamper(publication: RealityPublication) -> None:
    artifacts = dict(publication.artifacts)
    artifacts["reports/reality-publication-report.md"] += b"tampered"

    result = verify_reality_publication(
        manifest_json=publication.manifest_json,
        artifacts=artifacts,
    )

    assert not result.valid
    assert result.errors == ("publication-artifact-digest-mismatch",)


@pytest.mark.parametrize("mode", ["missing", "extra"])
def test_verifier_requires_exact_payload_coverage(
    publication: RealityPublication,
    mode: str,
) -> None:
    artifacts = dict(publication.artifacts)
    if mode == "missing":
        artifacts.pop(next(iter(artifacts)))
    else:
        artifacts["unexpected/payload.json"] = b"{}"

    result = verify_reality_publication(
        manifest_json=publication.manifest_json,
        artifacts=artifacts,
    )

    assert not result.valid
    assert result.errors == ("publication-artifact-coverage-mismatch",)


def test_verifier_rejects_unsafe_payload_path_before_resolution(
    publication: RealityPublication,
) -> None:
    artifacts = dict(publication.artifacts)
    artifacts["../escape.json"] = b"{}"

    result = verify_reality_publication(
        manifest_json=publication.manifest_json,
        artifacts=artifacts,
    )

    assert not result.valid
    assert result.errors == ("artifact-path-invalid",)


def test_report_cannot_be_coherently_reminted(publication: RealityPublication) -> None:
    path = "reports/reality-publication-report.md"
    artifacts = dict(publication.artifacts)
    artifacts[path] += b"\nProducer-authored conclusion.\n"
    manifest_json = _remint_manifest(publication, path=path, content=artifacts[path])

    result = verify_reality_publication(manifest_json=manifest_json, artifacts=artifacts)

    assert not result.valid
    assert result.errors == ("report-derivation-mismatch",)


def test_pre_artifact_cannot_be_reminted_only_in_final_manifest(
    publication: RealityPublication,
) -> None:
    manifest = RealityPublicationManifest.model_validate_json(publication.manifest_json)
    source_entry = next(
        entry
        for entry in manifest.entries
        if entry.role is PublicationArtifactRole.PRE_RECEIPT_ARTIFACT
    )
    artifacts = dict(publication.artifacts)
    artifacts[source_entry.path] += b"tampered"
    manifest_json = _remint_manifest(
        publication,
        path=source_entry.path,
        content=artifacts[source_entry.path],
    )

    result = verify_reality_publication(manifest_json=manifest_json, artifacts=artifacts)

    assert not result.valid
    assert result.errors == ("pre-receipt-manifest-projection-mismatch",)


def test_source_role_cannot_be_reminted_only_in_final_manifest(
    publication: RealityPublication,
) -> None:
    manifest = RealityPublicationManifest.model_validate_json(publication.manifest_json)
    payload = manifest.model_dump(mode="json")
    entries = cast(list[dict[str, object]], payload["entries"])
    source_entry = next(entry for entry in entries if entry["source_role"] == "scope")
    source_entry["source_role"] = "target-lock"
    manifest_json = RealityPublicationManifest.model_validate_json(
        canonical_json_bytes(payload)
    ).canonical_bytes()

    result = verify_reality_publication(
        manifest_json=manifest_json,
        artifacts=publication.artifacts,
    )

    assert not result.valid
    assert result.errors == ("pre-receipt-manifest-projection-mismatch",)


def test_noncanonical_receipt_remint_is_rejected(publication: RealityPublication) -> None:
    path = "claims/reality-replay-receipt.json"
    artifacts = dict(publication.artifacts)
    artifacts[path] += b"\n"
    manifest_json = _remint_manifest(publication, path=path, content=artifacts[path])

    result = verify_reality_publication(manifest_json=manifest_json, artifacts=artifacts)

    assert not result.valid
    assert result.errors == ("receipt-not-canonical",)


@pytest.mark.parametrize("mutation", ["whitespace", "default-omission"])
def test_publication_manifest_requires_exact_canonical_contract(
    publication: RealityPublication,
    mutation: str,
) -> None:
    if mutation == "whitespace":
        manifest_json = publication.manifest_json + b"\n"
    else:
        payload = json.loads(publication.manifest_json)
        del payload["authoritative"]
        manifest_json = canonical_json_bytes(payload)

    result = verify_reality_publication(
        manifest_json=manifest_json,
        artifacts=publication.artifacts,
    )

    assert not result.valid
    assert result.errors == ("publication-manifest-not-canonical",)
