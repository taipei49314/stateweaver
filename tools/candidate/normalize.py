"""Normalize wheel and sdist container metadata for reproducibility comparison."""

from __future__ import annotations

import argparse
import gzip
import io
import os
import sys
import tarfile
import zipfile
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

from .common import (
    CandidateError,
    canonical_json_bytes,
    sha256_bytes,
    snapshot_tree,
    verify_archive,
)


def _normalized_tar_gz(content: bytes, *, source_date_epoch: int) -> bytes:
    verify_archive("distribution.tar.gz", content)
    tar_output = io.BytesIO()
    try:
        with (
            tarfile.open(fileobj=io.BytesIO(content), mode="r:*") as source,
            tarfile.open(fileobj=tar_output, mode="w", format=tarfile.PAX_FORMAT) as target,
        ):
            for member in sorted(source.getmembers(), key=lambda item: item.name):
                normalized = tarfile.TarInfo(member.name)
                normalized.uid = 0
                normalized.gid = 0
                normalized.uname = ""
                normalized.gname = ""
                normalized.mtime = source_date_epoch
                normalized.mode = member.mode & 0o777
                if member.isdir():
                    normalized.type = tarfile.DIRTYPE
                    target.addfile(normalized)
                    continue
                extracted = source.extractfile(member)
                if extracted is None:
                    raise CandidateError("distribution-normalization-failed")
                payload = extracted.read()
                normalized.type = tarfile.REGTYPE
                normalized.size = len(payload)
                target.addfile(normalized, io.BytesIO(payload))
    except (EOFError, OSError, tarfile.TarError):
        raise CandidateError("distribution-normalization-failed") from None
    output = io.BytesIO()
    with gzip.GzipFile(
        fileobj=output,
        mode="wb",
        filename="",
        compresslevel=9,
        mtime=0,
    ) as compressor:
        compressor.write(tar_output.getvalue())
    return output.getvalue()


def _zip_timestamp(source_date_epoch: int) -> tuple[int, int, int, int, int, int]:
    epoch = max(source_date_epoch, 315532800)
    try:
        timestamp = datetime.fromtimestamp(epoch, tz=UTC)
    except (OSError, OverflowError, ValueError):
        raise CandidateError("source-date-epoch-invalid") from None
    if timestamp.year > 2107:
        raise CandidateError("source-date-epoch-invalid")
    return (
        timestamp.year,
        timestamp.month,
        timestamp.day,
        timestamp.hour,
        timestamp.minute,
        timestamp.second,
    )


def _normalized_wheel(content: bytes, *, source_date_epoch: int) -> bytes:
    verify_archive("distribution.whl", content)
    output = io.BytesIO()
    timestamp = _zip_timestamp(source_date_epoch)
    try:
        with (
            zipfile.ZipFile(io.BytesIO(content), mode="r") as source,
            zipfile.ZipFile(
                output,
                mode="w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=9,
                strict_timestamps=True,
            ) as target,
        ):
            for member in sorted(source.infolist(), key=lambda item: item.filename):
                normalized = zipfile.ZipInfo(member.filename, date_time=timestamp)
                normalized.create_system = 3
                normalized.compress_type = zipfile.ZIP_DEFLATED
                mode = (member.external_attr >> 16) & 0xFFFF
                if member.is_dir():
                    mode = 0o40755
                    payload = b""
                else:
                    mode = mode or 0o100644
                    payload = source.read(member)
                normalized.external_attr = mode << 16
                target.writestr(normalized, payload, compress_type=zipfile.ZIP_DEFLATED)
    except (OSError, RuntimeError, zipfile.BadZipFile):
        raise CandidateError("distribution-normalization-failed") from None
    return output.getvalue()


def _replace(path: Path, content: bytes) -> None:
    temporary = path.with_name(f".{path.name}.normalized-{os.getpid()}")
    try:
        with temporary.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    except OSError as error:
        with suppress(OSError):
            temporary.unlink(missing_ok=True)
        raise CandidateError("distribution-normalization-write-failed") from error


def normalize_distribution_root(root: Path, *, source_date_epoch: int) -> dict[str, str]:
    """Normalize an exact flat set of wheels and sdists in place."""

    if source_date_epoch < 0 or source_date_epoch > 4354819199:
        raise CandidateError("source-date-epoch-invalid")
    snapshot = snapshot_tree(root)
    if not snapshot or any("/" in path for path in snapshot):
        raise CandidateError("distribution-root-invalid")
    if not any(path.endswith(".whl") for path in snapshot) or not any(
        path.endswith(".tar.gz") for path in snapshot
    ):
        raise CandidateError("distribution-set-incomplete")
    for path, content in snapshot.items():
        if path.endswith(".whl"):
            normalized = _normalized_wheel(content, source_date_epoch=source_date_epoch)
        elif path.endswith(".tar.gz"):
            normalized = _normalized_tar_gz(content, source_date_epoch=source_date_epoch)
        elif path == ".gitignore" and content in {b"*", b"*\n"}:
            continue
        else:
            raise CandidateError("distribution-file-unexpected")
        verify_archive(path, normalized)
        _replace(root / path, normalized)
    normalized_snapshot = snapshot_tree(root)
    return {path: sha256_bytes(content) for path, content in normalized_snapshot.items()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("distribution_root", type=Path)
    parser.add_argument("--source-date-epoch", type=int, required=True)
    arguments = parser.parse_args(argv)
    try:
        digests = normalize_distribution_root(
            arguments.distribution_root,
            source_date_epoch=arguments.source_date_epoch,
        )
    except CandidateError as error:
        print(canonical_json_bytes({"error": error.code, "valid": False}).decode(), end="")
        return 1
    print(canonical_json_bytes({"digests": digests, "valid": True}).decode(), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
