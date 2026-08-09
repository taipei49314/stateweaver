"""Dependency-free primitives shared by candidate build and verification."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import struct
import tarfile
import zipfile
from collections.abc import Iterable, Mapping
from contextlib import suppress
from pathlib import Path, PurePosixPath
from typing import Final

MANIFEST_NAME: Final = "PAYLOAD_MANIFEST.json"
CHECKSUMS_NAME: Final = "SHA256SUMS"
RECEIPT_NAME: Final = "CANDIDATE_RECEIPT.json"
SBOM_PATH: Final = "payload/sbom/stateweaver.spdx.json"
SCHEMA_VERSION: Final = "stateweaver-candidate-payload-v1"
RECEIPT_SCHEMA_VERSION: Final = "stateweaver-candidate-receipt-v1"
CANDIDATE_STATUS: Final = "CANDIDATE_READY_FOR_EXTERNAL_QUALIFICATION"
SHA256_RE: Final = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE: Final = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE: Final = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[a-zA-Z0-9.+-]*)?$")
GIT_COMMIT_OBJECT_PATH: Final = "payload/source/git-commit-object"
MAX_CANDIDATE_ENTRIES: Final = 8_192
MAX_CANDIDATE_FILES: Final = 4_096
MAX_CANDIDATE_FILE_BYTES: Final = 64 * 1024 * 1024
MAX_CANDIDATE_TOTAL_BYTES: Final = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS: Final = 10_000
MAX_ARCHIVE_CENTRAL_DIRECTORY_BYTES: Final = 16 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES: Final = 64 * 1024 * 1024
MAX_ARCHIVE_EXPANDED_BYTES: Final = 512 * 1024 * 1024
MAX_ALL_ARCHIVE_EXPANDED_BYTES: Final = 1024 * 1024 * 1024
MAX_METADATA_JSON_BYTES: Final = 8 * 1024 * 1024
MAX_SBOM_JSON_BYTES: Final = 16 * 1024 * 1024
MAX_LOCKFILE_BYTES: Final = 16 * 1024 * 1024
MAX_JSON_DEPTH: Final = 64
MAX_JSON_NODES: Final = 200_000
MAX_JSON_STRING_BYTES: Final = 2 * 1024 * 1024
MAX_JSON_KEY_BYTES: Final = 4 * 1024
MAX_JSON_NUMBER_BYTES: Final = 1024

_SECRET_PATTERNS: Final = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"gh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(rb"sk-[A-Za-z0-9]{32,}"),
    re.compile(rb"AKIA[0-9A-Z]{16}"),
)


class CandidateError(ValueError):
    """Stable fail-closed rejection of an invalid candidate."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def canonical_json_bytes(value: object) -> bytes:
    """Return the candidate canonical JSON dialect: sorted, compact UTF-8 plus LF."""

    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def preflight_json_structure(
    content: bytes,
    *,
    code: str,
    max_bytes: int,
    max_depth: int = MAX_JSON_DEPTH,
    max_nodes: int = MAX_JSON_NODES,
    max_string_bytes: int = MAX_JSON_STRING_BYTES,
    max_key_bytes: int = MAX_JSON_KEY_BYTES,
) -> None:
    """Bound JSON structure before the standard decoder allocates an object graph."""

    if len(content) > max_bytes:
        raise CandidateError(code)
    depth = 0
    nodes = 0
    index = 0
    length = len(content)
    whitespace = b" \t\r\n"
    delimiters = b"{}[],: \t\r\n"
    while index < length:
        value = content[index]
        if value in whitespace:
            index += 1
            continue
        if value in (ord("{"), ord("[")):
            depth += 1
            nodes += 1
            if depth > max_depth or nodes > max_nodes:
                raise CandidateError(code)
            index += 1
            continue
        if value in (ord("}"), ord("]")):
            depth -= 1
            if depth < 0:
                raise CandidateError(code)
            index += 1
            continue
        if value == ord('"'):
            start = index
            index += 1
            escaped = False
            while index < length:
                current = content[index]
                if escaped:
                    escaped = False
                elif current == ord("\\"):
                    escaped = True
                elif current == ord('"'):
                    break
                index += 1
            if index >= length:
                raise CandidateError(code)
            string_bytes = index - start - 1
            index += 1
            lookahead = index
            while lookahead < length and content[lookahead] in whitespace:
                lookahead += 1
            limit = (
                max_key_bytes
                if lookahead < length and content[lookahead] == ord(":")
                else max_string_bytes
            )
            nodes += 1
            if string_bytes > limit or nodes > max_nodes:
                raise CandidateError(code)
            continue
        if value in (ord(":"), ord(",")):
            index += 1
            continue
        token_start = index
        nodes += 1
        if nodes > max_nodes:
            raise CandidateError(code)
        index += 1
        while index < length and content[index] not in delimiters:
            index += 1
        if value in b"-0123456789" and index - token_start > MAX_JSON_NUMBER_BYTES:
            raise CandidateError(code)
    if depth != 0:
        raise CandidateError(code)


def parse_canonical_json(
    content: bytes,
    *,
    code: str,
    max_bytes: int = MAX_METADATA_JSON_BYTES,
) -> object:
    """Parse JSON and require exact canonical encoding and no duplicate object keys."""

    def reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise CandidateError(code)
            result[key] = value
        return result

    def reject_constant(_value: str) -> object:
        raise CandidateError(code)

    preflight_json_structure(content, code=code, max_bytes=max_bytes)
    try:
        value = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=reject_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        MemoryError,
        OverflowError,
        RecursionError,
        ValueError,
    ):
        raise CandidateError(code) from None
    try:
        canonical = canonical_json_bytes(value)
    except (MemoryError, OverflowError, RecursionError):
        raise CandidateError(code) from None
    if canonical != content:
        raise CandidateError(code)
    return value


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def verify_git_commit_object(content: bytes, *, source_sha: str, tree_sha: str) -> None:
    """Bind the claimed source SHA to a raw Git commit object and its tree."""

    if not content or len(content) > 16 * 1024 * 1024 or b"\x00" in content:
        raise CandidateError("git-commit-object-invalid")
    first_line = content.split(b"\n", 1)[0]
    try:
        declared_tree = first_line.removeprefix(b"tree ").decode("ascii")
    except UnicodeDecodeError:
        raise CandidateError("git-commit-object-invalid") from None
    if first_line != f"tree {declared_tree}".encode() or not GIT_SHA_RE.fullmatch(declared_tree):
        raise CandidateError("git-commit-object-invalid")
    object_header = f"commit {len(content)}\0".encode()
    object_sha = hashlib.sha1(object_header + content, usedforsecurity=False).hexdigest()
    if object_sha != source_sha or declared_tree != tree_sha:
        raise CandidateError("git-commit-object-source-mismatch")


def safe_relative_path(value: object) -> str:
    """Return a normalized POSIX candidate path or fail closed."""

    if not isinstance(value, str) or not value or len(value) > 512:
        raise CandidateError("unsafe-relative-path")
    if "\\" in value or "\x00" in value or ":" in value:
        raise CandidateError("unsafe-relative-path")
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value:
        raise CandidateError("unsafe-relative-path")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise CandidateError("unsafe-relative-path")
    return value


def _is_reparse_or_link(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise CandidateError("candidate-tree-unreadable") from error
    if stat.S_ISLNK(metadata.st_mode):
        return True
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(attributes & reparse_flag)


def _read_descriptor_limited(descriptor: int, *, declared_size: int) -> bytes:
    if declared_size < 0 or declared_size > MAX_CANDIDATE_FILE_BYTES:
        raise CandidateError("candidate-file-size-limit")
    chunks: list[bytes] = []
    actual_size = 0
    while True:
        chunk = os.read(descriptor, min(1024 * 1024, MAX_CANDIDATE_FILE_BYTES + 1))
        if not chunk:
            break
        actual_size += len(chunk)
        if actual_size > MAX_CANDIDATE_FILE_BYTES:
            raise CandidateError("candidate-file-size-limit")
        chunks.append(chunk)
    if actual_size != declared_size:
        raise CandidateError("candidate-file-size-changed")
    return b"".join(chunks)


def snapshot_tree(root: Path) -> dict[str, bytes]:
    """Capture each regular file once while rejecting links, reparse points, and unsafe names."""

    if not root.is_dir() or _is_reparse_or_link(root):
        raise CandidateError("candidate-root-invalid")
    snapshot: dict[str, bytes] = {}
    casefolded: set[str] = set()
    entry_count = 0
    aggregate_size = 0
    try:
        paths = root.rglob("*")
        for path in paths:
            entry_count += 1
            if entry_count > MAX_CANDIDATE_ENTRIES:
                raise CandidateError("candidate-tree-entry-limit")
            if _is_reparse_or_link(path):
                raise CandidateError("candidate-tree-link-forbidden")
            if path.is_dir():
                continue
            if not path.is_file():
                raise CandidateError("candidate-tree-nonregular-file")
            if len(snapshot) >= MAX_CANDIDATE_FILES:
                raise CandidateError("candidate-file-count-limit")
            relative = safe_relative_path(path.relative_to(root).as_posix())
            folded = relative.casefold()
            if folded in casefolded:
                raise CandidateError("candidate-tree-case-collision")
            casefolded.add(folded)
            descriptor = os.open(
                path,
                os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode):
                    raise CandidateError("candidate-tree-nonregular-file")
                if metadata.st_size > MAX_CANDIDATE_FILE_BYTES:
                    raise CandidateError("candidate-file-size-limit")
                aggregate_size += metadata.st_size
                if aggregate_size > MAX_CANDIDATE_TOTAL_BYTES:
                    raise CandidateError("candidate-total-size-limit")
                snapshot[relative] = _read_descriptor_limited(
                    descriptor, declared_size=metadata.st_size
                )
            finally:
                os.close(descriptor)
    except CandidateError:
        raise
    except OSError as error:
        raise CandidateError("candidate-tree-unreadable") from error
    return dict(sorted(snapshot.items()))


def atomic_write(path: Path, content: bytes) -> None:
    """Create one file atomically without overwriting an existing output."""

    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise CandidateError("candidate-output-already-exists")
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        with temporary.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    except OSError as error:
        with suppress(OSError):
            temporary.unlink(missing_ok=True)
        raise CandidateError("candidate-output-write-failed") from error


def assert_secret_free(artifacts: Mapping[str, bytes]) -> None:
    for content in artifacts.values():
        if any(pattern.search(content) for pattern in _SECRET_PATTERNS):
            raise CandidateError("candidate-secret-scan-failed")


def _safe_archive_member(value: str) -> str:
    stripped = value.rstrip("/")
    if not stripped:
        raise CandidateError("archive-member-path-invalid")
    return safe_relative_path(stripped)


def _consume_archive_stream(stream: object, *, expected_size: int) -> int:
    if expected_size < 0 or expected_size > MAX_ARCHIVE_MEMBER_BYTES:
        raise CandidateError("archive-member-size-limit")
    read = getattr(stream, "read", None)
    if not callable(read):
        raise CandidateError("archive-integrity-failed")
    actual_size = 0
    while True:
        chunk = read(min(1024 * 1024, MAX_ARCHIVE_MEMBER_BYTES + 1))
        if not isinstance(chunk, bytes):
            raise CandidateError("archive-integrity-failed")
        if not chunk:
            break
        actual_size += len(chunk)
        if actual_size > MAX_ARCHIVE_MEMBER_BYTES:
            raise CandidateError("archive-member-size-limit")
    if actual_size != expected_size:
        raise CandidateError("archive-member-size-mismatch")
    return actual_size


def _preflight_zip_metadata(content: bytes) -> None:
    """Bound the central directory before ``zipfile`` allocates one object per member."""

    eocd_size = 22
    eocd_offset = content.rfind(b"PK\x05\x06", max(0, len(content) - (65_535 + eocd_size)))
    if eocd_offset < 0 or eocd_offset + eocd_size > len(content):
        raise CandidateError("archive-integrity-failed")
    try:
        (
            signature,
            disk_number,
            central_disk,
            disk_entries,
            total_entries,
            central_size,
            central_offset,
            comment_size,
        ) = struct.unpack_from("<4s4H2LH", content, eocd_offset)
    except struct.error:
        raise CandidateError("archive-integrity-failed") from None
    if signature != b"PK\x05\x06" or eocd_offset + eocd_size + comment_size != len(content):
        raise CandidateError("archive-integrity-failed")
    if (
        disk_number != 0
        or central_disk != 0
        or disk_entries != total_entries
        or total_entries == 0xFFFF
        or central_size == 0xFFFFFFFF
        or central_offset == 0xFFFFFFFF
    ):
        raise CandidateError("archive-zip64-or-multidisk-forbidden")
    if total_entries > MAX_ARCHIVE_MEMBERS:
        raise CandidateError("archive-member-count-limit")
    if central_size > MAX_ARCHIVE_CENTRAL_DIRECTORY_BYTES:
        raise CandidateError("archive-central-directory-size-limit")
    if central_offset + central_size > eocd_offset:
        raise CandidateError("archive-integrity-failed")


def verify_archive(path: str, content: bytes, *, allow_symlinks: bool = False) -> int:
    """Reject traversal, links, devices, duplicate members, encryption, and corrupt archives."""

    lower = path.lower()
    if lower.endswith((".whl", ".zip")):
        _preflight_zip_metadata(content)
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                members = archive.infolist()
                if len(members) > MAX_ARCHIVE_MEMBERS:
                    raise CandidateError("archive-member-count-limit")
                declared_total = 0
                zip_names: set[str] = set()
                for zip_member in members:
                    name = _safe_archive_member(zip_member.filename)
                    if name in zip_names:
                        raise CandidateError("archive-member-duplicate")
                    zip_names.add(name)
                    if zip_member.flag_bits & 0x1:
                        raise CandidateError("archive-encryption-forbidden")
                    unix_mode = (zip_member.external_attr >> 16) & 0xFFFF
                    if unix_mode and stat.S_ISLNK(unix_mode):
                        raise CandidateError("archive-link-forbidden")
                    if not zip_member.is_dir():
                        if zip_member.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                            raise CandidateError("archive-member-size-limit")
                        declared_total += zip_member.file_size
                        if declared_total > MAX_ARCHIVE_EXPANDED_BYTES:
                            raise CandidateError("archive-expanded-size-limit")
                actual_total = 0
                for zip_member in members:
                    if zip_member.is_dir():
                        continue
                    with archive.open(zip_member, "r") as stream:
                        actual_total += _consume_archive_stream(
                            stream, expected_size=zip_member.file_size
                        )
                    if actual_total > MAX_ARCHIVE_EXPANDED_BYTES:
                        raise CandidateError("archive-expanded-size-limit")
        except CandidateError:
            raise
        except (EOFError, OSError, RuntimeError, zipfile.BadZipFile):
            raise CandidateError("archive-integrity-failed") from None
        return actual_total
    if lower.endswith((".tar", ".tar.gz", ".tgz")):
        try:
            with tarfile.open(fileobj=io.BytesIO(content), mode="r:*") as archive:
                tar_names: set[str] = set()
                member_count = 0
                expanded_total = 0
                for tar_member in archive:
                    member_count += 1
                    if member_count > MAX_ARCHIVE_MEMBERS:
                        raise CandidateError("archive-member-count-limit")
                    name = _safe_archive_member(tar_member.name)
                    if name in tar_names:
                        raise CandidateError("archive-member-duplicate")
                    tar_names.add(name)
                    if tar_member.issym() and allow_symlinks:
                        if tar_member.size != 0 or not tar_member.linkname:
                            raise CandidateError("archive-link-invalid")
                        continue
                    if tar_member.issym() or tar_member.islnk():
                        raise CandidateError("archive-link-forbidden")
                    if tar_member.isdev() or tar_member.isfifo():
                        raise CandidateError("archive-special-file-forbidden")
                    if not (tar_member.isfile() or tar_member.isdir()):
                        raise CandidateError("archive-special-file-forbidden")
                    if not tar_member.isfile():
                        continue
                    if tar_member.size > MAX_ARCHIVE_MEMBER_BYTES:
                        raise CandidateError("archive-member-size-limit")
                    if expanded_total + tar_member.size > MAX_ARCHIVE_EXPANDED_BYTES:
                        raise CandidateError("archive-expanded-size-limit")
                    extracted = archive.extractfile(tar_member)
                    if extracted is None:
                        raise CandidateError("archive-integrity-failed")
                    expanded_total += _consume_archive_stream(
                        extracted, expected_size=tar_member.size
                    )
        except CandidateError:
            raise
        except (EOFError, OSError, tarfile.TarError):
            raise CandidateError("archive-integrity-failed") from None
        return expanded_total
    return 0


def verify_archives(artifacts: Mapping[str, bytes]) -> None:
    expanded_total = 0
    for path, content in artifacts.items():
        if path.lower().endswith((".whl", ".zip", ".tar", ".tar.gz", ".tgz")):
            expanded_total += verify_archive(
                path,
                content,
                allow_symlinks=path.startswith("payload/source/"),
            )
            if expanded_total > MAX_ALL_ARCHIVE_EXPANDED_BYTES:
                raise CandidateError("archive-aggregate-expanded-size-limit")


def _git_object_digest(kind: str, content: bytes) -> bytes:
    return hashlib.sha1(
        f"{kind} {len(content)}\0".encode() + content,
        usedforsecurity=False,
    ).digest()


def _git_tree_digest(entries: Mapping[str, tuple[int, bytes]]) -> str:
    tree: dict[str, object] = {}
    for path, entry in entries.items():
        cursor = tree
        parts = path.split("/")
        for part in parts[:-1]:
            existing = cursor.get(part)
            if existing is None:
                child: dict[str, object] = {}
                cursor[part] = child
                cursor = child
            elif isinstance(existing, dict):
                cursor = existing
            else:
                raise CandidateError("source-archive-tree-invalid")
        if parts[-1] in cursor:
            raise CandidateError("source-archive-tree-invalid")
        cursor[parts[-1]] = entry

    def digest(node: Mapping[str, object]) -> bytes:
        records: list[tuple[bytes, bytes]] = []
        for name, value in node.items():
            try:
                encoded_name = name.encode("utf-8")
            except UnicodeEncodeError:
                raise CandidateError("source-archive-path-invalid") from None
            if isinstance(value, dict):
                mode = b"40000"
                object_digest = digest(value)
                sort_key = encoded_name + b"/"
            else:
                if not isinstance(value, tuple) or len(value) != 2:
                    raise CandidateError("source-archive-tree-invalid")
                file_mode, payload = value
                if not isinstance(file_mode, int) or not isinstance(payload, bytes):
                    raise CandidateError("source-archive-tree-invalid")
                mode = str(file_mode).encode("ascii")
                object_digest = _git_object_digest("blob", payload)
                sort_key = encoded_name
            records.append((sort_key, mode + b" " + encoded_name + b"\0" + object_digest))
        tree_content = b"".join(record for _key, record in sorted(records))
        return _git_object_digest("tree", tree_content)

    return digest(tree).hex()


def verify_source_archive(
    content: bytes,
    *,
    python_lock: bytes,
    node_lock: bytes,
    expected_tree_sha: str,
    expected_prefix: str,
) -> None:
    """Bind a safe Git archive to its exact tree while checking packaged lockfiles."""

    if not GIT_SHA_RE.fullmatch(expected_tree_sha):
        raise CandidateError("source-archive-tree-invalid")
    if safe_relative_path(expected_prefix) != expected_prefix or "/" in expected_prefix:
        raise CandidateError("source-archive-prefix-invalid")
    matches: dict[str, list[tuple[str, bytes]]] = {"python": [], "node": []}
    entries: dict[str, tuple[int, bytes]] = {}
    directories: set[str] = set()
    casefolded: set[str] = set()
    verify_archive("source.tar.gz", content, allow_symlinks=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:*") as archive:
            member_count = 0
            for member in archive:
                member_count += 1
                if member_count > MAX_ARCHIVE_MEMBERS:
                    raise CandidateError("source-archive-lock-closure-invalid")
                name = _safe_archive_member(member.name)
                if name == expected_prefix:
                    relative = ""
                elif name.startswith(f"{expected_prefix}/"):
                    relative = name.removeprefix(f"{expected_prefix}/")
                    safe_relative_path(relative)
                else:
                    raise CandidateError("source-archive-prefix-invalid")
                folded = relative.casefold()
                if folded in casefolded:
                    raise CandidateError("source-archive-path-collision")
                casefolded.add(folded)
                mode = member.mode & 0o7777
                if member.isdir():
                    if mode != 0o775:
                        raise CandidateError("source-archive-mode-invalid")
                    directories.add(relative)
                    continue
                if not relative:
                    raise CandidateError("source-archive-root-invalid")
                if member.issym():
                    if mode != 0o777 or member.size != 0 or not member.linkname:
                        raise CandidateError("source-archive-mode-invalid")
                    try:
                        payload = member.linkname.encode("utf-8")
                    except UnicodeEncodeError:
                        raise CandidateError("source-archive-link-invalid") from None
                    if b"\0" in payload or len(payload) > MAX_ARCHIVE_MEMBER_BYTES:
                        raise CandidateError("source-archive-link-invalid")
                    entries[relative] = (120000, payload)
                    continue
                if not member.isfile() or mode not in {0o664, 0o775}:
                    raise CandidateError("source-archive-mode-invalid")
                extracted = archive.extractfile(member)
                if extracted is None or member.size > MAX_CANDIDATE_FILE_BYTES:
                    raise CandidateError("source-archive-lock-closure-invalid")
                payload = extracted.read(MAX_CANDIDATE_FILE_BYTES + 1)
                if len(payload) != member.size or len(payload) > MAX_CANDIDATE_FILE_BYTES:
                    raise CandidateError("source-archive-lock-closure-invalid")
                entries[relative] = (100755 if mode == 0o775 else 100644, payload)
                kind: str | None = None
                if relative == "uv.lock":
                    kind = "python"
                if relative == "apps/web/package-lock.json":
                    kind = "node"
                if kind is None:
                    continue
                matches[kind].append((relative, payload))
    except CandidateError:
        raise
    except (EOFError, OSError, tarfile.TarError):
        raise CandidateError("source-archive-lock-closure-invalid") from None
    if len(matches["python"]) != 1 or len(matches["node"]) != 1:
        raise CandidateError("source-archive-lock-closure-invalid")
    _python_name, archived_python_lock = matches["python"][0]
    _node_name, archived_node_lock = matches["node"][0]
    if archived_python_lock != python_lock or archived_node_lock != node_lock:
        raise CandidateError("source-archive-lock-closure-invalid")
    expected_directories = {""}
    for path in entries:
        parts = path.split("/")
        expected_directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
    if directories != expected_directories:
        raise CandidateError("source-archive-directory-set-invalid")
    if _git_tree_digest(entries) != expected_tree_sha:
        raise CandidateError("source-archive-tree-mismatch")


def exact_keys(value: Mapping[str, object], expected: Iterable[str], *, code: str) -> None:
    if set(value) != set(expected):
        raise CandidateError(code)


def require_mapping(value: object, *, code: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise CandidateError(code)
    return value


def require_list(value: object, *, code: str) -> list[object]:
    if not isinstance(value, list):
        raise CandidateError(code)
    return value
