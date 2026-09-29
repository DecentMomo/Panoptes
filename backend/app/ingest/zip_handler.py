import stat
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO
from zipfile import BadZipFile, ZipFile, ZipInfo

from app.ingest.validators import (
    PathEscapeError,
    assert_within,
    is_allowed_extension,
    is_safe_member_name,
)

UNSAFE_PATHS = "The archive was rejected: it contains unsafe paths."
TOO_LARGE = "The archive was rejected: it is too large."
TOO_MANY_FILES = "The archive was rejected: it contains too many files."
NOT_A_ZIP = "The archive was rejected: it is not a valid zip file."
EMPTY = "The archive was rejected: it is empty."


class UnsafeArchiveError(Exception):
    def __init__(self, public_message: str, detail: str) -> None:
        super().__init__(detail)
        self.public_message = public_message
        self.detail = detail


@dataclass(frozen=True)
class ArchiveLimits:
    max_uncompressed_bytes: int
    max_file_count: int


def save_upload(source: BinaryIO, dest: Path, max_bytes: int) -> None:
    """Stream an upload to disk and stop once it passes the size cap."""
    total = 0
    with dest.open("wb") as output:
        while True:
            chunk = source.read(64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise UnsafeArchiveError(TOO_LARGE, f"upload exceeded {max_bytes} bytes")
            output.write(chunk)
    if total == 0:
        raise UnsafeArchiveError(EMPTY, "upload was empty")


def is_zip_symlink(info: ZipInfo) -> bool:
    mode = info.external_attr >> 16
    return stat.S_ISLNK(mode)


def read_capped(source: BinaryIO, max_bytes: int) -> bytes:
    """Read a member, counting real bytes. Zip headers can under-report the size."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = source.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise UnsafeArchiveError(TOO_LARGE, f"decompressed data exceeded {max_bytes} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def extract_zip(zip_path: Path, dest: Path, limits: ArchiveLimits) -> tuple[int, int]:
    """Extract source files. Returns (extracted, skipped).

    Traversal, absolute paths, and symlinks reject the whole archive. Other
    extensions are skipped so a README or an image does not fail the scan.
    """
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    try:
        archive = ZipFile(zip_path)
    except BadZipFile as exc:
        raise UnsafeArchiveError(NOT_A_ZIP, "bad zip") from exc

    extracted = 0
    skipped = 0
    written = 0
    with archive:
        members = [info for info in archive.infolist() if not info.is_dir()]
        if len(members) > limits.max_file_count:
            raise UnsafeArchiveError(TOO_MANY_FILES, f"{len(members)} entries")
        declared = sum(info.file_size for info in members)
        if declared > limits.max_uncompressed_bytes:
            raise UnsafeArchiveError(TOO_LARGE, f"declared size {declared}")

        for info in members:
            if is_zip_symlink(info) or not is_safe_member_name(info.filename):
                raise UnsafeArchiveError(UNSAFE_PATHS, f"unsafe entry {info.filename!r}")
            if not is_allowed_extension(info.filename):
                skipped += 1
                continue
            target = root / info.filename
            try:
                safe_target = assert_within(root, target)
            except PathEscapeError as exc:
                raise UnsafeArchiveError(UNSAFE_PATHS, str(exc)) from exc
            safe_target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as member:
                payload = read_capped(member, limits.max_uncompressed_bytes - written)
            written += len(payload)
            safe_target.write_bytes(payload)
            extracted += 1
    return extracted, skipped
