import io
import stat
import tracemalloc
import zipfile
from pathlib import Path

import pytest

from app.ingest.zip_handler import (
    TOO_LARGE,
    TOO_MANY_FILES,
    UNSAFE_PATHS,
    ArchiveLimits,
    UnsafeArchiveError,
    copy_capped,
    extract_zip,
    save_upload,
)

LIMITS = ArchiveLimits(max_uncompressed_bytes=1024 * 1024, max_file_count=10)


def _write(
    path: Path, entries: list[tuple[str, bytes]], extra: list[zipfile.ZipInfo] | None = None
) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, payload in entries:
            archive.writestr(name, payload)
        for info in extra or []:
            archive.writestr(info, "target")
    return path


def test_zip_slip_is_rejected(tmp_path: Path) -> None:
    archive = _write(tmp_path / "slip.zip", [("../evil.py", b"print(1)\n")])
    with pytest.raises(UnsafeArchiveError) as caught:
        extract_zip(archive, tmp_path / "out", LIMITS)
    assert caught.value.public_message == UNSAFE_PATHS
    assert not (tmp_path / "evil.py").exists()


def test_absolute_path_is_rejected(tmp_path: Path) -> None:
    archive = _write(tmp_path / "abs.zip", [("/tmp/evil.py", b"print(1)\n")])
    with pytest.raises(UnsafeArchiveError) as caught:
        extract_zip(archive, tmp_path / "out", LIMITS)
    assert caught.value.public_message == UNSAFE_PATHS


def test_symlink_entry_is_rejected(tmp_path: Path) -> None:
    info = zipfile.ZipInfo("link.py")
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    archive = _write(tmp_path / "link.zip", [], extra=[info])
    with pytest.raises(UnsafeArchiveError) as caught:
        extract_zip(archive, tmp_path / "out", LIMITS)
    assert caught.value.public_message == UNSAFE_PATHS


def test_too_many_files_is_rejected(tmp_path: Path) -> None:
    entries = [(f"file{index}.py", b"x = 1\n") for index in range(3)]
    archive = _write(tmp_path / "many.zip", entries)
    limits = ArchiveLimits(max_uncompressed_bytes=1024 * 1024, max_file_count=2)
    with pytest.raises(UnsafeArchiveError) as caught:
        extract_zip(archive, tmp_path / "out", limits)
    assert caught.value.public_message == TOO_MANY_FILES


def test_disallowed_extension_is_skipped(tmp_path: Path) -> None:
    archive = _write(tmp_path / "mix.zip", [("app.py", b"x = 1\n"), ("photo.png", b"not-really")])
    extracted, skipped = extract_zip(archive, tmp_path / "out", LIMITS)
    assert extracted == 1
    assert skipped == 1
    assert (tmp_path / "out" / "app.py").is_file()
    assert not (tmp_path / "out" / "photo.png").exists()


def test_zip_bomb_is_rejected(tmp_path: Path) -> None:
    # 200MB of zeros compresses to almost nothing, which is the point of the check.
    archive_path = tmp_path / "bomb.zip"
    chunk = b"\0" * (1024 * 1024)
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        info = zipfile.ZipInfo("bomb.py")
        with archive.open(info, "w") as member:
            for _ in range(200):
                member.write(chunk)
    with pytest.raises(UnsafeArchiveError) as caught:
        extract_zip(archive_path, tmp_path / "out", LIMITS)
    assert caught.value.public_message == TOO_LARGE
    assert not (tmp_path / "out" / "bomb.py").exists()


class _CountingStream(io.RawIOBase):
    """A source that can report how many bytes were actually pulled."""

    def __init__(self, size: int) -> None:
        self._remaining = size
        self.read_bytes = 0

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if self._remaining <= 0:
            return b""
        take = self._remaining if size is None or size < 0 else min(size, self._remaining)
        self._remaining -= take
        self.read_bytes += take
        return b"\0" * take


def test_copy_capped_stops_early_and_deletes_the_partial(tmp_path: Path) -> None:
    dest = tmp_path / "member.py"
    source = _CountingStream(5 * 1024 * 1024)
    with pytest.raises(UnsafeArchiveError) as caught:
        copy_capped(source, dest, max_bytes=100_000)
    assert caught.value.public_message == TOO_LARGE
    assert not dest.exists()
    # One extra chunk past the cap is enough to notice the overflow.
    assert source.read_bytes <= 100_000 + 64 * 1024


def test_extract_streams_a_large_member(tmp_path: Path) -> None:
    archive_path = tmp_path / "big.zip"
    chunk = b"\0" * (1024 * 1024)
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
        info = zipfile.ZipInfo("big.py")
        with archive.open(info, "w") as member:
            for _ in range(32):
                member.write(chunk)
    limits = ArchiveLimits(max_uncompressed_bytes=64 * 1024 * 1024, max_file_count=10)
    tracemalloc.start()
    try:
        extracted, skipped = extract_zip(archive_path, tmp_path / "out", limits)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert (extracted, skipped) == (1, 0)
    assert (tmp_path / "out" / "big.py").stat().st_size == 32 * 1024 * 1024
    # A buffered extract of 32MB would peak well above this.
    assert peak < 8 * 1024 * 1024


def test_oversized_upload_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(UnsafeArchiveError) as caught:
        save_upload(io.BytesIO(b"abcdef"), tmp_path / "upload.zip", max_bytes=3)
    assert caught.value.public_message == TOO_LARGE
