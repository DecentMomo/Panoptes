import io
import stat
import zipfile
from pathlib import Path

import pytest

from app.ingest.zip_handler import (
    TOO_LARGE,
    TOO_MANY_FILES,
    UNSAFE_PATHS,
    ArchiveLimits,
    UnsafeArchiveError,
    extract_zip,
    read_capped,
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


def test_read_capped_counts_real_bytes() -> None:
    with pytest.raises(UnsafeArchiveError):
        read_capped(io.BytesIO(b"a" * 50), max_bytes=10)


def test_oversized_upload_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(UnsafeArchiveError) as caught:
        save_upload(io.BytesIO(b"abcdef"), tmp_path / "upload.zip", max_bytes=3)
    assert caught.value.public_message == TOO_LARGE
