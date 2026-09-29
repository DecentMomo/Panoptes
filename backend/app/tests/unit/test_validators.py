import os

import pytest

from app.ingest.validators import (
    PathEscapeError,
    assert_within,
    is_allowed_extension,
    is_safe_member_name,
)


def test_safe_and_unsafe_member_names() -> None:
    assert is_safe_member_name("pkg/app.py")
    assert not is_safe_member_name("../etc/passwd")
    assert not is_safe_member_name("foo/../../etc/passwd")
    assert not is_safe_member_name("/etc/passwd")
    assert not is_safe_member_name("C:/Windows/app.py")
    assert not is_safe_member_name("ok.py\x00.txt")


def test_extension_allowlist() -> None:
    assert is_allowed_extension("src/app.py")
    assert is_allowed_extension(".env")
    assert is_allowed_extension("config/.env.local")
    assert is_allowed_extension(".env.production")
    assert is_allowed_extension("keys/id_rsa.pem")
    assert is_allowed_extension("deploy/app.key")
    assert is_allowed_extension("Dockerfile")
    assert is_allowed_extension("services/Makefile")
    assert is_allowed_extension("README.md")
    assert is_allowed_extension("notes/infra.tfvars")
    assert not is_allowed_extension("photo.png")
    assert not is_allowed_extension("Dockerfile.prod")


def test_assert_within_rejects_parent_segments(tmp_path) -> None:
    root = tmp_path / "scan"
    root.mkdir()
    with pytest.raises(PathEscapeError):
        assert_within(root, root / ".." / "outside.py")


def test_assert_within_rejects_symlink_escape(tmp_path) -> None:
    root = tmp_path / "scan"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("x", encoding="utf-8")
    link = root / "link.py"
    try:
        os.symlink(outside, link)
    except OSError:
        pytest.skip("symlinks are not available")
    with pytest.raises(PathEscapeError):
        assert_within(root, link)
