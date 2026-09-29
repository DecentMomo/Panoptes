import socket
import stat
from pathlib import Path

import pytest

from app.ingest.git_clone import (
    RepoUrlError,
    assert_public_host,
    clone_args,
    clone_env,
    sanitize_tree,
    validate_repo_url,
)
from app.ingest.zip_handler import (
    TOO_LARGE,
    TOO_MANY_FILES,
    UNSAFE_PATHS,
    ArchiveLimits,
    UnsafeArchiveError,
)

LIMITS = ArchiveLimits(max_uncompressed_bytes=1024 * 1024, max_file_count=10)


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/org/repo",
        "ssh://git@github.com/org/repo",
        "git@github.com:org/repo",
        "https://evil@github.com/org/repo",
        "https://github.com@evil.com/org/repo",
        "https://github.com.evil.com/org/repo",
        "https://github.com:8443/org/repo",
        "https://github.com./org/repo",
        "https://github.com/org/../repo",
        "https://github.com/org/%2e%2e/repo",
        "https://github.com/org/repo?token=1",
        "https://github.com/org/repo#frag",
        "https://github.com/" + ("a" * 300),
    ],
)
def test_rejected_urls(url: str) -> None:
    with pytest.raises(RepoUrlError):
        validate_repo_url(url)


def test_github_and_gitlab_urls_are_accepted() -> None:
    url, host = validate_repo_url("https://github.com/org/repo.git")
    assert url == "https://github.com/org/repo.git"
    assert host == "github.com"
    _, gitlab = validate_repo_url("https://gitlab.com/group/sub/repo/")
    assert gitlab == "gitlab.com"


def test_clone_command_is_hardened() -> None:
    args = clone_args("https://github.com/org/repo", Path("/tmp/scan/src"))
    assert args[:1] == ["git"]
    assert "protocol.allow=never" in args
    assert "protocol.https.allow=always" in args
    assert "http.followRedirects=false" in args
    assert "core.symlinks=false" in args
    assert "core.hooksPath=/dev/null" in args
    assert "credential.helper=" in args
    assert args[args.index("--") + 1 :] == [
        "https://github.com/org/repo",
        str(Path("/tmp/scan/src")),
    ]
    env = clone_env(Path("/tmp/scan/home"))
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert "HOME" in env and "PATH" in env


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:127.0.0.1",
    ],
)
def test_private_and_special_addresses_are_rejected(monkeypatch, address: str) -> None:
    def fake_getaddrinfo(*_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))]

    monkeypatch.setattr("app.ingest.git_clone.socket.getaddrinfo", fake_getaddrinfo)
    with pytest.raises(RepoUrlError):
        assert_public_host("github.com")


def test_a_private_address_among_public_ones_is_rejected(monkeypatch) -> None:
    def fake_getaddrinfo(*_args, **_kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 443)),
        ]

    monkeypatch.setattr("app.ingest.git_clone.socket.getaddrinfo", fake_getaddrinfo)
    with pytest.raises(RepoUrlError):
        assert_public_host("github.com")


def test_public_address_is_allowed(monkeypatch) -> None:
    def fake_getaddrinfo(*_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443))]

    monkeypatch.setattr("app.ingest.git_clone.socket.getaddrinfo", fake_getaddrinfo)
    assert_public_host("github.com")


def test_symlink_in_a_clone_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "src"
    root.mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_text("nope", encoding="utf-8")
    link = root / "link.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks are not available")
    with pytest.raises(UnsafeArchiveError) as caught:
        sanitize_tree(root, LIMITS)
    assert caught.value.public_message == UNSAFE_PATHS


def test_sanitize_drops_git_and_disallowed_files(tmp_path: Path) -> None:
    root = tmp_path / "src"
    (root / ".git").mkdir(parents=True)
    (root / ".git" / "config").write_text("secret", encoding="utf-8")
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")
    (root / "photo.png").write_text("nope", encoding="utf-8")
    kept, skipped = sanitize_tree(root, LIMITS)
    assert (kept, skipped) == (1, 1)
    assert not (root / ".git").exists()
    assert (root / "app.py").is_file()
    assert not (root / "photo.png").exists()


def test_sanitize_enforces_count_and_size(tmp_path: Path) -> None:
    root = tmp_path / "src"
    root.mkdir()
    for index in range(3):
        (root / f"f{index}.py").write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(UnsafeArchiveError) as caught:
        sanitize_tree(root, ArchiveLimits(max_uncompressed_bytes=1024, max_file_count=2))
    assert caught.value.public_message == TOO_MANY_FILES

    (root / "big.py").write_bytes(b"x" * 50)
    for path in root.glob("f*.py"):
        path.unlink()
    with pytest.raises(UnsafeArchiveError) as caught:
        sanitize_tree(root, ArchiveLimits(max_uncompressed_bytes=10, max_file_count=10))
    assert caught.value.public_message == TOO_LARGE
    assert stat.S_ISREG((root / "big.py").stat().st_mode)
