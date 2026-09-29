import ipaddress
import os
import re
import shutil
import socket
import stat
from pathlib import Path
from urllib.parse import urlsplit

from app.ingest.validators import is_allowed_extension
from app.ingest.zip_handler import (
    TOO_LARGE,
    TOO_MANY_FILES,
    UNSAFE_PATHS,
    ArchiveLimits,
    UnsafeArchiveError,
)
from app.scanners.base import ToolResult, run_tool

ALLOWED_HOSTS = {"github.com", "gitlab.com"}
MAX_URL_LENGTH = 255
_SEGMENT = re.compile(r"[A-Za-z0-9._-]+")

URL_NOT_ALLOWED = "That repository URL is not allowed."


class RepoUrlError(Exception):
    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class CloneError(Exception):
    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


def validate_repo_url(url: str) -> tuple[str, str]:
    """Return ``(url, host)`` or raise ``RepoUrlError``.

    The host comparison is the whole netloc, not a prefix. ``https://evil@github.com``
    and ``https://github.com@evil.com`` both fail it, as do ports and a trailing dot.
    """
    candidate = url.strip()
    if not candidate or len(candidate) > MAX_URL_LENGTH:
        raise RepoUrlError("url length")
    if "\\" in candidate or "%" in candidate:
        raise RepoUrlError("encoded or backslash")
    parts = urlsplit(candidate)
    if parts.scheme != "https":
        raise RepoUrlError(f"scheme {parts.scheme!r}")
    if parts.username is not None or parts.password is not None:
        raise RepoUrlError("userinfo")
    if parts.query or parts.fragment:
        raise RepoUrlError("query or fragment")
    if parts.netloc.lower() not in ALLOWED_HOSTS:
        raise RepoUrlError(f"netloc {parts.netloc!r}")
    _check_path(parts.path)
    return candidate, parts.netloc.lower()


def _check_path(path: str) -> None:
    trimmed = path[:-1] if path.endswith("/") else path
    if trimmed.endswith(".git"):
        trimmed = trimmed[: -len(".git")]
    segments = trimmed.split("/")
    # A path from urlsplit starts with "/", so the first piece is empty.
    if len(segments) < 2 or segments[0] != "":
        raise RepoUrlError("path")
    names = segments[1:]
    # owner/repo, plus up to two GitLab subgroup levels.
    if not 2 <= len(names) <= 4:
        raise RepoUrlError("path depth")
    for name in names:
        if name in {".", ".."} or _SEGMENT.fullmatch(name) is None:
            raise RepoUrlError(f"segment {name!r}")


def assert_public_host(host: str) -> None:
    """Reject the clone unless every address for ``host`` is a public unicast address.

    Git resolves the name again itself. The allowlist is what keeps that second
    lookup from becoming an open proxy; this check is the one the user sees.
    """
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise RepoUrlError(f"dns {exc}") from exc
    if not infos:
        raise RepoUrlError("dns returned nothing")
    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        if not _is_public(address):
            raise RepoUrlError(f"blocked {address}")


def _is_public(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
        or not address.is_global
    ):
        return False
    return True


def clone_args(url: str, dest: Path) -> list[str]:
    return [
        "git",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.https.allow=always",
        "-c",
        "http.followRedirects=false",
        "-c",
        "core.symlinks=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "credential.helper=",
        "clone",
        "--depth",
        "1",
        "--no-recurse-submodules",
        "--single-branch",
        "--",
        url,
        str(dest),
    ]


def clone_env(home: Path) -> dict[str, str]:
    """A small environment so the host's git config cannot turn a protection back on."""
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
    }


def clone_repository(url: str, dest: Path, home: Path, timeout: int) -> ToolResult:
    home.mkdir(parents=True, exist_ok=True)
    return run_tool(clone_args(url, dest), timeout=timeout, env=clone_env(home))


def sanitize_tree(root: Path, limits: ArchiveLimits) -> tuple[int, int]:
    """Drop VCS data, refuse symlinks, then apply the same limits as a zip extract.

    ``core.symlinks=false`` should already have stopped git creating links. A link
    here means that did not hold, and a scanner that followed it could read a file
    outside the scan directory into a finding.
    """
    git_dir = root / ".git"
    if git_dir.exists():
        shutil.rmtree(git_dir)

    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in list(dirnames) + list(filenames):
            path = Path(dirpath) / name
            if path.is_symlink() or stat.S_ISLNK(os.lstat(path).st_mode):
                raise UnsafeArchiveError(UNSAFE_PATHS, f"symlink {path}")
        for name in filenames:
            files.append(Path(dirpath) / name)

    if len(files) > limits.max_file_count:
        raise UnsafeArchiveError(TOO_MANY_FILES, f"{len(files)} files")
    total = sum(path.stat().st_size for path in files)
    if total > limits.max_uncompressed_bytes:
        raise UnsafeArchiveError(TOO_LARGE, f"tree size {total}")

    kept = 0
    skipped = 0
    for path in files:
        relative = path.relative_to(root).as_posix()
        if is_allowed_extension(relative):
            kept += 1
            continue
        path.unlink()
        skipped += 1
    return kept, skipped
