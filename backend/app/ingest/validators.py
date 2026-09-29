from pathlib import Path

ALLOWED_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".cfg",
    ".env",
    ".txt",
    ".pem",
    ".key",
    ".crt",
    ".sh",
    ".bash",
    ".ps1",
    ".xml",
    ".properties",
    ".conf",
    ".tfvars",
    ".md",
}

# Names with no extension that still carry secrets or build instructions.
EXTENSIONLESS_NAMES = {"dockerfile", "makefile"}


class PathEscapeError(Exception):
    """A resolved path left the directory it was supposed to stay inside."""


def is_safe_member_name(name: str) -> bool:
    """Reject absolute paths and `..` segments (Zip Slip).

    Checked before anything is written. `assert_within` checks again after the
    path is joined, in case a later step builds a path differently.
    """
    if not name or "\x00" in name:
        return False
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
        return False
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    return all(part != ".." for part in parts)


def is_allowed_extension(name: str) -> bool:
    """Keep files a later scanner might flag, including secrets with odd names.

    `.env.local` is where real secrets live, and Gitleaks cannot find a secret
    in a file that was never extracted. A `.png` is still skipped.
    """
    filename = Path(name).name.lower()
    if filename.startswith(".env") or filename in EXTENSIONLESS_NAMES:
        return True
    return Path(filename).suffix in ALLOWED_EXTENSIONS


def assert_within(root: Path, path: Path) -> Path:
    """Resolve `path` and raise unless it is still inside `root`.

    `resolve` follows symlinks, so a link pointing outside the root fails too.
    """
    root_resolved = root.resolve()
    resolved = path.resolve()
    if not resolved.is_relative_to(root_resolved):
        raise PathEscapeError(f"{resolved} is outside {root_resolved}")
    return resolved
