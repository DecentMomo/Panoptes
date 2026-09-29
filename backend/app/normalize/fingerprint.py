import hashlib
from pathlib import Path

from app.scanners.base import RawFinding


def normalize_path(path: str) -> str:
    return Path(path).as_posix().removeprefix("./")


def normalize_snippet(snippet: str) -> str:
    """Drop all whitespace so reformatting does not look like a new finding."""
    return "".join(snippet.split())


def compute_fingerprint(path: str, rule_id: str, snippet: str, occurrence: int) -> str:
    """Line numbers are not part of the hash, so inserting an import does not move every finding.

    `occurrence` is the Nth identical snippet in the same file. Without it, two
    copies of `eval(x)` would collide and one would be dropped.
    """
    payload = f"{normalize_path(path)}\n{rule_id}\n{normalize_snippet(snippet)}\n{occurrence}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def assign_fingerprints(findings: list[RawFinding]) -> None:
    ordered = sorted(
        findings, key=lambda finding: (finding.file_path, finding.rule_id, finding.line_start)
    )
    seen: dict[tuple[str, str, str], int] = {}
    for finding in ordered:
        key = (
            normalize_path(finding.file_path),
            finding.rule_id,
            normalize_snippet(finding.flagged_snippet),
        )
        occurrence = seen.get(key, 0)
        seen[key] = occurrence + 1
        finding.fingerprint = compute_fingerprint(
            finding.file_path, finding.rule_id, finding.flagged_snippet, occurrence
        )
