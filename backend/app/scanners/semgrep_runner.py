import hashlib
import json
import logging
import os
from pathlib import Path

from app.core.config import settings
from app.normalize.cwe_map import normalize_cwe
from app.normalize.unified import map_confidence
from app.scanners.base import RawFinding, ToolResult, relative_path, run_tool

logger = logging.getLogger("panoptes")

_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
_version_cache: str | None = None


def version() -> str:
    global _version_cache
    if _version_cache:
        return _version_cache
    result = run_tool(
        ["semgrep", "--version"],
        timeout=20,
        env={
            "PATH": os.environ.get("PATH", ""),
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
        },
    )
    text = (result.stdout or result.stderr).strip().splitlines()
    if result.timed_out or result.exit_code != 0 or not text:
        return "unknown"
    _version_cache = f"{text[0][:80]} (rules {rules_digest()})"[:120]
    return _version_cache


def rules_digest() -> str:
    digest = hashlib.sha256()
    root = Path(settings.semgrep_rules_dir)
    found = False
    for name in ("security-audit.yml", "owasp-top-ten.yml"):
        path = root / name
        if not path.is_file():
            continue
        found = True
        digest.update(path.read_bytes())
    if not found:
        return "missing"
    return digest.hexdigest()[:12]


def scan(root: Path, workdir: Path | None = None) -> tuple[ToolResult, list[RawFinding]]:
    del workdir
    rules = Path(settings.semgrep_rules_dir)
    configs = [rules / "security-audit.yml", rules / "owasp-top-ten.yml"]
    if not all(path.is_file() for path in configs):
        return ToolResult("", "semgrep rules are not installed", 127, 0, False), []
    result = run_tool(
        [
            "semgrep",
            "scan",
            "--config",
            str(configs[0]),
            "--config",
            str(configs[1]),
            "--json",
            "--metrics=off",
            "--disable-version-check",
            "--quiet",
            str(root),
        ],
        timeout=settings.semgrep_timeout_seconds,
        env={
            "PATH": os.environ.get("PATH", ""),
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
        },
    )
    if result.timed_out:
        return result, []
    try:
        findings, duplicates_dropped = parse(result.stdout, root)
    except json.JSONDecodeError:
        if result.exit_code == 0:
            return result, []
        return ToolResult(
            result.stdout, result.stderr, result.exit_code or 1, result.duration_ms, False
        ), []
    if duplicates_dropped:
        logger.info("semgrep dropped %d exact duplicate results", duplicates_dropped)
    # Semgrep can exit 1 when it has findings. A parsed report is a finished scan.
    return ToolResult(
        result.stdout,
        result.stderr,
        0,
        result.duration_ms,
        False,
        duplicates_dropped,
    ), findings


def parse(json_text: str, root: Path) -> tuple[list[RawFinding], int]:
    """Parse a Semgrep JSON report, dropping exact duplicates.

    The two rulesets overlap, so the same rule can report the same line twice.
    The key is the full ``check_id``: two different rules may share the last
    segment of the id, and those are not duplicates.
    """
    payload = json.loads(json_text or "{}")
    findings: list[RawFinding] = []
    seen: set[tuple[str, str, int, int, int, int]] = set()
    duplicates_dropped = 0
    for item in payload.get("results", []):
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        start = item.get("start") or {}
        end = item.get("end") or {}
        line_start = int(start.get("line") or 1)
        line_end = int(end.get("line") or line_start)
        check_id = item.get("check_id") or "semgrep"
        key = (
            check_id,
            item.get("path") or "",
            line_start,
            int(start.get("col") or 1),
            line_end,
            int(end.get("col") or 1),
        )
        if key in seen:
            duplicates_dropped += 1
            continue
        seen.add(key)
        findings.append(
            RawFinding(
                rule_id=check_id.split(".")[-1][:80],
                title=(extra.get("message") or check_id)[:300],
                description=extra.get("message") or "",
                severity=_SEVERITY.get(str(extra.get("severity") or "").upper(), "info"),
                confidence=map_confidence(str(metadata.get("confidence") or "")),
                file_path=relative_path(item.get("path") or "", root),
                line_start=line_start,
                line_end=line_end,
                cwe_id=_first_cwe(metadata.get("cwe")),
                source_tool="semgrep",
            )
        )
    return findings, duplicates_dropped


def _first_cwe(value: object) -> str | None:
    if isinstance(value, list):
        value = value[0] if value else None
    if not isinstance(value, str):
        return None
    return normalize_cwe(value)
