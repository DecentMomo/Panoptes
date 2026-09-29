import json
import re
import sys
from pathlib import Path

from app.core.config import settings
from app.normalize.unified import map_confidence, map_severity
from app.scanners.base import RawFinding, ToolResult, relative_path, run_tool

_version_cache: str | None = None


def version() -> str:
    global _version_cache
    if _version_cache:
        return _version_cache
    result = run_tool([sys.executable, "-m", "bandit", "--version"], timeout=15)
    text = (result.stdout or result.stderr).strip().splitlines()
    if result.timed_out or result.exit_code != 0 or not text:
        return "unknown"
    # ``python -m bandit --version`` prints ``__main__.py 1.9.4``. Keep the number.
    match = re.search(r"\d+\.\d+(?:\.\d+)?", text[0])
    _version_cache = f"bandit {match.group(0)}" if match else text[0][:120]
    return _version_cache


def scan(root: Path, workdir: Path | None = None) -> tuple[ToolResult, list[RawFinding]]:
    del workdir
    # --exit-zero: Bandit exits 1 when it finds issues. A nonzero code is then a real failure.
    result = run_tool(
        [
            sys.executable,
            "-m",
            "bandit",
            "-r",
            str(root),
            "-f",
            "json",
            "--exit-zero",
            "-q",
        ],
        timeout=settings.bandit_timeout_seconds,
    )
    if result.timed_out or result.exit_code != 0:
        return result, []
    try:
        return result, parse(result.stdout, root)
    except json.JSONDecodeError:
        return ToolResult(result.stdout, result.stderr, 1, result.duration_ms, False), []


def parse(json_text: str, root: Path) -> list[RawFinding]:
    payload = json.loads(json_text or "{}")
    findings: list[RawFinding] = []
    for item in payload.get("results", []):
        line_range = item.get("line_range") or [item.get("line_number") or 1]
        line_start = min(line_range)
        line_end = max(line_range)
        cwe = item.get("issue_cwe") or {}
        cwe_id = f"CWE-{cwe['id']}" if cwe.get("id") else None
        findings.append(
            RawFinding(
                rule_id=item.get("test_id") or "bandit",
                title=(item.get("test_name") or "bandit finding").replace("_", " "),
                description=item.get("issue_text") or "",
                severity=map_severity(item.get("issue_severity") or ""),
                confidence=map_confidence(item.get("issue_confidence") or ""),
                file_path=relative_path(item.get("filename") or "", root),
                line_start=line_start,
                line_end=line_end,
                cwe_id=cwe_id,
                source_tool="bandit",
            )
        )
    return findings
