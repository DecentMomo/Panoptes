import json
import sys
from dataclasses import dataclass
from pathlib import Path

from app.core.config import settings
from app.normalize.unified import map_confidence, map_severity
from app.scanners.base import ToolResult, run_tool


@dataclass
class RawFinding:
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: str
    file_path: str
    line_start: int
    line_end: int
    cwe_id: str | None
    source_tool: str = "bandit"
    flagged_snippet: str = ""
    code_snippet: str = ""
    snippet_start_line: int = 1
    fingerprint: str = ""


def scan(root: Path) -> tuple[ToolResult, list[RawFinding]]:
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
    return result, parse(result.stdout, root)


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
                file_path=_relative_path(item.get("filename") or "", root),
                line_start=line_start,
                line_end=line_end,
                cwe_id=cwe_id,
            )
        )
    return findings


def _relative_path(filename: str, root: Path) -> str:
    path = Path(filename)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        if not path.is_absolute():
            return path.as_posix().removeprefix("./")
        return path.name
