import json
import os
from pathlib import Path

from app.core.config import settings
from app.scanners.base import RawFinding, ToolResult, relative_path, run_tool

_version_cache: str | None = None


def version() -> str:
    global _version_cache
    if _version_cache:
        return _version_cache
    result = run_tool(["gitleaks", "version"], timeout=15)
    text = (result.stdout or result.stderr).strip().splitlines()
    if result.timed_out or result.exit_code != 0 or not text:
        return "unknown"
    _version_cache = text[0][:120]
    return _version_cache


def scan(root: Path, workdir: Path) -> tuple[ToolResult, list[RawFinding]]:
    report = workdir / "gitleaks.json"
    result = run_tool(
        [
            "gitleaks",
            "dir",
            str(root),
            "--redact",
            "--no-banner",
            "--exit-code",
            "0",
            "--report-format",
            "json",
            "--report-path",
            str(report),
            "--log-level",
            "warn",
        ],
        timeout=settings.gitleaks_timeout_seconds,
        env={"PATH": os.environ.get("PATH", "")},
    )
    try:
        if result.timed_out:
            return result, []
        if not report.is_file():
            return result, []
        try:
            findings = parse(report.read_text(encoding="utf-8"), root)
        except json.JSONDecodeError:
            failed = ToolResult(
                result.stdout, result.stderr, result.exit_code or 1, result.duration_ms, False
            )
            return failed, []
        # Exit 1 would mean "leaks found" if --exit-code 0 was ignored. The report is the result.
        return ToolResult("", "", 0, result.duration_ms, False), findings
    finally:
        report.unlink(missing_ok=True)


def parse(json_text: str, root: Path) -> list[RawFinding]:
    payload = json.loads(json_text or "[]")
    if isinstance(payload, dict):
        payload = payload.get("findings") or payload.get("results") or []
    findings: list[RawFinding] = []
    for item in payload:
        match = item.get("Match") or ""
        # Never keep a match the tool failed to redact.
        if "REDACTED" not in match:
            match = "REDACTED"
        line_start = int(item.get("StartLine") or 1)
        line_end = int(item.get("EndLine") or line_start)
        findings.append(
            RawFinding(
                rule_id=str(item.get("RuleID") or "gitleaks")[:80],
                title=str(item.get("Description") or "Hardcoded secret")[:300],
                description=str(item.get("Description") or ""),
                severity="high",
                confidence="high",
                file_path=relative_path(item.get("File") or "", root),
                line_start=line_start,
                line_end=line_end,
                cwe_id="CWE-798",
                source_tool="gitleaks",
                flagged_snippet=match[:120],
                code_snippet=match[:120],
                snippet_start_line=line_start,
                secret_start_column=_column(item.get("StartColumn")),
                secret_end_column=_column(item.get("EndColumn")),
            )
        )
    return findings


def _column(value: object) -> int | None:
    if isinstance(value, int) and value > 0:
        return value
    return None
