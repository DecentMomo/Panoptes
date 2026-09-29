import json
from pathlib import Path

from app.scanners.semgrep_runner import parse

FIXTURE = Path(__file__).parents[1] / "fixtures" / "semgrep_output.json"


def test_parser_uses_cwe_and_ignores_owasp_metadata(tmp_path: Path) -> None:
    (tmp_path / "command.py").write_text("x = 1\n", encoding="utf-8")
    findings, duplicates_dropped = parse(FIXTURE.read_text(encoding="utf-8"), tmp_path)
    assert duplicates_dropped == 0
    assert len(findings) == 1
    finding = findings[0]
    assert finding.source_tool == "semgrep"
    assert finding.severity == "high"
    assert finding.cwe_id == "CWE-78"
    assert finding.file_path == "command.py"
    assert finding.owasp_category is None
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    labels = payload["results"][0]["extra"]["metadata"]["owasp"]
    assert any("2021" in label for label in labels)


def _result(check_id: str, path: str = "command.py", line: int = 5, col: int = 1) -> dict:
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line, "col": col},
        "end": {"line": line, "col": col + 9},
        "extra": {
            "message": "dangerous call",
            "severity": "ERROR",
            "metadata": {"cwe": ["CWE-78"], "confidence": "HIGH"},
        },
    }


def test_exact_duplicate_results_are_dropped_once(tmp_path: Path) -> None:
    (tmp_path / "command.py").write_text("x = 1\n", encoding="utf-8")
    payload = {
        "results": [
            _result("python.lang.security.audit.dangerous-system-call"),
            _result("python.lang.security.audit.dangerous-system-call"),
            # Same rule and line, different expression: not a duplicate.
            _result("python.lang.security.audit.dangerous-system-call", col=20),
            # Same last segment, different rule: not a duplicate.
            _result("other.ruleset.dangerous-system-call"),
        ]
    }
    findings, duplicates_dropped = parse(json.dumps(payload), tmp_path)
    assert duplicates_dropped == 1
    assert len(findings) == 3
    assert {finding.rule_id for finding in findings} == {"dangerous-system-call"}
