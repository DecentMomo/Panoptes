import json
from pathlib import Path

from app.scanners.gitleaks_runner import parse

FIXTURE = Path(__file__).parents[1] / "fixtures" / "gitleaks_output.json"


def test_parser_keeps_only_redacted_text(tmp_path: Path) -> None:
    (tmp_path / "secrets.py").write_text("x = 1\n", encoding="utf-8")
    findings = parse(FIXTURE.read_text(encoding="utf-8"), tmp_path)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "generic-api-key"
    assert finding.cwe_id == "CWE-798"
    assert finding.code_snippet == 'api_key = "REDACTED"'
    assert "Secret" not in finding.code_snippet


def test_unredacted_match_is_not_stored(tmp_path: Path) -> None:
    payload = json.dumps(
        [
            {
                "RuleID": "generic-api-key",
                "Description": "Detected a Generic API Key",
                "StartLine": 1,
                "EndLine": 1,
                "Match": "api_key = raw-value-should-not-be-kept",
                "Secret": "raw-value-should-not-be-kept",
                "File": "secrets.py",
            }
        ]
    )
    finding = parse(payload, tmp_path)[0]
    assert finding.code_snippet == "REDACTED"
    assert "raw-value" not in finding.code_snippet
    assert "raw-value" not in finding.description
