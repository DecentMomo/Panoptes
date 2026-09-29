import json
from pathlib import Path

from app.scanners.semgrep_runner import parse

FIXTURE = Path(__file__).parents[1] / "fixtures" / "semgrep_output.json"


def test_parser_uses_cwe_and_ignores_owasp_metadata(tmp_path: Path) -> None:
    (tmp_path / "command.py").write_text("x = 1\n", encoding="utf-8")
    findings = parse(FIXTURE.read_text(encoding="utf-8"), tmp_path)
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
