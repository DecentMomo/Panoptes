import json
from pathlib import Path

from app.scanners.bandit_runner import parse

FIXTURE = Path(__file__).parents[1] / "fixtures" / "bandit_output.json"


def test_parser_maps_bandit_json(tmp_path: Path) -> None:
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    for item in raw["results"]:
        filename = Path(item["filename"]).name
        (tmp_path / filename).write_text("x = 1\n", encoding="utf-8")
    findings = parse(FIXTURE.read_text(encoding="utf-8"), tmp_path)

    by_rule = {finding.rule_id: finding for finding in findings}
    assert "B602" in by_rule
    shell = by_rule["B602"]
    assert shell.severity == "high"
    assert shell.confidence == "high"
    assert shell.cwe_id == "CWE-78"
    assert shell.file_path == "command.py"
    assert "/" not in shell.file_path and "\\" not in shell.file_path
    assert "B307" in by_rule
    assert by_rule["B307"].severity == "medium"
