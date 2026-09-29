from app.normalize.dedupe import dedupe
from app.scanners.base import RawFinding


def _finding(tool: str, rule: str, cwe: str | None, line: int = 4) -> RawFinding:
    return RawFinding(
        rule_id=rule,
        title=rule,
        description=tool,
        severity="medium" if tool == "bandit" else "high",
        confidence="low" if tool == "bandit" else "high",
        file_path="pkg/command.py",
        line_start=line,
        line_end=line,
        cwe_id=cwe,
        source_tool=tool,
        flagged_snippet="call()",
    )


def test_same_file_line_and_cwe_merges_bandit_and_semgrep() -> None:
    merged = dedupe(
        [
            _finding("semgrep", "semgrep-rule", "CWE-78"),
            _finding("bandit", "B602", "CWE-78"),
        ]
    )
    assert len(merged) == 1
    assert merged[0].rule_id == "B602"
    assert merged[0].source_tools == ["bandit", "semgrep"]
    assert merged[0].severity == "high"
    assert merged[0].confidence == "high"


def test_merge_does_not_depend_on_input_order() -> None:
    forward = dedupe(
        [_finding("bandit", "B602", "CWE-78"), _finding("semgrep", "semgrep-rule", "CWE-78")]
    )
    backward = dedupe(
        [_finding("semgrep", "semgrep-rule", "CWE-78"), _finding("bandit", "B602", "CWE-78")]
    )
    assert forward[0].rule_id == backward[0].rule_id == "B602"
    assert forward[0].source_tools == backward[0].source_tools


def test_different_cwe_or_line_is_not_merged() -> None:
    assert (
        len(dedupe([_finding("bandit", "B602", "CWE-78"), _finding("semgrep", "s", "CWE-95")])) == 2
    )
    assert (
        len(
            dedupe(
                [_finding("bandit", "B602", "CWE-78"), _finding("semgrep", "s", "CWE-78", line=9)]
            )
        )
        == 2
    )


def test_gitleaks_is_never_merged() -> None:
    findings = dedupe(
        [
            _finding("bandit", "B105", "CWE-798"),
            _finding("gitleaks", "generic-api-key", "CWE-798"),
        ]
    )
    assert len(findings) == 2
    assert {item.source_tool for item in findings} == {"bandit", "gitleaks"}
