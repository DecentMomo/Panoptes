import itertools

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
    merged, merges = dedupe(
        [
            _finding("semgrep", "semgrep-rule", "CWE-78"),
            _finding("bandit", "B602", "CWE-78"),
        ]
    )
    assert merges == 1
    assert len(merged) == 1
    assert merged[0].rule_id == "B602"
    assert merged[0].source_tools == ["bandit", "semgrep"]
    assert merged[0].severity == "high"
    assert merged[0].confidence == "high"


def test_merge_does_not_depend_on_input_order() -> None:
    forward, forward_merges = dedupe(
        [_finding("bandit", "B602", "CWE-78"), _finding("semgrep", "semgrep-rule", "CWE-78")]
    )
    backward, backward_merges = dedupe(
        [_finding("semgrep", "semgrep-rule", "CWE-78"), _finding("bandit", "B602", "CWE-78")]
    )
    assert (forward_merges, backward_merges) == (1, 1)
    assert forward[0].rule_id == backward[0].rule_id == "B602"
    assert forward[0].source_tools == backward[0].source_tools


def test_two_bandit_and_one_semgrep_keeps_the_unpaired_bandit() -> None:
    merged, merges = dedupe(
        [
            _finding("bandit", "B602", "CWE-78"),
            _finding("bandit", "B404", "CWE-78"),
            _finding("semgrep", "semgrep-rule", "CWE-78"),
        ]
    )
    assert merges == 1
    assert len(merged) == 2
    paired = [item for item in merged if item.source_tools == ["bandit", "semgrep"]]
    unpaired = [item for item in merged if item.source_tools != ["bandit", "semgrep"]]
    assert len(paired) == 1
    # B404 sorts before B602, so it is the one paired with the Semgrep finding.
    assert paired[0].rule_id == "B404"
    assert [item.rule_id for item in unpaired] == ["B602"]


def test_one_bandit_and_two_semgrep_keeps_the_unpaired_semgrep() -> None:
    merged, merges = dedupe(
        [
            _finding("bandit", "B602", "CWE-78"),
            _finding("semgrep", "b-rule", "CWE-78"),
            _finding("semgrep", "a-rule", "CWE-78"),
        ]
    )
    assert merges == 1
    assert len(merged) == 2
    paired = [item for item in merged if item.source_tools == ["bandit", "semgrep"]]
    unpaired = [item for item in merged if item.source_tool == "semgrep"]
    assert len(paired) == 1
    assert paired[0].rule_id == "B602"
    assert [item.rule_id for item in unpaired] == ["b-rule"]


def test_pairing_does_not_depend_on_input_order() -> None:
    findings = [
        _finding("bandit", "B602", "CWE-78"),
        _finding("bandit", "B404", "CWE-78"),
        _finding("semgrep", "semgrep-rule", "CWE-78"),
    ]
    seen = set()
    for ordering in itertools.permutations(findings):
        merged, merges = dedupe(list(ordering))
        assert merges == 1
        seen.add(tuple((item.rule_id, tuple(item.source_tools)) for item in merged))
    assert len(seen) == 1


def test_different_cwe_or_line_is_not_merged() -> None:
    merged, merges = dedupe(
        [_finding("bandit", "B602", "CWE-78"), _finding("semgrep", "s", "CWE-95")]
    )
    assert (merges, len(merged)) == (0, 2)
    merged, merges = dedupe(
        [_finding("bandit", "B602", "CWE-78"), _finding("semgrep", "s", "CWE-78", line=9)]
    )
    assert (merges, len(merged)) == (0, 2)


def test_gitleaks_is_never_merged() -> None:
    merged, merges = dedupe(
        [
            _finding("bandit", "B105", "CWE-798"),
            _finding("gitleaks", "generic-api-key", "CWE-798"),
        ]
    )
    assert merges == 0
    assert len(merged) == 2
    assert {item.source_tool for item in merged} == {"bandit", "gitleaks"}
