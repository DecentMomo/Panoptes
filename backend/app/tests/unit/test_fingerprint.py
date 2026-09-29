from app.normalize.fingerprint import assign_fingerprints, compute_fingerprint
from app.scanners.base import RawFinding


def _finding(path: str, rule: str, snippet: str, line: int) -> RawFinding:
    return RawFinding(
        rule_id=rule,
        title="t",
        description="d",
        severity="high",
        confidence="high",
        file_path=path,
        line_start=line,
        line_end=line,
        cwe_id=None,
        flagged_snippet=snippet,
    )


def test_fingerprint_ignores_line_shifts_and_whitespace() -> None:
    original = compute_fingerprint("pkg/app.py", "B307", "return eval(expr)", 0)
    shifted = compute_fingerprint("pkg/app.py", "B307", "return   eval(expr)", 0)
    assert original == shifted
    changed = compute_fingerprint("pkg/app.py", "B307", "return eval(other)", 0)
    assert original != changed


def test_occurrence_index_splits_identical_lines() -> None:
    findings = [
        _finding("calc.py", "B307", "eval(x)", 10),
        _finding("calc.py", "B307", "eval(x)", 4),
    ]
    assign_fingerprints(findings)
    by_line = {finding.line_start: finding.fingerprint for finding in findings}
    assert by_line[4] != by_line[10]
    # Order is by line, so the earlier copy is occurrence 0 and stays put if lines shift together.
    again = [
        _finding("calc.py", "B307", "  eval(x)", 20),
        _finding("calc.py", "B307", "eval(x)", 30),
    ]
    assign_fingerprints(again)
    assert again[0].fingerprint == by_line[4]
    assert again[1].fingerprint == by_line[10]
