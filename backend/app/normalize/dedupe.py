from app.normalize.fingerprint import normalize_path
from app.scanners.base import RawFinding

# Bandit wins the rule id and the title. Severity and confidence take the worse of the two.
_PRIORITY = {"bandit": 0, "semgrep": 1}
_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def dedupe(findings: list[RawFinding]) -> tuple[list[RawFinding], int]:
    """Merge Bandit and Semgrep when they share a file, a line, and a CWE.

    At most one Bandit finding merges with at most one Semgrep finding: pairs
    inside a (file, line, CWE) group are matched deterministically, and every
    finding left without a partner is kept. Gitleaks is never merged. Two
    findings from the same tool are not merged. A missing CWE is not a reason
    to guess that two findings are the same issue.

    Returns the kept findings and the number of pairs merged.
    """
    groups: dict[tuple[str, int, str], list[RawFinding]] = {}
    kept: list[RawFinding] = []
    for finding in findings:
        if finding.source_tool == "gitleaks" or not finding.cwe_id:
            kept.append(finding)
            continue
        if finding.source_tool not in _PRIORITY:
            kept.append(finding)
            continue
        key = (normalize_path(finding.file_path), finding.line_start, finding.cwe_id)
        groups.setdefault(key, []).append(finding)

    merges = 0
    for group in groups.values():
        bandit = sorted((item for item in group if item.source_tool == "bandit"), key=_sort_key)
        semgrep = sorted((item for item in group if item.source_tool == "semgrep"), key=_sort_key)
        for bandit_finding, semgrep_finding in zip(bandit, semgrep, strict=False):
            kept.append(_merge_pair(bandit_finding, semgrep_finding))
            merges += 1
        kept.extend(bandit[len(semgrep) :])
        kept.extend(semgrep[len(bandit) :])
    return kept, merges


def _sort_key(item: RawFinding) -> tuple[str, int, str]:
    return (item.rule_id, item.line_end, item.title)


def _merge_pair(bandit_finding: RawFinding, semgrep_finding: RawFinding) -> RawFinding:
    pair = (bandit_finding, semgrep_finding)
    bandit_finding.source_tools = sorted({item.source_tool for item in pair})
    bandit_finding.severity = max(pair, key=lambda item: _RANK.get(item.severity, 0)).severity
    bandit_finding.confidence = max(pair, key=lambda item: _RANK.get(item.confidence, 0)).confidence
    return bandit_finding
