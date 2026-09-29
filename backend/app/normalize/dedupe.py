from app.normalize.fingerprint import normalize_path
from app.scanners.base import RawFinding

# Bandit wins the rule id and the title. Severity and confidence take the worse of the two.
_PRIORITY = {"bandit": 0, "semgrep": 1}
_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def dedupe(findings: list[RawFinding]) -> list[RawFinding]:
    """Merge Bandit and Semgrep when they share a file, a line, and a CWE.

    Gitleaks is never merged. Two findings from the same tool are not merged.
    A missing CWE is not a reason to guess that two findings are the same issue.
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

    for group in groups.values():
        tools = {item.source_tool for item in group}
        if tools == {"bandit", "semgrep"}:
            kept.append(_merge(group))
        else:
            kept.extend(group)
    return kept


def _merge(group: list[RawFinding]) -> RawFinding:
    primary = min(group, key=lambda item: _PRIORITY[item.source_tool])
    primary.source_tools = sorted({item.source_tool for item in group})
    primary.severity = max(group, key=lambda item: _RANK.get(item.severity, 0)).severity
    primary.confidence = max(group, key=lambda item: _RANK.get(item.confidence, 0)).confidence
    return primary
