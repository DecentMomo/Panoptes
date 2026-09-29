from app.normalize.redact import apply_redaction
from app.scanners.base import RawFinding


def test_other_tools_lose_the_secret_span() -> None:
    line = 'api_key = "super-secret-value"'
    start = line.index("super-secret-value") + 1
    end = start + len("super-secret-value")
    bandit = RawFinding(
        rule_id="B105",
        title="password",
        description="hardcoded",
        severity="low",
        confidence="low",
        file_path="secrets.py",
        line_start=2,
        line_end=2,
        cwe_id="CWE-259",
        source_tool="bandit",
        flagged_snippet=line,
        code_snippet=line,
        snippet_start_line=2,
    )
    gitleaks = RawFinding(
        rule_id="generic-api-key",
        title="key",
        description="Detected a Generic API Key",
        severity="high",
        confidence="high",
        file_path="secrets.py",
        line_start=2,
        line_end=2,
        cwe_id="CWE-798",
        source_tool="gitleaks",
        code_snippet="api_key = REDACTED",
        flagged_snippet="api_key = REDACTED",
        secret_start_column=start,
        secret_end_column=end,
    )
    apply_redaction([bandit, gitleaks])
    assert "super-secret-value" not in bandit.code_snippet
    assert "super-secret-value" not in bandit.flagged_snippet
    assert bandit.code_snippet.startswith('api_key = "')
    assert "REDACTED" in bandit.code_snippet
    assert gitleaks.code_snippet == "api_key = REDACTED"


def test_captured_gitleaks_columns_hide_the_sample_key() -> None:
    # Columns taken from a real Gitleaks 8.30.1 report of secrets.py (end exclusive).
    line = 'api_key = "a8f3c1e9b7d2046f5c8e1a9b3d7f0c2e4a6b8d1f"'
    bandit = RawFinding(
        rule_id="B105",
        title="password",
        description="hardcoded",
        severity="low",
        confidence="low",
        file_path="secrets.py",
        line_start=2,
        line_end=2,
        cwe_id="CWE-259",
        source_tool="bandit",
        flagged_snippet=line,
        code_snippet=line,
        snippet_start_line=2,
    )
    gitleaks = RawFinding(
        rule_id="generic-api-key",
        title="key",
        description="Detected a Generic API Key",
        severity="high",
        confidence="high",
        file_path="secrets.py",
        line_start=2,
        line_end=2,
        cwe_id="CWE-798",
        source_tool="gitleaks",
        code_snippet='api_key = "REDACTED"',
        flagged_snippet='api_key = "REDACTED"',
        secret_start_column=2,
        secret_end_column=53,
    )
    apply_redaction([bandit, gitleaks])
    assert "a8f3c1e9" not in bandit.code_snippet
    assert "REDACTED" in bandit.code_snippet
