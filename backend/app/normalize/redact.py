from app.normalize.fingerprint import normalize_path
from app.scanners.base import RawFinding


def apply_redaction(findings: list[RawFinding]) -> None:
    """Keep Gitleaks values redacted, and mask the same lines in other tools' snippets.

    Gitleaks is run with ``--redact``. Its snippet is that redacted match, not a
    window read back from the file. Another tool's window can still contain the
    raw secret, so those lines are masked too.
    """
    secrets = [finding for finding in findings if finding.source_tool == "gitleaks"]
    for finding in findings:
        if finding.source_tool == "gitleaks":
            redacted = _already_redacted(finding.code_snippet or finding.flagged_snippet)
            finding.code_snippet = redacted[:120]
            finding.flagged_snippet = finding.code_snippet
            finding.snippet_start_line = finding.line_start
            continue
        for secret in secrets:
            if normalize_path(secret.file_path) != normalize_path(finding.file_path):
                continue
            finding.flagged_snippet = _mask_window(
                finding.flagged_snippet, finding.line_start, secret
            )
            finding.code_snippet = _mask_window(
                finding.code_snippet, finding.snippet_start_line, secret
            )


def _already_redacted(text: str) -> str:
    if not text or "REDACTED" not in text:
        return "REDACTED"
    return text


def _mask_window(text: str, window_start: int, secret: RawFinding) -> str:
    if not text or window_start < 1:
        return text
    lines = text.split("\n")
    index = secret.line_start - window_start
    if index < 0 or index >= len(lines):
        return text
    lines[index] = _mask_line(lines[index], secret.secret_start_column, secret.secret_end_column)
    return "\n".join(lines)


def _mask_line(line: str, start_column: int | None, end_column: int | None) -> str:
    """Mask one span. Gitleaks columns are 1-based and the end column is exclusive.

    A span that does not sit inside the line is not trusted: the whole line goes.
    """
    if start_column is None or end_column is None:
        return "REDACTED"
    start = start_column - 1
    end = end_column - 1
    if start < 0 or end <= start or end > len(line):
        return "REDACTED"
    return f"{line[:start]}REDACTED{line[end:]}"
