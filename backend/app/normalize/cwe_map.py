import re


def normalize_cwe(value: str | int | None) -> str | None:
    """Turn ``CWE-78: OS Command Injection``, ``cwe-78``, or ``78`` into ``CWE-78``."""
    if value is None:
        return None
    match = re.search(r"\d+", str(value))
    if match is None:
        return None
    return f"CWE-{int(match.group())}"
