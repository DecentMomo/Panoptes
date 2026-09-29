def map_severity(bandit_severity: str) -> str:
    return {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(bandit_severity.upper(), "info")


def map_confidence(bandit_confidence: str) -> str:
    return {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(bandit_confidence.upper(), "low")
