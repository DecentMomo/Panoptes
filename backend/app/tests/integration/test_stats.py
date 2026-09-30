from sqlalchemy import select

from app.models.ai_explanation import AIExplanation
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.models.user import User
from app.tests.conftest import register_and_login


def _seed_scan(session_factory, email: str, severity: str, status: str, fingerprint: str) -> None:
    db = session_factory()
    user = db.scalar(select(User).where(User.email == email))
    project = Project(owner_id=user.id, name=email)
    db.add(project)
    db.flush()
    scan = Scan(
        project_id=project.id,
        status="completed",
        source_type="zip",
        source_name="sample.zip",
        files_scanned=1,
        files_skipped=0,
    )
    db.add(scan)
    db.flush()
    db.add(
        Finding(
            scan_id=scan.id,
            fingerprint=fingerprint,
            source_tools=["bandit"],
            rule_id="B307",
            title="eval",
            description="eval",
            severity=severity,
            confidence="high",
            file_path="calc.py",
            line_start=1,
            line_end=1,
            code_snippet="eval(value)",
            snippet_start_line=1,
            cwe_id="CWE-95",
            status=status,
        )
    )
    db.add(
        AIExplanation(
            fingerprint=fingerprint,
            model_name="qwen2.5-coder:7b",
            prompt_version="v2",
            status="completed",
            latency_ms=60_000,
            prompt_tokens=10,
            completion_tokens=10,
            plain_explanation="text",
            why_it_matters="text",
            fixed_code="safe()",
            fix_rationale="safer",
            ai_confidence="high",
        )
    )
    db.commit()
    db.close()


async def test_stats_are_scoped_to_the_current_user(clients, session_factory) -> None:
    alice = clients()
    bob = clients()
    await register_and_login(alice, "alice@example.com")
    await register_and_login(bob, "bob@example.com")
    _seed_scan(session_factory, "alice@example.com", "high", "open", "a" * 64)
    _seed_scan(session_factory, "bob@example.com", "low", "false_positive", "b" * 64)

    alice_stats = (await alice.get("/stats")).json()
    bob_stats = (await bob.get("/stats")).json()
    assert alice_stats["project_count"] == 1
    assert alice_stats["scan_count"] == 1
    assert alice_stats["open_by_severity"] == {"high": 1}
    assert alice_stats["suppressed_count"] == 0
    assert alice_stats["explanations_completed"] == 1
    assert alice_stats["avg_latency_ms"] == 60000

    assert bob_stats["open_by_severity"] == {}
    assert bob_stats["suppressed_count"] == 1
    assert bob_stats["explanations_completed"] == 1
    assert bob_stats["avg_latency_ms"] == 60000
    assert alice_stats["open_by_severity"] != bob_stats["open_by_severity"]
