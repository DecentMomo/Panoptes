import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.models.finding import Finding
from app.models.finding_status_history import FindingStatusHistory
from app.models.project import Project
from app.models.scan import Scan
from app.models.user import User
from app.tests.conftest import register_and_login


def _finding(session_factory, email: str = "ada@example.com") -> int:
    db = session_factory()
    user = db.scalar(select(User).where(User.email == email))
    project = Project(owner_id=user.id, name="Status")
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
    finding = Finding(
        scan_id=scan.id,
        fingerprint="c" * 64,
        source_tools=["bandit"],
        rule_id="B307",
        title="eval",
        description="eval",
        severity="medium",
        confidence="high",
        file_path="prompt_injection.py",
        line_start=1,
        line_end=1,
        code_snippet="eval(value)",
        snippet_start_line=1,
        cwe_id="CWE-95",
        status="open",
    )
    db.add(finding)
    db.commit()
    finding_id = finding.id
    db.close()
    return finding_id


def _history_count(session_factory, finding_id: int) -> int:
    db = session_factory()
    count = len(
        list(
            db.scalars(
                select(FindingStatusHistory).where(FindingStatusHistory.finding_id == finding_id)
            )
        )
    )
    db.close()
    return count


async def test_false_positive_requires_a_reason(client, session_factory) -> None:
    await register_and_login(client, "ada@example.com")
    finding_id = _finding(session_factory)
    for body in ({"status": "false_positive"}, {"status": "false_positive", "reason": "   "}):
        response = await client.patch(f"/findings/{finding_id}/status", json=body)
        assert response.status_code == 400
    assert (await client.get(f"/findings/{finding_id}")).json()["status"] == "open"
    assert _history_count(session_factory, finding_id) == 0


async def test_each_transition_is_recorded(client, session_factory) -> None:
    logged_in = await register_and_login(client, "ada@example.com")
    user_id = logged_in.json()["id"]
    finding_id = _finding(session_factory)
    changed = await client.patch(
        f"/findings/{finding_id}/status",
        json={"status": "false_positive", "reason": "test fixture"},
    )
    assert changed.status_code == 200
    assert changed.json()["status"] == "false_positive"
    assert changed.json()["status_reason"] == "test fixture"
    history = (await client.get(f"/findings/{finding_id}/history")).json()
    assert len(history) == 1
    assert history[0]["user_id"] == user_id
    assert history[0]["from_status"] == "open"
    assert history[0]["to_status"] == "false_positive"
    assert history[0]["created_at"]

    same = await client.patch(
        f"/findings/{finding_id}/status",
        json={"status": "false_positive", "reason": "again"},
    )
    assert same.status_code == 400
    assert _history_count(session_factory, finding_id) == 1


async def test_database_rejects_a_reasonless_false_positive(client, session_factory) -> None:
    await register_and_login(client, "ada@example.com")
    finding_id = _finding(session_factory)
    db = session_factory()
    user = db.scalar(select(User).where(User.email == "ada@example.com"))
    db.add(
        FindingStatusHistory(
            finding_id=finding_id,
            user_id=user.id,
            from_status="open",
            to_status="false_positive",
            reason="   ",
        )
    )
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()
    finding = db.get(Finding, finding_id)
    finding.status = "suppressed"
    with pytest.raises(IntegrityError):
        db.commit()
    db.close()


async def test_another_user_cannot_change_status(clients, session_factory) -> None:
    alice = clients()
    bob = clients()
    await register_and_login(alice, "alice@example.com")
    await register_and_login(bob, "bob@example.com")
    finding_id = _finding(session_factory, "alice@example.com")
    changed = await alice.patch(
        f"/findings/{finding_id}/status",
        json={"status": "fixed"},
    )
    assert changed.status_code == 200
    stolen = await bob.patch(
        f"/findings/{finding_id}/status",
        json={"status": "false_positive", "reason": "hide it"},
    )
    assert stolen.status_code == 404
    assert (await bob.get(f"/findings/{finding_id}/history")).status_code == 404
    assert (await alice.get(f"/findings/{finding_id}")).json()["status"] == "fixed"
    history = (await alice.get(f"/findings/{finding_id}/history")).json()
    assert [item["to_status"] for item in history] == ["fixed"]
