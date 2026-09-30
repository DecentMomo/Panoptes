import logging
import shutil
from pathlib import Path

import pytest

from app.scanners.base import RawFinding, ToolResult
from app.tests.conftest import register_and_login
from app.tests.scan_helpers import empty_scanner as _empty
from app.tests.scan_helpers import sample_zip as _sample_zip
from app.tests.scan_helpers import stub_other_scanners as _stub_other_scanners


async def test_upload_scans_the_sample(client, session_factory, monkeypatch, tmp_path) -> None:
    del session_factory
    monkeypatch.setattr("app.services.scan_orchestrator.work_root", lambda: tmp_path)
    monkeypatch.setattr("app.api.scans.scan_directory", lambda scan_id: tmp_path / str(scan_id))
    _stub_other_scanners(monkeypatch)

    await register_and_login(client, "ada@example.com")
    created = await client.post("/projects", json={"name": "Sample"})
    project_id = created.json()["id"]
    archive = tmp_path / "sample.zip"
    _sample_zip(archive)

    response = await client.post(
        f"/projects/{project_id}/scans",
        files={"file": ("sample.zip", archive.read_bytes(), "application/zip")},
    )
    assert response.status_code == 202, response.text
    scan_id = response.json()["id"]

    detail = await client.get(f"/scans/{scan_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["status"] == "completed"
    assert body["scanner_runs"][0]["tool"] == "bandit"
    assert body["scanner_runs"][0]["status"] == "completed"
    assert body["severity_counts"]
    findings = await client.get(f"/scans/{scan_id}/findings")
    rules = {item["rule_id"] for item in findings.json()}
    assert "B602" in rules
    assert "B307" in rules
    assert not (tmp_path / str(scan_id)).exists()


async def test_bandit_timeout_leaves_a_partial_scan(
    client, session_factory, monkeypatch, tmp_path
) -> None:
    del session_factory
    monkeypatch.setattr("app.services.scan_orchestrator.work_root", lambda: tmp_path)
    monkeypatch.setattr("app.api.scans.scan_directory", lambda scan_id: tmp_path / str(scan_id))
    _stub_other_scanners(monkeypatch)

    def timed_out(root, workdir):
        return ToolResult("", "timed out", -1, 50, True), []

    monkeypatch.setattr("app.services.scan_orchestrator.run_bandit", timed_out)

    await register_and_login(client, "ada@example.com")
    created = await client.post("/projects", json={"name": "Sample"})
    archive = tmp_path / "sample.zip"
    _sample_zip(archive)
    response = await client.post(
        f"/projects/{created.json()['id']}/scans",
        files={"file": ("sample.zip", archive.read_bytes(), "application/zip")},
    )
    scan_id = response.json()["id"]

    detail = (await client.get(f"/scans/{scan_id}")).json()
    assert detail["status"] == "partial"
    by_tool = {run["tool"]: run for run in detail["scanner_runs"]}
    assert by_tool["bandit"]["status"] == "timeout"
    assert by_tool["semgrep"]["status"] == "completed"
    assert detail["error_message"] is None


async def test_every_scanner_failing_fails_the_scan(client, monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("app.services.scan_orchestrator.work_root", lambda: tmp_path)
    monkeypatch.setattr("app.api.scans.scan_directory", lambda scan_id: tmp_path / str(scan_id))

    def broken(root, workdir):
        return ToolResult("", "nope", 1, 1, False), []

    monkeypatch.setattr("app.services.scan_orchestrator.run_bandit", broken)
    monkeypatch.setattr("app.services.scan_orchestrator.run_semgrep", broken)
    monkeypatch.setattr("app.services.scan_orchestrator.run_gitleaks", broken)
    await register_and_login(client, "ada@example.com")
    created = await client.post("/projects", json={"name": "Sample"})
    archive = tmp_path / "sample.zip"
    _sample_zip(archive)
    response = await client.post(
        f"/projects/{created.json()['id']}/scans",
        files={"file": ("sample.zip", archive.read_bytes(), "application/zip")},
    )
    detail = (await client.get(f"/scans/{response.json()['id']}")).json()
    assert detail["status"] == "failed"
    assert detail["error_message"] == "Scan failed."
    assert {run["status"] for run in detail["scanner_runs"]} == {"failed"}


async def test_a_full_queue_returns_429(client, session_factory, monkeypatch, tmp_path) -> None:
    from app.models.scan import Scan

    monkeypatch.setattr("app.api.scans.settings.max_queued_scans", 1)
    await register_and_login(client, "ada@example.com")
    created = await client.post("/projects", json={"name": "Sample"})
    session = session_factory()
    session.add(
        Scan(
            project_id=created.json()["id"],
            status="queued",
            source_type="zip",
            source_name="waiting.zip",
            files_scanned=0,
            files_skipped=0,
        )
    )
    session.commit()
    session.close()
    archive = tmp_path / "sample.zip"
    _sample_zip(archive)
    response = await client.post(
        f"/projects/{created.json()['id']}/scans",
        files={"file": ("sample.zip", archive.read_bytes(), "application/zip")},
    )
    assert response.status_code == 429


async def test_git_url_with_userinfo_is_rejected(client) -> None:
    await register_and_login(client, "ada@example.com")
    created = await client.post("/projects", json={"name": "Sample"})
    response = await client.post(
        f"/projects/{created.json()['id']}/scans/git",
        json={"url": "https://evil@github.com/org/repo"},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "That repository URL is not allowed."


def _raw(tool: str, rule: str) -> RawFinding:
    return RawFinding(
        rule_id=rule,
        title=rule,
        description=tool,
        severity="medium",
        confidence="low",
        file_path="pkg/command.py",
        line_start=4,
        line_end=4,
        cwe_id="CWE-78",
        source_tool=tool,
        flagged_snippet="call()",
    )


async def test_finding_arithmetic_is_logged_and_nothing_is_lost(
    client, monkeypatch, tmp_path, caplog
) -> None:
    monkeypatch.setattr("app.services.scan_orchestrator.work_root", lambda: tmp_path)
    monkeypatch.setattr("app.api.scans.scan_directory", lambda scan_id: tmp_path / str(scan_id))

    def bandit_two(root, workdir):
        return ToolResult("", "", 0, 1, False), [_raw("bandit", "B404"), _raw("bandit", "B602")]

    def semgrep_with_duplicate(root, workdir):
        return ToolResult("", "", 0, 1, False, duplicates_dropped=1), [_raw("semgrep", "sg-rule")]

    monkeypatch.setattr("app.services.scan_orchestrator.run_bandit", bandit_two)
    monkeypatch.setattr("app.services.scan_orchestrator.run_semgrep", semgrep_with_duplicate)
    monkeypatch.setattr("app.services.scan_orchestrator.run_gitleaks", _empty)

    await register_and_login(client, "ada@example.com")
    created = await client.post("/projects", json={"name": "Sample"})
    archive = tmp_path / "sample.zip"
    _sample_zip(archive)
    with caplog.at_level(logging.INFO, logger="panoptes"):
        response = await client.post(
            f"/projects/{created.json()['id']}/scans",
            files={"file": ("sample.zip", archive.read_bytes(), "application/zip")},
        )
    scan_id = response.json()["id"]
    detail = (await client.get(f"/scans/{scan_id}")).json()
    assert detail["status"] == "completed"
    # raw 4 (2 bandit + 1 semgrep + 1 duplicate) - 1 duplicate - 1 merge = 2 stored.
    findings = (await client.get(f"/scans/{scan_id}/findings")).json()
    assert len(findings) == 2
    assert sorted(len(item["source_tools"]) for item in findings) == [1, 2]
    by_tool = {run["tool"]: run for run in detail["scanner_runs"]}
    assert by_tool["semgrep"]["finding_count"] == 1
    assert any(
        "raw=4 duplicates=1 merged=1 stored=2" in record.message for record in caplog.records
    )


async def test_a_silent_finding_loss_fails_the_scan(client, monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("app.services.scan_orchestrator.work_root", lambda: tmp_path)
    monkeypatch.setattr("app.api.scans.scan_directory", lambda scan_id: tmp_path / str(scan_id))

    def bandit_two(root, workdir):
        return ToolResult("", "", 0, 1, False), [_raw("bandit", "B404"), _raw("bandit", "B602")]

    monkeypatch.setattr("app.services.scan_orchestrator.run_bandit", bandit_two)
    monkeypatch.setattr("app.services.scan_orchestrator.run_semgrep", _empty)
    monkeypatch.setattr("app.services.scan_orchestrator.run_gitleaks", _empty)
    # A dedupe that drops a finding without counting it must not pass silently.
    monkeypatch.setattr("app.services.scan_orchestrator.dedupe", lambda findings: (findings[1:], 0))

    await register_and_login(client, "ada@example.com")
    created = await client.post("/projects", json={"name": "Sample"})
    archive = tmp_path / "sample.zip"
    _sample_zip(archive)
    response = await client.post(
        f"/projects/{created.json()['id']}/scans",
        files={"file": ("sample.zip", archive.read_bytes(), "application/zip")},
    )
    detail = (await client.get(f"/scans/{response.json()['id']}")).json()
    assert detail["status"] == "failed"
    assert detail["error_message"] == "Scan failed."


@pytest.mark.skipif(
    shutil.which("semgrep") is None or shutil.which("gitleaks") is None,
    reason="semgrep and gitleaks are installed in the backend image",
)
async def test_installed_scanners_all_report(client, monkeypatch, tmp_path) -> None:
    from app.core.config import settings

    rules = Path(settings.semgrep_rules_dir)
    if not (rules / "security-audit.yml").is_file():
        pytest.skip("semgrep rules are not in this environment")
    monkeypatch.setattr("app.services.scan_orchestrator.work_root", lambda: tmp_path)
    monkeypatch.setattr("app.api.scans.scan_directory", lambda scan_id: tmp_path / str(scan_id))
    await register_and_login(client, "ada@example.com")
    created = await client.post("/projects", json={"name": "Sample"})
    archive = tmp_path / "sample.zip"
    _sample_zip(archive)
    response = await client.post(
        f"/projects/{created.json()['id']}/scans",
        files={"file": ("sample.zip", archive.read_bytes(), "application/zip")},
    )
    body = (await client.get(f"/scans/{response.json()['id']}")).json()
    assert body["status"] == "completed"
    assert {run["tool"] for run in body["scanner_runs"]} == {"bandit", "semgrep", "gitleaks"}
    assert all(run["status"] == "completed" for run in body["scanner_runs"])
