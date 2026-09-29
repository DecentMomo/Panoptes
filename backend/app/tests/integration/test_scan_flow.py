import shutil
import zipfile
from pathlib import Path

import pytest

from app.scanners.base import ToolResult
from app.tests.conftest import register_and_login


def _sample_dir() -> Path:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "samples" / "vulnerable-python"
        if candidate.is_dir():
            return candidate
    raise FileNotFoundError("samples/vulnerable-python")


SAMPLE = _sample_dir()


def _sample_zip(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for source in SAMPLE.iterdir():
            if source.is_file():
                archive.write(source, source.name)


def _empty(root, workdir):
    return ToolResult("", "", 0, 1, False), []


def _stub_other_scanners(monkeypatch) -> None:
    monkeypatch.setattr("app.services.scan_orchestrator.run_semgrep", _empty)
    monkeypatch.setattr("app.services.scan_orchestrator.run_gitleaks", _empty)


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
