import zipfile
from pathlib import Path

from app.scanners.base import ToolResult
from app.services.scan_orchestrator import run_scan
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


async def test_upload_scans_the_sample(client, session_factory, monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("app.services.scan_orchestrator.work_root", lambda: tmp_path)
    monkeypatch.setattr("app.api.scans.scan_directory", lambda scan_id: tmp_path / str(scan_id))
    monkeypatch.setattr("app.api.scans.run_scan", lambda scan_id: None)

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
    assert response.json()["status"] == "queued"

    run_scan(scan_id, session_factory=session_factory)

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


async def test_bandit_timeout_fails_the_scan(
    client, session_factory, monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr("app.services.scan_orchestrator.work_root", lambda: tmp_path)
    monkeypatch.setattr("app.api.scans.scan_directory", lambda scan_id: tmp_path / str(scan_id))
    monkeypatch.setattr("app.api.scans.run_scan", lambda scan_id: None)

    def timed_out(root):
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
    run_scan(scan_id, session_factory=session_factory)

    detail = (await client.get(f"/scans/{scan_id}")).json()
    assert detail["status"] == "failed"
    assert detail["error_message"] == "Scan failed."
    assert detail["scanner_runs"][0]["status"] == "timeout"
    assert detail["error_message"] == "Scan failed."
