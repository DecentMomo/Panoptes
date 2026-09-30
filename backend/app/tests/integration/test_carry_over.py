import shutil
from pathlib import Path

from app.tests.conftest import register_and_login
from app.tests.scan_helpers import SAMPLE, stub_other_scanners, zip_dir


def _prepare(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("app.services.scan_orchestrator.work_root", lambda: tmp_path)
    monkeypatch.setattr("app.api.scans.scan_directory", lambda scan_id: tmp_path / str(scan_id))
    stub_other_scanners(monkeypatch)


async def _scan(client, project_id: int, archive: Path) -> int:
    response = await client.post(
        f"/projects/{project_id}/scans",
        files={"file": (archive.name, archive.read_bytes(), "application/zip")},
    )
    assert response.status_code == 202, response.text
    return response.json()["id"]


def _calc(findings: list[dict]) -> dict:
    return next(
        item for item in findings if item["file_path"] == "calc.py" and item["rule_id"] == "B307"
    )


async def test_false_positive_carries_to_an_unchanged_rescan(client, monkeypatch, tmp_path) -> None:
    _prepare(monkeypatch, tmp_path)
    logged_in = await register_and_login(client, "ada@example.com")
    user_id = logged_in.json()["id"]
    project_id = (await client.post("/projects", json={"name": "Carry"})).json()["id"]
    archive = tmp_path / "sample.zip"
    zip_dir(SAMPLE, archive)
    first_id = await _scan(client, project_id, archive)
    first = (await client.get(f"/scans/{first_id}/findings")).json()
    finding = _calc(first)
    changed = await client.patch(
        f"/findings/{finding['id']}/status",
        json={"status": "false_positive", "reason": "test fixture"},
    )
    assert changed.status_code == 200

    second_id = await _scan(client, project_id, archive)
    second = (await client.get(f"/scans/{second_id}/findings")).json()
    carried = _calc(second)
    assert carried["status"] == "false_positive"
    assert carried["status_reason"] == "test fixture"
    history = (await client.get(f"/findings/{carried['id']}/history")).json()
    assert len(history) == 1
    assert history[0]["user_id"] == user_id
    assert history[0]["reason"] == "test fixture"
    assert history[0]["carried_from_scan_id"] == first_id
    assert history[0]["to_status"] == "false_positive"


async def test_a_changed_flagged_line_does_not_inherit_a_suppression(
    client, monkeypatch, tmp_path
) -> None:
    _prepare(monkeypatch, tmp_path)
    await register_and_login(client, "ada@example.com")
    project_id = (await client.post("/projects", json={"name": "Carry"})).json()["id"]
    tree = tmp_path / "tree"
    shutil.copytree(SAMPLE, tree)
    archive = tmp_path / "sample.zip"
    zip_dir(tree, archive)
    first_id = await _scan(client, project_id, archive)
    finding = _calc((await client.get(f"/scans/{first_id}/findings")).json())
    await client.patch(
        f"/findings/{finding['id']}/status",
        json={"status": "false_positive", "reason": "old line"},
    )

    (tree / "calc.py").write_text(
        "def calculate(expr: str) -> object:\n    return eval(expr.strip())\n",
        encoding="utf-8",
    )
    changed_archive = tmp_path / "changed.zip"
    zip_dir(tree, changed_archive)
    second_id = await _scan(client, project_id, changed_archive)
    second = _calc((await client.get(f"/scans/{second_id}/findings")).json())
    assert second["fingerprint"] != finding["fingerprint"]
    assert second["status"] == "open"
    history = (await client.get(f"/findings/{second['id']}/history")).json()
    assert history == []


async def test_accepted_risk_carries_and_fixed_does_not(client, monkeypatch, tmp_path) -> None:
    _prepare(monkeypatch, tmp_path)
    await register_and_login(client, "ada@example.com")
    project_id = (await client.post("/projects", json={"name": "Carry"})).json()["id"]
    archive = tmp_path / "sample.zip"
    zip_dir(SAMPLE, archive)
    first_id = await _scan(client, project_id, archive)
    findings = (await client.get(f"/scans/{first_id}/findings")).json()
    calc = _calc(findings)
    other = next(item for item in findings if item["id"] != calc["id"])
    await client.patch(
        f"/findings/{calc['id']}/status",
        json={"status": "accepted_risk"},
    )
    await client.patch(f"/findings/{other['id']}/status", json={"status": "fixed"})

    second_id = await _scan(client, project_id, archive)
    second = {
        item["fingerprint"]: item
        for item in (await client.get(f"/scans/{second_id}/findings")).json()
    }
    assert second[calc["fingerprint"]]["status"] == "accepted_risk"
    assert second[other["fingerprint"]]["status"] == "open"


async def test_another_project_does_not_inherit_a_suppression(
    client, monkeypatch, tmp_path
) -> None:
    _prepare(monkeypatch, tmp_path)
    await register_and_login(client, "ada@example.com")
    first_project = (await client.post("/projects", json={"name": "A"})).json()["id"]
    second_project = (await client.post("/projects", json={"name": "B"})).json()["id"]
    archive = tmp_path / "sample.zip"
    zip_dir(SAMPLE, archive)
    first_id = await _scan(client, first_project, archive)
    finding = _calc((await client.get(f"/scans/{first_id}/findings")).json())
    await client.patch(
        f"/findings/{finding['id']}/status",
        json={"status": "false_positive", "reason": "only for A"},
    )
    other_id = await _scan(client, second_project, archive)
    other = _calc((await client.get(f"/scans/{other_id}/findings")).json())
    assert other["status"] == "open"
    assert (await client.get(f"/findings/{other['id']}/history")).json() == []


async def test_a_two_hop_carry_still_names_the_original_user(client, monkeypatch, tmp_path) -> None:
    _prepare(monkeypatch, tmp_path)
    logged_in = await register_and_login(client, "ada@example.com")
    user_id = logged_in.json()["id"]
    project_id = (await client.post("/projects", json={"name": "Carry"})).json()["id"]
    archive = tmp_path / "sample.zip"
    zip_dir(SAMPLE, archive)
    first_id = await _scan(client, project_id, archive)
    finding = _calc((await client.get(f"/scans/{first_id}/findings")).json())
    await client.patch(
        f"/findings/{finding['id']}/status",
        json={"status": "false_positive", "reason": "kept"},
    )
    second_id = await _scan(client, project_id, archive)
    third_id = await _scan(client, project_id, archive)
    third = _calc((await client.get(f"/scans/{third_id}/findings")).json())
    history = (await client.get(f"/findings/{third['id']}/history")).json()
    assert len(history) == 1
    assert history[0]["user_id"] == user_id
    assert history[0]["reason"] == "kept"
    assert history[0]["carried_from_scan_id"] == second_id
    assert third["status"] == "false_positive"
