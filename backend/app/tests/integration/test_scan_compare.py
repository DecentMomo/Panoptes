import shutil
from pathlib import Path

from app.models.scan import Scan
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


async def test_fix_then_rescan_moves_only_that_finding_to_fixed(
    client, monkeypatch, tmp_path
) -> None:
    _prepare(monkeypatch, tmp_path)
    await register_and_login(client, "ada@example.com")
    project_id = (await client.post("/projects", json={"name": "Diff"})).json()["id"]
    tree = tmp_path / "tree"
    shutil.copytree(SAMPLE, tree)
    first_archive = tmp_path / "before.zip"
    zip_dir(tree, first_archive)
    base_id = await _scan(client, project_id, first_archive)
    base_findings = (await client.get(f"/scans/{base_id}/findings")).json()
    calc = next(
        item
        for item in base_findings
        if item["file_path"] == "calc.py" and item["rule_id"] == "B307"
    )

    (tree / "calc.py").write_text(
        "import ast\n\ndef calculate(expr: str) -> object:\n    return ast.literal_eval(expr)\n",
        encoding="utf-8",
    )
    query = (tree / "query.py").read_text(encoding="utf-8")
    (tree / "query.py").write_text("\n" + query, encoding="utf-8")
    second_archive = tmp_path / "after.zip"
    zip_dir(tree, second_archive)
    head_id = await _scan(client, project_id, second_archive)

    compared = await client.get(
        f"/projects/{project_id}/compare", params={"base": base_id, "head": head_id}
    )
    assert compared.status_code == 200, compared.text
    body = compared.json()
    assert [item["fingerprint"] for item in body["fixed"]] == [calc["fingerprint"]]
    assert body["fixed"][0]["file_path"] == "calc.py"
    assert body["new"] == []
    still = {item["fingerprint"] for item in body["still_open"]}
    expected = {
        item["fingerprint"] for item in base_findings if item["fingerprint"] != calc["fingerprint"]
    }
    assert still == expected


async def test_compare_rejects_the_same_scan_and_unfinished_scans(
    client, session_factory, monkeypatch, tmp_path
) -> None:
    _prepare(monkeypatch, tmp_path)
    await register_and_login(client, "ada@example.com")
    project_id = (await client.post("/projects", json={"name": "Diff"})).json()["id"]
    archive = tmp_path / "sample.zip"
    zip_dir(SAMPLE, archive)
    scan_id = await _scan(client, project_id, archive)
    same = await client.get(
        f"/projects/{project_id}/compare", params={"base": scan_id, "head": scan_id}
    )
    assert same.status_code == 400

    db = session_factory()
    queued = Scan(
        project_id=project_id,
        status="queued",
        source_type="zip",
        source_name="waiting.zip",
        files_scanned=0,
        files_skipped=0,
    )
    db.add(queued)
    db.flush()
    queued_id = queued.id
    db.commit()
    db.close()
    unfinished = await client.get(
        f"/projects/{project_id}/compare", params={"base": scan_id, "head": queued_id}
    )
    assert unfinished.status_code == 400


async def test_compare_is_scoped_to_the_owner_and_project(clients, monkeypatch, tmp_path) -> None:
    _prepare(monkeypatch, tmp_path)
    alice = clients()
    bob = clients()
    await register_and_login(alice, "alice@example.com")
    await register_and_login(bob, "bob@example.com")
    alice_project = (await alice.post("/projects", json={"name": "A"})).json()["id"]
    other_project = (await alice.post("/projects", json={"name": "A2"})).json()["id"]
    bob_project = (await bob.post("/projects", json={"name": "B"})).json()["id"]
    archive = tmp_path / "sample.zip"
    zip_dir(SAMPLE, archive)
    base_id = await _scan(alice, alice_project, archive)
    head_id = await _scan(alice, alice_project, archive)
    other_id = await _scan(alice, other_project, archive)
    stolen = await bob.get(
        f"/projects/{alice_project}/compare", params={"base": base_id, "head": head_id}
    )
    assert stolen.status_code == 404
    wrong_project = await alice.get(
        f"/projects/{alice_project}/compare", params={"base": base_id, "head": other_id}
    )
    assert wrong_project.status_code == 404
    bob_ids = await bob.get(
        f"/projects/{bob_project}/compare", params={"base": base_id, "head": head_id}
    )
    assert bob_ids.status_code == 404
