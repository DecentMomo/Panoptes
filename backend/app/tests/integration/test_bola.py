from app.tests.conftest import register_and_login


async def test_user_cannot_access_another_users_project(clients) -> None:
    alice = clients()
    bob = clients()
    await register_and_login(alice, "alice@example.com")
    await register_and_login(bob, "bob@example.com")

    created = await alice.post("/projects", json={"name": "Alice only"})
    assert created.status_code == 201
    project_id = created.json()["id"]

    assert (await bob.get(f"/projects/{project_id}")).status_code == 404
    assert (await bob.patch(f"/projects/{project_id}", json={"name": "stolen"})).status_code == 404
    assert (await bob.delete(f"/projects/{project_id}")).status_code == 404

    bobs_projects = (await bob.get("/projects")).json()
    assert project_id not in [project["id"] for project in bobs_projects]

    # Alice's project is unchanged.
    assert (await alice.get(f"/projects/{project_id}")).json()["name"] == "Alice only"


async def test_user_cannot_access_another_users_scan(clients, tmp_path) -> None:
    alice = clients()
    bob = clients()
    await register_and_login(alice, "alice@example.com")
    await register_and_login(bob, "bob@example.com")

    created = await alice.post("/projects", json={"name": "Alice only"})
    project_id = created.json()["id"]
    archive = tmp_path / "code.zip"
    import zipfile

    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("app.py", "x = 1\n")
    uploaded = await alice.post(
        f"/projects/{project_id}/scans",
        files={"file": ("code.zip", archive.read_bytes(), "application/zip")},
    )
    assert uploaded.status_code == 202, uploaded.text
    scan_id = uploaded.json()["id"]

    assert (await bob.get(f"/scans/{scan_id}")).status_code == 404
    assert (await bob.get(f"/scans/{scan_id}/findings")).status_code == 404
    assert (await bob.get(f"/projects/{project_id}/scans")).status_code == 404
    stolen = await bob.post(
        f"/projects/{project_id}/scans",
        files={"file": ("code.zip", archive.read_bytes(), "application/zip")},
    )
    assert stolen.status_code == 404
    stolen_git = await bob.post(
        f"/projects/{project_id}/scans/git",
        json={"url": "https://github.com/org/repo"},
    )
    assert stolen_git.status_code == 404
