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
