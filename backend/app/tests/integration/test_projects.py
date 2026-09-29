from app.tests.conftest import register_and_login


async def test_project_crud(client) -> None:
    await register_and_login(client, "ada@example.com")

    created = await client.post("/projects", json={"name": "PyGoat", "description": "practice app"})
    assert created.status_code == 201
    project = created.json()
    assert project["name"] == "PyGoat"
    assert project["description"] == "practice app"
    project_id = project["id"]

    listed = await client.get("/projects")
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()] == [project_id]

    fetched = await client.get(f"/projects/{project_id}")
    assert fetched.status_code == 200
    assert fetched.json()["name"] == "PyGoat"

    updated = await client.patch(f"/projects/{project_id}", json={"name": "PyGoat fork"})
    assert updated.status_code == 200
    assert updated.json()["name"] == "PyGoat fork"
    assert updated.json()["description"] == "practice app"

    deleted = await client.delete(f"/projects/{project_id}")
    assert deleted.status_code == 204
    assert (await client.get(f"/projects/{project_id}")).status_code == 404
    assert (await client.get("/projects")).json() == []


async def test_blank_project_name_is_rejected(client) -> None:
    await register_and_login(client, "ada@example.com")
    empty = await client.post("/projects", json={"name": ""})
    whitespace = await client.post("/projects", json={"name": "   "})
    assert empty.status_code == 422
    assert whitespace.status_code == 422


async def test_create_project_without_csrf_header_returns_403(client) -> None:
    await register_and_login(client, "ada@example.com")
    del client.headers["X-CSRF-Token"]
    response = await client.post("/projects", json={"name": "PyGoat"})
    assert response.status_code == 403

    mismatched = await client.post(
        "/projects",
        json={"name": "PyGoat"},
        headers={"X-CSRF-Token": "not-the-cookie"},
    )
    assert mismatched.status_code == 403


async def test_projects_require_login(client) -> None:
    response = await client.get("/projects")
    assert response.status_code == 401
