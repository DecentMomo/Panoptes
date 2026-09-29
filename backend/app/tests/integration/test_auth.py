from datetime import UTC, datetime, timedelta

import jwt

from app.core.config import settings
from app.core.rate_limit import RateLimiter
from app.tests.conftest import register_and_login


async def test_register_login_and_me(client) -> None:
    logged_in = await register_and_login(client, "ada@example.com")
    cookies = logged_in.headers.get_list("set-cookie")
    access_cookie = next(value for value in cookies if value.startswith("access_token="))
    csrf_cookie = next(value for value in cookies if value.startswith("csrf_token="))
    assert "httponly" in access_cookie.lower()
    assert "httponly" not in csrf_cookie.lower()

    me = await client.get("/auth/me")
    assert me.status_code == 200
    body = me.json()
    assert body["email"] == "ada@example.com"
    assert "hashed_password" not in body


async def test_email_is_stored_lowercase(client) -> None:
    registered = await client.post(
        "/auth/register", json={"email": "Ada@Example.com", "password": "password123"}
    )
    assert registered.status_code == 201
    assert registered.json()["email"] == "ada@example.com"


async def test_duplicate_email_returns_409(client) -> None:
    payload = {"email": "ada@example.com", "password": "password123"}
    assert (await client.post("/auth/register", json=payload)).status_code == 201
    duplicate = await client.post("/auth/register", json=payload)
    assert duplicate.status_code == 409


async def test_unknown_email_and_wrong_password_look_the_same(client) -> None:
    await client.post(
        "/auth/register", json={"email": "ada@example.com", "password": "password123"}
    )
    wrong_password = await client.post(
        "/auth/login", json={"email": "ada@example.com", "password": "not-the-password"}
    )
    unknown_email = await client.post(
        "/auth/login", json={"email": "nobody@example.com", "password": "not-the-password"}
    )
    assert wrong_password.status_code == unknown_email.status_code == 401
    assert wrong_password.json() == unknown_email.json()


async def test_me_without_cookie_returns_401(client) -> None:
    response = await client.get("/auth/me")
    assert response.status_code == 401


async def test_short_password_is_rejected(client) -> None:
    response = await client.post(
        "/auth/register", json={"email": "ada@example.com", "password": "short"}
    )
    assert response.status_code == 422


async def test_logout_clears_the_session(client) -> None:
    await register_and_login(client, "ada@example.com")
    logged_out = await client.post("/auth/logout")
    assert logged_out.status_code == 204
    assert (await client.get("/auth/me")).status_code == 401


async def test_logout_succeeds_with_an_expired_access_token(client) -> None:
    await register_and_login(client, "ada@example.com")
    user_id = (await client.get("/auth/me")).json()["id"]
    expired = jwt.encode(
        {"sub": str(user_id), "exp": datetime.now(UTC) - timedelta(minutes=5)},
        settings.secret_key,
        algorithm="HS256",
    )
    client.cookies.set("access_token", expired)
    logged_out = await client.post("/auth/logout")
    assert logged_out.status_code == 204
    cleared = " ".join(logged_out.headers.get_list("set-cookie")).lower()
    assert "access_token=" in cleared
    assert "csrf_token=" in cleared
    assert (await client.get("/auth/me")).status_code == 401


async def test_forged_csrf_pair_is_rejected(client) -> None:
    await register_and_login(client, "ada@example.com")
    forged = "not-a-real-token.deadbeef"
    client.cookies.set("csrf_token", forged)
    client.headers["X-CSRF-Token"] = forged
    response = await client.post("/projects", json={"name": "Nope"})
    assert response.status_code == 403


def _quiet_limiters(monkeypatch, ip_limit: int, email_limit: int) -> None:
    monkeypatch.setattr("app.api.auth.login_ip_limiter", RateLimiter(ip_limit, 60))
    monkeypatch.setattr("app.api.auth.login_email_limiter", RateLimiter(email_limit, 60))


async def test_one_ip_is_limited_before_it_locks_the_account(client, monkeypatch) -> None:
    _quiet_limiters(monkeypatch, ip_limit=2, email_limit=20)
    addresses = iter(["attacker", "attacker", "attacker", "owner"])
    monkeypatch.setattr("app.api.auth.client_ip", lambda request: next(addresses))
    await client.post(
        "/auth/register", json={"email": "ada@example.com", "password": "password123"}
    )
    payload = {"email": "ada@example.com", "password": "not-the-password"}
    assert (await client.post("/auth/login", json=payload)).status_code == 401
    assert (await client.post("/auth/login", json=payload)).status_code == 401
    blocked = await client.post("/auth/login", json=payload)
    assert blocked.status_code == 429
    owner = await client.post(
        "/auth/login", json={"email": "ada@example.com", "password": "password123"}
    )
    assert owner.status_code == 200


async def test_email_bucket_stops_a_distributed_login_spray(client, monkeypatch) -> None:
    _quiet_limiters(monkeypatch, ip_limit=100, email_limit=2)
    addresses = iter(["one", "two", "three"])
    monkeypatch.setattr("app.api.auth.client_ip", lambda request: next(addresses))
    await client.post(
        "/auth/register", json={"email": "ada@example.com", "password": "password123"}
    )
    payload = {"email": "ada@example.com", "password": "not-the-password"}
    assert (await client.post("/auth/login", json=payload)).status_code == 401
    assert (await client.post("/auth/login", json=payload)).status_code == 401
    assert (await client.post("/auth/login", json=payload)).status_code == 429
