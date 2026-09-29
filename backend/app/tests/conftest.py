import os

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine.url import make_url
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models import Project, User  # noqa: F401

# 127.0.0.1 rather than localhost: on Docker Desktop for Windows, "localhost" can
# resolve to IPv6 and hang. Compose and CI override this with their own host.
TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+psycopg://panoptes:panoptes@127.0.0.1:5432/panoptes_test",
)

_engine = None
_SessionLocal = None


def _ensure_test_database() -> None:
    global _engine, _SessionLocal
    if _engine is not None:
        return

    url = make_url(TEST_DATABASE_URL)
    database_name = url.database or ""
    if not database_name.replace("_", "").isalnum():
        raise RuntimeError(f"Refusing to create a database named {database_name!r}")
    admin_engine = create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin_engine.connect() as connection:
        exists = connection.execute(
            text("SELECT 1 FROM pg_database WHERE datname = :name"),
            {"name": database_name},
        ).scalar()
        if exists is None:
            connection.execute(text(f'CREATE DATABASE "{database_name}"'))
    admin_engine.dispose()

    _engine = create_engine(TEST_DATABASE_URL, pool_pre_ping=True)
    _SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False)


def _override_get_db():
    session = _SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
async def clients():
    """Fresh tables per test, and a way to open extra clients (for BOLA)."""
    _ensure_test_database()
    Base.metadata.drop_all(_engine)
    Base.metadata.create_all(_engine)
    app.dependency_overrides[get_db] = _override_get_db

    transport = ASGITransport(app=app)
    opened: list[AsyncClient] = []

    def open_client() -> AsyncClient:
        client = AsyncClient(transport=transport, base_url="http://test")
        opened.append(client)
        return client

    yield open_client

    for client in opened:
        await client.aclose()
    app.dependency_overrides.clear()


@pytest.fixture
async def client(clients):
    return clients()


async def register_and_login(client: AsyncClient, email: str, password: str = "password123"):
    registered = await client.post("/auth/register", json={"email": email, "password": password})
    assert registered.status_code == 201, registered.text
    logged_in = await client.post("/auth/login", json={"email": email, "password": password})
    assert logged_in.status_code == 200, logged_in.text
    csrf = client.cookies.get("csrf_token")
    assert csrf
    client.headers["X-CSRF-Token"] = csrf
    return logged_in
