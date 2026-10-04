import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

ALEMBIC_INI = Path(__file__).resolve().parent.parent / "alembic.ini"


SAFE_DATABASE_SUFFIXES = ("_test", "_ci")


def ensure_disposable_database(url: str) -> None:
    """Refuse to run destructive fixtures against a non-test database."""
    name = make_url(url).database or ""
    if not name.endswith(SAFE_DATABASE_SUFFIXES):
        pytest.fail(
            f"refusing to run: database {name!r} does not end with "
            f"{' or '.join(SAFE_DATABASE_SUFFIXES)}; the tests truncate tables "
            "and run downgrades, so point GATEWAY_DATABASE_URL at a throwaway "
            "database"
        )


def alembic_config() -> Config:
    return Config(str(ALEMBIC_INI))


@pytest.fixture(autouse=True)
def app_settings(monkeypatch):
    """Fake, fixed values so no test depends on the developer's shell."""
    monkeypatch.setenv("GATEWAY_JWT_ISSUER", "h4tt3r-gateway-test")
    monkeypatch.setenv("GATEWAY_JWT_AUDIENCE", "h4tt3r-web-test")
    monkeypatch.setenv("GATEWAY_ALLOWED_ORIGIN", "https://testserver")


@pytest.fixture(scope="session")
def database_url() -> str:
    """URL of the PostgreSQL used by the DB tests.

    Missing configuration fails the test on purpose: a DB test that is skipped
    silently would look green without proving anything.
    """
    url = os.environ.get("GATEWAY_DATABASE_URL")
    if not url:
        pytest.fail(
            "GATEWAY_DATABASE_URL is not set: start PostgreSQL "
            "(docker compose up -d postgres) and export it to run the DB tests"
        )
    return url


@pytest.fixture(scope="session")
def migrated_db(database_url):
    ensure_disposable_database(database_url)
    command.upgrade(alembic_config(), "head")
    return database_url


@pytest.fixture
def db_engine(migrated_db):
    ensure_disposable_database(migrated_db)
    engine = create_engine(migrated_db)
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE users, refresh_families, login_attempts CASCADE"))
    yield engine
    engine.dispose()
