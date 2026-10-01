import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text

ALEMBIC_INI = Path(__file__).resolve().parent.parent / "alembic.ini"


def alembic_config() -> Config:
    return Config(str(ALEMBIC_INI))


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
    command.upgrade(alembic_config(), "head")
    return database_url


@pytest.fixture
def db_engine(migrated_db):
    engine = create_engine(migrated_db)
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE users, refresh_families CASCADE"))
    yield engine
    engine.dispose()
