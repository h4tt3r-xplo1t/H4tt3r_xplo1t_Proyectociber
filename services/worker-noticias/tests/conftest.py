"""Fixtures for the database tests.

They need WORKER_NOTICIAS_TEST_ADMIN_URL: a superuser URL of a DISPOSABLE
database (name ending in `_ci` or `_test`). Without it the database tests are
skipped with a reason locally and fail in CI (`CI=true`), where the job always
sets it. The tests create the app role
with a random throwaway password, run the real migrations as the admin and
connect as the role, so the privilege tests prove what the app can really do.
"""

import os
import secrets

import pytest
from alembic import command
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import make_url

from tests.dbsupport import APP_ROLE, alembic_config

SAFE_DATABASE_SUFFIXES = ("_test", "_ci")


@pytest.fixture(scope="session")
def admin_url() -> str:
    url = os.environ.get("WORKER_NOTICIAS_TEST_ADMIN_URL")
    if not url:
        # In CI a missing variable must fail, never skip: the privilege tests
        # are the proof of acceptance criterion 7 and a silent skip is green.
        if os.environ.get("CI") == "true":
            pytest.fail("WORKER_NOTICIAS_TEST_ADMIN_URL must be set in CI")
        pytest.skip(
            "WORKER_NOTICIAS_TEST_ADMIN_URL is not set: point it at a superuser "
            "URL of a disposable PostgreSQL database to run the database tests"
        )
    name = make_url(url).database or ""
    if not name.endswith(SAFE_DATABASE_SUFFIXES):
        pytest.fail(
            f"refusing to run: database {name!r} does not end with "
            f"{' or '.join(SAFE_DATABASE_SUFFIXES)}; the tests drop the "
            "`noticias` schema and run downgrades"
        )
    return url


@pytest.fixture(scope="session")
def admin_engine(admin_url) -> Engine:
    engine = create_engine(admin_url, hide_parameters=True)
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def role_password() -> str:
    return secrets.token_hex(16)


@pytest.fixture(scope="session")
def migrated_db(admin_engine, admin_url, role_password):
    """Role created, schema rebuilt from scratch and migrated to head."""
    with admin_engine.begin() as conn:
        exists = conn.execute(
            text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": APP_ROLE}
        ).scalar()
        verb = "ALTER" if exists else "CREATE"
        statement = conn.execute(
            text("SELECT format(:t, CAST(:r AS text), CAST(:p AS text))"),
            {
                "t": verb + " ROLE %I LOGIN PASSWORD %L",
                "r": APP_ROLE,
                "p": role_password,
            },
        ).scalar_one()
        conn.exec_driver_sql(statement.replace("%", "%%"))
        conn.execute(text("DROP SCHEMA IF EXISTS noticias CASCADE"))
        conn.execute(text("DROP TABLE IF EXISTS public.admin_only_table"))
        conn.execute(text("DROP TABLE IF EXISTS public.evil"))
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("WORKER_NOTICIAS_MIGRATION_DATABASE_URL", admin_url)
        command.upgrade(alembic_config(), "head")
    yield admin_url
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("WORKER_NOTICIAS_MIGRATION_DATABASE_URL", admin_url)
        command.downgrade(alembic_config(), "base")
    with admin_engine.begin() as conn:
        conn.execute(text("DROP SCHEMA IF EXISTS noticias CASCADE"))
        conn.execute(text("DROP TABLE IF EXISTS public.admin_only_table"))
        conn.execute(text("DROP TABLE IF EXISTS public.evil"))
        conn.execute(text(f"DROP OWNED BY {APP_ROLE}"))
        conn.execute(text(f"DROP ROLE {APP_ROLE}"))


@pytest.fixture
def app_engine(migrated_db, admin_engine, role_password):
    """Engine connected as the least-privilege app role, with an empty table."""
    with admin_engine.begin() as conn:
        conn.execute(text("TRUNCATE noticias.news_items"))
    url = make_url(migrated_db).set(username=APP_ROLE, password=role_password)
    engine = create_engine(url, hide_parameters=True)
    yield engine
    engine.dispose()
