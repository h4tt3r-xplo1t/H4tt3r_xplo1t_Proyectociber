"""Fixtures for the database tests.

They need WORKER_NOTICIAS_TEST_ADMIN_URL: a superuser URL of a DISPOSABLE
database (name ending in `_ci` or `_test`). Without it the database tests are
skipped with a reason locally and fail in CI (`CI=true`), where the job always
sets it. The tests create the app role
with a random throwaway password, run the real migrations as the admin and
connect as the role, so the privilege tests prove what the app can really do.

Roles are cluster-wide, so the session fixture refuses to run if a
`worker_noticias` role already exists (it would reset the password of, and
finally drop, a role that may be somebody's real one). After a crashed run
that left the role behind, set WORKER_NOTICIAS_TEST_RESET_ROLE=1 once.
"""

import os
import secrets
import socket

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


LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """No test may reach the outlets or anything else: only loopback resolves.

    A test that forgets to inject a fake fetcher would otherwise send real
    requests to third-party sites; with this guard it fails with a `dns` error
    instead. The test servers bind 127.0.0.1, and PostgreSQL goes through libpq,
    which does not use Python's resolver.
    """
    real_getaddrinfo = socket.getaddrinfo

    def guarded(host, *args, **kwargs):
        name = host.decode() if isinstance(host, bytes) else str(host)
        if name not in LOOPBACK_HOSTS:
            raise OSError("network access is disabled in the tests")
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", guarded)


@pytest.fixture(scope="session")
def role_password() -> str:
    return secrets.token_hex(16)


def _drop_test_objects(conn) -> None:
    """Remove everything the tests create, so each session starts and ends clean."""
    conn.execute(text("DROP SCHEMA IF EXISTS noticias CASCADE"))
    conn.execute(text("DROP TABLE IF EXISTS public.admin_only_table"))
    conn.execute(text("DROP TABLE IF EXISTS public.evil"))


@pytest.fixture(scope="session")
def migrated_db(admin_engine, admin_url, role_password):
    """Role created, schema rebuilt from scratch and migrated to head."""
    with admin_engine.begin() as conn:
        exists = conn.execute(
            text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": APP_ROLE}
        ).scalar()
        if exists and os.environ.get("WORKER_NOTICIAS_TEST_RESET_ROLE") != "1":
            pytest.fail(
                f"role {APP_ROLE!r} already exists in this cluster: the tests "
                "would reset its password and drop it. If it is a leftover of a "
                "crashed test run, set WORKER_NOTICIAS_TEST_RESET_ROLE=1"
            )
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
        _drop_test_objects(conn)
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("WORKER_NOTICIAS_MIGRATION_DATABASE_URL", admin_url)
        command.upgrade(alembic_config(), "head")
    yield admin_url
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("WORKER_NOTICIAS_MIGRATION_DATABASE_URL", admin_url)
        command.downgrade(alembic_config(), "base")
    with admin_engine.begin() as conn:
        _drop_test_objects(conn)
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
