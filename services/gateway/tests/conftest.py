import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from gateway import auth
from gateway.db import get_engine
from gateway.main import create_app
from tests.test_login import KEYS, Clock

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
        conn.execute(
            text(
                "TRUNCATE users, refresh_families, refresh_tokens, revoked_jtis, "
                "login_attempts, recovery_codes CASCADE"
            )
        )
    yield engine
    engine.dispose()


@pytest.fixture
def clock():
    """Movable 'now' shared by the session tests."""
    return Clock()


@pytest.fixture
def client(db_engine, clock):
    """App with fake keys and the movable clock; each test sets its own headers.

    test_login and test_register define their own `client` and take precedence
    in their modules.
    """
    app = create_app()
    app.dependency_overrides[auth.get_keys] = lambda: KEYS
    app.dependency_overrides[auth.get_now] = clock
    yield TestClient(app, base_url="https://testserver")
    get_engine().dispose()


ENV_VARS = (
    "GATEWAY_OPENBAO_ADDR",
    "GATEWAY_OPENBAO_ROLE_ID_FILE",
    "GATEWAY_OPENBAO_SECRET_ID_FILE",
)


@pytest.fixture(scope="session")
def openbao_env() -> dict[str, str]:
    """Connection settings of the OpenBao used by these tests.

    Missing configuration fails the test on purpose, like the database tests:
    a silently skipped test would look green without proving anything.
    """
    missing = [name for name in ENV_VARS if not os.environ.get(name)]
    if missing:
        pytest.fail(
            f"{', '.join(missing)} not set: start OpenBao "
            "(docker compose up -d --wait openbao), run "
            "scripts/openbao-dev-init.sh and export the three GATEWAY_OPENBAO_* "
            "variables to run the OpenBao tests"
        )
    return {name: os.environ[name] for name in ENV_VARS}


@pytest.fixture(scope="session")
def bootstrap_files(openbao_env) -> dict[str, str]:
    """Paths of the bootstrap AppRole credentials, next to the gateway ones.

    scripts/openbao-dev-init.sh writes both pairs into the same directory, so
    the bootstrap tests need no extra environment (CI sets only the gateway
    variables). Missing files fail the test, like the other OpenBao fixtures.
    """
    directory = Path(openbao_env["GATEWAY_OPENBAO_ROLE_ID_FILE"]).parent
    files = {
        "GATEWAY_BOOTSTRAP_ROLE_ID_FILE": str(directory / "bootstrap-role-id"),
        "GATEWAY_BOOTSTRAP_SECRET_ID_FILE": str(directory / "bootstrap-secret-id"),
    }
    missing = [name for name, path in files.items() if not Path(path).is_file()]
    if missing:
        pytest.fail(
            f"{', '.join(missing)} not found next to the gateway credentials: "
            "recreate the dev OpenBao and run scripts/openbao-dev-init.sh (the "
            "bootstrap AppRole is created on the first setup)"
        )
    return files


@pytest.fixture(scope="session")
def seed_files(openbao_env) -> dict[str, str]:
    """Paths of the DEV/CI-only `bootstrap-seed` AppRole credentials.

    That role exists only so the tests can write `secret/bootstrap/admin`; in
    production the responsible person writes it with their own credentials.
    """
    directory = Path(openbao_env["GATEWAY_OPENBAO_ROLE_ID_FILE"]).parent
    files = {
        "role_id": str(directory / "bootstrap-seed-role-id"),
        "secret_id": str(directory / "bootstrap-seed-secret-id"),
    }
    missing = [name for name, path in files.items() if not Path(path).is_file()]
    if missing:
        pytest.fail(
            "bootstrap-seed credential files not found next to the gateway "
            "ones: recreate the dev OpenBao and run scripts/openbao-dev-init.sh"
        )
    return files
