"""Integration tests against a real OpenBao (see scripts/openbao-dev-init.sh)."""

import os
import socket
import time
from pathlib import Path

import hvac
import pytest

from gateway import secrets
from gateway.secrets import SecretsError, get_gateway_keys, login

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


@pytest.fixture
def client(openbao_env):
    role_id = Path(openbao_env["GATEWAY_OPENBAO_ROLE_ID_FILE"]).read_text().strip()
    secret_id = Path(openbao_env["GATEWAY_OPENBAO_SECRET_ID_FILE"]).read_text().strip()
    return login(openbao_env["GATEWAY_OPENBAO_ADDR"], role_id, secret_id)


@pytest.fixture
def fresh_cache():
    get_gateway_keys.cache_clear()
    yield
    get_gateway_keys.cache_clear()


def test_gateway_reads_its_keys_from_openbao(openbao_env, fresh_cache):
    keys = get_gateway_keys()

    assert keys.jwt_kid
    assert len(keys.jwt_key) >= 32
    assert len(keys.csrf_key) >= 32
    assert keys.jwt_key != keys.csrf_key


def test_keys_are_cached_after_the_first_read(openbao_env, fresh_cache):
    assert get_gateway_keys() is get_gateway_keys()


def test_gateway_token_cannot_write_its_own_keys(client):
    with pytest.raises(hvac.exceptions.Forbidden):
        client.secrets.kv.v2.create_or_update_secret(
            path="gateway/jwt", secret={"kid": "x", "key": "x"}, mount_point="secret"
        )


def test_gateway_token_cannot_read_other_paths(client):
    with pytest.raises(hvac.exceptions.Forbidden):
        client.secrets.kv.v2.read_secret_version(
            path="other", mount_point="secret", raise_on_deleted_version=True
        )


def test_wrong_secret_id_fails_closed(openbao_env):
    role_id = Path(openbao_env["GATEWAY_OPENBAO_ROLE_ID_FILE"]).read_text().strip()

    with pytest.raises(SecretsError) as excinfo:
        login(openbao_env["GATEWAY_OPENBAO_ADDR"], role_id, "wrong-secret-id")

    assert "wrong-secret-id" not in str(excinfo.value)
    assert role_id not in str(excinfo.value)


def test_unreachable_server_fails_closed_within_the_timeout(monkeypatch):
    monkeypatch.setattr(secrets, "REQUEST_TIMEOUT_SECONDS", 1)
    # Accepts connections at TCP level but never answers: only the client
    # timeout can end the request.
    with socket.socket() as silent:
        silent.bind(("127.0.0.1", 0))
        silent.listen(1)
        addr = f"http://127.0.0.1:{silent.getsockname()[1]}"
        started = time.monotonic()

        with pytest.raises(SecretsError):
            login(addr, "role", "secret")

    assert time.monotonic() - started < 5


def test_missing_settings_fail_closed(monkeypatch, fresh_cache):
    monkeypatch.delenv("GATEWAY_OPENBAO_ADDR", raising=False)

    with pytest.raises(SecretsError, match="GATEWAY_OPENBAO_ADDR"):
        get_gateway_keys()


def test_gateway_token_is_revoked_after_reading_the_keys(
    openbao_env, fresh_cache, monkeypatch
):
    used = []
    real_login = secrets.login

    def capturing_login(*args):
        client = real_login(*args)
        used.append((client, client.token))
        return client

    monkeypatch.setattr(secrets, "login", capturing_login)

    get_gateway_keys()

    ((_, token),) = used
    probe = hvac.Client(url=openbao_env["GATEWAY_OPENBAO_ADDR"], token=token)
    assert probe.is_authenticated() is False
