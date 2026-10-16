"""The break-glass AppRoles and policies against a real OpenBao.

`secret/breakglass/account` is written by the responsible person with their own
credentials, never by the gateway, bootstrap or break-glass role, so these tests
prove the policies from capabilities and from the way each role is refused.
"""

from pathlib import Path

import hvac
import pytest

from gateway.secrets import login

DATA_PATH = "secret/data/breakglass/account"
METADATA_PATH = "secret/metadata/breakglass/account"


def _client(addr: str, role_id_file: str, secret_id_file: str):
    role_id = Path(role_id_file).read_text().strip()
    secret_id = Path(secret_id_file).read_text().strip()
    return login(addr, role_id, secret_id)


@pytest.fixture
def gateway_client(openbao_env):
    return _client(
        openbao_env["GATEWAY_OPENBAO_ADDR"],
        openbao_env["GATEWAY_OPENBAO_ROLE_ID_FILE"],
        openbao_env["GATEWAY_OPENBAO_SECRET_ID_FILE"],
    )


@pytest.fixture
def bootstrap_client(openbao_env, bootstrap_files):
    return _client(
        openbao_env["GATEWAY_OPENBAO_ADDR"],
        bootstrap_files["GATEWAY_BOOTSTRAP_ROLE_ID_FILE"],
        bootstrap_files["GATEWAY_BOOTSTRAP_SECRET_ID_FILE"],
    )


@pytest.fixture
def breakglass_client(openbao_env, breakglass_files):
    return _client(
        openbao_env["GATEWAY_OPENBAO_ADDR"],
        breakglass_files["GATEWAY_BREAKGLASS_ROLE_ID_FILE"],
        breakglass_files["GATEWAY_BREAKGLASS_SECRET_ID_FILE"],
    )


@pytest.fixture
def seed_client(openbao_env, breakglass_seed_files):
    return _client(
        openbao_env["GATEWAY_OPENBAO_ADDR"],
        breakglass_seed_files["role_id"],
        breakglass_seed_files["secret_id"],
    )


def _capabilities(client, path: str) -> set[str]:
    response = client.adapter.post("/v1/sys/capabilities-self", json={"paths": [path]})
    return set(response["capabilities"]) - {"deny"}


def test_breakglass_role_can_only_read_the_secret_data(breakglass_client):
    assert _capabilities(breakglass_client, DATA_PATH) == {"read"}


def test_breakglass_role_can_only_delete_the_secret_metadata(breakglass_client):
    assert _capabilities(breakglass_client, METADATA_PATH) == {"delete"}


def test_breakglass_role_is_allowed_to_read_but_not_to_write(breakglass_client):
    # Nothing is stored there in the test run: a permitted read is a 404, a
    # refused one a 403.
    with pytest.raises(hvac.exceptions.InvalidPath):
        breakglass_client.secrets.kv.v2.read_secret_version(
            path="breakglass/account",
            mount_point="secret",
            raise_on_deleted_version=True,
        )
    with pytest.raises(hvac.exceptions.Forbidden):
        breakglass_client.secrets.kv.v2.create_or_update_secret(
            path="breakglass/account", secret={"password": "x"}, mount_point="secret"
        )


def test_breakglass_role_cannot_reach_anything_else(breakglass_client):
    for path in ("gateway/jwt", "bootstrap/admin", "breakglass/other"):
        with pytest.raises(hvac.exceptions.Forbidden):
            breakglass_client.secrets.kv.v2.read_secret_version(
                path=path, mount_point="secret", raise_on_deleted_version=True
            )
    with pytest.raises(hvac.exceptions.Forbidden):
        breakglass_client.secrets.transit.encrypt_data(name="totp", plaintext="eA==")
    with pytest.raises(hvac.exceptions.Forbidden):
        breakglass_client.secrets.kv.v2.list_secrets(path="", mount_point="secret")


def test_gateway_and_bootstrap_roles_have_no_capability_on_the_secret(
    gateway_client, bootstrap_client
):
    for client in (gateway_client, bootstrap_client):
        assert _capabilities(client, DATA_PATH) == set()
        assert _capabilities(client, METADATA_PATH) == set()


def test_gateway_and_bootstrap_roles_cannot_read_or_delete_the_secret(
    gateway_client, bootstrap_client
):
    for client in (gateway_client, bootstrap_client):
        with pytest.raises(hvac.exceptions.Forbidden):
            client.secrets.kv.v2.read_secret_version(
                path="breakglass/account",
                mount_point="secret",
                raise_on_deleted_version=True,
            )
        with pytest.raises(hvac.exceptions.Forbidden):
            client.secrets.kv.v2.delete_metadata_and_all_versions(
                path="breakglass/account", mount_point="secret"
            )


def test_the_breakglass_role_gained_nothing_for_the_other_roles(
    gateway_client, bootstrap_client
):
    assert _capabilities(gateway_client, "secret/data/gateway/jwt") == {"read"}
    assert _capabilities(bootstrap_client, "secret/data/bootstrap/admin") == {"read"}
    assert _capabilities(bootstrap_client, "secret/metadata/bootstrap/admin") == {
        "delete"
    }


def test_seed_role_can_only_create_and_update_the_breakglass_secret(seed_client):
    assert _capabilities(seed_client, DATA_PATH) == {"create", "update"}
    assert _capabilities(seed_client, METADATA_PATH) == set()


def test_seed_role_cannot_read_delete_list_or_reach_anything_else(seed_client):
    with pytest.raises(hvac.exceptions.Forbidden):
        seed_client.secrets.kv.v2.read_secret_version(
            path="breakglass/account",
            mount_point="secret",
            raise_on_deleted_version=True,
        )
    with pytest.raises(hvac.exceptions.Forbidden):
        seed_client.secrets.kv.v2.delete_metadata_and_all_versions(
            path="breakglass/account", mount_point="secret"
        )
    with pytest.raises(hvac.exceptions.Forbidden):
        seed_client.secrets.kv.v2.create_or_update_secret(
            path="bootstrap/admin", secret={"password": "x"}, mount_point="secret"
        )
    with pytest.raises(hvac.exceptions.Forbidden):
        seed_client.secrets.kv.v2.read_secret_version(
            path="gateway/jwt", mount_point="secret", raise_on_deleted_version=True
        )
    with pytest.raises(hvac.exceptions.Forbidden):
        seed_client.secrets.transit.encrypt_data(name="totp", plaintext="eA==")


def test_the_seed_role_gave_nothing_to_the_others(
    gateway_client, bootstrap_client, breakglass_client
):
    assert _capabilities(gateway_client, DATA_PATH) == set()
    assert _capabilities(bootstrap_client, DATA_PATH) == set()
    assert _capabilities(breakglass_client, DATA_PATH) == {"read"}
    assert _capabilities(breakglass_client, METADATA_PATH) == {"delete"}
