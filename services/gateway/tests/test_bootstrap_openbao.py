"""The bootstrap AppRole and policy against a real OpenBao.

The secret `secret/bootstrap/admin` itself is written by the responsible person
with their own credentials, never by the gateway or the bootstrap role, so these
tests prove the policy from capabilities and from the way each role is refused.
"""

from pathlib import Path

import hvac
import pytest

from gateway.secrets import login

DATA_PATH = "secret/data/bootstrap/admin"
METADATA_PATH = "secret/metadata/bootstrap/admin"


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


def _capabilities(client, path: str) -> set[str]:
    response = client.adapter.post("/v1/sys/capabilities-self", json={"paths": [path]})
    return set(response["capabilities"]) - {"deny"}


def test_bootstrap_role_can_only_read_the_secret_data(bootstrap_client):
    assert _capabilities(bootstrap_client, DATA_PATH) == {"read"}


def test_bootstrap_role_can_only_delete_the_secret_metadata(bootstrap_client):
    assert _capabilities(bootstrap_client, METADATA_PATH) == {"delete"}


def test_gateway_role_has_no_capability_on_the_bootstrap_secret(gateway_client):
    assert _capabilities(gateway_client, DATA_PATH) == set()
    assert _capabilities(gateway_client, METADATA_PATH) == set()


def test_gateway_role_cannot_read_or_delete_the_bootstrap_secret(gateway_client):
    with pytest.raises(hvac.exceptions.Forbidden):
        gateway_client.secrets.kv.v2.read_secret_version(
            path="bootstrap/admin", mount_point="secret", raise_on_deleted_version=True
        )
    with pytest.raises(hvac.exceptions.Forbidden):
        gateway_client.secrets.kv.v2.delete_metadata_and_all_versions(
            path="bootstrap/admin", mount_point="secret"
        )


def test_bootstrap_role_is_allowed_to_read_and_delete_but_not_to_write(
    bootstrap_client,
):
    # Nothing is stored there in the test run: a permitted read is a 404, a
    # refused one a 403.
    with pytest.raises(hvac.exceptions.InvalidPath):
        bootstrap_client.secrets.kv.v2.read_secret_version(
            path="bootstrap/admin", mount_point="secret", raise_on_deleted_version=True
        )
    with pytest.raises(hvac.exceptions.Forbidden):
        bootstrap_client.secrets.kv.v2.create_or_update_secret(
            path="bootstrap/admin", secret={"password": "x"}, mount_point="secret"
        )


def test_bootstrap_role_cannot_reach_the_gateway_keys(bootstrap_client):
    with pytest.raises(hvac.exceptions.Forbidden):
        bootstrap_client.secrets.kv.v2.read_secret_version(
            path="gateway/jwt", mount_point="secret", raise_on_deleted_version=True
        )
    with pytest.raises(hvac.exceptions.Forbidden):
        bootstrap_client.secrets.kv.v2.read_secret_version(
            path="bootstrap/other", mount_point="secret", raise_on_deleted_version=True
        )


def test_bootstrap_role_cannot_use_transit_or_list(bootstrap_client):
    with pytest.raises(hvac.exceptions.Forbidden):
        bootstrap_client.secrets.transit.encrypt_data(name="totp", plaintext="eA==")
    with pytest.raises(hvac.exceptions.Forbidden):
        bootstrap_client.secrets.kv.v2.list_secrets(path="", mount_point="secret")


def test_gateway_policy_gained_nothing_for_the_bootstrap(gateway_client):
    assert _capabilities(gateway_client, "secret/data/gateway/jwt") == {"read"}
    assert _capabilities(gateway_client, "secret/data/bootstrap/admin") == set()


@pytest.fixture
def seed_client(openbao_env, seed_files):
    return _client(
        openbao_env["GATEWAY_OPENBAO_ADDR"],
        seed_files["role_id"],
        seed_files["secret_id"],
    )


def test_seed_role_can_only_create_and_update_the_bootstrap_secret(seed_client):
    assert _capabilities(seed_client, DATA_PATH) == {"create", "update"}
    assert _capabilities(seed_client, METADATA_PATH) == set()


def test_seed_role_cannot_read_delete_list_or_reach_anything_else(seed_client):
    with pytest.raises(hvac.exceptions.Forbidden):
        seed_client.secrets.kv.v2.read_secret_version(
            path="bootstrap/admin", mount_point="secret", raise_on_deleted_version=True
        )
    with pytest.raises(hvac.exceptions.Forbidden):
        seed_client.secrets.kv.v2.delete_metadata_and_all_versions(
            path="bootstrap/admin", mount_point="secret"
        )
    with pytest.raises(hvac.exceptions.Forbidden):
        seed_client.secrets.kv.v2.read_secret_version(
            path="gateway/jwt", mount_point="secret", raise_on_deleted_version=True
        )
    with pytest.raises(hvac.exceptions.Forbidden):
        seed_client.secrets.kv.v2.create_or_update_secret(
            path="gateway/jwt", secret={"key": "x"}, mount_point="secret"
        )
    with pytest.raises(hvac.exceptions.Forbidden):
        seed_client.secrets.transit.encrypt_data(name="totp", plaintext="eA==")


def test_gateway_and_bootstrap_roles_gained_nothing_from_the_seed_role(
    gateway_client, bootstrap_client
):
    assert _capabilities(gateway_client, DATA_PATH) == set()
    assert _capabilities(bootstrap_client, DATA_PATH) == {"read"}
    assert _capabilities(bootstrap_client, METADATA_PATH) == {"delete"}
