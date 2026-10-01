import base64

import pytest

from gateway.secrets import GatewayKeys, SecretsError, load_keys

GOOD_JWT = base64.b64encode(b"j" * 32).decode()
GOOD_CSRF = base64.b64encode(b"c" * 32).decode()


class FakeKv:
    def __init__(self, data):
        self.data = data

    def read_secret_version(self, path, mount_point, raise_on_deleted_version):
        assert mount_point == "secret"
        assert raise_on_deleted_version is True
        if path not in self.data:
            raise RuntimeError(f"no such path {path}")
        return {"data": {"data": self.data[path]}}


class FakeClient:
    def __init__(self, data):
        self.secrets = type("S", (), {"kv": type("K", (), {"v2": FakeKv(data)})()})()


def good_data(**overrides):
    data = {
        "gateway/jwt": {"kid": "kid-1", "key": GOOD_JWT},
        "gateway/csrf": {"key": GOOD_CSRF},
    }
    for path, fields in overrides.items():
        data[path.replace("__", "/")] = fields
    return data


def test_load_keys_decodes_both_secrets():
    keys = load_keys(FakeClient(good_data()))

    assert keys.jwt_kid == "kid-1"
    assert keys.jwt_key == b"j" * 32
    assert keys.csrf_key == b"c" * 32


@pytest.mark.parametrize("size", [1, 16, 31])
def test_load_keys_rejects_short_jwt_key(size):
    short = base64.b64encode(b"s" * size).decode()

    with pytest.raises(SecretsError, match="32 bytes"):
        load_keys(FakeClient(good_data(gateway__jwt={"kid": "k", "key": short})))


def test_load_keys_rejects_short_csrf_key():
    short = base64.b64encode(b"s" * 31).decode()

    with pytest.raises(SecretsError, match="32 bytes"):
        load_keys(FakeClient(good_data(gateway__csrf={"key": short})))


def test_load_keys_rejects_invalid_base64_without_echoing_it():
    bad = "!!!not-base64-SECRETVALUE!!!"

    with pytest.raises(SecretsError) as excinfo:
        load_keys(FakeClient(good_data(gateway__jwt={"kid": "k", "key": bad})))

    assert "SECRETVALUE" not in str(excinfo.value)


@pytest.mark.parametrize("kid", [None, "", "   "])
def test_load_keys_rejects_missing_or_empty_kid(kid):
    fields = {"key": GOOD_JWT} if kid is None else {"kid": kid, "key": GOOD_JWT}

    with pytest.raises(SecretsError, match="kid"):
        load_keys(FakeClient(good_data(gateway__jwt=fields)))


def test_load_keys_rejects_missing_key_field():
    with pytest.raises(SecretsError, match="key"):
        load_keys(FakeClient(good_data(gateway__csrf={})))


def test_read_failures_become_secrets_errors_without_the_original_message():
    class Boom(FakeKv):
        def read_secret_version(self, **_):
            raise RuntimeError("token s.SECRETTOKEN rejected")

    client = FakeClient({})
    client.secrets.kv.v2 = Boom({})

    with pytest.raises(SecretsError) as excinfo:
        load_keys(client)

    assert "SECRETTOKEN" not in str(excinfo.value)
    assert excinfo.value.__cause__ is None


def test_repr_never_shows_key_material():
    keys = GatewayKeys(
        jwt_kid="kid-1", jwt_key=b"JWTKEYBYTES" * 3, csrf_key=b"CSRFKEYBYTES" * 3
    )

    text = repr(keys) + str(keys)

    assert "JWTKEYBYTES" not in text
    assert "CSRFKEYBYTES" not in text
    assert "kid-1" in text
