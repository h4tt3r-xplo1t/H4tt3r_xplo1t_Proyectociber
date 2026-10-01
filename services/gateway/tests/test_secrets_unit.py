import base64

import pytest

from gateway import secrets
from gateway.secrets import GatewayKeys, SecretsError, load_keys, login

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


def test_read_failure_carries_no_exception_context():
    class Boom(FakeKv):
        def read_secret_version(self, **_):
            raise RuntimeError("token s.SECRETTOKEN rejected")

    client = FakeClient({})
    client.secrets.kv.v2 = Boom({})

    with pytest.raises(SecretsError) as excinfo:
        load_keys(client)

    assert excinfo.value.__cause__ is None
    assert excinfo.value.__context__ is None


def test_unexpected_kv_response_shape_fails_closed():
    class Odd(FakeKv):
        def read_secret_version(self, **_):
            return {"unexpected": "SECRETSHAPE"}

    client = FakeClient({})
    client.secrets.kv.v2 = Odd({})

    with pytest.raises(SecretsError) as excinfo:
        load_keys(client)

    assert "SECRETSHAPE" not in str(excinfo.value)
    assert excinfo.value.__context__ is None


class FakeHvac:
    """Stands in for hvac.Client and records how it was built and used."""

    instances: list = []
    login_error: Exception | None = None

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.token = kwargs.get("token")
        self.auth = type("A", (), {"approle": self})()
        FakeHvac.instances.append(self)

    def login(self, role_id, secret_id):
        if FakeHvac.login_error is not None:
            raise FakeHvac.login_error
        self.token = object()

    def is_authenticated(self):
        return self.token is not None


@pytest.fixture
def fake_hvac(monkeypatch):
    FakeHvac.instances = []
    FakeHvac.login_error = None
    monkeypatch.setattr(secrets.hvac, "Client", FakeHvac)
    return FakeHvac


@pytest.mark.parametrize(
    "addr",
    [
        "http://openbao.example:8200",
        "http://10.0.0.5:8200",
        "http://127.0.0.1.evil.example:8200",
        "ftp://127.0.0.1:8200",
        "127.0.0.1:8200",
    ],
)
def test_login_rejects_plain_http_to_non_loopback(fake_hvac, addr):
    with pytest.raises(SecretsError, match="https"):
        login(addr, "role", "secret")

    assert fake_hvac.instances == []


@pytest.mark.parametrize(
    "addr",
    [
        "http://127.0.0.1:8200",
        "http://localhost:8200",
        "http://[::1]:8200",
        "https://openbao.example:8200",
    ],
)
def test_login_accepts_loopback_http_and_any_https(fake_hvac, addr):
    client = login(addr, "role", "secret")

    assert client.is_authenticated()


def test_login_failure_carries_no_exception_context(fake_hvac):
    fake_hvac.login_error = RuntimeError("secret_id SECRETVALUE rejected")

    with pytest.raises(SecretsError) as excinfo:
        login("http://127.0.0.1:8200", "role", "secret")

    assert "SECRETVALUE" not in str(excinfo.value)
    assert excinfo.value.__cause__ is None
    assert excinfo.value.__context__ is None


def test_login_ignores_ambient_vault_token(fake_hvac, monkeypatch):
    monkeypatch.setenv("VAULT_TOKEN", "ambient-root-token")

    login("http://127.0.0.1:8200", "role", "secret")

    assert fake_hvac.instances[0].kwargs["token"] is None


@pytest.mark.parametrize("which", ["role", "secret"])
def test_unreadable_credential_files_fail_closed(monkeypatch, tmp_path, which):
    good = tmp_path / "good"
    good.write_text("value")
    missing = str(tmp_path / "missing")
    monkeypatch.setenv("GATEWAY_OPENBAO_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv(
        "GATEWAY_OPENBAO_ROLE_ID_FILE", missing if which == "role" else str(good)
    )
    monkeypatch.setenv(
        "GATEWAY_OPENBAO_SECRET_ID_FILE", missing if which == "secret" else str(good)
    )
    secrets.get_gateway_keys.cache_clear()

    with pytest.raises(SecretsError, match="file"):
        secrets.get_gateway_keys()

    secrets.get_gateway_keys.cache_clear()


def test_real_hvac_client_does_not_keep_the_ambient_token(monkeypatch):
    monkeypatch.setenv("VAULT_TOKEN", "ambient-root-token")
    seen = []

    def fake_login(self, **_):
        seen.append(self._adapter.token if hasattr(self, "_adapter") else None)
        raise RuntimeError("stop before any network call")

    monkeypatch.setattr("hvac.api.auth_methods.AppRole.login", fake_login, raising=True)

    with pytest.raises(SecretsError):
        login("http://127.0.0.1:1", "role", "secret")

    assert seen == [None]


class FailingLogoutClient:
    """Client whose revoke always fails with text that must not leak."""

    def __init__(self):
        self.token = "fake-token-value"  # noqa: S105  (fake, never sent anywhere)
        self.calls = 0

    def logout(self, revoke_token=False):
        self.calls += 1
        raise RuntimeError("http://openbao.internal:8200 token=fake-token-value")


def test_failed_revoke_raises_nothing_and_drops_the_local_token():
    client = FailingLogoutClient()

    secrets._revoke(client)

    assert client.token is None


def test_failed_revoke_does_not_replace_keys_already_read(monkeypatch, tmp_path):
    role = tmp_path / "role-id"
    secret = tmp_path / "secret-id"
    role.write_text("role")
    secret.write_text("secret")
    monkeypatch.setenv("GATEWAY_OPENBAO_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("GATEWAY_OPENBAO_ROLE_ID_FILE", str(role))
    monkeypatch.setenv("GATEWAY_OPENBAO_SECRET_ID_FILE", str(secret))
    expected = load_keys(FakeClient(good_data()))
    monkeypatch.setattr(secrets, "login", lambda *args: FailingLogoutClient())
    monkeypatch.setattr(secrets, "load_keys", lambda client: expected)
    secrets.get_gateway_keys.cache_clear()
    try:
        assert secrets.get_gateway_keys() == expected
    finally:
        secrets.get_gateway_keys.cache_clear()
