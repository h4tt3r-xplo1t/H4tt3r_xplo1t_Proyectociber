"""Read the gateway's signing and CSRF keys from OpenBao.

The gateway logs in with AppRole (role_id and secret_id come from files, never
from the environment itself) and reads two KV v2 secrets. Every failure raises
SecretsError with a fixed message: error text from the server or the HTTP
library can carry tokens or URLs, so it is never copied.
"""

import base64
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

import hvac

MIN_KEY_BYTES = 32
REQUEST_TIMEOUT_SECONDS = 5
KV_MOUNT = "secret"
JWT_PATH = "gateway/jwt"
CSRF_PATH = "gateway/csrf"
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class SecretsError(RuntimeError):
    """The keys could not be obtained or are not acceptable. Fail closed."""


@dataclass(frozen=True)
class GatewayKeys:
    jwt_kid: str
    jwt_key: bytes = field(repr=False)
    csrf_key: bytes = field(repr=False)

    def __str__(self) -> str:
        return repr(self)


def _read(client, path: str) -> dict:
    # The raise happens outside the except block so the SecretsError carries
    # neither __cause__ nor __context__: hvac and requests text (URLs, tokens)
    # never travels with it.
    data = None
    failed = False
    try:
        response = client.secrets.kv.v2.read_secret_version(
            path=path, mount_point=KV_MOUNT, raise_on_deleted_version=True
        )
        data = response["data"]["data"]
    except Exception:
        failed = True
    if failed:
        raise SecretsError(f"could not read secret {path!r} from OpenBao")
    if not isinstance(data, dict):
        raise SecretsError(f"secret {path!r} has an unexpected shape")
    return data


def _decode_key(data: dict, path: str) -> bytes:
    value = data.get("key")
    if not isinstance(value, str) or not value:
        raise SecretsError(f"secret {path!r} has no 'key' field")
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError:  # binascii.Error is a ValueError
        raise SecretsError(f"secret {path!r} key is not valid base64") from None
    if len(raw) < MIN_KEY_BYTES:
        raise SecretsError(f"secret {path!r} key is shorter than {MIN_KEY_BYTES} bytes")
    return raw


def load_keys(client) -> GatewayKeys:
    jwt = _read(client, JWT_PATH)
    csrf = _read(client, CSRF_PATH)
    kid = jwt.get("kid")
    if not isinstance(kid, str) or not kid.strip():
        raise SecretsError(f"secret {JWT_PATH!r} has no 'kid' field")
    return GatewayKeys(
        jwt_kid=kid,
        jwt_key=_decode_key(jwt, JWT_PATH),
        csrf_key=_decode_key(csrf, CSRF_PATH),
    )


def _env(name: str) -> str:
    # No defaults on purpose, like GATEWAY_DATABASE_URL.
    value = os.environ.get(name)
    if not value:
        raise SecretsError(f"{name} is not set")
    return value


def _read_file(path: str, what: str) -> str:
    try:
        value = Path(path).read_text().strip()
    except OSError:
        raise SecretsError(f"could not read the {what} file") from None
    if not value:
        raise SecretsError(f"the {what} file is empty")
    return value


def _check_address(addr: str) -> None:
    """Allow plain HTTP only on loopback: credentials must not cross a network."""
    try:
        parsed = urlparse(addr)
        scheme, host = parsed.scheme, parsed.hostname
    except ValueError:
        scheme, host = "", None
    if scheme == "https" and host:
        return
    if scheme == "http" and host in LOOPBACK_HOSTS:
        return
    raise SecretsError(
        "GATEWAY_OPENBAO_ADDR must use https (plain http only on loopback)"
    )


def login(addr: str, role_id: str, secret_id: str):
    """Return an hvac client authenticated with AppRole."""
    _check_address(addr)
    # hvac copies VAULT_TOKEN (or ~/.vault-token) into the client even with
    # token=None, so the token is cleared explicitly right after: this client
    # must only ever hold its own AppRole token.
    client = hvac.Client(url=addr, token=None, timeout=REQUEST_TIMEOUT_SECONDS)
    client.token = None
    authenticated = False
    try:
        client.auth.approle.login(role_id=role_id, secret_id=secret_id)
        authenticated = bool(client.is_authenticated())
    except Exception:
        authenticated = False
    if not authenticated:
        raise SecretsError("AppRole login to OpenBao failed")
    return client


def _revoke(client) -> None:
    """Best effort: drop the token once the keys are read. No error text kept.

    A failed revoke must not replace keys already read nor leak hvac or
    requests text; the token still expires on its own (15 min TTL).
    """
    try:
        client.logout(revoke_token=True)
    except Exception:
        client.token = None


@lru_cache
def get_gateway_keys() -> GatewayKeys:
    """Fetch the keys on first use, so the app starts without OpenBao."""
    addr = _env("GATEWAY_OPENBAO_ADDR")
    role_id = _read_file(_env("GATEWAY_OPENBAO_ROLE_ID_FILE"), "role_id")
    secret_id = _read_file(_env("GATEWAY_OPENBAO_SECRET_ID_FILE"), "secret_id")
    client = login(addr, role_id, secret_id)
    try:
        return load_keys(client)
    finally:
        _revoke(client)
