"""Encrypt and decrypt TOTP secrets with the OpenBao transit engine.

The encryption key (`totp`) never leaves OpenBao and the gateway's policy only
allows `encrypt` and `decrypt` with it. Each call logs in with AppRole, does
one request and revokes its token, like the key read in gateway.secrets. Every
failure raises TransitError with a fixed message and no exception context:
hvac and requests text can carry tokens or URLs, and plaintexts must never
travel with an error.
"""

import base64

from gateway import secrets

TOTP_KEY = "totp"
TRANSIT_MOUNT = "transit"
CIPHERTEXT_PREFIX = "vault:v"
FAILED = "transit operation failed"


class TransitError(RuntimeError):
    """The transit call failed. Fail closed; the app answers a fixed 503."""


def _connect():
    """Return an AppRole client, or raise TransitError (no context kept)."""
    client = None
    try:
        addr = secrets._env("GATEWAY_OPENBAO_ADDR")
        role_id = secrets._read_file(
            secrets._env("GATEWAY_OPENBAO_ROLE_ID_FILE"), "role_id"
        )
        secret_id = secrets._read_file(
            secrets._env("GATEWAY_OPENBAO_SECRET_ID_FILE"), "secret_id"
        )
        client = secrets.login(addr, role_id, secret_id)
    except Exception:
        client = None
    if client is None:
        raise TransitError(FAILED)
    return client


def encrypt_totp_secret(plaintext: bytes) -> str:
    """Return the transit ciphertext (`vault:v1:...`) of a TOTP secret."""
    client = _connect()
    ciphertext = None
    try:
        response = client.secrets.transit.encrypt_data(
            name=TOTP_KEY,
            plaintext=base64.b64encode(plaintext).decode("ascii"),
            mount_point=TRANSIT_MOUNT,
        )
        ciphertext = response["data"]["ciphertext"]
    except Exception:
        ciphertext = None
    finally:
        secrets._revoke(client)
    if not isinstance(ciphertext, str) or not ciphertext.startswith(CIPHERTEXT_PREFIX):
        raise TransitError(FAILED)
    return ciphertext


def decrypt_totp_secret(ciphertext: str) -> bytes:
    """Return the TOTP secret a transit ciphertext holds."""
    client = _connect()
    plaintext = None
    try:
        response = client.secrets.transit.decrypt_data(
            name=TOTP_KEY, ciphertext=ciphertext, mount_point=TRANSIT_MOUNT
        )
        plaintext = base64.b64decode(response["data"]["plaintext"], validate=True)
    except Exception:
        plaintext = None
    finally:
        secrets._revoke(client)
    if plaintext is None:
        raise TransitError(FAILED)
    return plaintext
