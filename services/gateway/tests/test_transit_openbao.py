"""Transit tests against a real OpenBao (see scripts/openbao-dev-init.sh)."""

import base64
import socket
import time
from pathlib import Path

import hvac
import pytest

from gateway import secrets, transit
from gateway.secrets import login
from gateway.transit import TransitError, decrypt_totp_secret, encrypt_totp_secret

PLAINTEXT = b"JBSWY3DPEHPK3PXP"


@pytest.fixture
def bao_client(openbao_env):
    role_id = Path(openbao_env["GATEWAY_OPENBAO_ROLE_ID_FILE"]).read_text().strip()
    secret_id = Path(openbao_env["GATEWAY_OPENBAO_SECRET_ID_FILE"]).read_text().strip()
    return login(openbao_env["GATEWAY_OPENBAO_ADDR"], role_id, secret_id)


def test_round_trip_returns_the_same_secret(openbao_env):
    ciphertext = encrypt_totp_secret(PLAINTEXT)

    assert decrypt_totp_secret(ciphertext) == PLAINTEXT


def test_ciphertext_is_versioned_transit_text_without_the_plaintext(openbao_env):
    ciphertext = encrypt_totp_secret(PLAINTEXT)

    assert ciphertext.startswith("vault:v1:")
    assert PLAINTEXT.decode() not in ciphertext


def test_two_encryptions_of_the_same_secret_differ(openbao_env):
    assert encrypt_totp_secret(PLAINTEXT) != encrypt_totp_secret(PLAINTEXT)


def test_gateway_token_cannot_read_the_transit_key(bao_client):
    with pytest.raises(hvac.exceptions.Forbidden):
        bao_client.secrets.transit.read_key(name="totp")


def test_gateway_token_cannot_encrypt_with_another_key(bao_client):
    with pytest.raises(hvac.exceptions.Forbidden):
        bao_client.secrets.transit.encrypt_data(
            name="other", plaintext=base64.b64encode(b"x").decode()
        )


def test_tampered_ciphertext_fails_closed(openbao_env):
    with pytest.raises(TransitError) as excinfo:
        decrypt_totp_secret("vault:v1:not-a-real-ciphertext")

    assert "not-a-real-ciphertext" not in str(excinfo.value)
    assert excinfo.value.__cause__ is None
    assert excinfo.value.__context__ is None


def test_unreachable_openbao_fails_closed(openbao_env, monkeypatch):
    monkeypatch.setenv("GATEWAY_OPENBAO_ADDR", "http://127.0.0.1:1")
    monkeypatch.setattr(secrets, "REQUEST_TIMEOUT_SECONDS", 1)

    with pytest.raises(TransitError):
        encrypt_totp_secret(PLAINTEXT)
    with pytest.raises(TransitError):
        decrypt_totp_secret("vault:v1:abc")


def test_missing_settings_fail_closed(openbao_env, monkeypatch):
    monkeypatch.delenv("GATEWAY_OPENBAO_ADDR", raising=False)

    with pytest.raises(TransitError):
        encrypt_totp_secret(PLAINTEXT)


def test_plain_http_to_a_remote_host_is_refused(openbao_env, monkeypatch):
    monkeypatch.setenv("GATEWAY_OPENBAO_ADDR", "http://openbao.example:8200")

    with pytest.raises(TransitError):
        encrypt_totp_secret(PLAINTEXT)


def test_token_is_revoked_after_each_call(openbao_env, monkeypatch):
    used = []
    real_login = secrets.login

    def capturing_login(*args):
        bao_client = real_login(*args)
        used.append(bao_client.token)
        return bao_client

    monkeypatch.setattr(secrets, "login", capturing_login)

    ciphertext = encrypt_totp_secret(PLAINTEXT)
    decrypt_totp_secret(ciphertext)

    assert len(used) == 2
    for token in used:
        probe = hvac.Client(url=openbao_env["GATEWAY_OPENBAO_ADDR"], token=token)
        assert probe.is_authenticated() is False
    assert transit.TOTP_KEY == "totp"


def test_a_slow_openbao_fails_fast_as_a_transit_error(monkeypatch):
    monkeypatch.setattr(transit, "TRANSIT_TIMEOUT_SECONDS", 1)
    # Accepts connections at TCP level but never answers: only the client
    # timeout can end the request.
    with socket.socket() as silent:
        silent.bind(("127.0.0.1", 0))
        silent.listen(1)
        monkeypatch.setenv(
            "GATEWAY_OPENBAO_ADDR", f"http://127.0.0.1:{silent.getsockname()[1]}"
        )
        started = time.monotonic()

        with pytest.raises(TransitError):
            encrypt_totp_secret(PLAINTEXT)

    assert time.monotonic() - started < 3
