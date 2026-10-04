import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from gateway import passwords
from gateway.db import get_engine
from gateway.main import create_app
from gateway.passwords import verify_password

URL = "/api/auth/register"
SAME_ORIGIN = {"Sec-Fetch-Site": "same-origin"}
# Fake passphrases used only by these tests.
GOOD = "correct horse battery staple"  # noqa: S105
NON_ASCII = "contraseña-ñandú-密码-🔒🔒"  # noqa: S105


@pytest.fixture
def client(db_engine):
    yield TestClient(create_app(), headers=SAME_ORIGIN)
    # The app's cached engine keeps pooled connections open; close them so
    # psycopg does not warn about connections left open at exit.
    get_engine().dispose()


def register(client, username="alice", password=GOOD):
    return client.post(URL, json={"username": username, "password": password})


def test_register_returns_201_with_public_fields_only(client):
    response = register(client)

    assert response.status_code == 201
    body = response.json()
    assert set(body) == {"id", "username", "role"}
    assert body["username"] == "alice"
    assert body["role"] == "lector"
    assert "argon2" not in response.text


def test_stored_hash_is_argon2id_with_adr_parameters(client, db_engine):
    register(client)

    with db_engine.connect() as conn:
        stored = conn.execute(text("SELECT password_hash FROM users")).scalar_one()
    assert stored.startswith("$argon2id$")
    assert "m=19456,t=2,p=1" in stored
    assert GOOD not in stored


def test_short_password_is_rejected_with_422(client):
    assert register(client, password="x" * 14).status_code == 422


@pytest.mark.parametrize("length", [15, 64, 128])
def test_password_lengths_within_bounds_are_accepted(client, length):
    assert register(client, password="p" * length).status_code == 201


def test_password_over_128_chars_is_rejected(client):
    assert register(client, password="p" * 129).status_code == 422


def test_non_ascii_password_is_accepted(client):
    assert register(client, password=NON_ASCII).status_code == 201


@pytest.mark.parametrize(
    "username",
    ["ab", "a" * 33, "Alice", "bad name", "bad/name", "ñandu", "x;drop", ""],
)
def test_invalid_username_is_rejected_with_422(client, username):
    assert register(client, username=username).status_code == 422


@pytest.mark.parametrize("username", ["abc", "a" * 32, "a.b_c-1"])
def test_valid_usernames_are_accepted(client, username):
    assert register(client, username=username).status_code == 201


def test_duplicate_username_returns_generic_409(client):
    register(client)
    response = register(client)

    assert response.status_code == 409
    assert response.json() == {"detail": "Username not available"}


def test_role_in_the_body_is_rejected_and_no_user_is_created(client, db_engine):
    response = client.post(
        URL, json={"username": "mallory", "password": GOOD, "role": "administrador"}
    )

    assert response.status_code == 422
    with db_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM users")).scalar_one() == 0


def test_password_never_appears_in_error_bodies(client):
    secret = "q" * 14  # too short, so the request is rejected
    response = register(client, password=secret)

    assert response.status_code == 422
    assert secret not in response.text


def test_password_never_appears_when_username_is_invalid(client):
    response = register(client, username="BAD NAME", password=GOOD)

    assert response.status_code == 422
    assert GOOD not in response.text


def test_password_never_appears_on_success_or_conflict(client):
    created = register(client)
    conflict = register(client)

    assert GOOD not in created.text
    assert GOOD not in conflict.text


def test_malformed_body_is_rejected_without_echo(client):
    response = client.post(URL, content=GOOD, headers={"content-type": "text/plain"})

    assert response.status_code == 422
    assert GOOD not in response.text


def test_missing_database_url_fails_closed(monkeypatch):
    monkeypatch.delenv("GATEWAY_DATABASE_URL", raising=False)
    from gateway import db

    db.get_engine.cache_clear()
    client = TestClient(
        create_app(), raise_server_exceptions=False, headers=SAME_ORIGIN
    )

    response = register(client)

    assert response.status_code == 500
    assert GOOD not in response.text
    db.get_engine.cache_clear()


def test_non_unique_db_error_does_not_carry_the_hash(client, monkeypatch):
    # A CHECK violation makes PostgreSQL add "DETAIL: Failing row contains
    # (...)" with the whole row, hash included. That text must not reach
    # the error that the server logs.
    import traceback

    import gateway.auth
    from gateway.models import User

    def user_with_invalid_role(**kwargs):
        return User(role="intruso", **kwargs)

    monkeypatch.setattr(gateway.auth, "User", user_with_invalid_role)

    with pytest.raises(RuntimeError, match=r"sqlstate 23514") as excinfo:
        register(client)

    logged = "".join(traceback.format_exception(excinfo.value))
    assert "$argon2id$" not in logged
    assert "Failing row" not in logged


def test_register_hashes_the_nfc_form_of_the_password(client, db_engine):
    decomposed = "contrase\u0301a-muy-larga-123"  # "e" + combining acute
    precomposed = "contrase\u0301a-muy-larga-123".replace("e\u0301", "\u00e9")
    assert decomposed != precomposed
    register(client, password=decomposed)

    with db_engine.connect() as conn:
        stored = conn.execute(text("SELECT password_hash FROM users")).scalar_one()
    assert verify_password(stored, precomposed) is True


def test_register_answers_503_when_hashing_is_saturated(client, monkeypatch, caplog):
    monkeypatch.setattr(passwords, "HASH_WAIT_SECONDS", 0.05)
    for _ in range(passwords.MAX_CONCURRENT_HASHES):
        passwords._slots.acquire()
    try:
        response = register(client)
    finally:
        for _ in range(passwords.MAX_CONCURRENT_HASHES):
            passwords._slots.release()

    assert response.status_code == 503
    assert response.json() == {"detail": "Service busy; try again later"}
    assert GOOD not in response.text
    assert "event=service_busy cause=hash_saturated" in caplog.text


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Origin": "https://evil.example"},
        {"Sec-Fetch-Site": "cross-site"},
        {"Sec-Fetch-Site": "cross-site", "Origin": "https://testserver"},
        {"Sec-Fetch-Site": "same-site"},
    ],
)
def test_register_fails_closed_without_a_same_origin_signal(db_engine, headers):
    client = TestClient(create_app())

    response = client.post(
        URL, json={"username": "alice", "password": GOOD}, headers=headers
    )

    assert response.status_code == 403
    with db_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM users")).scalar_one() == 0
    get_engine().dispose()


def test_register_accepts_the_allowed_origin_when_sec_fetch_site_is_missing(db_engine):
    client = TestClient(create_app())

    response = client.post(
        URL,
        json={"username": "alice", "password": GOOD},
        headers={"Origin": "https://testserver"},
    )

    assert response.status_code == 201
    get_engine().dispose()
