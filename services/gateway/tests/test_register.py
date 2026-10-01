import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from gateway.main import create_app

URL = "/api/auth/register"
# Fake passphrases used only by these tests.
GOOD = "correct horse battery staple"  # noqa: S105
NON_ASCII = "contraseña-ñandú-密码-🔒🔒"  # noqa: S105


@pytest.fixture
def client(db_engine):
    return TestClient(create_app())


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
    client = TestClient(create_app(), raise_server_exceptions=False)

    response = register(client)

    assert response.status_code == 500
    assert GOOD not in response.text
    db.get_engine.cache_clear()
