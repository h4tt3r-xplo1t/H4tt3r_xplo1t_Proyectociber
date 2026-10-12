"""POST /api/auth/password and the must-change-password gate (ADR 0004, 4/5/11)."""

import logging
from datetime import timedelta

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text, update

from gateway import auth
from gateway.db import get_engine
from gateway.main import create_app
from gateway.models import User
from gateway.passwords import verify_password
from gateway.tokens import decode_access_token
from tests.test_login import (
    GOOD,
    KEYS,
    LOGIN_FAILED,
    NOT_AUTHENTICATED,
    SAME_ORIGIN,
    attempt_row,
    login,
    refresh_cookie_value,
    register,
)
from tests.test_mfa import FrozenClock, Interfere, run_sql
from tests.test_refresh import refresh, start

URL = "/api/auth/password"
ME = "/api/auth/me"
NEW = "an entirely new passphrase"
ENROLL = "/api/auth/mfa/enroll"
CONFIRM = "/api/auth/mfa/confirm"
LOGIN_MFA = "/api/auth/login/mfa"


@pytest.fixture
def clock():
    return FrozenClock()


@pytest.fixture
def client(db_engine, clock, openbao_env):
    app = create_app()
    app.dependency_overrides[auth.get_keys] = lambda: KEYS
    app.dependency_overrides[auth.get_now] = clock
    yield TestClient(app, base_url="https://testserver")
    get_engine().dispose()


def other_browser(client):
    return TestClient(client.app, base_url="https://testserver")


def change(
    client,
    current=GOOD,
    new=NEW,
    *,
    close=None,
    csrf=True,
    headers=SAME_ORIGIN,
    body=None,
):
    sent = dict(headers)
    if csrf is True:
        csrf = client.cookies.get("__Host-csrf")
    if csrf is not None:
        sent["X-CSRF-Token"] = csrf
    if body is None:
        body = {"current_password": current, "new_password": new}
        if close is not None:
            body["close_other_sessions"] = close
    return client.post(URL, json=body, headers=sent)


def post(client, path, body=None):
    return client.post(
        path,
        json=body,
        headers={**SAME_ORIGIN, "X-CSRF-Token": client.cookies.get("__Host-csrf")},
    )


def user_row(db_engine, username="alice"):
    with db_engine.connect() as conn:
        return (
            conn.execute(
                text("SELECT * FROM users WHERE username = :n"), {"n": username}
            )
            .mappings()
            .one()
        )


def set_user(db_engine, **columns):
    with db_engine.begin() as conn:
        conn.execute(update(User).values(**columns))


def claims_of(client):
    return decode_access_token(client.cookies.get("__Host-access"), KEYS)


def totp(secret, clock):
    return pyotp.TOTP(secret).at(clock())


# --- the change itself ---------------------------------------------------


def test_changes_the_password_of_a_full_session(client, db_engine):
    start(client)

    response = change(client)

    assert response.status_code == 200
    assert response.json() == {"mfa_enrollment_required": False}
    assert response.headers["cache-control"] == "no-store"
    assert verify_password(user_row(db_engine)["password_hash"], NEW)
    client.cookies.clear()
    assert login(other_browser(client)).status_code == 401
    assert login(other_browser(client), password=NEW).status_code == 200


@pytest.mark.parametrize("headers", [{}, {"Sec-Fetch-Site": "cross-site"}])
def test_requires_the_same_origin(client, db_engine, headers):
    start(client)
    old_hash = user_row(db_engine)["password_hash"]

    response = change(client, headers=headers)

    assert response.status_code == 403
    assert user_row(db_engine)["password_hash"] == old_hash


def test_requires_the_session_csrf_token(client, db_engine):
    start(client)
    old_hash = user_row(db_engine)["password_hash"]

    assert change(client, csrf=None).status_code == 403
    assert change(client, csrf="not-the-token").status_code == 403
    assert user_row(db_engine)["password_hash"] == old_hash


def test_requires_a_session(client):
    assert change(client, csrf="x").status_code == 401


def test_a_wrong_current_password_is_the_generic_401_and_is_counted(
    client, db_engine, caplog
):
    start(client)
    caplog.set_level(logging.INFO, logger="gateway.auth")
    old_hash = user_row(db_engine)["password_hash"]

    response = change(client, current="not the password at all")

    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert user_row(db_engine)["password_hash"] == old_hash
    assert attempt_row(db_engine).failures == 1
    assert "event=password_change_failure" in caplog.text
    assert "not the password at all" not in caplog.text


def test_wrong_current_passwords_lock_the_account_like_login(client, db_engine):
    start(client)
    for _ in range(4):
        assert change(client, current="wrong password here").status_code == 401

    assert attempt_row(db_engine).locked_until is not None
    # Locked: even the right current password is refused, and so is login.
    assert change(client).status_code == 401
    assert verify_password(user_row(db_engine)["password_hash"], GOOD)
    assert login(other_browser(client)).status_code == 401


@pytest.mark.parametrize(
    "new",
    [
        "tiny",
        "é" * 7,  # 14 characters once composed
        "x" * 129,
        GOOD,  # equal to the current password
    ],
)
def test_the_registration_policy_applies_to_the_new_password(
    client, db_engine, caplog, new
):
    start(client)
    old_hash = user_row(db_engine)["password_hash"]

    response = change(client, new=new)

    assert response.status_code == 422
    assert new not in response.text
    assert GOOD not in response.text
    assert user_row(db_engine)["password_hash"] == old_hash
    # Refused before anything was checked: nothing is counted.
    assert attempt_row(db_engine).failures == 0


def test_a_new_password_equal_after_normalization_is_refused(client, db_engine):
    composed = "caf\u00e9 " * 3 + "caf\u00e9"
    decomposed = "cafe\u0301 " * 3 + "cafe\u0301"
    register(client, password=composed)
    login(client, password=composed)

    response = change(client, current=composed, new=decomposed)

    assert response.status_code == 422


@pytest.mark.parametrize(
    "body",
    [
        {"new_password": NEW},
        {"current_password": GOOD},
        {"current_password": GOOD, "new_password": NEW, "role": "administrador"},
        {"current_password": GOOD, "new_password": NEW, "close_other_sessions": "x"},
    ],
)
def test_malformed_bodies_are_422(client, body):
    start(client)

    assert change(client, body=body).status_code == 422


def test_without_the_option_other_sessions_stay_valid(client, db_engine):
    start(client)
    second = other_browser(client)
    login(second)
    before = user_row(db_engine)["tokens_valid_since"]

    assert change(client).status_code == 200

    assert second.get(ME).status_code == 200
    assert user_row(db_engine)["tokens_valid_since"] == before


def test_closing_other_sessions_ends_them_and_continues_in_a_new_session(
    client, db_engine, clock
):
    session = start(client)
    second = other_browser(client)
    login(second)
    old_access = client.cookies.get("__Host-access")
    old_sid = decode_access_token(old_access, KEYS)["sid"]
    clock.now += timedelta(seconds=5)

    response = change(client, close=True)

    assert response.status_code == 200
    # The other browser is out.
    assert second.get(ME).status_code == 401
    # This one continues: fresh access token, new session id, new refresh token.
    assert client.get(ME).status_code == 200
    assert client.cookies.get("__Host-access") != old_access
    assert claims_of(client)["sid"] != old_sid
    assert user_row(db_engine)["tokens_valid_since"] == clock()
    with db_engine.connect() as conn:
        live = conn.execute(
            text("SELECT id FROM refresh_families WHERE revoked_at IS NULL")
        ).all()
    assert [str(row.id) for row in live] == [claims_of(client)["sid"]]
    assert refresh(client, session.refresh, session.csrf).status_code == 401
    new_refresh = refresh_cookie_value(response)
    assert (
        refresh(client, new_refresh, client.cookies.get("__Host-csrf")).status_code
        == 200
    )


def test_the_replaced_access_token_is_denied_even_inside_the_same_second(
    client, db_engine
):
    start(client)
    old_access = client.cookies.get("__Host-access")

    assert change(client, close=True).status_code == 200

    old_client = other_browser(client)
    old_client.cookies.set("__Host-access", old_access)
    assert old_client.get(ME).status_code == 401
    assert client.get(ME).status_code == 200


def test_events_never_carry_passwords(client, db_engine, caplog):
    start(client)
    caplog.set_level(logging.DEBUG)

    change(client, current="wrong password here")
    change(client, close=True)

    user_id = str(user_row(db_engine)["id"])
    assert f"event=password_changed subject={user_id}" in caplog.text
    assert "event=other_sessions_closed" in caplog.text
    for secret in (GOOD, NEW, "wrong password here"):
        assert secret not in caplog.text


# --- the must-change-password gate ---------------------------------------


def flag_must_change(db_engine, clock, *, role="administrador", window=True):
    until = clock() + timedelta(hours=24) if window else None
    set_user(
        db_engine,
        role=role,
        must_change_password=True,
        mfa_enroll_until=until,
        tokens_valid_since=clock(),
    )


def test_a_user_who_must_change_gets_only_the_enroll_token(client, db_engine, clock):
    register(client)
    flag_must_change(db_engine, clock)

    response = login(client)

    assert response.status_code == 200
    assert response.json() == {"status": "password_change_required"}
    assert claims_of(client)["scope"] == "enroll-mfa"
    with db_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM refresh_families")).scalar() == 0


def test_with_that_token_every_other_endpoint_answers_401(client, db_engine, clock):
    register(client)
    flag_must_change(db_engine, clock)
    login(client)

    assert client.get(ME).status_code == 401
    assert client.get(ME).json() == NOT_AUTHENTICATED
    assert refresh(client, None, client.cookies.get("__Host-csrf")).status_code == 401
    assert post(client, LOGIN_MFA, {"code": "123456"}).status_code == 401


def test_the_password_change_then_the_mfa_enrollment_complete_the_login(
    client, db_engine, clock
):
    register(client)
    flag_must_change(db_engine, clock)
    login(client)

    changed = change(client)

    assert changed.status_code == 200
    assert changed.json() == {"mfa_enrollment_required": True}
    assert user_row(db_engine)["must_change_password"] is False
    # The enroll token still works for the MFA, and only for the MFA.
    assert client.get(ME).status_code == 401
    secret = post(client, ENROLL).json()["secret"]
    confirmed = post(client, CONFIRM, {"code": totp(secret, clock)})
    assert confirmed.status_code == 200
    # Now a normal login asks for the second factor and gives a full session.
    client.cookies.clear()
    clock.now += timedelta(seconds=30)
    assert login(client, password=GOOD).status_code == 401
    assert login(client, password=NEW).json() == {"status": "mfa_required"}
    full = post(client, LOGIN_MFA, {"code": totp(secret, clock)})
    assert full.status_code == 200
    assert client.get(ME).json()["role"] == "administrador"


def test_enrolling_before_the_password_change_still_ends_in_the_gate(
    client, db_engine, clock
):
    register(client)
    flag_must_change(db_engine, clock)
    login(client)
    secret = post(client, ENROLL).json()["secret"]
    assert post(client, CONFIRM, {"code": totp(secret, clock)}).status_code == 200

    client.cookies.clear()
    clock.now += timedelta(seconds=30)
    assert login(client).json() == {"status": "mfa_required"}
    assert post(client, LOGIN_MFA, {"code": totp(secret, clock)}).status_code == 200

    # A full session exists but nothing but the password change answers.
    assert client.get(ME).status_code == 401
    assert change(client).status_code == 200
    assert client.get(ME).status_code == 200


def test_an_enroll_token_cannot_change_the_password_when_nothing_is_pending(
    client, db_engine, clock
):
    register(client)
    set_user(
        db_engine,
        role="editor",
        mfa_enroll_until=clock() + timedelta(hours=24),
        tokens_valid_since=clock(),
    )
    assert login(client).json() == {"status": "mfa_enrollment_required"}

    response = change(client)

    assert response.status_code == 401
    assert verify_password(user_row(db_engine)["password_hash"], GOOD)


def test_a_reader_who_must_change_can_change_without_a_window(client, db_engine, clock):
    register(client)
    flag_must_change(db_engine, clock, role="lector", window=False)

    assert login(client).json() == {"status": "password_change_required"}
    assert change(client).json() == {"mfa_enrollment_required": False}

    client.cookies.clear()
    assert login(client, password=NEW).status_code == 200
    assert client.get(ME).status_code == 200


def test_a_privileged_user_who_must_change_without_a_window_cannot_sign_in(
    client, db_engine, clock
):
    register(client)
    flag_must_change(db_engine, clock, window=False)

    response = login(client)

    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert "__Host-access" not in client.cookies


def test_the_enroll_token_changing_the_password_can_close_other_sessions(
    client, db_engine, clock
):
    register(client)
    flag_must_change(db_engine, clock)
    login(client)
    old_access = client.cookies.get("__Host-access")
    clock.now += timedelta(seconds=3)

    assert change(client, close=True).status_code == 200

    assert claims_of(client)["scope"] == "enroll-mfa"
    assert claims_of(client)["sid"] == decode_access_token(old_access, KEYS)["sid"]
    assert post(client, ENROLL).status_code == 200
    stale = other_browser(client)
    stale.cookies.set("__Host-access", old_access)
    stale.cookies.set("__Host-csrf", client.cookies.get("__Host-csrf"))
    assert post(stale, ENROLL).status_code == 401


def test_a_session_token_of_the_second_factor_cannot_change_the_password(
    client, db_engine, clock
):
    register(client)
    secret = None
    set_user(db_engine, role="lector")
    # Give the user MFA through the enroll path as a reader, then log in again.
    login(client)
    enrolled = post(client, ENROLL, {"current_password": GOOD})
    secret = enrolled.json()["secret"]
    assert post(client, CONFIRM, {"code": totp(secret, clock)}).status_code == 200
    client.cookies.clear()
    clock.now += timedelta(seconds=30)
    assert login(client).json() == {"status": "mfa_required"}

    assert change(client).status_code == 401
    assert verify_password(user_row(db_engine)["password_hash"], GOOD)


def test_a_privileged_session_without_mfa_cannot_change_the_password(client, db_engine):
    start(client)
    set_user(db_engine, role="editor", mfa_enabled_at=None)

    assert change(client).status_code == 401
    assert verify_password(user_row(db_engine)["password_hash"], GOOD)


def test_current_user_leaves_an_event_for_a_session_that_must_change_the_password(
    client, db_engine, clock, caplog
):
    start(client)
    set_user(db_engine, must_change_password=True)
    caplog.set_level(logging.INFO, logger="gateway.auth")

    assert client.get(ME).status_code == 401

    user_id = user_row(db_engine)["id"]
    assert f"event=session_refused_password_change_required subject={user_id}" in (
        caplog.text
    )


# --- the recheck under the second lock -----------------------------------


def test_a_password_changed_while_hashing_is_not_overwritten(
    client, db_engine, monkeypatch
):
    start(client)
    other_hash = auth.hash_password("another passphrase entirely")
    monkeypatch.setattr(
        auth,
        "hash_password",
        Interfere(
            auth.hash_password,
            lambda: run_sql(
                db_engine, "UPDATE users SET password_hash = :h", h=other_hash
            ),
        ),
    )

    response = change(client)

    assert response.status_code == 401
    assert response.json() == NOT_AUTHENTICATED
    assert user_row(db_engine)["password_hash"] == other_hash


def test_a_lifted_duty_while_hashing_refuses_the_enroll_session(
    client, db_engine, clock, monkeypatch
):
    register(client)
    flag_must_change(db_engine, clock)
    login(client)
    assert "scope" in claims_of(client)
    monkeypatch.setattr(
        auth,
        "hash_password",
        Interfere(
            auth.hash_password,
            lambda: run_sql(db_engine, "UPDATE users SET must_change_password = false"),
        ),
    )

    response = change(client)

    assert response.status_code == 401
    assert response.json() == NOT_AUTHENTICATED
    assert verify_password(user_row(db_engine)["password_hash"], GOOD)
