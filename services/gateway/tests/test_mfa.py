"""TOTP enrollment and the second factor at login (ADR 0004, decisions 4, 8, 11).

These tests use the real OpenBao transit engine (see scripts/openbao-dev-init.sh)
and a frozen clock that starts at the beginning of a TOTP step, so the step
arithmetic is deterministic.
"""

import logging
import re
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from gateway import auth, secrets
from gateway.db import get_engine
from gateway.main import create_app
from gateway.tokens import decode_access_token, issue_access_token, make_csrf
from tests.test_login import (
    GOOD,
    KEYS,
    LOGIN_FAILED,
    OTHER,
    SAME_ORIGIN,
    attempt_row,
    get_csrf,
    login,
    register,
)

ENROLL = "/api/auth/mfa/enroll"
CONFIRM = "/api/auth/mfa/confirm"
LOGIN_MFA = "/api/auth/login/mfa"
NOT_AUTHENTICATED = {"detail": "Not authenticated"}
RECOVERY_FORMAT = re.compile(r"^[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}$")


class FrozenClock:
    """A 'now' that only moves when a test says so, set at the start of a step."""

    def __init__(self):
        real = datetime.now(UTC).replace(microsecond=0)
        self.now = real - timedelta(seconds=int(real.timestamp()) % 30)

    def __call__(self):
        return self.now


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


def post(client, path, body=None, *, csrf=True, headers=SAME_ORIGIN):
    sent = dict(headers)
    if csrf is True:
        csrf = client.cookies.get("__Host-csrf")
    if csrf is not None:
        sent["X-CSRF-Token"] = csrf
    return client.post(path, json=body, headers=sent)


def totp(secret, clock, offset=0):
    return pyotp.TOTP(secret).at(clock(), offset)


def make_user(client, db_engine, clock, username="alice", role="editor", window=True):
    """Register a user and give it a role and, by default, an open enroll window."""
    register(client, username)
    until = clock() + timedelta(hours=24) if window else None
    with db_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE users SET role = :r, mfa_enroll_until = :u WHERE username = :n"
            ),
            {"r": role, "u": until, "n": username},
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


def enroll(client, db_engine, clock, username="alice", role="editor"):
    """Run the whole enrollment; return the TOTP secret and the recovery codes."""
    make_user(client, db_engine, clock, username, role)
    response = login(client, username)
    assert response.json() == {"status": "mfa_enrollment_required"}
    secret = post(client, ENROLL).json()["secret"]
    response = post(client, CONFIRM, {"code": totp(secret, clock)})
    assert response.status_code == 200
    return secret, response.json()["recovery_codes"]


def to_pending(client, username="alice"):
    response = login(client, username)
    assert response.status_code == 200
    assert response.json() == {"status": "mfa_required"}


def clear_replay_guard(db_engine):
    with db_engine.begin() as conn:
        conn.execute(text("UPDATE users SET mfa_last_step = NULL"))


def access_claims(client):
    return decode_access_token(client.cookies.get("__Host-access"), KEYS)


# --- enrollment-required login -------------------------------------------


def test_privileged_login_without_mfa_only_gets_an_enroll_token(
    client, db_engine, clock
):
    make_user(client, db_engine, clock)

    response = login(client)

    assert response.status_code == 200
    assert response.json() == {"status": "mfa_enrollment_required"}
    assert response.headers["cache-control"] == "no-store"
    claims = access_claims(client)
    assert claims["scope"] == "enroll-mfa"
    assert claims["exp"] - claims["iat"] == 600
    cookies = response.headers.get_list("set-cookie")
    assert not any(c.startswith("__Secure-refresh=") for c in cookies)
    with db_engine.connect() as conn:
        families = conn.execute(text("SELECT count(*) FROM refresh_families")).scalar()
    assert families == 0
    # The sid is its own random id and the CSRF cookie is bound to it.
    assert claims["sid"] != str(user_row(db_engine)["id"])
    uuid.UUID(claims["sid"])


@pytest.mark.parametrize("role", ["editor", "auditor", "administrador"])
def test_every_privileged_role_must_enroll(client, db_engine, clock, role):
    make_user(client, db_engine, clock, role=role)

    assert login(client).json() == {"status": "mfa_enrollment_required"}


def test_privileged_login_without_a_deadline_is_the_generic_401(
    client, db_engine, clock
):
    make_user(client, db_engine, clock, window=False)

    response = login(client)

    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert attempt_row(db_engine).failures == 1
    assert "__Host-access" not in client.cookies


def test_privileged_login_past_the_deadline_is_the_generic_401(
    client, db_engine, clock
):
    make_user(client, db_engine, clock)
    clock.now += timedelta(hours=24, seconds=1)

    response = login(client)

    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert attempt_row(db_engine).failures == 1


def test_lector_without_mfa_still_gets_a_normal_session(client, db_engine, clock):
    register(client)

    response = login(client)

    assert response.status_code == 200
    assert response.json()["role"] == "lector"
    assert "scope" not in access_claims(client)


def test_scoped_tokens_cannot_use_the_normal_session(client, db_engine, clock):
    make_user(client, db_engine, clock)
    login(client)

    assert client.get("/api/auth/me").status_code == 401


def test_a_token_with_any_unknown_scope_is_not_a_session(client, db_engine, clock):
    register(client)
    user = user_row(db_engine)
    family_id = uuid.uuid4()
    with db_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO refresh_families (id, user_id) VALUES (:i, :u)"),
            {"i": family_id, "u": user["id"]},
        )
    token, _ = issue_access_token(
        user["id"], "lector", str(family_id), KEYS, clock(), scope="other"
    )

    client.cookies.clear()
    client.cookies.set("__Host-access", token)
    response = client.get("/api/auth/me")

    assert response.status_code == 401


def test_enroll_token_is_refused_once_tokens_are_invalidated(client, db_engine, clock):
    make_user(client, db_engine, clock)
    login(client)
    with db_engine.begin() as conn:
        conn.execute(
            text("UPDATE users SET tokens_valid_since = :t"),
            {"t": clock() + timedelta(seconds=5)},
        )

    assert post(client, ENROLL).status_code == 401


def test_enroll_token_is_refused_once_its_jti_is_denied(client, db_engine, clock):
    make_user(client, db_engine, clock)
    login(client)
    claims = access_claims(client)
    with db_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO revoked_jtis (jti, expires_at) VALUES (:j, :e)"),
            {"j": claims["jti"], "e": clock() + timedelta(minutes=10)},
        )

    assert post(client, ENROLL).status_code == 401


# --- enroll ---------------------------------------------------------------


def test_enroll_returns_the_secret_once_and_stores_only_ciphertext(
    client, db_engine, clock
):
    make_user(client, db_engine, clock)
    login(client)

    response = post(client, ENROLL)

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert set(body) == {"otpauth_uri", "secret"}
    parsed = pyotp.parse_uri(body["otpauth_uri"])
    assert parsed.secret == body["secret"]
    assert parsed.issuer == "h4tt3r-1nf0rm4t1v0"
    assert parsed.name == "alice"
    row = user_row(db_engine)
    assert row["mfa_pending_ciphertext"].startswith("vault:v1:")
    assert body["secret"] not in row["mfa_pending_ciphertext"]
    assert row["mfa_secret_ciphertext"] is None
    assert row["mfa_enabled_at"] is None


def test_each_enroll_generates_a_new_secret(client, db_engine, clock):
    make_user(client, db_engine, clock)
    login(client)

    first = post(client, ENROLL).json()["secret"]
    second = post(client, ENROLL).json()["secret"]

    assert first != second
    assert len(first) >= 32


@pytest.mark.parametrize(
    ("headers", "csrf", "status"),
    [
        ({}, True, 403),
        ({"Sec-Fetch-Site": "cross-site"}, True, 403),
        (SAME_ORIGIN, None, 403),
        (SAME_ORIGIN, "forged.1.deadbeef", 403),
    ],
)
def test_enroll_needs_same_origin_and_its_csrf_token(
    client, db_engine, clock, headers, csrf, status
):
    make_user(client, db_engine, clock)
    login(client)

    response = post(client, ENROLL, csrf=csrf, headers=headers)

    assert response.status_code == status
    assert user_row(db_engine)["mfa_pending_ciphertext"] is None


def test_enroll_without_a_token_is_401(client):
    assert post(client, ENROLL, csrf="x").status_code == 401


def test_the_pre_session_csrf_token_is_not_enough_to_enroll(client, db_engine, clock):
    make_user(client, db_engine, clock)
    login(client)
    pre_session = get_csrf(client)  # replaces the cookie with the other binding

    assert post(client, ENROLL, csrf=pre_session).status_code == 403


def test_enroll_refuses_a_user_with_mfa_active(client, db_engine, clock):
    enroll(client, db_engine, clock)
    to_pending(client)

    assert post(client, ENROLL).status_code == 401  # pending token, wrong scope


def test_enroll_when_mfa_is_already_enabled_is_a_conflict(client, db_engine, clock):
    register(client)
    login(client)
    post(client, CONFIRM, {"code": "000000"})
    with db_engine.begin() as conn:
        conn.execute(text("UPDATE users SET mfa_enabled_at = now()"))

    assert post(client, ENROLL).status_code == 409


# --- confirm --------------------------------------------------------------


def test_confirm_activates_mfa_and_returns_ten_recovery_codes_once(
    client, db_engine, clock
):
    make_user(client, db_engine, clock)
    login(client)
    secret = post(client, ENROLL).json()["secret"]
    pending = user_row(db_engine)["mfa_pending_ciphertext"]

    response = post(client, CONFIRM, {"code": totp(secret, clock)})

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    codes = response.json()["recovery_codes"]
    assert len(codes) == len(set(codes)) == 10
    assert all(RECOVERY_FORMAT.match(c) for c in codes)
    row = user_row(db_engine)
    assert row["mfa_secret_ciphertext"] == pending
    assert row["mfa_pending_ciphertext"] is None
    assert row["mfa_enroll_until"] is None
    assert row["mfa_enabled_at"] == clock()
    assert row["mfa_last_step"] == pyotp.TOTP(secret).timecode(clock())
    with db_engine.connect() as conn:
        hashes = conn.execute(text("SELECT code_hash FROM recovery_codes")).scalars()
        hashes = list(hashes)
    assert len(hashes) == 10
    assert all(h.startswith("$argon2id$") for h in hashes)
    assert not any(code in h for code in codes for h in hashes)


def test_confirm_ends_the_enroll_session_of_a_privileged_user(client, db_engine, clock):
    make_user(client, db_engine, clock)
    login(client)
    secret = post(client, ENROLL).json()["secret"]
    enroll_token = client.cookies.get("__Host-access")
    enroll_csrf = client.cookies.get("__Host-csrf")

    response = post(client, CONFIRM, {"code": totp(secret, clock)})

    assert response.status_code == 200
    # The token is denied: a copy of it cannot enroll or confirm again.
    client.cookies.clear()
    client.cookies.set("__Host-access", enroll_token)
    client.cookies.set("__Host-csrf", enroll_csrf)
    again = post(client, ENROLL)
    assert again.status_code == 401
    with db_engine.connect() as conn:
        denied = conn.execute(text("SELECT count(*) FROM revoked_jtis")).scalar()
    assert denied == 1


@pytest.mark.parametrize(("offset", "accepted"), [(-1, True), (0, True), (1, True)])
def test_confirm_accepts_one_step_either_side(
    client, db_engine, clock, offset, accepted
):
    make_user(client, db_engine, clock)
    login(client)
    secret = post(client, ENROLL).json()["secret"]

    response = post(client, CONFIRM, {"code": totp(secret, clock, offset)})

    assert (response.status_code == 200) is accepted


@pytest.mark.parametrize("offset", [-2, 2])
def test_confirm_rejects_two_steps_away(client, db_engine, clock, offset):
    make_user(client, db_engine, clock)
    login(client)
    secret = post(client, ENROLL).json()["secret"]

    response = post(client, CONFIRM, {"code": totp(secret, clock, offset)})

    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert user_row(db_engine)["mfa_enabled_at"] is None


def test_wrong_confirm_codes_count_and_lock_the_account(client, db_engine, clock):
    make_user(client, db_engine, clock)
    login(client)
    secret = post(client, ENROLL).json()["secret"]
    wrong = totp(secret, clock, 2)

    for _ in range(4):
        assert post(client, CONFIRM, {"code": wrong}).status_code == 401

    row = attempt_row(db_engine)
    assert row.failures == 4
    assert row.locked_until == clock() + timedelta(minutes=1)
    # Locked: even the right code gets the generic 401.
    response = post(client, CONFIRM, {"code": totp(secret, clock)})
    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert user_row(db_engine)["mfa_enabled_at"] is None


def test_locked_confirm_does_not_decrypt_anything(
    client, db_engine, clock, monkeypatch
):
    make_user(client, db_engine, clock)
    login(client)
    secret = post(client, ENROLL).json()["secret"]
    for _ in range(4):
        post(client, CONFIRM, {"code": totp(secret, clock, 2)})

    def boom(_):
        raise AssertionError("transit must not be called for a locked account")

    monkeypatch.setattr(auth, "decrypt_totp_secret", boom)

    assert post(client, CONFIRM, {"code": totp(secret, clock)}).status_code == 401


def test_confirm_without_a_pending_secret_is_a_conflict(client, db_engine, clock):
    make_user(client, db_engine, clock)
    login(client)

    assert post(client, CONFIRM, {"code": "123456"}).status_code == 409


@pytest.mark.parametrize("code", ["", "12345", "1234567", "abcdef", "12 456", None])
def test_confirm_validates_the_code_shape(client, db_engine, clock, code):
    make_user(client, db_engine, clock)
    login(client)
    post(client, ENROLL)

    response = post(client, CONFIRM, {"code": code})

    assert response.status_code == 422
    assert "detail" in response.json()


def test_confirm_needs_same_origin_and_csrf(client, db_engine, clock):
    make_user(client, db_engine, clock)
    login(client)
    secret = post(client, ENROLL).json()["secret"]
    body = {"code": totp(secret, clock)}

    assert post(client, CONFIRM, body, headers={}).status_code == 403
    assert post(client, CONFIRM, body, csrf=None).status_code == 403
    assert user_row(db_engine)["mfa_enabled_at"] is None


def test_lector_can_enroll_from_a_normal_session(client, db_engine, clock):
    register(client)
    assert login(client).json()["role"] == "lector"

    secret = post(client, ENROLL, {"current_password": GOOD}).json()["secret"]
    response = post(client, CONFIRM, {"code": totp(secret, clock)})

    assert response.status_code == 200
    assert len(response.json()["recovery_codes"]) == 10
    assert response.json()["relogin_required"] is True
    assert user_row(db_engine)["mfa_enabled_at"] is not None


def second_client(client):
    """Another browser: same app, its own cookie jar."""
    return TestClient(client.app, base_url="https://testserver")


@pytest.mark.parametrize("body", [None, {}, {"current_password": OTHER}])
def test_full_session_enroll_needs_the_current_password(client, db_engine, clock, body):
    register(client)
    login(client)

    response = post(client, ENROLL, body)

    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert user_row(db_engine)["mfa_pending_ciphertext"] is None
    assert attempt_row(db_engine).failures == 1


def test_wrong_passwords_at_enroll_lock_the_account(client, db_engine, clock):
    register(client)
    login(client)

    for _ in range(4):
        post(client, ENROLL, {"current_password": OTHER})

    assert attempt_row(db_engine).locked_until == clock() + timedelta(minutes=1)
    # Locked: even the right password gets the generic 401.
    assert post(client, ENROLL, {"current_password": GOOD}).status_code == 401


def test_the_enroll_token_flow_does_not_ask_for_the_password(client, db_engine, clock):
    make_user(client, db_engine, clock)
    login(client)

    assert post(client, ENROLL).status_code == 200


@pytest.mark.parametrize("role", ["lector", "editor"])
def test_confirm_ends_every_session_of_the_user(client, db_engine, clock, role):
    make_user(client, db_engine, clock, role=role)
    other = second_client(client)
    if role == "lector":
        login(other)  # a pre-existing full session in another browser
        assert other.get("/api/auth/me").status_code == 200
        login(client)
        body = {"current_password": GOOD}
    else:
        login(client)
        body = None
    secret = post(client, ENROLL, body).json()["secret"]
    access, csrf = (
        client.cookies.get("__Host-access"),
        client.cookies.get("__Host-csrf"),
    )

    response = post(client, CONFIRM, {"code": totp(secret, clock)})

    assert response.status_code == 200
    assert response.json()["relogin_required"] is True
    assert user_row(db_engine)["tokens_valid_since"] == clock()
    # The presented token is denied and the cookies are cleared.
    cleared = [c for c in response.headers.get_list("set-cookie") if "Max-Age=0" in c]
    assert any(c.startswith("__Host-access=") for c in cleared)
    client.cookies.clear()
    client.cookies.set("__Host-access", access)
    client.cookies.set("__Host-csrf", csrf)
    assert client.get("/api/auth/me").status_code == 401
    if role == "lector":
        assert other.get("/api/auth/me").status_code == 401
        refreshed = other.post(
            "/api/auth/refresh",
            headers={**SAME_ORIGIN, "X-CSRF-Token": other.cookies.get("__Host-csrf")},
        )
        assert refreshed.status_code == 401
        with db_engine.connect() as conn:
            live = conn.execute(
                text("SELECT count(*) FROM refresh_families WHERE revoked_at IS NULL")
            ).scalar()
        assert live == 0


def test_other_roles_cannot_enroll_from_a_normal_session(client, db_engine, clock):
    register(client)
    login(client)
    with db_engine.begin() as conn:
        conn.execute(text("UPDATE users SET role = 'editor'"))

    assert post(client, ENROLL).status_code == 403


def test_transit_down_gives_a_fixed_503_on_enroll(
    client, db_engine, clock, monkeypatch
):
    make_user(client, db_engine, clock)
    login(client)
    monkeypatch.setenv("GATEWAY_OPENBAO_ADDR", "http://127.0.0.1:1")
    monkeypatch.setattr(secrets, "REQUEST_TIMEOUT_SECONDS", 1)

    response = post(client, ENROLL)

    assert response.status_code == 503
    assert response.json() == {"detail": "Service busy; try again later"}
    assert user_row(db_engine)["mfa_pending_ciphertext"] is None


def test_transit_down_gives_a_fixed_503_on_confirm_and_counts_nothing(
    client, db_engine, clock, monkeypatch
):
    make_user(client, db_engine, clock)
    login(client)
    secret = post(client, ENROLL).json()["secret"]
    monkeypatch.setenv("GATEWAY_OPENBAO_ADDR", "http://127.0.0.1:1")
    monkeypatch.setattr(secrets, "REQUEST_TIMEOUT_SECONDS", 1)

    response = post(client, CONFIRM, {"code": totp(secret, clock)})

    assert response.status_code == 503
    assert response.json() == {"detail": "Service busy; try again later"}
    assert attempt_row(db_engine).failures == 0
    assert user_row(db_engine)["mfa_enabled_at"] is None


# --- second factor at login ----------------------------------------------


def test_login_with_mfa_only_gets_a_pending_token(client, db_engine, clock):
    enroll(client, db_engine, clock)

    response = login(client)

    assert response.status_code == 200
    assert response.json() == {"status": "mfa_required"}
    assert response.headers["cache-control"] == "no-store"
    claims = access_claims(client)
    assert claims["scope"] == "mfa-pending"
    assert claims["exp"] - claims["iat"] == 300
    assert not any(
        c.startswith("__Secure-refresh=")
        for c in response.headers.get_list("set-cookie")
    )
    assert client.get("/api/auth/me").status_code == 401


def test_lector_with_mfa_is_asked_for_the_second_factor_too(client, db_engine, clock):
    register(client)
    login(client)
    secret = post(client, ENROLL, {"current_password": GOOD}).json()["secret"]
    post(client, CONFIRM, {"code": totp(secret, clock)})

    assert login(client).json() == {"status": "mfa_required"}


def test_password_step_does_not_reset_the_counter_when_mfa_is_pending(
    client, db_engine, clock
):
    enroll(client, db_engine, clock)
    login(client, password=OTHER)
    assert attempt_row(db_engine).failures == 1

    to_pending(client)

    assert attempt_row(db_engine).failures == 1


def test_a_good_totp_completes_the_login_like_a_password_login(
    client, db_engine, clock
):
    secret, _ = enroll(client, db_engine, clock)
    login(client, password=OTHER)
    to_pending(client)
    pending_jti = access_claims(client)["jti"]
    clear_replay_guard(db_engine)

    response = post(client, LOGIN_MFA, {"code": totp(secret, clock)})

    assert response.status_code == 200
    assert response.json()["username"] == "alice"
    assert response.headers["cache-control"] == "no-store"
    cookies = response.headers.get_list("set-cookie")
    assert any(c.startswith("__Secure-refresh=") for c in cookies)
    assert "scope" not in access_claims(client)
    assert client.get("/api/auth/me").status_code == 200
    row = attempt_row(db_engine)
    assert (row.failures, row.locked_until) == (0, None)
    with db_engine.connect() as conn:
        denied = conn.execute(text("SELECT jti FROM revoked_jtis")).scalars().all()
        families = conn.execute(text("SELECT count(*) FROM refresh_families")).scalar()
    assert pending_jti in denied
    assert families == 1


def test_the_pending_token_is_single_use(client, db_engine, clock):
    secret, _ = enroll(client, db_engine, clock)
    to_pending(client)
    pending = client.cookies.get("__Host-access")
    csrf = client.cookies.get("__Host-csrf")
    clear_replay_guard(db_engine)
    assert post(client, LOGIN_MFA, {"code": totp(secret, clock)}).status_code == 200

    client.cookies.clear()
    client.cookies.set("__Host-access", pending)
    client.cookies.set("__Host-csrf", csrf)
    again = post(client, LOGIN_MFA, {"code": totp(secret, clock, 1)})

    assert again.status_code == 401


@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_login_accepts_one_step_either_side(client, db_engine, clock, offset):
    secret, _ = enroll(client, db_engine, clock)
    to_pending(client)
    clear_replay_guard(db_engine)

    response = post(client, LOGIN_MFA, {"code": totp(secret, clock, offset)})

    assert response.status_code == 200


@pytest.mark.parametrize("offset", [-2, 2])
def test_login_rejects_two_steps_away(client, db_engine, clock, offset):
    secret, _ = enroll(client, db_engine, clock)
    to_pending(client)
    clear_replay_guard(db_engine)

    response = post(client, LOGIN_MFA, {"code": totp(secret, clock, offset)})

    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert attempt_row(db_engine).failures == 1


def test_a_totp_step_is_accepted_once(client, db_engine, clock):
    secret, _ = enroll(client, db_engine, clock)
    code = totp(secret, clock, 1)
    to_pending(client)
    assert post(client, LOGIN_MFA, {"code": code}).status_code == 200
    step = user_row(db_engine)["mfa_last_step"]
    assert step == pyotp.TOTP(secret).timecode(clock()) + 1

    to_pending(client)
    replay = post(client, LOGIN_MFA, {"code": code})

    assert replay.status_code == 401
    assert replay.json() == LOGIN_FAILED


def test_the_confirm_code_cannot_be_replayed_at_login(client, db_engine, clock):
    secret, _ = enroll(client, db_engine, clock)
    to_pending(client)

    response = post(client, LOGIN_MFA, {"code": totp(secret, clock)})

    assert response.status_code == 401


def test_an_older_step_than_the_last_one_is_rejected(client, db_engine, clock):
    secret, _ = enroll(client, db_engine, clock)
    with db_engine.begin() as conn:
        conn.execute(text("UPDATE users SET mfa_last_step = mfa_last_step + 1"))
    to_pending(client)

    assert post(client, LOGIN_MFA, {"code": totp(secret, clock)}).status_code == 401


def test_a_recovery_code_works_once(client, db_engine, clock):
    _, codes = enroll(client, db_engine, clock)
    to_pending(client)

    first = post(client, LOGIN_MFA, {"code": codes[0]})

    assert first.status_code == 200
    assert client.get("/api/auth/me").status_code == 200
    with db_engine.connect() as conn:
        used = conn.execute(
            text("SELECT count(*) FROM recovery_codes WHERE used_at IS NOT NULL")
        ).scalar()
    assert used == 1
    to_pending(client)
    second = post(client, LOGIN_MFA, {"code": codes[0]})
    assert second.status_code == 401
    assert second.json() == LOGIN_FAILED
    # The other codes are untouched.
    to_pending(client)
    assert post(client, LOGIN_MFA, {"code": codes[1]}).status_code == 200


def test_a_recovery_code_is_accepted_in_lowercase_without_the_dashes(
    client, db_engine, clock
):
    _, codes = enroll(client, db_engine, clock)
    to_pending(client)

    response = post(client, LOGIN_MFA, {"code": codes[2].replace("-", "").lower()})

    assert response.status_code == 200


def test_a_wrong_recovery_code_is_a_counted_failure(client, db_engine, clock):
    enroll(client, db_engine, clock)
    to_pending(client)

    response = post(client, LOGIN_MFA, {"code": "AAAA-AAAA-AAAA"})

    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert attempt_row(db_engine).failures == 1


def test_mfa_failures_lock_the_account_with_the_login_rules(client, db_engine, clock):
    secret, _ = enroll(client, db_engine, clock)
    to_pending(client)
    wrong = totp(secret, clock, 2)

    for _ in range(4):
        assert post(client, LOGIN_MFA, {"code": wrong}).status_code == 401

    row = attempt_row(db_engine)
    assert row.failures == 4
    assert row.locked_until == clock() + timedelta(minutes=1)
    clear_replay_guard(db_engine)
    response = post(client, LOGIN_MFA, {"code": totp(secret, clock, 1)})
    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    # The password step answers the same generic 401 while locked.
    blocked = login(client)
    assert blocked.status_code == 401
    assert blocked.json() == LOGIN_FAILED


def test_locked_second_factor_does_not_verify_anything(
    client, db_engine, clock, monkeypatch
):
    secret, _ = enroll(client, db_engine, clock)
    to_pending(client)
    for _ in range(4):
        post(client, LOGIN_MFA, {"code": totp(secret, clock, 2)})

    def boom(_):
        raise AssertionError("transit must not be called for a locked account")

    monkeypatch.setattr(auth, "decrypt_totp_secret", boom)

    assert post(client, LOGIN_MFA, {"code": totp(secret, clock, 1)}).status_code == 401


def test_login_mfa_needs_same_origin_and_its_csrf_token(client, db_engine, clock):
    secret, _ = enroll(client, db_engine, clock)
    to_pending(client)
    body = {"code": totp(secret, clock, 1)}

    assert post(client, LOGIN_MFA, body, headers={}).status_code == 403
    assert post(client, LOGIN_MFA, body, csrf=None).status_code == 403
    assert post(client, LOGIN_MFA, body, csrf="forged.1.deadbeef").status_code == 403
    assert attempt_row(db_engine).failures == 0


def test_login_mfa_without_a_token_is_401(client):
    assert post(client, LOGIN_MFA, {"code": "123456"}, csrf="x").status_code == 401


def test_login_mfa_refuses_an_enroll_token_and_a_full_session(client, db_engine, clock):
    secret, _ = enroll(client, db_engine, clock)
    make_user(client, db_engine, clock, "bob")
    login(client, "bob")  # enroll token

    assert post(client, LOGIN_MFA, {"code": "123456"}).status_code == 401

    register(client, "carol")
    login(client, "carol")  # full session
    assert post(client, LOGIN_MFA, {"code": "123456"}).status_code == 401
    assert secret


def test_enrollment_endpoints_refuse_the_pending_token(client, db_engine, clock):
    enroll(client, db_engine, clock)
    to_pending(client)

    assert post(client, ENROLL).status_code == 401
    assert post(client, CONFIRM, {"code": "123456"}).status_code == 401


def test_transit_down_gives_a_fixed_503_at_login(client, db_engine, clock, monkeypatch):
    secret, _ = enroll(client, db_engine, clock)
    to_pending(client)
    monkeypatch.setenv("GATEWAY_OPENBAO_ADDR", "http://127.0.0.1:1")
    monkeypatch.setattr(secrets, "REQUEST_TIMEOUT_SECONDS", 1)
    clear_replay_guard(db_engine)

    response = post(client, LOGIN_MFA, {"code": totp(secret, clock, 1)})

    assert response.status_code == 503
    assert response.json() == {"detail": "Service busy; try again later"}
    assert attempt_row(db_engine).failures == 0


def test_a_recovery_code_still_works_with_transit_down(
    client, db_engine, clock, monkeypatch
):
    _, codes = enroll(client, db_engine, clock)
    to_pending(client)
    monkeypatch.setenv("GATEWAY_OPENBAO_ADDR", "http://127.0.0.1:1")

    assert post(client, LOGIN_MFA, {"code": codes[0]}).status_code == 200


# --- security log ---------------------------------------------------------


def events(caplog):
    return [
        m.split("event=")[1].split()[0]
        for m in (r.getMessage() for r in caplog.records)
        if "security_event" in m
    ]


def test_events_are_logged_and_no_secret_ever_is(client, db_engine, clock, caplog):
    caplog.set_level(logging.DEBUG)
    make_user(client, db_engine, clock)
    login(client)
    body = post(client, ENROLL).json()
    secret = body["secret"]
    ciphertext = user_row(db_engine)["mfa_pending_ciphertext"]
    confirm = post(client, CONFIRM, {"code": totp(secret, clock)}).json()
    codes = confirm["recovery_codes"]
    to_pending(client)
    wrong = totp(secret, clock, 2)
    post(client, LOGIN_MFA, {"code": wrong})
    to_pending(client)
    post(client, LOGIN_MFA, {"code": codes[0]})
    to_pending(client)
    clear_replay_guard(db_engine)
    good = totp(secret, clock, 1)
    post(client, LOGIN_MFA, {"code": good})

    seen = events(caplog)
    for name in (
        "mfa_enrollment_started",
        "mfa_enabled",
        "mfa_failure",
        "mfa_success",
        "recovery_code_used",
    ):
        assert name in seen
    for forbidden in (
        secret,
        body["otpauth_uri"],
        ciphertext,
        wrong,
        good,
        *codes,
        *(c.replace("-", "") for c in codes),
    ):
        assert forbidden not in caplog.text


def test_enroll_token_forgery_with_a_wrong_csrf_binding_is_refused(
    client, db_engine, clock
):
    make_user(client, db_engine, clock)
    login(client)
    other_binding = make_csrf("some-other-sid", KEYS.csrf_key, clock())

    assert post(client, ENROLL, csrf=other_binding).status_code == 403


# --- the enrollment window also binds the enroll token -------------------


def test_enroll_token_is_refused_once_the_window_has_closed(client, db_engine, clock):
    make_user(client, db_engine, clock)
    login(client)  # the 10-minute token is still valid when the window ends
    clock.now += timedelta(hours=24, seconds=1)

    response = post(client, ENROLL)

    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert user_row(db_engine)["mfa_pending_ciphertext"] is None


def test_confirm_is_refused_once_the_window_has_closed(client, db_engine, clock):
    make_user(client, db_engine, clock)
    login(client)
    secret = post(client, ENROLL).json()["secret"]
    clock.now += timedelta(hours=24, seconds=1)

    response = post(client, CONFIRM, {"code": totp(secret, clock)})

    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert user_row(db_engine)["mfa_enabled_at"] is None


# --- the pending token is consumed once, also under concurrency -----------

WAIT_SECONDS = 10


class Gate:
    """Holds the first caller of `_check_second_factor` inside the counter lock."""

    def __init__(self, real):
        self.real = real
        self.mutex = threading.Lock()
        self.first = True
        self.entered = threading.Event()
        self.release = threading.Event()

    def __call__(self, *args):
        with self.mutex:
            leader, self.first = self.first, False
        if leader:
            self.entered.set()
            assert self.release.wait(WAIT_SECONDS)
        return self.real(*args)


def lock_waiters(db_engine):
    with db_engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT count(*) FROM pg_stat_activity "
                "WHERE datname = current_database() AND wait_event_type = 'Lock'"
            )
        ).scalar()


def wait_until(predicate):
    deadline = time.monotonic() + WAIT_SECONDS
    while not predicate():
        assert time.monotonic() < deadline, "timed out"
        threading.Event().wait(0.005)


def test_a_wrong_code_does_not_burn_the_pending_token(client, db_engine, clock):
    secret, _ = enroll(client, db_engine, clock)
    to_pending(client)
    clear_replay_guard(db_engine)

    assert post(client, LOGIN_MFA, {"code": totp(secret, clock, 2)}).status_code == 401
    assert post(client, LOGIN_MFA, {"code": totp(secret, clock, 1)}).status_code == 200


def test_two_codes_in_parallel_consume_the_pending_token_once(
    client, db_engine, clock, monkeypatch
):
    secret, codes = enroll(client, db_engine, clock)
    for attempt in range(20):
        with db_engine.begin() as conn:
            conn.execute(text("UPDATE recovery_codes SET used_at = NULL"))
            conn.execute(text("UPDATE users SET mfa_last_step = NULL"))
        to_pending(client)
        racers = []
        for _ in range(2):
            other = second_client(client)
            other.cookies.set("__Host-access", client.cookies.get("__Host-access"))
            other.cookies.set("__Host-csrf", client.cookies.get("__Host-csrf"))
            racers.append(other)
        # One racer brings a TOTP, the other a recovery code; swap each round.
        bodies = [{"code": totp(secret, clock, 1)}, {"code": codes[attempt % 10]}]
        if attempt % 2:
            bodies.reverse()
        gate = Gate(auth._check_second_factor)
        monkeypatch.setattr(auth, "_check_second_factor", gate)
        statuses = []

        def run(racer, body, results):
            results.append(post(racer, LOGIN_MFA, body).status_code)

        first = threading.Thread(target=run, args=(racers[0], bodies[0], statuses))
        second = threading.Thread(target=run, args=(racers[1], bodies[1], statuses))
        first.start()
        assert gate.entered.wait(WAIT_SECONDS)
        second.start()
        # The second request is now queued on the counter row's lock.
        wait_until(lambda: lock_waiters(db_engine) >= 1)
        gate.release.set()
        first.join(WAIT_SECONDS)
        second.join(WAIT_SECONDS)

        assert sorted(statuses) == [200, 401], f"round {attempt}: {statuses}"
        with db_engine.connect() as conn:
            families = conn.execute(text("SELECT count(*) FROM refresh_families"))
            assert families.scalar() == attempt + 1
        with db_engine.begin() as conn:
            conn.execute(text("UPDATE login_attempts SET failures = 0"))
