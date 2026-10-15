"""An administrator resets another user's MFA (ADR 0004, decisions 10 and 11).

A reader needs one administrator. A privileged account needs two distinct
administrators, neither of them the affected user: one requests, another
approves. Sessions are real; the MFA state is set directly in the database
(what the routes read), so no transit call is involved.
"""

import logging
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from gateway import auth, recovery
from gateway.auth import NO_STORE
from gateway.db import get_engine
from gateway.main import create_app
from tests.helpers import DbError, FrozenClock
from tests.test_admin import (
    USERS,
    admin,
    call,
    set_user,
    signed_in,
    user_id,
    user_row,
)
from tests.test_login import GOOD, KEYS, login

MFA_COLUMNS = (
    "mfa_secret_ciphertext",
    "mfa_pending_ciphertext",
    "mfa_enabled_at",
    "mfa_last_step",
    "mfa_enroll_until",
)
TWO_ADMINS = "Two administrators are required to reset the MFA of a privileged account"
NO_MFA = "The user has no MFA to reset"
NO_REQUEST = "No pending MFA reset request for this user"
ALREADY = "An MFA reset request is already pending for this user"
GONE = "The MFA reset request is no longer valid"


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


def reset_url(target_id):
    return f"{USERS}/{target_id}/mfa-reset"


def approve_url(target_id):
    return f"{USERS}/{target_id}/mfa-reset/approve"


def requests_rows(db_engine):
    with db_engine.connect() as conn:
        return conn.execute(text("SELECT * FROM mfa_reset_requests")).mappings().all()


def with_mfa(db_engine, clock, username, *, pending=False):
    """Give a user an active MFA, a pending secret, a replay step and codes."""
    columns = {
        "mfa_secret_ciphertext": "vault:v1:secret",
        "mfa_pending_ciphertext": "vault:v1:pending" if pending else None,
        "mfa_enabled_at": clock(),
        "mfa_last_step": 7,
        "mfa_enroll_until": None,
    }
    set_user(db_engine, username, **columns)
    with db_engine.begin() as conn:
        for n in range(3):
            conn.execute(
                text(
                    "INSERT INTO recovery_codes (user_id, code_hash) "
                    "VALUES ((SELECT id FROM users WHERE username = :u), :h)"
                ),
                {"u": username, "h": f"hash-{n}"},
            )


def target_user(client, db_engine, clock, username="target", role="lector", **kw):
    c = signed_in(client, db_engine, clock, username)
    with_mfa(db_engine, clock, username, **kw)
    if role != "lector":
        set_user(db_engine, username, role=role)
    return c


def mfa_state(db_engine, username="target"):
    row = user_row(db_engine, username)
    return {name: row[name] for name in MFA_COLUMNS}


def recovery_count(db_engine):
    with db_engine.connect() as conn:
        return conn.execute(text("SELECT count(*) FROM recovery_codes")).scalar_one()


def open_families(db_engine, username="target"):
    with db_engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT count(*) FROM refresh_families "
                "WHERE user_id = :i AND revoked_at IS NULL"
            ),
            {"i": user_id(db_engine, username)},
        ).scalar_one()


def request_reset(c, db_engine, username="target"):
    return call(c, "POST", reset_url(user_id(db_engine, username)))


def approve(c, db_engine, username="target"):
    return call(c, "POST", approve_url(user_id(db_engine, username)))


def untouched(db_engine, before):
    assert mfa_state(db_engine) == before


# --- a reader: one administrator ------------------------------------------------


def test_one_administrator_resets_the_mfa_of_a_reader_at_once(
    client, db_engine, clock, caplog
):
    boss = admin(client, db_engine, clock)
    target = target_user(client, db_engine, clock, pending=True)
    generation = user_row(db_engine, "target")["token_generation"]
    assert target.get("/api/auth/me").status_code == 200
    caplog.set_level(logging.INFO, logger="gateway.admin")

    response = request_reset(boss, db_engine)

    assert response.status_code == 200
    assert response.json() == {"status": "mfa_reset"}
    for header, value in NO_STORE.items():
        assert response.headers[header] == value
    assert mfa_state(db_engine) == dict.fromkeys(MFA_COLUMNS)
    assert recovery_count(db_engine) == 0
    assert requests_rows(db_engine) == []
    assert user_row(db_engine, "target")["token_generation"] == generation + 1
    assert open_families(db_engine) == 0
    assert target.get("/api/auth/me").status_code == 401
    assert "event=mfa_reset " in caplog.text
    assert f"actor={user_id(db_engine, 'boss')}" in caplog.text
    assert f"target={user_id(db_engine, 'target')}" in caplog.text


def test_the_reader_then_signs_in_with_the_password_only(client, db_engine, clock):
    boss = admin(client, db_engine, clock)
    target_user(client, db_engine, clock)
    request_reset(boss, db_engine)

    fresh = TestClient(client.app, base_url="https://testserver")
    response = login(fresh, "target", GOOD)

    assert response.status_code == 200
    assert response.json()["username"] == "target"
    assert fresh.get("/api/auth/me").status_code == 200


def test_a_reader_with_a_pending_role_needs_two_administrators(
    client, db_engine, clock
):
    # Option B: a pending role makes the account need two administrators, and
    # the reset keeps a 24 h enrollment window for it (B3).
    boss = admin(client, db_engine, clock)
    boss2 = admin(client, db_engine, clock, "boss2")
    target_user(client, db_engine, clock)
    set_user(db_engine, "target", pending_role="editor")

    assert request_reset(boss, db_engine).status_code == 202
    assert mfa_state(db_engine)["mfa_enabled_at"] is not None
    assert approve(boss2, db_engine).status_code == 200

    state = mfa_state(db_engine)
    assert state["mfa_enabled_at"] is None
    assert state["mfa_enroll_until"] == clock() + timedelta(hours=24)
    assert user_row(db_engine, "target")["pending_role"] == "editor"


def test_a_reader_with_a_pending_role_and_one_administrator_is_a_conflict(
    client, db_engine, clock
):
    boss = admin(client, db_engine, clock)
    target_user(client, db_engine, clock)
    set_user(db_engine, "target", pending_role="editor")
    before = mfa_state(db_engine)

    response = request_reset(boss, db_engine)

    assert response.status_code == 409
    assert response.json() == {"detail": TWO_ADMINS}
    untouched(db_engine, before)


# --- a privileged account: request and approval -------------------------------------


@pytest.mark.parametrize("role", ["editor", "auditor", "administrador"])
def test_the_request_for_a_privileged_account_changes_nothing_yet(
    client, db_engine, clock, caplog, role
):
    boss = admin(client, db_engine, clock)
    admin(client, db_engine, clock, "boss2")
    target = target_user(client, db_engine, clock, role=role)
    before = mfa_state(db_engine)
    codes = recovery_count(db_engine)
    caplog.set_level(logging.INFO, logger="gateway.admin")

    response = request_reset(boss, db_engine)

    assert response.status_code == 202
    body = response.json()
    assert set(body) == {"status", "expires_at"}
    assert body["status"] == "approval_required"
    assert body["expires_at"].startswith(
        (clock() + recovery.MFA_RESET_REQUEST_TTL).strftime("%Y-%m-%dT%H:%M:%S")
    )
    for header, value in NO_STORE.items():
        assert response.headers[header] == value
    untouched(db_engine, before)
    assert recovery_count(db_engine) == codes
    assert open_families(db_engine) == 1
    assert target.get("/api/auth/me").status_code == 200
    (row,) = requests_rows(db_engine)
    assert str(row["target_user_id"]) == user_id(db_engine, "target")
    assert str(row["requested_by"]) == user_id(db_engine, "boss")
    assert row["created_at"] == clock()
    assert row["expires_at"] == clock() + timedelta(hours=1)
    assert "event=mfa_reset_requested " in caplog.text
    assert "event=mfa_reset " not in caplog.text


def test_the_request_lives_one_hour(client, db_engine, clock):
    assert recovery.MFA_RESET_REQUEST_TTL == timedelta(hours=1)


def test_a_second_administrator_approves_and_the_mfa_is_reset(
    client, db_engine, clock, caplog
):
    boss = admin(client, db_engine, clock)
    boss2 = admin(client, db_engine, clock, "boss2")
    target = target_user(client, db_engine, clock, role="editor", pending=True)
    generation = user_row(db_engine, "target")["token_generation"]
    request_reset(boss, db_engine)
    caplog.set_level(logging.INFO, logger="gateway.admin")

    response = approve(boss2, db_engine)

    assert response.status_code == 200
    assert response.json() == {"status": "mfa_reset"}
    for header, value in NO_STORE.items():
        assert response.headers[header] == value
    state = mfa_state(db_engine)
    assert state["mfa_enroll_until"] == clock() + timedelta(hours=24)
    assert {k: v for k, v in state.items() if k != "mfa_enroll_until"} == {
        k: None for k in MFA_COLUMNS if k != "mfa_enroll_until"
    }
    assert user_row(db_engine, "target")["role"] == "editor"
    assert recovery_count(db_engine) == 0
    assert requests_rows(db_engine) == []
    assert user_row(db_engine, "target")["token_generation"] == generation + 1
    assert open_families(db_engine) == 0
    assert target.get("/api/auth/me").status_code == 401
    assert "event=mfa_reset_approved " in caplog.text
    assert f"actor={user_id(db_engine, 'boss2')}" in caplog.text
    assert f"requested_by={user_id(db_engine, 'boss')}" in caplog.text
    assert "event=mfa_reset " in caplog.text


def test_the_next_login_of_the_reset_account_is_the_scoped_enrollment(
    client, db_engine, clock
):
    boss = admin(client, db_engine, clock)
    boss2 = admin(client, db_engine, clock, "boss2")
    target_user(client, db_engine, clock, role="editor")
    request_reset(boss, db_engine)
    approve(boss2, db_engine)

    fresh = TestClient(client.app, base_url="https://testserver")
    response = login(fresh, "target", GOOD)

    assert response.status_code == 200
    assert response.json() == {"status": "mfa_enrollment_required"}


def test_the_same_administrator_cannot_approve_their_own_request(
    client, db_engine, clock, caplog
):
    boss = admin(client, db_engine, clock)
    admin(client, db_engine, clock, "boss2")
    target_user(client, db_engine, clock, role="editor")
    request_reset(boss, db_engine)
    before = mfa_state(db_engine)
    (request,) = requests_rows(db_engine)
    caplog.set_level(logging.INFO, logger="gateway.admin")

    response = approve(boss, db_engine)

    assert response.status_code == 403
    assert response.json() == {"detail": "Forbidden"}
    untouched(db_engine, before)
    assert requests_rows(db_engine) == [request]
    assert "event=admin_denied " in caplog.text


def test_approving_without_a_request_is_a_conflict(client, db_engine, clock):
    admin(client, db_engine, clock)
    boss2 = admin(client, db_engine, clock, "boss2")
    target_user(client, db_engine, clock, role="editor")
    before = mfa_state(db_engine)

    response = approve(boss2, db_engine)

    assert response.status_code == 409
    assert response.json() == {"detail": NO_REQUEST}
    untouched(db_engine, before)


def test_approving_an_expired_request_is_a_conflict(client, db_engine, clock):
    boss = admin(client, db_engine, clock)
    boss2 = admin(client, db_engine, clock, "boss2")
    target_user(client, db_engine, clock, role="editor")
    request_reset(boss, db_engine)
    before = mfa_state(db_engine)
    with db_engine.begin() as conn:
        conn.execute(
            text("UPDATE mfa_reset_requests SET created_at = :c, expires_at = :e"),
            {"c": clock() - timedelta(hours=2), "e": clock()},
        )

    response = approve(boss2, db_engine)

    assert response.status_code == 409
    assert response.json() == {"detail": NO_REQUEST}
    untouched(db_engine, before)


def test_a_second_request_while_one_is_live_is_a_conflict(client, db_engine, clock):
    boss = admin(client, db_engine, clock)
    boss2 = admin(client, db_engine, clock, "boss2")
    admin(client, db_engine, clock, "boss3")
    target_user(client, db_engine, clock, role="editor")
    request_reset(boss, db_engine)
    (first,) = requests_rows(db_engine)

    for c in (boss, boss2):
        response = request_reset(c, db_engine)
        assert response.status_code == 409
        assert response.json() == {"detail": ALREADY}
    assert requests_rows(db_engine) == [first]


def test_an_expired_request_is_replaced_by_a_new_one(client, db_engine, clock):
    boss = admin(client, db_engine, clock)
    boss2 = admin(client, db_engine, clock, "boss2")
    admin(client, db_engine, clock, "boss3")
    target_user(client, db_engine, clock, role="editor")
    request_reset(boss, db_engine)
    with db_engine.begin() as conn:
        conn.execute(
            text("UPDATE mfa_reset_requests SET created_at = :c, expires_at = :e"),
            {"c": clock() - timedelta(hours=2), "e": clock()},
        )

    response = request_reset(boss2, db_engine)

    assert response.status_code == 202
    (row,) = requests_rows(db_engine)
    assert str(row["requested_by"]) == user_id(db_engine, "boss2")
    assert row["expires_at"] == clock() + timedelta(hours=1)


def test_an_administrator_target_cannot_approve_its_own_reset(
    client, db_engine, clock, caplog
):
    boss = admin(client, db_engine, clock)
    admin(client, db_engine, clock, "boss3")
    target = admin(client, db_engine, clock, "target")
    with_mfa(db_engine, clock, "target")
    request_reset(boss, db_engine)
    before = mfa_state(db_engine)
    caplog.set_level(logging.INFO, logger="gateway.admin")

    response = call(target, "POST", approve_url(user_id(db_engine, "target")))

    assert response.status_code == 403
    untouched(db_engine, before)
    assert len(requests_rows(db_engine)) == 1
    assert "event=admin_denied " in caplog.text


def test_an_administrator_target_cannot_request_its_own_reset(
    client, db_engine, clock, caplog
):
    admin(client, db_engine, clock)
    admin(client, db_engine, clock, "boss3")
    target = admin(client, db_engine, clock, "target")
    with_mfa(db_engine, clock, "target")
    before = mfa_state(db_engine)
    caplog.set_level(logging.INFO, logger="gateway.admin")

    response = call(target, "POST", reset_url(user_id(db_engine, "target")))

    assert response.status_code == 403
    assert response.json() == {"detail": "Forbidden"}
    untouched(db_engine, before)
    assert requests_rows(db_engine) == []
    assert "event=admin_denied " in caplog.text


def test_an_administrator_target_is_reset_by_two_others(client, db_engine, clock):
    boss = admin(client, db_engine, clock)
    boss2 = admin(client, db_engine, clock, "boss2")
    target_user(client, db_engine, clock, role="administrador")

    assert request_reset(boss, db_engine).status_code == 202
    assert approve(boss2, db_engine).status_code == 200

    assert mfa_state(db_engine)["mfa_enabled_at"] is None
    assert user_row(db_engine, "target")["role"] == "administrador"


def test_fewer_than_two_other_administrators_is_a_conflict_at_request_time(
    client, db_engine, clock
):
    boss = admin(client, db_engine, clock)
    target_user(client, db_engine, clock, role="editor")
    before = mfa_state(db_engine)

    response = request_reset(boss, db_engine)

    assert response.status_code == 409
    assert response.json() == {"detail": TWO_ADMINS}
    untouched(db_engine, before)
    assert requests_rows(db_engine) == []


def test_the_target_does_not_count_among_the_two_administrators(
    client, db_engine, clock
):
    boss = admin(client, db_engine, clock)
    target_user(client, db_engine, clock, role="administrador")

    response = request_reset(boss, db_engine)

    assert response.status_code == 409
    assert response.json() == {"detail": TWO_ADMINS}


def test_an_administrator_without_an_active_mfa_does_not_count(
    client, db_engine, clock
):
    boss = admin(client, db_engine, clock)
    admin(client, db_engine, clock, "boss2")
    set_user(db_engine, "boss2", mfa_enabled_at=None)
    target_user(client, db_engine, clock, role="editor")

    response = request_reset(boss, db_engine)

    assert response.status_code == 409
    assert response.json() == {"detail": TWO_ADMINS}


def test_a_reader_needs_no_second_administrator(client, db_engine, clock):
    boss = admin(client, db_engine, clock)
    target_user(client, db_engine, clock)

    assert request_reset(boss, db_engine).status_code == 200


# --- the request goes stale before the approval ----------


def test_a_requester_demoted_before_the_approval_voids_the_request(
    client, db_engine, clock
):
    boss = admin(client, db_engine, clock)
    boss2 = admin(client, db_engine, clock, "boss2")
    target_user(client, db_engine, clock, role="editor")
    request_reset(boss, db_engine)
    before = mfa_state(db_engine)
    set_user(db_engine, "boss", role="lector")

    response = approve(boss2, db_engine)

    assert response.status_code == 409
    assert response.json() == {"detail": GONE}
    untouched(db_engine, before)
    assert requests_rows(db_engine) == []


def test_a_requester_deleted_before_the_approval_voids_the_request(
    client, db_engine, clock
):
    boss = admin(client, db_engine, clock)
    boss2 = admin(client, db_engine, clock, "boss2")
    target_user(client, db_engine, clock, role="editor")
    request_reset(boss, db_engine)
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users WHERE username = 'boss'"))
    assert requests_rows(db_engine) == []

    response = approve(boss2, db_engine)

    assert response.status_code == 409
    assert response.json() == {"detail": NO_REQUEST}


def test_a_target_that_became_a_reader_is_still_reset_on_approval(
    client, db_engine, clock
):
    boss = admin(client, db_engine, clock)
    boss2 = admin(client, db_engine, clock, "boss2")
    target_user(client, db_engine, clock, role="editor")
    request_reset(boss, db_engine)
    set_user(db_engine, "target", role="lector")

    response = approve(boss2, db_engine)

    assert response.status_code == 200
    assert mfa_state(db_engine) == dict.fromkeys(MFA_COLUMNS)
    assert requests_rows(db_engine) == []


def test_a_target_that_lost_its_mfa_voids_the_request_on_approval(
    client, db_engine, clock
):
    boss = admin(client, db_engine, clock)
    boss2 = admin(client, db_engine, clock, "boss2")
    target_user(client, db_engine, clock, role="editor")
    request_reset(boss, db_engine)
    set_user(
        db_engine,
        "target",
        mfa_secret_ciphertext=None,
        mfa_pending_ciphertext=None,
        mfa_enabled_at=None,
    )

    response = approve(boss2, db_engine)

    assert response.status_code == 409
    assert response.json() == {"detail": GONE}
    assert requests_rows(db_engine) == []


# --- refusals ----------


def test_a_target_without_any_mfa_is_a_conflict(client, db_engine, clock):
    boss = admin(client, db_engine, clock)
    signed_in(client, db_engine, clock, "target")

    response = request_reset(boss, db_engine)

    assert response.status_code == 409
    assert response.json() == {"detail": NO_MFA}
    assert requests_rows(db_engine) == []


def test_a_user_with_only_a_pending_secret_has_mfa_to_reset(client, db_engine, clock):
    boss = admin(client, db_engine, clock)
    signed_in(client, db_engine, clock, "target")
    set_user(db_engine, "target", mfa_pending_ciphertext="vault:v1:pending")

    response = request_reset(boss, db_engine)

    assert response.status_code == 200
    assert mfa_state(db_engine) == dict.fromkeys(MFA_COLUMNS)


def test_an_administrator_cannot_reset_their_own_mfa(client, db_engine, clock, caplog):
    boss = admin(client, db_engine, clock)
    admin(client, db_engine, clock, "boss2")
    admin(client, db_engine, clock, "boss3")
    own = user_row(db_engine, "boss")
    caplog.set_level(logging.INFO, logger="gateway.admin")

    response = call(boss, "POST", reset_url(own["id"]))

    assert response.status_code == 403
    assert user_row(db_engine, "boss")["mfa_enabled_at"] == own["mfa_enabled_at"]
    assert requests_rows(db_engine) == []
    assert "event=admin_denied " in caplog.text


@pytest.mark.parametrize("role", ["lector", "editor", "auditor"])
@pytest.mark.parametrize("route", [reset_url, approve_url])
def test_a_user_who_is_not_an_administrator_gets_403(
    client, db_engine, clock, role, route
):
    c = signed_in(client, db_engine, clock, "someone", role, mfa=True)
    target_user(client, db_engine, clock)
    before = mfa_state(db_engine)

    response = call(c, "POST", route(user_id(db_engine, "target")))

    assert response.status_code == 403
    untouched(db_engine, before)


@pytest.mark.parametrize("route", [reset_url, approve_url])
def test_an_unknown_user_is_404(client, db_engine, clock, route):
    boss = admin(client, db_engine, clock)

    response = call(boss, "POST", route("0b2f6a52-5a2e-4f0a-8a5e-9d1f4c3b7e11"))

    assert response.status_code == 404


@pytest.mark.parametrize("route", [reset_url, approve_url])
def test_both_routes_need_the_same_origin_and_the_csrf_token(
    client, db_engine, clock, route
):
    boss = admin(client, db_engine, clock)
    target_user(client, db_engine, clock)
    url = route(user_id(db_engine, "target"))
    before = mfa_state(db_engine)

    assert call(boss, "POST", url, csrf=None).status_code == 403
    assert call(boss, "POST", url, headers={}).status_code == 403
    untouched(db_engine, before)


# --- busy rows ----------


def fail_lock(monkeypatch, table, sqlstate):
    real_scalar = Session.scalar

    def scalar(self, statement, *args, **kwargs):
        sql = str(statement)
        if f"FROM {table}" in sql and "FOR UPDATE" in sql:
            raise OperationalError("SELECT", {}, DbError(sqlstate))
        return real_scalar(self, statement, *args, **kwargs)

    monkeypatch.setattr(Session, "scalar", scalar)


@pytest.mark.parametrize("sqlstate", ["55P03", "40P01", "40001"])
@pytest.mark.parametrize("route", [reset_url, approve_url])
def test_a_busy_target_lock_is_a_503_and_writes_nothing(
    client, db_engine, clock, monkeypatch, sqlstate, route
):
    boss = admin(client, db_engine, clock)
    admin(client, db_engine, clock, "boss2")
    target_user(client, db_engine, clock)
    before = mfa_state(db_engine)
    fail_lock(monkeypatch, "users", sqlstate)

    response = call(boss, "POST", route(user_id(db_engine, "target")))

    assert response.status_code == 503
    untouched(db_engine, before)
    assert requests_rows(db_engine) == []


@pytest.mark.parametrize("sqlstate", ["55P03", "40P01", "40001"])
def test_a_busy_request_lock_on_a_new_request_is_a_503_and_writes_nothing(
    client, db_engine, clock, monkeypatch, sqlstate
):
    boss = admin(client, db_engine, clock)
    admin(client, db_engine, clock, "boss2")
    target_user(client, db_engine, clock, role="editor")
    before = mfa_state(db_engine)
    fail_lock(monkeypatch, "mfa_reset_requests", sqlstate)

    response = request_reset(boss, db_engine)

    assert response.status_code == 503
    untouched(db_engine, before)
    assert requests_rows(db_engine) == []


@pytest.mark.parametrize("sqlstate", ["55P03", "40P01", "40001"])
def test_a_busy_request_lock_on_an_approval_is_a_503_and_changes_nothing(
    client, db_engine, clock, monkeypatch, sqlstate
):
    boss = admin(client, db_engine, clock)
    boss2 = admin(client, db_engine, clock, "boss2")
    target_user(client, db_engine, clock, role="editor")
    request_reset(boss, db_engine)
    before = mfa_state(db_engine)
    (request,) = requests_rows(db_engine)
    fail_lock(monkeypatch, "mfa_reset_requests", sqlstate)

    response = approve(boss2, db_engine)

    assert response.status_code == 503
    untouched(db_engine, before)
    assert requests_rows(db_engine) == [request]


# --- events ----------


def test_the_events_carry_no_secret_material(client, db_engine, clock, caplog):
    boss = admin(client, db_engine, clock)
    boss2 = admin(client, db_engine, clock, "boss2")
    target_user(client, db_engine, clock, role="editor", pending=True)
    caplog.set_level(logging.DEBUG)

    request_reset(boss, db_engine)
    approve(boss2, db_engine)

    for event in ("mfa_reset_requested", "mfa_reset_approved", "mfa_reset"):
        assert f"event={event} " in caplog.text
    for secret in ("vault:v1", "hash-0", GOOD):
        assert secret not in caplog.text
