"""Accounts that are or were privileged need two administrators to recover.

ADR 0004, decision 10, option B. `users.privileged_at` records the first time an
account got a privileged role or pending role and is never cleared, so demoting
an account to reader does not lower the bar for resetting its MFA or issuing it
a reset code. A reader that was never privileged still needs one administrator.
"""

import logging
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from gateway import admin as admin_module
from gateway import auth
from gateway.auth import NO_STORE
from gateway.db import get_engine
from gateway.main import create_app
from tests.helpers import DbError, FrozenClock, run_sql
from tests.test_admin import (
    USERS,
    admin,
    assign,
    call,
    set_user,
    signed_in,
    user_id,
    user_row,
)
from tests.test_login import KEYS, attempt_row
from tests.test_mfa_reset import approve as approve_mfa_reset
from tests.test_mfa_reset import (
    fail_requester_lock,
    mfa_state,
    request_reset,
    requests_rows,
    target_user,
)
from tests.test_password_reset import browser, code_rows, reset

ALREADY = "A reset code request is already pending for this user"
NO_REQUEST = "No pending reset code request for this user"
GONE = "The reset code request is no longer valid"
CODE_TWO_ADMINS = (
    "Two administrators are required to issue a reset code for this account"
)


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


def code_url(username_id):
    return f"{USERS}/{username_id}/reset-code"


def approve_url(username_id):
    return f"{USERS}/{username_id}/reset-code/approve"


def request_code(c, db_engine, username="target"):
    return call(c, "POST", code_url(user_id(db_engine, username)))


def approve_code(c, db_engine, username="target"):
    return call(c, "POST", approve_url(user_id(db_engine, username)))


def code_requests(db_engine):
    return [r for r in requests_rows(db_engine) if r["kind"] == "reset_code"]


def marker(db_engine, username="target"):
    return user_row(db_engine, username)["privileged_at"]


def privileged_with_mfa(client, db_engine, clock, boss, role="editor"):
    """A target with an active MFA that got its role through the admin route."""
    target = target_user(client, db_engine, clock)
    assert assign(boss, user_id(db_engine, "target"), role).status_code == 200
    assert user_row(db_engine, "target")["role"] == role
    return target


def two_admins(client, db_engine, clock):
    return (
        admin(client, db_engine, clock),
        admin(client, db_engine, clock, "boss2"),
    )


# --- the marker ----------


def test_a_role_that_applies_now_sets_the_marker(client, db_engine, clock):
    boss = admin(client, db_engine, clock)
    target_user(client, db_engine, clock)
    assert marker(db_engine) is None

    assert assign(boss, user_id(db_engine, "target"), "auditor").status_code == 200

    assert marker(db_engine) == clock()


def test_a_pending_role_sets_the_marker(client, db_engine, clock):
    boss = admin(client, db_engine, clock)
    signed_in(client, db_engine, clock, "target")

    assert assign(boss, user_id(db_engine, "target"), "editor").status_code == 200

    assert user_row(db_engine, "target")["pending_role"] == "editor"
    assert marker(db_engine) == clock()


def test_demotion_keeps_the_marker_and_it_is_set_only_once(client, db_engine, clock):
    boss = admin(client, db_engine, clock)
    privileged_with_mfa(client, db_engine, clock, boss)
    first = marker(db_engine)
    clock.now += timedelta(hours=1)

    assign(boss, user_id(db_engine, "target"), "lector")
    assert marker(db_engine) == first
    assign(boss, user_id(db_engine, "target"), "administrador")
    assert marker(db_engine) == first


def test_a_reader_that_was_never_privileged_has_no_marker(client, db_engine, clock):
    boss = admin(client, db_engine, clock)
    target_user(client, db_engine, clock)

    assign(boss, user_id(db_engine, "target"), "lector")

    assert marker(db_engine) is None


def test_demoting_an_account_that_became_privileged_outside_the_routes_marks_it(
    client, db_engine, clock
):
    boss = admin(client, db_engine, clock)
    target_user(client, db_engine, clock, role="editor")
    assert marker(db_engine) is None

    assign(boss, user_id(db_engine, "target"), "lector")

    assert marker(db_engine) == clock()


def test_the_marker_is_not_part_of_the_admin_listing(client, db_engine, clock):
    boss = admin(client, db_engine, clock)
    privileged_with_mfa(client, db_engine, clock, boss)

    body = call(boss, "GET", USERS).json()

    assert "privileged_at" not in str(body)


# --- the M1 chain is refused ----------


def test_demoting_a_privileged_account_does_not_open_a_single_admin_mfa_reset(
    client, db_engine, clock
):
    boss, _ = two_admins(client, db_engine, clock)
    privileged_with_mfa(client, db_engine, clock, boss)
    assign(boss, user_id(db_engine, "target"), "lector")
    before = mfa_state(db_engine)

    response = request_reset(boss, db_engine)

    assert response.status_code == 202
    assert response.json()["status"] == "approval_required"
    assert mfa_state(db_engine) == before
    assert user_row(db_engine, "target")["mfa_enabled_at"] is not None


def test_demoting_a_privileged_account_does_not_open_a_single_admin_code(
    client, db_engine, clock
):
    boss, _ = two_admins(client, db_engine, clock)
    privileged_with_mfa(client, db_engine, clock, boss)
    assign(boss, user_id(db_engine, "target"), "lector")

    response = request_code(boss, db_engine)

    assert response.status_code == 202
    assert response.json()["status"] == "approval_required"
    assert "code" not in response.json()
    assert code_rows(db_engine) == []


def test_the_whole_chain_with_one_administrator_leads_nowhere(client, db_engine, clock):
    boss = admin(client, db_engine, clock)
    privileged_with_mfa(client, db_engine, clock, boss)
    assign(boss, user_id(db_engine, "target"), "lector")

    # With a single administrator even the two-administrator path is closed.
    assert request_reset(boss, db_engine).status_code == 409
    assert request_code(boss, db_engine).status_code == 409
    assert code_rows(db_engine) == []
    assert user_row(db_engine, "target")["mfa_enabled_at"] is not None


def test_a_reader_that_was_never_privileged_keeps_the_single_admin_paths(
    client, db_engine, clock
):
    boss = admin(client, db_engine, clock)
    target_user(client, db_engine, clock)
    signed_in(client, db_engine, clock, "plain")

    assert request_reset(boss, db_engine).status_code == 200
    assert request_code(boss, db_engine, "plain").status_code == 200
    assert len(code_rows(db_engine)) == 1


# --- requesting a reset code ----------


def test_a_request_for_a_privileged_account_records_it_and_issues_no_code(
    client, db_engine, clock, caplog
):
    boss, _ = two_admins(client, db_engine, clock)
    privileged_with_mfa(client, db_engine, clock, boss)
    caplog.set_level(logging.INFO, logger="gateway.admin")

    response = request_code(boss, db_engine)

    assert response.status_code == 202
    assert set(response.json()) == {"status", "expires_at"}
    for header, value in NO_STORE.items():
        assert response.headers[header] == value
    assert code_rows(db_engine) == []
    (row,) = code_requests(db_engine)
    assert str(row["target_user_id"]) == user_id(db_engine, "target")
    assert str(row["requested_by"]) == user_id(db_engine, "boss")
    assert row["expires_at"] == clock() + timedelta(hours=1)
    assert "event=reset_code_requested " in caplog.text
    assert "event=password_reset_code_issued " not in caplog.text


def test_a_pending_role_counts_as_privileged_for_a_code(client, db_engine, clock):
    boss, _ = two_admins(client, db_engine, clock)
    signed_in(client, db_engine, clock, "target")
    set_user(db_engine, "target", pending_role="editor")

    assert request_code(boss, db_engine).status_code == 202


def test_fewer_than_two_other_administrators_is_a_conflict_for_a_code(
    client, db_engine, clock
):
    boss = admin(client, db_engine, clock)
    target_user(client, db_engine, clock, role="editor")

    response = request_code(boss, db_engine)

    assert response.status_code == 409
    assert response.json() == {"detail": CODE_TWO_ADMINS}
    assert code_requests(db_engine) == []


def test_a_live_code_request_is_a_conflict(client, db_engine, clock):
    boss, boss2 = two_admins(client, db_engine, clock)
    admin(client, db_engine, clock, "boss3")
    target_user(client, db_engine, clock, role="editor")
    request_code(boss, db_engine)
    (first,) = code_requests(db_engine)

    for c in (boss, boss2):
        response = request_code(c, db_engine)
        assert response.status_code == 409
        assert response.json() == {"detail": ALREADY}
    assert code_requests(db_engine) == [first]


def test_a_code_request_and_an_mfa_reset_request_coexist(client, db_engine, clock):
    boss, _ = two_admins(client, db_engine, clock)
    target_user(client, db_engine, clock, role="editor")

    assert request_code(boss, db_engine).status_code == 202
    assert request_reset(boss, db_engine).status_code == 202

    assert sorted(r["kind"] for r in requests_rows(db_engine)) == [
        "mfa_reset",
        "reset_code",
    ]


def test_an_expired_code_request_is_replaced(client, db_engine, clock):
    boss, boss2 = two_admins(client, db_engine, clock)
    admin(client, db_engine, clock, "boss3")
    target_user(client, db_engine, clock, role="editor")
    request_code(boss, db_engine)
    run_sql(
        db_engine,
        "UPDATE mfa_reset_requests SET created_at = :c, expires_at = :e",
        c=clock() - timedelta(hours=2),
        e=clock(),
    )

    assert request_code(boss2, db_engine).status_code == 202

    (row,) = code_requests(db_engine)
    assert str(row["requested_by"]) == user_id(db_engine, "boss2")


def test_an_administrator_cannot_request_a_code_for_themselves(
    client, db_engine, clock
):
    boss, _ = two_admins(client, db_engine, clock)

    assert request_code(boss, db_engine, "boss").status_code == 403
    assert code_requests(db_engine) == []


# --- approving a reset code ----------


def test_a_second_administrator_approves_and_receives_the_code_once(
    client, db_engine, clock, caplog
):
    boss, boss2 = two_admins(client, db_engine, clock)
    signed_in(client, db_engine, clock, "target")
    assign(boss, user_id(db_engine, "target"), "editor")  # pending: no MFA yet
    request_code(boss, db_engine)
    caplog.set_level(logging.INFO, logger="gateway.admin")

    response = approve_code(boss2, db_engine)

    assert response.status_code == 200
    for header, value in NO_STORE.items():
        assert response.headers[header] == value
    body = response.json()
    assert set(body) == {"code", "expires_at"}
    (row,) = code_rows(db_engine)
    assert str(row["user_id"]) == user_id(db_engine, "target")
    assert str(row["issued_by"]) == user_id(db_engine, "boss")
    assert str(row["approved_by"]) == user_id(db_engine, "boss2")
    assert row["expires_at"] == clock() + timedelta(minutes=15)
    assert body["code"] not in row["code_hash"]
    assert code_requests(db_engine) == []
    assert "event=reset_code_approved " in caplog.text
    assert f"requested_by={user_id(db_engine, 'boss')}" in caplog.text
    assert "event=password_reset_code_issued " in caplog.text
    assert body["code"] not in caplog.text
    # Nothing but the response carries it: a second approval has no request.
    assert approve_code(boss2, db_engine).status_code == 409

    # The approved code resets the password of the privileged account without MFA.
    done = reset(browser(client), "target", body["code"])
    assert done.status_code == 200
    assert code_rows(db_engine) == []


def test_approving_replaces_an_earlier_code_of_the_target(client, db_engine, clock):
    boss, boss2 = two_admins(client, db_engine, clock)
    target_user(client, db_engine, clock, role="editor")
    run_sql(
        db_engine,
        "INSERT INTO password_reset_codes "
        "(user_id, code_hash, created_at, expires_at) "
        "SELECT id, 'old', :c, :e FROM users WHERE username = 'target'",
        c=clock(),
        e=clock() + timedelta(minutes=5),
    )
    request_code(boss, db_engine)

    assert approve_code(boss2, db_engine).status_code == 200

    (row,) = code_rows(db_engine)
    assert row["code_hash"] != "old"


def test_the_requester_cannot_approve_their_own_request(
    client, db_engine, clock, caplog
):
    boss, _ = two_admins(client, db_engine, clock)
    target_user(client, db_engine, clock, role="editor")
    request_code(boss, db_engine)
    (request,) = code_requests(db_engine)
    caplog.set_level(logging.INFO, logger="gateway.admin")

    response = approve_code(boss, db_engine)

    assert response.status_code == 403
    assert response.json() == {"detail": "Forbidden"}
    assert code_requests(db_engine) == [request]
    assert code_rows(db_engine) == []
    assert "event=admin_denied " in caplog.text


def test_the_target_cannot_approve_its_own_code(client, db_engine, clock, caplog):
    boss, _ = two_admins(client, db_engine, clock)
    admin(client, db_engine, clock, "boss3")
    target = admin(client, db_engine, clock, "target")
    request_code(boss, db_engine)
    caplog.set_level(logging.INFO, logger="gateway.admin")

    response = call(target, "POST", approve_url(user_id(db_engine, "target")))

    assert response.status_code == 403
    assert len(code_requests(db_engine)) == 1
    assert code_rows(db_engine) == []
    assert "event=admin_denied " in caplog.text


def test_approving_without_a_request_is_a_conflict(client, db_engine, clock):
    _, boss2 = two_admins(client, db_engine, clock)
    target_user(client, db_engine, clock, role="editor")

    response = approve_code(boss2, db_engine)

    assert response.status_code == 409
    assert response.json() == {"detail": NO_REQUEST}
    assert code_rows(db_engine) == []


def test_an_mfa_reset_request_cannot_be_approved_as_a_code(client, db_engine, clock):
    boss, boss2 = two_admins(client, db_engine, clock)
    target_user(client, db_engine, clock, role="editor")
    request_reset(boss, db_engine)

    response = approve_code(boss2, db_engine)

    assert response.status_code == 409
    assert response.json() == {"detail": NO_REQUEST}
    assert code_rows(db_engine) == []
    assert len(requests_rows(db_engine)) == 1


def test_a_code_request_cannot_be_approved_as_an_mfa_reset(client, db_engine, clock):
    boss, boss2 = two_admins(client, db_engine, clock)
    target_user(client, db_engine, clock, role="editor")
    request_code(boss, db_engine)
    before = mfa_state(db_engine)

    response = approve_mfa_reset(boss2, db_engine)

    assert response.status_code == 409
    assert mfa_state(db_engine) == before
    assert len(code_requests(db_engine)) == 1


def test_approving_an_expired_request_is_a_conflict(client, db_engine, clock):
    boss, boss2 = two_admins(client, db_engine, clock)
    target_user(client, db_engine, clock, role="editor")
    request_code(boss, db_engine)
    run_sql(
        db_engine,
        "UPDATE mfa_reset_requests SET created_at = :c, expires_at = :e",
        c=clock() - timedelta(hours=2),
        e=clock(),
    )

    response = approve_code(boss2, db_engine)

    assert response.status_code == 409
    assert response.json() == {"detail": NO_REQUEST}
    assert code_rows(db_engine) == []


def test_a_requester_demoted_before_the_approval_voids_the_request(
    client, db_engine, clock
):
    boss, boss2 = two_admins(client, db_engine, clock)
    target_user(client, db_engine, clock, role="editor")
    request_code(boss, db_engine)
    set_user(db_engine, "boss", role="lector")

    response = approve_code(boss2, db_engine)

    assert response.status_code == 409
    assert response.json() == {"detail": GONE}
    assert code_rows(db_engine) == []
    assert code_requests(db_engine) == []


def test_a_voided_code_request_leaves_an_event(client, db_engine, clock, caplog):
    boss, boss2 = two_admins(client, db_engine, clock)
    target_user(client, db_engine, clock, role="editor")
    request_code(boss, db_engine)
    set_user(db_engine, "boss", role="lector")
    caplog.set_level(logging.INFO, logger="gateway.admin")

    assert approve_code(boss2, db_engine).status_code == 409

    (record,) = [
        r for r in caplog.records if "event=reset_code_request_voided " in r.message
    ]
    assert record.levelno == logging.WARNING
    assert f"actor={user_id(db_engine, 'boss2')} " in record.message
    assert f"target={user_id(db_engine, 'target')} " in record.message
    assert f"requested_by={user_id(db_engine, 'boss')} " in record.message
    assert "reason=requester_not_admin" in record.message


def test_a_user_who_is_not_an_administrator_cannot_approve(client, db_engine, clock):
    boss, _ = two_admins(client, db_engine, clock)
    target_user(client, db_engine, clock, role="editor")
    request_code(boss, db_engine)
    other = signed_in(client, db_engine, clock, "someone", "auditor", mfa=True)

    assert approve_code(other, db_engine).status_code == 403
    assert code_rows(db_engine) == []


def test_an_unknown_target_is_404(client, db_engine, clock):
    boss, _ = two_admins(client, db_engine, clock)

    response = call(boss, "POST", approve_url("0b2f6a52-5a2e-4f0a-8a5e-9d1f4c3b7e11"))

    assert response.status_code == 404


# --- the use-time check ----------


def test_a_single_admin_code_is_refused_once_the_account_became_privileged(
    client, db_engine, clock
):
    boss = admin(client, db_engine, clock)
    signed_in(client, db_engine, clock, "alice")
    issued = request_code(boss, db_engine, "alice")
    assert issued.status_code == 200
    # The account is given a (pending) privileged role before the code is used.
    assert assign(boss, user_id(db_engine, "alice"), "editor").status_code == 200
    before = user_row(db_engine, "alice")

    response = reset(browser(client), "alice", issued.json()["code"])

    assert response.status_code == 401
    assert attempt_row(db_engine) == (1, None)
    assert user_row(db_engine, "alice")["password_hash"] == before["password_hash"]
    assert len(code_rows(db_engine)) == 1


# --- B2: the demoted actor ----------


def test_an_actor_demoted_under_the_lock_gets_403_and_no_code(
    client, db_engine, clock, monkeypatch
):
    boss = admin(client, db_engine, clock)
    signed_in(client, db_engine, clock, "target")
    real = admin_module._lock_target

    def lock_then_demote(session, target_id):
        target = real(session, target_id)
        run_sql(db_engine, "UPDATE users SET role = 'lector' WHERE username = 'boss'")
        return target

    monkeypatch.setattr(admin_module, "_lock_target", lock_then_demote)

    response = request_code(boss, db_engine)

    assert response.status_code == 403
    assert code_rows(db_engine) == []
    assert code_requests(db_engine) == []


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
@pytest.mark.parametrize("route", [code_url, approve_url])
def test_a_busy_target_lock_is_a_503_and_writes_nothing(
    client, db_engine, clock, monkeypatch, sqlstate, route
):
    boss, _ = two_admins(client, db_engine, clock)
    target_user(client, db_engine, clock, role="editor")
    fail_lock(monkeypatch, "users", sqlstate)

    response = call(boss, "POST", route(user_id(db_engine, "target")))

    assert response.status_code == 503
    assert code_rows(db_engine) == []
    assert code_requests(db_engine) == []


@pytest.mark.parametrize("sqlstate", ["55P03", "40P01", "40001"])
def test_a_busy_request_lock_on_a_new_request_is_a_503(
    client, db_engine, clock, monkeypatch, sqlstate
):
    boss, _ = two_admins(client, db_engine, clock)
    target_user(client, db_engine, clock, role="editor")
    fail_lock(monkeypatch, "mfa_reset_requests", sqlstate)

    response = request_code(boss, db_engine)

    assert response.status_code == 503
    assert code_requests(db_engine) == []


@pytest.mark.parametrize("sqlstate", ["55P03", "40P01", "40001"])
def test_a_busy_request_lock_on_an_approval_is_a_503_and_keeps_the_request(
    client, db_engine, clock, monkeypatch, sqlstate
):
    boss, boss2 = two_admins(client, db_engine, clock)
    target_user(client, db_engine, clock, role="editor")
    request_code(boss, db_engine)
    (request,) = code_requests(db_engine)
    fail_lock(monkeypatch, "mfa_reset_requests", sqlstate)

    response = approve_code(boss2, db_engine)

    assert response.status_code == 503
    assert code_rows(db_engine) == []
    assert code_requests(db_engine) == [request]


@pytest.mark.parametrize("sqlstate", ["55P03", "40P01", "40001"])
def test_a_busy_requester_lock_on_an_approval_is_a_503_and_keeps_the_request(
    client, db_engine, clock, monkeypatch, sqlstate
):
    boss, boss2 = two_admins(client, db_engine, clock)
    target_user(client, db_engine, clock, role="editor")
    request_code(boss, db_engine)
    (request,) = code_requests(db_engine)
    seen = fail_requester_lock(monkeypatch, sqlstate, user_id(db_engine, "boss"))

    response = approve_code(boss2, db_engine)

    assert response.status_code == 503
    assert len(seen) == 1
    assert code_rows(db_engine) == []
    assert code_requests(db_engine) == [request]


# --- B3 and events ----------


def test_the_events_carry_no_code_or_hash(client, db_engine, clock, caplog):
    boss, boss2 = two_admins(client, db_engine, clock)
    target_user(client, db_engine, clock, role="editor")
    caplog.set_level(logging.DEBUG)

    request_code(boss, db_engine)
    code = approve_code(boss2, db_engine).json()["code"]

    for event in (
        "reset_code_requested",
        "reset_code_approved",
        "password_reset_code_issued",
    ):
        assert f"event={event} " in caplog.text
    (row,) = code_rows(db_engine)
    assert code not in caplog.text
    assert row["code_hash"] not in caplog.text
