"""One-use password reset codes issued by an administrator (ADR 0004, decision 10).

The pure helpers are unit tests; the route runs against real sessions like the
rest of /api/admin. Neither the code nor its hash may reach a log line.
"""

import logging
import re
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from gateway import admin as admin_module
from gateway import auth, recovery
from gateway.auth import NO_STORE
from gateway.db import get_engine
from gateway.main import create_app
from gateway.passwords import verify_password
from tests.helpers import DbError, FrozenClock, run_sql
from tests.test_admin import (
    USERS,
    admin,
    call,
    signed_in,
    user_id,
    user_row,
)
from tests.test_login import KEYS


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


CODE_FORMAT = re.compile(r"[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){3}")


def reset_url(target_id):
    return f"{USERS}/{target_id}/reset-code"


def code_rows(db_engine):
    with db_engine.connect() as conn:
        return conn.execute(text("SELECT * FROM password_reset_codes")).mappings().all()


def issue(c, db_engine, username):
    return call(c, "POST", reset_url(user_id(db_engine, username)))


# --- the pure helpers ------------------------------------------------------


def test_the_code_has_four_groups_of_five_unambiguous_symbols():
    code = recovery.new_reset_code()

    assert CODE_FORMAT.fullmatch(code)
    assert len(code.replace("-", "")) == 20
    assert set(recovery.RESET_ALPHABET) == set("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    assert not set("ILOU") & set(code)


def test_codes_are_different_on_every_call():
    codes = {recovery.new_reset_code() for _ in range(200)}

    assert len(codes) == 200


def test_the_ttl_is_fifteen_minutes():
    assert recovery.RESET_CODE_TTL == timedelta(minutes=15)


@pytest.mark.parametrize(
    "typed",
    ["abcde-fghjk-mnpqr-stvwx", " ABCDE FGHJK MNPQR STVWX ", "abcdefghjkmnpqrstvwx"],
)
def test_normalization_strips_spaces_and_dashes_and_uppercases(typed):
    assert recovery.normalize_reset_code(typed) == "ABCDEFGHJKMNPQRSTVWX"


# --- issuing -----------------------------------------------------------------


def test_an_administrator_issues_a_code_stored_only_as_a_hash(
    client, db_engine, clock, caplog
):
    c = admin(client, db_engine, clock)
    signed_in(client, db_engine, clock, "target")
    caplog.set_level(logging.INFO, logger="gateway.admin")

    response = issue(c, db_engine, "target")

    assert response.status_code == 200
    for header, value in NO_STORE.items():
        assert response.headers[header] == value
    body = response.json()
    assert set(body) == {"code", "expires_at"}
    assert CODE_FORMAT.fullmatch(body["code"])
    (row,) = code_rows(db_engine)
    assert str(row["user_id"]) == user_id(db_engine, "target")
    assert str(row["issued_by"]) == user_id(db_engine, "boss")
    assert row["code_hash"].startswith("$argon2id$")
    assert body["code"] not in row["code_hash"]
    assert verify_password(row["code_hash"], body["code"])
    assert row["created_at"] == clock()
    assert row["expires_at"] == clock() + timedelta(minutes=15)
    assert body["expires_at"].startswith(
        (clock() + timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%S")
    )


def test_the_event_names_actor_and_target_but_never_the_code_or_its_hash(
    client, db_engine, clock, caplog
):
    c = admin(client, db_engine, clock)
    signed_in(client, db_engine, clock, "target")
    caplog.set_level(logging.DEBUG)

    response = issue(c, db_engine, "target")

    code = response.json()["code"]
    (row,) = code_rows(db_engine)
    assert "event=password_reset_code_issued" in caplog.text
    assert f"actor={user_id(db_engine, 'boss')}" in caplog.text
    assert f"target={user_id(db_engine, 'target')}" in caplog.text
    assert code not in caplog.text
    assert code.replace("-", "") not in caplog.text
    assert row["code_hash"] not in caplog.text


def test_a_second_issuance_replaces_the_first(client, db_engine, clock):
    c = admin(client, db_engine, clock)
    signed_in(client, db_engine, clock, "target")
    first = issue(c, db_engine, "target").json()["code"]
    clock.now += timedelta(minutes=5)

    second = issue(c, db_engine, "target").json()["code"]

    (row,) = code_rows(db_engine)
    assert first != second
    assert not verify_password(row["code_hash"], first)
    assert verify_password(row["code_hash"], second)
    assert row["expires_at"] == clock() + timedelta(minutes=15)


def test_each_user_has_their_own_code(client, db_engine, clock):
    c = admin(client, db_engine, clock)
    signed_in(client, db_engine, clock, "one")
    signed_in(client, db_engine, clock, "two")

    issue(c, db_engine, "one")
    issue(c, db_engine, "two")

    assert len(code_rows(db_engine)) == 2


def test_a_reader_receives_a_code_from_one_administrator(client, db_engine, clock):
    c = admin(client, db_engine, clock)
    signed_in(client, db_engine, clock, "target", "lector")

    assert issue(c, db_engine, "target").status_code == 200
    assert len(code_rows(db_engine)) == 1


@pytest.mark.parametrize("role", ["editor", "auditor", "administrador"])
def test_a_privileged_target_gets_a_request_and_no_code_from_one_administrator(
    client, db_engine, clock, role
):
    # Option B: accounts that are or were privileged need two administrators
    # (see tests/test_two_administrator_recovery.py for the full flow).
    c = admin(client, db_engine, clock)
    admin(client, db_engine, clock, "boss2")
    admin(client, db_engine, clock, "boss3")
    signed_in(client, db_engine, clock, "target", role, mfa=True)

    response = issue(c, db_engine, "target")

    assert response.status_code == 202
    assert response.json()["status"] == "approval_required"
    assert code_rows(db_engine) == []


def test_an_administrator_cannot_issue_a_code_for_their_own_account(
    client, db_engine, clock, caplog
):
    c = admin(client, db_engine, clock)
    caplog.set_level(logging.INFO, logger="gateway.admin")

    response = issue(c, db_engine, "boss")

    assert response.status_code == 403
    assert response.json() == {"detail": "Forbidden"}
    assert code_rows(db_engine) == []
    assert "event=admin_denied" in caplog.text


@pytest.mark.parametrize("role", ["lector", "editor", "auditor"])
def test_a_user_who_is_not_an_administrator_gets_403_and_no_code(
    client, db_engine, clock, role
):
    c = signed_in(client, db_engine, clock, "actor", role, mfa=role != "lector")
    signed_in(client, db_engine, clock, "target")

    response = issue(c, db_engine, "target")

    assert response.status_code == 403
    assert code_rows(db_engine) == []


def test_an_unknown_target_is_404_and_stores_nothing(client, db_engine, clock):
    c = admin(client, db_engine, clock)

    response = call(c, "POST", reset_url("00000000-0000-4000-8000-000000000000"))

    assert response.status_code == 404
    assert code_rows(db_engine) == []


def test_a_request_without_csrf_is_refused_and_stores_nothing(client, db_engine, clock):
    c = admin(client, db_engine, clock)
    signed_in(client, db_engine, clock, "target")

    response = call(c, "POST", reset_url(user_id(db_engine, "target")), csrf=None)

    assert response.status_code == 403
    assert code_rows(db_engine) == []


def test_issuing_a_code_changes_nothing_else_of_the_target(client, db_engine, clock):
    c = admin(client, db_engine, clock)
    target = signed_in(client, db_engine, clock, "target")
    before = dict(user_row(db_engine, "target"))
    with db_engine.connect() as conn:
        families = conn.execute(
            text("SELECT id, revoked_at FROM refresh_families ORDER BY id")
        ).all()

    assert issue(c, db_engine, "target").status_code == 200

    assert dict(user_row(db_engine, "target")) == before
    with db_engine.connect() as conn:
        assert (
            conn.execute(
                text("SELECT id, revoked_at FROM refresh_families ORDER BY id")
            ).all()
            == families
        )
    assert target.get("/api/auth/me").status_code == 200


def test_a_pending_role_cleared_between_the_peek_and_the_lock_is_a_409(
    client, db_engine, clock, monkeypatch
):
    # The peek sees a pending role (no hash is made); the role is cleared before
    # the lock, and the account has no `privileged_at` marker, so under the lock
    # it no longer needs two administrators. There is no hash to store: the
    # request ends in a 409 with no code and no request row.
    c = admin(client, db_engine, clock)
    signed_in(client, db_engine, clock, "target")
    run_sql(
        db_engine, "UPDATE users SET pending_role = 'editor' WHERE username = 'target'"
    )
    target_id = user_id(db_engine, "target")
    real_lock = admin_module._lock_target

    def clear_then_lock(session, locked_id):
        run_sql(
            db_engine, "UPDATE users SET pending_role = NULL WHERE username = 'target'"
        )
        return real_lock(session, locked_id)

    monkeypatch.setattr(admin_module, "_lock_target", clear_then_lock)

    response = call(c, "POST", reset_url(target_id))

    assert response.status_code == 409
    assert response.json() == {"detail": "The account changed; try again"}
    assert code_rows(db_engine) == []
    with db_engine.connect() as conn:
        assert (
            conn.execute(text("SELECT count(*) FROM mfa_reset_requests")).scalar() == 0
        )


@pytest.mark.parametrize("sqlstate", ["55P03", "40P01", "40001"])
def test_a_busy_target_lock_is_a_503_and_writes_no_code(
    client, db_engine, clock, monkeypatch, sqlstate
):
    c = admin(client, db_engine, clock)
    signed_in(client, db_engine, clock, "target")
    target_id = user_id(db_engine, "target")
    real_scalar = Session.scalar

    def scalar(self, statement, *args, **kwargs):
        sql = str(statement)
        if "FROM users" in sql and "FOR UPDATE" in sql:
            raise OperationalError("SELECT", {}, DbError(sqlstate))
        return real_scalar(self, statement, *args, **kwargs)

    monkeypatch.setattr(Session, "scalar", scalar)

    response = call(c, "POST", reset_url(target_id))

    assert response.status_code == 503
    assert code_rows(db_engine) == []
