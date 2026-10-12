"""/api/admin: user management by an administrator (ADR 0004, decisions 5 and 11).

Sessions are real: a user registers, signs in as a reader and the test then sets
the role (and, where it matters, an active MFA) directly in the database, which
is exactly what `current_user` re-reads on every request. The MFA enrollment
that applies a pending role uses the real OpenBao transit engine.
"""

import logging
import threading
from datetime import timedelta
from typing import get_args

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text, update

from gateway import auth
from gateway.admin import Role
from gateway.db import get_engine
from gateway.main import create_app
from gateway.models import ROLES, User
from gateway.tokens import decode_access_token
from tests.helpers import FrozenClock
from tests.test_login import (
    GOOD,
    KEYS,
    LOGIN_FAILED,
    NOT_AUTHENTICATED,
    SAME_ORIGIN,
    attempt_row,
    login,
    register,
)
from tests.test_refresh import refresh, refresh_cookie_value

USERS = "/api/admin/users"
ME = "/api/auth/me"
ENROLL = "/api/auth/mfa/enroll"
CONFIRM = "/api/auth/mfa/confirm"
LOGIN_MFA = "/api/auth/login/mfa"
FORBIDDEN = {"detail": "Forbidden"}


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


def browser(client):
    return TestClient(client.app, base_url="https://testserver")


def set_user(db_engine, username, **columns):
    with db_engine.begin() as conn:
        conn.execute(update(User).where(User.username == username).values(**columns))


def user_row(db_engine, username):
    with db_engine.connect() as conn:
        return (
            conn.execute(
                text("SELECT * FROM users WHERE username = :n"), {"n": username}
            )
            .mappings()
            .one()
        )


def user_id(db_engine, username):
    return str(user_row(db_engine, username)["id"])


def signed_in(client, db_engine, clock, username, role="lector", *, mfa=False):
    """A browser with a full session of a new user, then the role set in the DB."""
    c = browser(client)
    register(c, username)
    assert login(c, username).status_code == 200
    columns = {"role": role}
    if mfa:
        columns["mfa_enabled_at"] = clock()
    set_user(db_engine, username, **columns)
    return c


def admin(client, db_engine, clock, username="boss"):
    return signed_in(client, db_engine, clock, username, "administrador", mfa=True)


def call(c, method, path, body=None, *, csrf=True, headers=SAME_ORIGIN):
    sent = dict(headers)
    if csrf is True:
        csrf = c.cookies.get("__Host-csrf")
    if csrf is not None:
        sent["X-CSRF-Token"] = csrf
    return c.request(method, path, json=body, headers=sent)


def assign(c, target_id, role):
    return call(c, "PUT", f"{USERS}/{target_id}/role", {"role": role})


def totp(secret, clock):
    return pyotp.TOTP(secret).at(clock())


def test_the_role_type_matches_the_roles_of_the_model():
    assert get_args(Role) == ROLES


# --- who may call --------------------------------------------------------


@pytest.mark.parametrize("role", ["lector", "editor", "auditor"])
def test_a_user_who_is_not_an_administrator_gets_403(client, db_engine, clock, role):
    c = signed_in(client, db_engine, clock, "someone", role, mfa=True)

    response = call(c, "GET", USERS)

    assert response.status_code == 403
    assert response.json() == FORBIDDEN
    assert response.headers["cache-control"] == "no-store"


def test_no_session_is_401(client):
    response = client.get(USERS)

    assert response.status_code == 401
    assert response.json() == NOT_AUTHENTICATED


def test_an_administrator_without_mfa_is_401_not_403(client, db_engine, clock):
    c = signed_in(client, db_engine, clock, "boss", "administrador", mfa=False)

    assert call(c, "GET", USERS).status_code == 401


def test_an_administrator_who_must_change_the_password_is_401(client, db_engine, clock):
    c = admin(client, db_engine, clock)
    set_user(db_engine, "boss", must_change_password=True)

    assert call(c, "GET", USERS).status_code == 401


def test_a_limited_session_cannot_reach_the_admin_routes(client, db_engine, clock):
    register(client, "boss")
    set_user(
        db_engine,
        "boss",
        role="administrador",
        mfa_enroll_until=clock() + timedelta(hours=1),
    )
    login(client, "boss")
    assert decode_access_token(client.cookies.get("__Host-access"), KEYS)["scope"]

    assert call(client, "GET", USERS).status_code == 401


def test_the_role_is_rechecked_in_the_database_on_every_request(
    client, db_engine, clock
):
    c = admin(client, db_engine, clock)
    assert call(c, "GET", USERS).status_code == 200

    set_user(db_engine, "boss", role="editor")

    assert call(c, "GET", USERS).status_code == 403


@pytest.mark.parametrize(
    ("method", "suffix", "body"),
    [
        ("PUT", "role", {"role": "editor"}),
        ("POST", "enrollment-window", None),
        ("POST", "unlock", None),
        ("POST", "sessions/end", None),
    ],
)
def test_state_changing_routes_need_same_origin_and_csrf(
    client, db_engine, clock, method, suffix, body
):
    c = admin(client, db_engine, clock)
    register(browser(client), "target")
    path = f"{USERS}/{user_id(db_engine, 'target')}/{suffix}"

    assert call(c, method, path, body, headers={}).status_code == 403
    assert (
        call(
            c, method, path, body, headers={"Sec-Fetch-Site": "cross-site"}
        ).status_code
        == 403
    )
    assert call(c, method, path, body, csrf=None).status_code == 403
    assert call(c, method, path, body, csrf="not-the-token").status_code == 403
    after = user_row(db_engine, "target")
    assert after["role"] == "lector"
    assert after["pending_role"] is None


def test_unknown_targets_are_404(client, db_engine, clock):
    c = admin(client, db_engine, clock)
    ghost = "00000000-0000-4000-8000-000000000001"

    assert assign(c, ghost, "editor").status_code == 404
    for suffix in ("enrollment-window", "unlock", "sessions/end"):
        assert call(c, "POST", f"{USERS}/{ghost}/{suffix}").status_code == 404
    assert assign(c, "not-a-uuid", "editor").status_code == 422


# --- listing -------------------------------------------------------------


def test_the_list_has_minimal_fields_and_no_secrets(client, db_engine, clock):
    c = admin(client, db_engine, clock)
    register(browser(client), "reader")
    signed_in(client, db_engine, clock, "editor-one", "editor", mfa=True)

    response = call(c, "GET", USERS)

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"items", "total", "limit", "offset"}
    assert body["total"] == 3
    expected = {"id", "username", "role", "pending_role", "mfa_enabled", "locked"}
    assert all(set(item) == expected for item in body["items"])
    assert [item["username"] for item in body["items"]] == [
        "boss",
        "editor-one",
        "reader",
    ]
    by_name = {item["username"]: item for item in body["items"]}
    assert by_name["boss"]["mfa_enabled"] is True
    assert by_name["reader"]["mfa_enabled"] is False
    assert by_name["reader"]["locked"] is False
    assert "$argon2" not in response.text
    assert "ciphertext" not in response.text


def test_the_list_is_paginated(client, db_engine, clock):
    c = admin(client, db_engine, clock, "aaa-boss")
    for name in ("user-b", "user-c", "user-d"):
        register(browser(client), name)

    first = call(c, "GET", f"{USERS}?limit=2&offset=0").json()
    second = call(c, "GET", f"{USERS}?limit=2&offset=2").json()

    assert [i["username"] for i in first["items"]] == ["aaa-boss", "user-b"]
    assert [i["username"] for i in second["items"]] == ["user-c", "user-d"]
    assert first["total"] == second["total"] == 4
    assert (first["limit"], first["offset"]) == (2, 0)


@pytest.mark.parametrize("query", ["limit=0", "limit=101", "offset=-1", "limit=x"])
def test_bad_pagination_is_422(client, db_engine, clock, query):
    c = admin(client, db_engine, clock)

    assert call(c, "GET", f"{USERS}?{query}").status_code == 422


def test_a_locked_account_shows_as_locked_until_the_lock_ends(client, db_engine, clock):
    c = admin(client, db_engine, clock)
    register(browser(client), "victim")
    for _ in range(4):
        assert (
            login(browser(client), "victim", "wrong password here").status_code == 401
        )

    def locked():
        items = call(c, "GET", USERS).json()["items"]
        return {i["username"]: i["locked"] for i in items}["victim"]

    assert locked() is True
    clock.now += timedelta(minutes=2)
    assert locked() is False


# --- assigning roles -----------------------------------------------------


def test_a_privileged_role_for_a_user_with_mfa_applies_now(
    client, db_engine, clock, caplog
):
    c = admin(client, db_engine, clock)
    target = signed_in(client, db_engine, clock, "target", mfa=True)
    caplog.set_level(logging.INFO, logger="gateway.admin")
    clock.now += timedelta(seconds=5)

    response = assign(c, user_id(db_engine, "target"), "editor")

    assert response.status_code == 200
    assert response.json()["role"] == "editor"
    assert response.json()["pending_role"] is None
    row = user_row(db_engine, "target")
    assert (row["role"], row["pending_role"]) == ("editor", None)
    assert row["tokens_valid_since"] == clock()
    # The target's session from before the change is over.
    assert target.get(ME).status_code == 401
    boss_id = user_id(db_engine, "boss")
    assert (
        f"event=role_assigned actor={boss_id} target={user_id(db_engine, 'target')}"
        in (caplog.text)
    )
    assert "role=editor" in caplog.text


def test_a_privileged_role_for_a_user_without_mfa_is_pending(
    client, db_engine, clock, caplog
):
    c = admin(client, db_engine, clock)
    target = signed_in(client, db_engine, clock, "target")
    caplog.set_level(logging.INFO, logger="gateway.admin")
    clock.now += timedelta(seconds=5)

    response = assign(c, user_id(db_engine, "target"), "auditor")

    assert response.status_code == 200
    assert (response.json()["role"], response.json()["pending_role"]) == (
        "lector",
        "auditor",
    )
    row = user_row(db_engine, "target")
    assert (row["role"], row["pending_role"]) == ("lector", "auditor")
    assert row["mfa_enroll_until"] == clock() + timedelta(hours=24)
    assert row["tokens_valid_since"] == clock()
    assert target.get(ME).status_code == 401
    assert "event=role_assignment_pending" in caplog.text
    assert "role=auditor" in caplog.text


def test_a_privileged_user_without_mfa_is_demoted_to_pending(client, db_engine, clock):
    # The #43 case: a privileged user that existed before MFA was required.
    c = admin(client, db_engine, clock)
    signed_in(client, db_engine, clock, "legacy", "editor", mfa=False)

    response = assign(c, user_id(db_engine, "legacy"), "editor")

    assert response.status_code == 200
    assert (response.json()["role"], response.json()["pending_role"]) == (
        "lector",
        "editor",
    )
    legacy = browser(client)
    assert login(legacy, "legacy").json() == {"status": "mfa_enrollment_required"}


def test_assigning_a_reader_clears_the_pending_role(client, db_engine, clock):
    c = admin(client, db_engine, clock)
    signed_in(client, db_engine, clock, "target")
    assign(c, user_id(db_engine, "target"), "editor")

    response = assign(c, user_id(db_engine, "target"), "lector")

    assert response.status_code == 200
    assert (response.json()["role"], response.json()["pending_role"]) == (
        "lector",
        None,
    )
    assert user_row(db_engine, "target")["pending_role"] is None


def test_a_reader_assignment_demotes_a_privileged_user_with_mfa(
    client, db_engine, clock
):
    c = admin(client, db_engine, clock)
    signed_in(client, db_engine, clock, "target", "editor", mfa=True)

    response = assign(c, user_id(db_engine, "target"), "lector")

    assert response.json()["role"] == "lector"


def test_assigning_the_same_role_changes_nothing(client, db_engine, clock):
    c = admin(client, db_engine, clock)
    signed_in(client, db_engine, clock, "target", "editor", mfa=True)
    before = user_row(db_engine, "target")["tokens_valid_since"]
    clock.now += timedelta(seconds=5)

    response = assign(c, user_id(db_engine, "target"), "editor")

    assert response.status_code == 200
    assert user_row(db_engine, "target")["tokens_valid_since"] == before


@pytest.mark.parametrize(
    "body", [{"role": "root"}, {}, {"role": "editor", "extra": 1}, {"role": None}]
)
def test_a_bad_role_body_is_422(client, db_engine, clock, body):
    c = admin(client, db_engine, clock)
    signed_in(client, db_engine, clock, "target")

    response = call(c, "PUT", f"{USERS}/{user_id(db_engine, 'target')}/role", body)

    assert response.status_code == 422
    assert user_row(db_engine, "target")["role"] == "lector"


# --- separation of duties and the last administrator ---------------------


def test_an_administrator_cannot_assign_the_auditor_role_to_themselves(
    client, db_engine, clock
):
    c = admin(client, db_engine, clock)

    response = assign(c, user_id(db_engine, "boss"), "auditor")

    assert response.status_code == 403
    assert user_row(db_engine, "boss")["role"] == "administrador"
    assert call(c, "GET", USERS).status_code == 200


def test_an_administrator_cannot_be_made_auditor_by_another(client, db_engine, clock):
    c = admin(client, db_engine, clock)
    admin(client, db_engine, clock, "second")

    response = assign(c, user_id(db_engine, "second"), "auditor")

    assert response.status_code == 403
    assert user_row(db_engine, "second")["role"] == "administrador"


def test_the_auditor_role_can_go_to_a_non_administrator(client, db_engine, clock):
    c = admin(client, db_engine, clock)
    signed_in(client, db_engine, clock, "target", mfa=True)

    assert assign(c, user_id(db_engine, "target"), "auditor").status_code == 200


def test_the_last_administrator_cannot_lose_the_role(client, db_engine, clock):
    c = admin(client, db_engine, clock)

    for role in ("lector", "editor"):
        response = assign(c, user_id(db_engine, "boss"), role)
        assert response.status_code == 409
    assert user_row(db_engine, "boss")["role"] == "administrador"
    assert call(c, "GET", USERS).status_code == 200


def test_an_administrator_without_mfa_does_not_count_as_a_second_one(
    client, db_engine, clock
):
    c = admin(client, db_engine, clock)
    signed_in(client, db_engine, clock, "unusable", "administrador", mfa=False)

    assert assign(c, user_id(db_engine, "boss"), "lector").status_code == 409


def test_an_administrator_can_step_down_when_another_one_remains(
    client, db_engine, clock
):
    c = admin(client, db_engine, clock)
    admin(client, db_engine, clock, "second")
    clock.now += timedelta(seconds=5)

    response = assign(c, user_id(db_engine, "boss"), "lector")

    assert response.status_code == 200
    assert call(c, "GET", USERS).status_code == 401  # the old session is over


def test_two_administrators_cannot_remove_each_other(client, db_engine, clock):
    first = admin(client, db_engine, clock, "first")
    second = admin(client, db_engine, clock, "second")
    ids = {name: user_id(db_engine, name) for name in ("first", "second")}
    start = threading.Barrier(2)
    codes = []

    def demote(c, target):
        start.wait()
        codes.append(assign(c, ids[target], "lector").status_code)

    threads = [
        threading.Thread(target=demote, args=(first, "second")),
        threading.Thread(target=demote, args=(second, "first")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    with db_engine.connect() as conn:
        admins = conn.execute(
            text("SELECT count(*) FROM users WHERE role = 'administrador'")
        ).scalar()
    assert admins == 1
    assert sorted(codes)[0] == 200
    assert sorted(codes)[1] in (403, 409)


# --- the enrollment window -----------------------------------------------


def test_an_expired_window_is_reissued(client, db_engine, clock, caplog):
    c = admin(client, db_engine, clock)
    signed_in(client, db_engine, clock, "target")
    assign(c, user_id(db_engine, "target"), "editor")
    clock.now += timedelta(hours=25)
    assert login(browser(client), "target").status_code == 200  # plain reader again
    caplog.set_level(logging.INFO, logger="gateway.admin")

    response = call(
        c, "POST", f"{USERS}/{user_id(db_engine, 'target')}/enrollment-window"
    )

    assert response.status_code == 200
    assert user_row(db_engine, "target")["mfa_enroll_until"] == clock() + timedelta(
        hours=24
    )
    assert login(browser(client), "target").json() == {
        "status": "mfa_enrollment_required"
    }
    assert "event=enrollment_window_reissued" in caplog.text


def test_a_window_that_is_still_open_is_not_reissued(client, db_engine, clock):
    c = admin(client, db_engine, clock)
    signed_in(client, db_engine, clock, "target")
    assign(c, user_id(db_engine, "target"), "editor")
    until = user_row(db_engine, "target")["mfa_enroll_until"]
    clock.now += timedelta(hours=1)

    response = call(
        c, "POST", f"{USERS}/{user_id(db_engine, 'target')}/enrollment-window"
    )

    assert response.status_code == 409
    assert user_row(db_engine, "target")["mfa_enroll_until"] == until


@pytest.mark.parametrize(
    "columns",
    [
        {"role": "editor", "mfa_enabled": True},  # already has the factor
        {"role": "lector"},  # nothing to enroll for
    ],
)
def test_the_window_is_only_for_who_still_has_to_enroll(
    client, db_engine, clock, columns
):
    c = admin(client, db_engine, clock)
    signed_in(
        client,
        db_engine,
        clock,
        "target",
        columns["role"],
        mfa=columns.get("mfa_enabled", False),
    )
    if columns["role"] == "editor":
        set_user(db_engine, "target", mfa_enroll_until=None)

    response = call(
        c, "POST", f"{USERS}/{user_id(db_engine, 'target')}/enrollment-window"
    )

    assert response.status_code == 409
    assert user_row(db_engine, "target")["mfa_enroll_until"] is None


def test_a_privileged_user_without_a_window_gets_one(client, db_engine, clock):
    c = admin(client, db_engine, clock)
    signed_in(client, db_engine, clock, "legacy", "editor", mfa=False)

    response = call(
        c, "POST", f"{USERS}/{user_id(db_engine, 'legacy')}/enrollment-window"
    )

    assert response.status_code == 200
    assert login(browser(client), "legacy").json() == {
        "status": "mfa_enrollment_required"
    }


# --- unlocking and ending sessions ---------------------------------------


def test_unlocking_resets_the_counter_for_the_next_login(
    client, db_engine, clock, caplog
):
    c = admin(client, db_engine, clock)
    register(browser(client), "victim")
    for _ in range(4):
        login(browser(client), "victim", "wrong password here")
    assert attempt_row(db_engine, "victim").locked_until is not None
    assert login(browser(client), "victim").status_code == 401
    caplog.set_level(logging.INFO, logger="gateway.admin")

    response = call(c, "POST", f"{USERS}/{user_id(db_engine, 'victim')}/unlock")

    assert response.status_code == 200
    assert response.json()["locked"] is False
    row = attempt_row(db_engine, "victim")
    assert (row.failures, row.locked_until) == (0, None)
    assert login(browser(client), "victim").status_code == 200
    assert "event=account_unlocked" in caplog.text


def test_unlocking_an_account_that_never_failed_is_harmless(client, db_engine, clock):
    c = admin(client, db_engine, clock)
    register(browser(client), "fine")

    response = call(c, "POST", f"{USERS}/{user_id(db_engine, 'fine')}/unlock")

    assert response.status_code == 200
    assert login(browser(client), "fine").status_code == 200


def test_ending_sessions_revokes_every_family_and_the_tokens(
    client, db_engine, clock, caplog
):
    c = admin(client, db_engine, clock)
    register(browser(client), "target")
    first, second = browser(client), browser(client)
    login_a = login(first, "target")
    login(second, "target")
    refresh_a = refresh_cookie_value(login_a)
    csrf_a = first.cookies.get("__Host-csrf")
    caplog.set_level(logging.INFO, logger="gateway.admin")
    clock.now += timedelta(seconds=5)

    response = call(c, "POST", f"{USERS}/{user_id(db_engine, 'target')}/sessions/end")

    assert response.status_code == 200
    assert first.get(ME).status_code == 401
    assert second.get(ME).status_code == 401
    assert refresh(first, refresh_a, csrf_a).status_code == 401
    with db_engine.connect() as conn:
        live = conn.execute(
            text("SELECT count(*) FROM refresh_families WHERE revoked_at IS NULL")
        ).scalar()
    assert live == 1  # the administrator's own
    assert user_row(db_engine, "target")["tokens_valid_since"] == clock()
    assert login(browser(client), "target").status_code == 200
    assert "event=sessions_ended" in caplog.text


# --- the pending role becomes the role at MFA confirmation ---------------


def test_confirming_the_mfa_applies_the_pending_role(client, db_engine, clock, caplog):
    c = admin(client, db_engine, clock)
    register(browser(client), "target")
    assign(c, user_id(db_engine, "target"), "editor")
    target = browser(client)
    assert login(target, "target").json() == {"status": "mfa_enrollment_required"}
    secret = call(target, "POST", ENROLL).json()["secret"]
    caplog.set_level(logging.INFO, logger="gateway.auth")
    before = user_row(db_engine, "target")["tokens_valid_since"]
    clock.now += timedelta(seconds=5)

    response = call(target, "POST", CONFIRM, {"code": totp(secret, clock)})

    assert response.status_code == 200
    row = user_row(db_engine, "target")
    assert (row["role"], row["pending_role"]) == ("editor", None)
    assert row["tokens_valid_since"] == clock() > before
    assert row["mfa_enroll_until"] is None
    assert "event=pending_role_applied" in caplog.text
    # A normal login now asks for the factor and ends as an editor.
    set_user(db_engine, "target", mfa_last_step=None)
    again = browser(client)
    assert login(again, "target").json() == {"status": "mfa_required"}
    done = call(again, "POST", LOGIN_MFA, {"code": totp(secret, clock)})
    assert done.json()["role"] == "editor"
    assert again.get(ME).json()["role"] == "editor"


def test_confirm_holds_the_user_row_while_it_applies_the_pending_role(
    client, db_engine, clock, monkeypatch
):
    """`assign_role` locks the user row; so must the confirmation that reads it.

    Without that lock the confirmation can apply a pending role that an
    administrator changed or cleared in between (the last writer would win). A
    separate connection asks for `FOR UPDATE NOWAIT` on the row at the point
    where the eligibility is checked again: if the request did not hold it,
    PostgreSQL would grant it at once, so there is nothing to time.
    """
    c = admin(client, db_engine, clock)
    register(browser(client), "target")
    assign(c, user_id(db_engine, "target"), "editor")
    target = browser(client)
    assert login(target, "target").json() == {"status": "mfa_enrollment_required"}
    secret = call(target, "POST", ENROLL).json()["secret"]
    held = []
    real = auth._recheck_can_enroll

    def probing(*args, **kwargs):
        with db_engine.connect() as conn:
            try:
                conn.execute(
                    text(
                        "SELECT 1 FROM users WHERE username = 'target' "
                        "FOR UPDATE NOWAIT"
                    )
                ).one()
            except Exception as exc:
                held.append(type(exc.orig).__name__)
        return real(*args, **kwargs)

    monkeypatch.setattr(auth, "_recheck_can_enroll", probing)

    response = call(target, "POST", CONFIRM, {"code": totp(secret, clock)})

    assert response.status_code == 200
    assert held == ["LockNotAvailable"]


def test_a_reader_with_a_pending_role_cannot_enroll_after_the_window(
    client, db_engine, clock
):
    c = admin(client, db_engine, clock)
    signed_in(client, db_engine, clock, "target")
    assign(c, user_id(db_engine, "target"), "editor")
    # The window lapsed (set in the database: tokens cannot be issued in the
    # future, so the clock stays put).
    set_user(db_engine, "target", mfa_enroll_until=clock() - timedelta(hours=1))
    full = browser(client)
    assert login(full, "target").status_code == 200  # a plain reader session

    response = call(full, "POST", ENROLL, {"current_password": GOOD})

    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert user_row(db_engine, "target")["pending_role"] == "editor"


def test_a_reader_without_a_pending_role_can_still_enroll_with_a_full_session(
    client, db_engine, clock
):
    register(client, "plain")
    login(client, "plain")

    response = call(client, "POST", ENROLL, {"current_password": GOOD})

    assert response.status_code == 200


def test_a_pending_user_inside_the_window_is_sent_to_the_enrollment(
    client, db_engine, clock
):
    c = admin(client, db_engine, clock)
    register(browser(client), "target")
    assign(c, user_id(db_engine, "target"), "auditor")

    target = browser(client)
    response = login(target, "target")

    assert response.json() == {"status": "mfa_enrollment_required"}
    assert decode_access_token(target.cookies.get("__Host-access"), KEYS)["scope"] == (
        "enroll-mfa"
    )
