"""POST /api/auth/password-reset: an anonymous reset with an administrator-issued code.

ADR 0004, decision 10. The route is anonymous (the user cannot sign in), so it
is guarded like login: same origin plus the pre-session CSRF token, one generic
401 for every failure, and failures counted on the login attempt key. These
tests use the real OpenBao transit engine for the MFA cases and a frozen clock.
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
from gateway.passwords import hash_password
from tests.helpers import DbError, FrozenClock, Interfere, current_step, run_sql
from tests.test_admin import admin, set_user, signed_in
from tests.test_admin import user_id as admin_user_id
from tests.test_login import (
    GOOD,
    KEYS,
    LOGIN_FAILED,
    OTHER,
    SAME_ORIGIN,
    attempt_key,
    attempt_row,
    get_csrf,
    login,
    register,
)
from tests.test_mfa import (
    CONFIRM,
    ENROLL,
    enroll,
    events,
    make_user,
    post,
    totp,
    user_row,
)
from tests.test_reset_code import issue

RESET = "/api/auth/password-reset"
ME = "/api/auth/me"
REFRESH = "/api/auth/refresh"
NEW = "an entirely new passphrase"
CODE = "ABCDE-FGHJK-MNPQR-STVWX"
BUSY = "Service busy; try again later"


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


def reset(
    client,
    username="alice",
    code=CODE,
    new=NEW,
    mfa_code=None,
    *,
    token=None,
    headers=SAME_ORIGIN,
):
    token = get_csrf(client) if token is None else token
    body = {"username": username, "code": code, "new_password": new}
    if mfa_code is not None:
        body["mfa_code"] = mfa_code
    return client.post(RESET, json=body, headers={**headers, "X-CSRF-Token": token})


def put_code(
    db_engine, clock, username="alice", code=CODE, *, ttl_minutes=15, approved_by=None
):
    """Store a live reset code the way the issuing route does (hash of the code).

    `approved_by` is the username of the second administrator, for the codes that
    accounts which are or were privileged need.
    """
    run_sql(
        db_engine,
        "DELETE FROM password_reset_codes WHERE user_id = "
        "(SELECT id FROM users WHERE username = :n)",
        n=username,
    )
    run_sql(
        db_engine,
        "INSERT INTO password_reset_codes "
        "(user_id, code_hash, created_at, expires_at, approved_by) "
        "SELECT id, :h, :c, :e, (SELECT id FROM users WHERE username = :a) "
        "FROM users WHERE username = :n",
        h=hash_password(code),
        c=clock(),
        e=clock() + timedelta(minutes=ttl_minutes),
        n=username,
        a=approved_by,
    )


def lock_account(db_engine, until):
    """Five failures on alice's counter and a lock until `until`."""
    run_sql(
        db_engine,
        "INSERT INTO login_attempts (attempt_key, failures, locked_until) "
        "VALUES (:k, 5, :u) ON CONFLICT (attempt_key) DO UPDATE "
        "SET failures = 5, locked_until = :u",
        k=attempt_key(),
        u=until,
    )


def code_rows(db_engine):
    with db_engine.connect() as conn:
        return conn.execute(text("SELECT * FROM password_reset_codes")).mappings().all()


def reader(client, db_engine, clock, username="alice", **columns):
    """A registered reader (no MFA) with a live code; a session of it is returned."""
    session = browser(client)
    register(session, username)
    assert login(session, username).status_code == 200
    if columns:
        set_user(db_engine, username, **columns)
    put_code(db_engine, clock, username)
    return session


def mfa_reader(client, db_engine, clock, username="alice"):
    """A reader with MFA active and a live code; return the secret and the codes.

    The clock moves one TOTP step on, so the next TOTP is not a replay of the one
    that confirmed the enrollment.
    """
    make_user(client, db_engine, clock, username, role="lector", window=False)
    assert login(client, username).status_code == 200
    secret = post(client, ENROLL, {"current_password": GOOD}).json()["secret"]
    confirmed = post(client, CONFIRM, {"code": totp(secret, clock)})
    assert confirmed.status_code == 200
    client.cookies.clear()
    clock.now += timedelta(seconds=30)
    put_code(db_engine, clock, username)
    return secret, confirmed.json()["recovery_codes"]


def nothing_changed(db_engine, before, *, rows=1):
    row = user_row(db_engine)
    assert row["password_hash"] == before["password_hash"]
    assert row["token_generation"] == before["token_generation"]
    assert row["password_reset_notice_at"] == before["password_reset_notice_at"]
    assert len(code_rows(db_engine)) == rows


# --- the code, as typed ---------------------------------------------------------


def test_the_canonical_form_regroups_what_was_typed():
    assert recovery.canonical_reset_code(" abcde fghjk-mnpqr stvwx ") == CODE
    assert recovery.canonical_reset_code("abcdefghjkmnpqrstvwx") == CODE


@pytest.mark.parametrize(
    "typed",
    ["", "ABCDE", CODE + "A", "ABCDE-FGHJK-MNPQR-STVWI", "ÁBCDE-FGHJK-MNPQR-STVW"],
)
def test_a_malformed_code_has_no_canonical_form(typed):
    assert recovery.canonical_reset_code(typed) is None


# --- success --------------------------------------------------------------------


def test_a_valid_code_resets_the_password_and_ends_every_session(
    client, db_engine, clock
):
    old = reader(client, db_engine, clock, must_change_password=True)
    old_csrf = old.cookies.get("__Host-csrf")
    before = user_row(db_engine)
    anonymous = browser(client)
    assert login(anonymous, password=OTHER).status_code == 401  # counter at 1
    assert attempt_row(db_engine) == (1, None)

    response = reset(anonymous)

    assert response.status_code == 200
    assert response.json() == {"status": "password_reset"}
    for header, value in NO_STORE.items():
        assert response.headers[header] == value
    # No session is opened by a reset.
    assert response.headers.get_list("set-cookie") == []
    after = user_row(db_engine)
    assert after["password_hash"] != before["password_hash"]
    assert after["must_change_password"] is False
    assert after["token_generation"] == before["token_generation"] + 1
    assert before["password_reset_notice_at"] is None
    assert after["password_reset_notice_at"] == clock()
    assert code_rows(db_engine) == []
    assert attempt_row(db_engine) == (0, None)
    # The old password is gone, the new one works.
    assert login(browser(client), password=GOOD).status_code == 401
    assert login(browser(client), password=NEW).status_code == 200
    # Every earlier session is dead: access token and refresh family.
    assert old.get(ME).status_code == 401
    refreshed = old.post(
        REFRESH,
        headers={**SAME_ORIGIN, "X-CSRF-Token": old_csrf},
    )
    assert refreshed.status_code == 401


def test_every_refresh_family_of_the_user_is_revoked(client, db_engine, clock):
    reader(client, db_engine, clock)
    assert login(browser(client)).status_code == 200  # a second family
    assert reset(browser(client)).status_code == 200
    with db_engine.connect() as conn:
        open_families = conn.execute(
            text("SELECT count(*) FROM refresh_families WHERE revoked_at IS NULL")
        ).scalar()
    assert open_families == 0


@pytest.mark.parametrize(
    "typed",
    [
        "ABCDE-FGHJK-MNPQR-STVWX",
        "abcde-fghjk-mnpqr-stvwx",
        " ABCDE FGHJK MNPQR STVWX ",
        "abcdefghjkmnpqrstvwx",
    ],
)
def test_the_grouped_and_the_ungrouped_forms_are_both_accepted(
    client, db_engine, clock, typed
):
    reader(client, db_engine, clock)

    response = reset(browser(client), code=typed)

    assert response.status_code == 200
    assert login(browser(client), password=NEW).status_code == 200


def test_a_code_issued_by_an_administrator_works_end_to_end(client, db_engine, clock):
    boss = admin(client, db_engine, clock)
    signed_in(client, db_engine, clock, "alice")
    issued = issue(boss, db_engine, "alice").json()

    response = reset(browser(client), code=issued["code"])

    assert response.status_code == 200
    assert login(browser(client), password=NEW).status_code == 200


def test_a_reader_with_a_pending_role_is_judged_by_the_current_role(
    client, db_engine, clock
):
    # Still no second factor (no MFA, a reader now), but the pending role makes
    # the account need the code approved by two administrators.
    admin(client, db_engine, clock)
    reader(client, db_engine, clock, pending_role="editor")
    put_code(db_engine, clock, approved_by="boss")

    assert reset(browser(client)).status_code == 200


def test_an_unneeded_mfa_code_is_ignored(client, db_engine, clock):
    reader(client, db_engine, clock)

    assert reset(browser(client), mfa_code="123456").status_code == 200


# --- failures ---------------------------------------------------------------------


def test_a_used_code_is_refused_and_counted(client, db_engine, clock):
    reader(client, db_engine, clock)
    assert reset(browser(client)).status_code == 200
    before = user_row(db_engine)

    response = reset(browser(client), new="yet another passphrase")

    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert attempt_row(db_engine) == (1, None)
    nothing_changed(db_engine, before, rows=0)


@pytest.mark.parametrize(("minutes", "valid"), [(14, True), (15, False), (16, False)])
def test_a_code_lives_fifteen_minutes(client, db_engine, clock, minutes, valid):
    reader(client, db_engine, clock)
    before = user_row(db_engine)
    clock.now += timedelta(minutes=minutes)

    response = reset(browser(client))

    if valid:
        assert response.status_code == 200
        return
    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert attempt_row(db_engine) == (1, None)
    nothing_changed(db_engine, before)


def test_a_replaced_code_voids_the_previous_one(client, db_engine, clock):
    boss = admin(client, db_engine, clock)
    signed_in(client, db_engine, clock, "alice")
    first = issue(boss, db_engine, "alice").json()["code"]
    second = issue(boss, db_engine, "alice").json()["code"]

    refused = reset(browser(client), code=first)

    assert refused.status_code == 401
    assert refused.json() == LOGIN_FAILED
    assert attempt_row(db_engine) == (1, None)
    assert reset(browser(client), code=second).status_code == 200


def test_a_wrong_code_an_unknown_user_and_no_code_look_the_same(
    client, db_engine, clock
):
    reader(client, db_engine, clock)  # alice has a code
    register(browser(client), "bob")  # bob has none

    wrong = reset(browser(client), code="ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ")
    unknown = reset(browser(client), username="ghost")
    no_code = reset(browser(client), username="bob")
    malformed = reset(browser(client), code="ABC")

    answers = [wrong, unknown, no_code, malformed]
    assert [a.status_code for a in answers] == [401] * 4
    assert {a.text for a in answers} == {wrong.text}
    assert wrong.json() == LOGIN_FAILED
    for a in answers:
        for header, value in NO_STORE.items():
            assert a.headers[header] == value
    assert attempt_row(db_engine, "alice") == (2, None)  # wrong and malformed
    assert attempt_row(db_engine, "ghost") == (1, None)
    assert attempt_row(db_engine, "bob") == (1, None)
    assert len(code_rows(db_engine)) == 1


def test_failures_lock_the_account_like_login_does(client, db_engine, clock):
    reader(client, db_engine, clock)

    for _ in range(4):
        reset(browser(client), code="ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ")

    failures, locked_until = attempt_row(db_engine)
    assert failures == 4
    assert locked_until == clock() + timedelta(minutes=1)
    # The right code does not open a locked account, and nothing is counted.
    assert reset(browser(client)).status_code == 401
    assert attempt_row(db_engine) == (4, locked_until)
    assert len(code_rows(db_engine)) == 1


def test_a_locked_account_is_refused_without_checking_the_code(
    client, db_engine, clock, monkeypatch
):
    reader(client, db_engine, clock)
    locked = clock() + timedelta(minutes=5)
    lock_account(db_engine, locked)
    verified = []
    real = auth.verify_password
    monkeypatch.setattr(
        auth, "verify_password", lambda *a: verified.append(a) or real(*a)
    )
    before = user_row(db_engine)

    response = reset(browser(client))

    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert verified == []
    assert attempt_row(db_engine) == (5, locked)
    nothing_changed(db_engine, before)


def test_unknown_users_and_missing_codes_cost_a_dummy_verification(
    client, db_engine, clock, monkeypatch
):
    register(browser(client), "bob")
    dummies = []
    real = auth.verify_dummy
    monkeypatch.setattr(auth, "verify_dummy", lambda p: dummies.append(p) or real(p))

    reset(browser(client), username="ghost")
    reset(browser(client), username="bob")

    assert len(dummies) == 2


def test_the_new_password_is_not_hashed_for_a_wrong_code(
    client, db_engine, clock, monkeypatch
):
    reader(client, db_engine, clock)
    hashed = []
    real = auth.hash_password
    monkeypatch.setattr(auth, "hash_password", lambda p: hashed.append(p) or real(p))

    reset(browser(client), code="ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ")
    assert hashed == []
    reset(browser(client))
    assert hashed == [NEW]


# --- the second factor ------------------------------------------------------------


def test_an_mfa_reader_needs_the_second_factor(client, db_engine, clock):
    secret, _ = mfa_reader(client, db_engine, clock)
    before = user_row(db_engine)

    missing = reset(browser(client))
    wrong = reset(browser(client), mfa_code="000000")
    shaped_like_a_recovery_code = reset(browser(client), mfa_code="AAAA-BBBB-CCCC")

    for response in (missing, wrong, shaped_like_a_recovery_code):
        assert response.status_code == 401
        assert response.json() == LOGIN_FAILED
    assert attempt_row(db_engine) == (3, None)
    nothing_changed(db_engine, before)


def test_a_totp_completes_the_reset_and_its_step_is_spent(client, db_engine, clock):
    secret, _ = mfa_reader(client, db_engine, clock)

    response = reset(browser(client), mfa_code=totp(secret, clock))

    assert response.status_code == 200
    assert user_row(db_engine)["mfa_last_step"] == current_step(clock)
    # The same TOTP step cannot be used again, with a fresh code.
    put_code(db_engine, clock)
    replay = reset(
        browser(client), new="yet another passphrase", mfa_code=totp(secret, clock)
    )
    assert replay.status_code == 401
    assert len(code_rows(db_engine)) == 1


def test_a_recovery_code_completes_the_reset_and_is_spent(
    client, db_engine, clock, caplog
):
    _, codes = mfa_reader(client, db_engine, clock)
    caplog.set_level(logging.INFO, logger="gateway.auth")

    response = reset(browser(client), mfa_code=codes[0].lower())

    assert response.status_code == 200
    with db_engine.connect() as conn:
        used = conn.execute(
            text("SELECT count(*) FROM recovery_codes WHERE used_at IS NOT NULL")
        ).scalar()
    assert used == 1
    assert events(caplog) == ["recovery_code_used", "password_reset"]
    # MFA stays enabled: a reset changes the password, nothing else.
    assert user_row(db_engine)["mfa_enabled_at"] is not None


def test_a_wrong_second_factor_does_not_spend_the_reset_code(client, db_engine, clock):
    secret, _ = mfa_reader(client, db_engine, clock)

    assert reset(browser(client), mfa_code="000000").status_code == 401
    assert len(code_rows(db_engine)) == 1
    assert reset(browser(client), mfa_code=totp(secret, clock)).status_code == 200


def test_a_privileged_role_with_mfa_needs_the_second_factor(client, db_engine, clock):
    admin(client, db_engine, clock)
    secret, _ = enroll(client, db_engine, clock, "alice", "editor")
    client.cookies.clear()
    clock.now += timedelta(seconds=30)
    put_code(db_engine, clock, approved_by="boss")

    assert reset(browser(client)).status_code == 401
    assert reset(browser(client), mfa_code=totp(secret, clock)).status_code == 200


def test_a_privileged_role_without_mfa_uses_a_two_administrator_code_alone(
    client, db_engine, clock
):
    # ADR 0004, decision 10 (option B): the second factor is due only while MFA
    # is active. A privileged account without MFA recovers with a code that two
    # administrators approved, and no factor.
    admin(client, db_engine, clock)
    make_user(client, db_engine, clock, "alice", role="editor", window=True)
    put_code(db_engine, clock, approved_by="boss")

    response = reset(browser(client))

    assert response.status_code == 200
    assert code_rows(db_engine) == []


def test_a_privileged_role_without_mfa_refuses_a_single_administrator_code(
    client, db_engine, clock
):
    make_user(client, db_engine, clock, "alice", role="editor", window=True)
    put_code(db_engine, clock)
    before = user_row(db_engine)

    for mfa_code in (None, "123456"):
        response = reset(browser(client), mfa_code=mfa_code)
        assert response.status_code == 401
        assert response.json() == LOGIN_FAILED

    assert attempt_row(db_engine) == (2, None)
    nothing_changed(db_engine, before)


# --- input ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        {"username": "alice", "code": CODE, "new_password": "tiny pass"},
        {"username": "alice", "code": CODE, "new_password": "é" * 8},
        {"username": "ALICE", "code": CODE, "new_password": NEW},
        {"username": "alice", "code": "bad!code", "new_password": NEW},
        {"username": "alice", "code": "A" * 33, "new_password": NEW},
        {"username": "alice", "code": CODE, "new_password": NEW, "mfa_code": "no!"},
        {"username": "alice", "code": CODE, "new_password": NEW, "extra": "x"},
        {"username": "alice", "code": CODE},
    ],
)
def test_a_body_that_breaks_the_schema_is_a_422_that_echoes_nothing(
    client, db_engine, clock, body
):
    reader(client, db_engine, clock)
    before = user_row(db_engine)
    anonymous = browser(client)

    response = anonymous.post(
        RESET, json=body, headers={**SAME_ORIGIN, "X-CSRF-Token": get_csrf(anonymous)}
    )

    assert response.status_code == 422
    for value in body.values():
        if isinstance(value, str) and len(value) > 4:
            assert value not in response.text
    assert attempt_row(db_engine) == (0, None)  # only the login's
    nothing_changed(db_engine, before)


# --- the request guards -----------------------------------------------------------


@pytest.mark.parametrize(
    "headers", [{}, {"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site"}]
)
def test_a_request_without_the_same_origin_signal_is_refused(
    client, db_engine, clock, headers
):
    reader(client, db_engine, clock)
    before = user_row(db_engine)

    response = reset(browser(client), headers=headers)

    assert response.status_code == 403
    assert attempt_row(db_engine) == (0, None)  # only the login's
    nothing_changed(db_engine, before)


def test_a_request_without_the_pre_session_csrf_is_refused(client, db_engine, clock):
    reader(client, db_engine, clock)
    before = user_row(db_engine)
    anonymous = browser(client)
    forged = anonymous.post(
        RESET,
        json={"username": "alice", "code": CODE, "new_password": NEW},
        headers={**SAME_ORIGIN, "X-CSRF-Token": "forged"},
    )
    bare = anonymous.post(
        RESET,
        json={"username": "alice", "code": CODE, "new_password": NEW},
        headers=SAME_ORIGIN,
    )

    assert forged.status_code == bare.status_code == 403
    assert attempt_row(db_engine) == (0, None)  # only the login's
    nothing_changed(db_engine, before)


def test_a_session_bound_csrf_token_is_not_a_pre_session_token(
    client, db_engine, clock
):
    session = reader(client, db_engine, clock)

    response = reset(browser(client), token=session.cookies.get("__Host-csrf"))

    assert response.status_code == 403


# --- busy rows ---------------------------------------------------------------------


@pytest.mark.parametrize("sqlstate", ["55P03", "40P01", "40001"])
@pytest.mark.parametrize("table", ["login_attempts", "users", "password_reset_codes"])
def test_a_busy_row_is_a_503_that_counts_and_changes_nothing(
    client, db_engine, clock, monkeypatch, caplog, sqlstate, table
):
    reader(client, db_engine, clock)
    assert reset(browser(client), code="ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ").status_code == 401
    before = user_row(db_engine)
    caplog.set_level(logging.INFO, logger="gateway.auth")
    real_execute = Session.execute

    def execute(self, statement, *args, **kwargs):
        sql = str(statement)
        if f"FROM {table}" in sql and "FOR UPDATE" in sql:
            raise OperationalError("SELECT", {}, DbError(sqlstate))
        return real_execute(self, statement, *args, **kwargs)

    monkeypatch.setattr(Session, "execute", execute)
    anonymous = browser(client)
    token = get_csrf(anonymous)

    response = reset(anonymous, token=token)

    assert response.status_code == 503
    assert response.json() == {"detail": BUSY}
    assert attempt_row(db_engine) == (1, None)
    nothing_changed(db_engine, before)
    assert "event=service_busy" in caplog.text


# --- races between the slow work and the locks --------------------------------------


def hashing_between(monkeypatch, change):
    """Run `change` after the new password is hashed: before any lock is taken."""
    monkeypatch.setattr(auth, "hash_password", Interfere(auth.hash_password, change))


def test_a_code_replaced_while_the_password_hashes_is_refused(
    client, db_engine, clock, monkeypatch
):
    reader(client, db_engine, clock)
    before = user_row(db_engine)
    other = "VVVVV-WWWWW-XXXXX-YYYYY"
    hashing_between(monkeypatch, lambda: put_code(db_engine, clock, code=other))

    response = reset(browser(client))

    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert attempt_row(db_engine) == (1, None)
    nothing_changed(db_engine, before)
    monkeypatch.undo()
    assert reset(browser(client), code=other).status_code == 200


def test_a_code_used_while_the_password_hashes_is_refused(
    client, db_engine, clock, monkeypatch
):
    reader(client, db_engine, clock)
    before = user_row(db_engine)
    hashing_between(
        monkeypatch,
        lambda: run_sql(db_engine, "DELETE FROM password_reset_codes"),
    )

    response = reset(browser(client))

    assert response.status_code == 401
    assert attempt_row(db_engine) == (1, None)
    nothing_changed(db_engine, before, rows=0)


def test_an_account_locked_while_the_password_hashes_is_refused_uncounted(
    client, db_engine, clock, monkeypatch
):
    reader(client, db_engine, clock)
    before = user_row(db_engine)
    locked = clock() + timedelta(minutes=5)
    hashing_between(
        monkeypatch,
        lambda: lock_account(db_engine, locked),
    )

    response = reset(browser(client))

    assert response.status_code == 401
    assert attempt_row(db_engine) == (5, locked)
    nothing_changed(db_engine, before)


def test_a_second_factor_spent_while_the_password_hashes_is_refused(
    client, db_engine, clock, monkeypatch
):
    secret, _ = mfa_reader(client, db_engine, clock)
    before = user_row(db_engine)
    step = current_step(clock)
    hashing_between(
        monkeypatch,
        lambda: run_sql(db_engine, "UPDATE users SET mfa_last_step = :s", s=step),
    )

    response = reset(browser(client), mfa_code=totp(secret, clock))

    assert response.status_code == 401
    assert attempt_row(db_engine) == (1, None)
    assert user_row(db_engine)["password_hash"] == before["password_hash"]
    assert len(code_rows(db_engine)) == 1


def test_a_second_factor_that_ends_while_the_code_verifies_is_refused(
    client, db_engine, clock, monkeypatch
):
    # MFA disabled between the plain read and the locks: the second factor the
    # request prepared is no longer the user's, so nothing is spent.
    secret, _ = mfa_reader(client, db_engine, clock)
    before = user_row(db_engine)
    hashing_between(
        monkeypatch,
        lambda: run_sql(
            db_engine,
            "UPDATE users SET mfa_secret_ciphertext = 'v1:other', mfa_last_step = NULL",
        ),
    )

    response = reset(browser(client), mfa_code=totp(secret, clock))

    assert response.status_code == 401
    assert user_row(db_engine)["password_hash"] == before["password_hash"]
    assert len(code_rows(db_engine)) == 1


# --- events -----------------------------------------------------------------------


def test_the_events_never_carry_the_code_the_passwords_or_a_hash(
    client, db_engine, clock, caplog
):
    reader(client, db_engine, clock)
    caplog.set_level(logging.DEBUG)

    assert reset(browser(client), code="ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ").status_code == 401
    assert reset(browser(client), username="ghost").status_code == 401
    old_hash = user_row(db_engine)["password_hash"]
    assert reset(browser(client)).status_code == 200

    assert events(caplog) == [
        "password_reset_failure",
        "password_reset_failure",
        "password_reset",
    ]
    new_hash = user_row(db_engine)["password_hash"]
    for secret in (CODE, CODE.replace("-", ""), "ZZZZZ", NEW, GOOD, old_hash, new_hash):
        assert secret not in caplog.text
    assert "ghost" not in caplog.text
    assert f"subject={admin_user_id(db_engine, 'alice')}" in caplog.text
    assert f"subject=unknown:{attempt_key('ghost')[:16]}" in caplog.text
    assert "event=password_reset " in caplog.text
    assert any(
        r.levelno == logging.WARNING and "event=password_reset " in r.getMessage()
        for r in caplog.records
    )


def test_a_blocked_reset_is_logged_like_a_blocked_login(
    client, db_engine, clock, caplog
):
    reader(client, db_engine, clock)
    lock_account(db_engine, clock() + timedelta(minutes=5))
    caplog.set_level(logging.INFO, logger="gateway.auth")

    reset(browser(client))

    assert events(caplog) == ["login_blocked"]
