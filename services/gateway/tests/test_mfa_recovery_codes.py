"""POST /api/auth/mfa/recovery-codes: replace the ten recovery codes (issue #51).

The caller proves the password and a TOTP again; the old codes, used or not, stop
working and the new ones are shown once. Like test_mfa these tests use the real
OpenBao transit engine and a frozen clock.
"""

import logging
import re
import threading
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from gateway import auth
from gateway.db import get_engine
from gateway.main import create_app
from tests.helpers import DbError, FrozenClock, Interfere, run_sql
from tests.test_login import (
    GOOD,
    KEYS,
    LOGIN_FAILED,
    NOT_AUTHENTICATED,
    OTHER,
    SAME_ORIGIN,
    attempt_row,
    login,
    register,
)
from tests.test_mfa import (
    CONFIRM,
    ENROLL,
    LOGIN_MFA,
    count,
    enroll,
    events,
    make_user,
    post,
    second_client,
    to_pending,
    totp,
    user_row,
)

REGENERATE = "/api/auth/mfa/recovery-codes"
ME = "/api/auth/me"
REFRESH = "/api/auth/refresh"
CODE_SHAPE = re.compile(r"^[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")


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


def user_with_mfa(client, db_engine, clock, role="lector", username="alice"):
    """A user with MFA and a full session; return the secret and unused codes.

    The session was opened with the first recovery code, and the clock then moves
    one TOTP step on, so the next TOTP is not a replay of the one that confirmed.
    """
    if role == "lector":
        make_user(client, db_engine, clock, username, role=role, window=False)
        assert login(client, username).json()["role"] == "lector"
        secret = post(client, ENROLL, {"current_password": GOOD}).json()["secret"]
        confirmed = post(client, CONFIRM, {"code": totp(secret, clock)})
        codes = confirmed.json()["recovery_codes"]
    else:
        secret, codes = enroll(client, db_engine, clock, username, role)
    to_pending(client, username)
    assert post(client, LOGIN_MFA, {"code": codes[0]}).status_code == 200
    clock.now += timedelta(seconds=30)
    return secret, codes


def body(secret, clock, **overrides):
    return {"current_password": GOOD, "code": totp(secret, clock)} | overrides


def current_step(clock):
    return int(clock().timestamp()) // 30


def stored_hashes(db_engine):
    with db_engine.connect() as conn:
        return {
            row[0] for row in conn.execute(text("SELECT code_hash FROM recovery_codes"))
        }


def assert_codes_untouched(db_engine, before):
    assert stored_hashes(db_engine) == before
    assert count(db_engine, "recovery_codes") == 10


def codes_log_in(client, db_engine, codes, username="alice"):
    """Whether each code is accepted at /login/mfa (a fresh browser each time)."""
    results = []
    for code in codes:
        browser = second_client(client)
        run_sql(db_engine, "DELETE FROM login_attempts")
        to_pending(browser, username)
        results.append(post(browser, LOGIN_MFA, {"code": code}).status_code)
    return results


def test_regenerating_replaces_all_ten_codes_shown_once(client, db_engine, clock):
    secret, old = user_with_mfa(client, db_engine, clock)
    before = stored_hashes(db_engine)

    response = post(client, REGENERATE, body(secret, clock))

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    new = response.json()["recovery_codes"]
    assert len(new) == len(set(new)) == 10
    assert all(CODE_SHAPE.match(code) for code in new)
    assert not set(new) & set(old)
    assert response.json()["relogin_required"] is False
    assert count(db_engine, "recovery_codes") == 10
    assert stored_hashes(db_engine).isdisjoint(before)
    assert user_row(db_engine)["mfa_last_step"] == current_step(clock)
    assert attempt_row(db_engine) is None or attempt_row(db_engine).failures == 0


def test_the_response_codes_are_stored_only_as_argon2_hashes(client, db_engine, clock):
    secret, _ = user_with_mfa(client, db_engine, clock)

    new = post(client, REGENERATE, body(secret, clock)).json()["recovery_codes"]

    hashes = stored_hashes(db_engine)
    assert len(hashes) == 10
    for stored in hashes:
        assert stored.startswith("$argon2")
        for code in new:
            assert code not in stored
            assert code.replace("-", "") not in stored


def test_every_old_code_stops_working_and_each_new_one_works_once(
    client, db_engine, clock
):
    secret, old = user_with_mfa(client, db_engine, clock)
    # old[0] was spent opening the session, the others are unused.
    new = post(client, REGENERATE, body(secret, clock)).json()["recovery_codes"]

    assert codes_log_in(client, db_engine, [old[0], old[1], old[9]]) == [401, 401, 401]
    assert codes_log_in(client, db_engine, [new[0], new[0], new[9]]) == [200, 401, 200]


def test_the_session_survives_a_regeneration(client, db_engine, clock):
    secret, _ = user_with_mfa(client, db_engine, clock)

    assert post(client, REGENERATE, body(secret, clock)).status_code == 200

    assert client.get(ME).status_code == 200
    refreshed = client.post(
        REFRESH,
        headers={**SAME_ORIGIN, "X-CSRF-Token": client.cookies.get("__Host-csrf")},
    )
    assert refreshed.status_code == 200


@pytest.mark.parametrize("role", ["editor", "auditor", "administrador"])
def test_a_privileged_role_can_regenerate(client, db_engine, clock, role):
    secret, old = user_with_mfa(client, db_engine, clock, role=role)

    response = post(client, REGENERATE, body(secret, clock))

    assert response.status_code == 200
    assert len(response.json()["recovery_codes"]) == 10
    assert user_row(db_engine)["mfa_enabled_at"] is not None


def test_a_successful_regeneration_does_not_reset_the_counter(client, db_engine, clock):
    secret, _ = user_with_mfa(client, db_engine, clock)
    assert (
        post(client, REGENERATE, body(secret, clock, code="000000")).status_code == 401
    )
    assert post(client, REGENERATE, body(secret, clock)).status_code == 200

    assert attempt_row(db_engine).failures == 1


def test_a_wrong_password_is_a_counted_failure(client, db_engine, clock):
    secret, _ = user_with_mfa(client, db_engine, clock)
    before = stored_hashes(db_engine)

    response = post(client, REGENERATE, body(secret, clock, current_password=OTHER))

    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert attempt_row(db_engine).failures == 1
    assert_codes_untouched(db_engine, before)


def test_a_wrong_totp_is_a_counted_failure(client, db_engine, clock):
    secret, _ = user_with_mfa(client, db_engine, clock)
    before = stored_hashes(db_engine)

    response = post(
        client, REGENERATE, body(secret, clock, code=totp(secret, clock, 2))
    )

    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert attempt_row(db_engine).failures == 1
    assert_codes_untouched(db_engine, before)


def test_a_replayed_totp_step_is_a_counted_failure(client, db_engine, clock):
    secret, _ = user_with_mfa(client, db_engine, clock)
    before = stored_hashes(db_engine)
    run_sql(db_engine, "UPDATE users SET mfa_last_step = :s", s=current_step(clock))

    response = post(client, REGENERATE, body(secret, clock))

    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert attempt_row(db_engine).failures == 1
    assert_codes_untouched(db_engine, before)


def test_a_recovery_code_cannot_replace_the_totp(client, db_engine, clock):
    """A code that could be stolen along with the list must not mint a new list.

    The schema accepts only six digits, so this is a 422 before anything is
    verified: nothing is counted and nothing changes.
    """
    _, codes = user_with_mfa(client, db_engine, clock)
    before = stored_hashes(db_engine)

    for code in (codes[1], codes[1].replace("-", "").lower()):
        response = post(client, REGENERATE, {"current_password": GOOD, "code": code})
        assert response.status_code == 422
        assert GOOD not in response.text

    assert attempt_row(db_engine) is None or attempt_row(db_engine).failures == 0
    assert_codes_untouched(db_engine, before)


def test_failures_lock_the_account_and_a_locked_one_verifies_nothing(
    client, db_engine, clock, monkeypatch
):
    secret, _ = user_with_mfa(client, db_engine, clock)
    before = stored_hashes(db_engine)
    for _ in range(4):
        post(client, REGENERATE, body(secret, clock, current_password=OTHER))
    assert attempt_row(db_engine).locked_until == clock() + timedelta(minutes=1)

    def boom(*_):
        raise AssertionError("nothing may be verified for a locked account")

    monkeypatch.setattr(auth, "verify_password", boom)
    monkeypatch.setattr(auth, "hash_password", boom)
    monkeypatch.setattr(auth, "decrypt_totp_secret", boom)
    response = post(client, REGENERATE, body(secret, clock))

    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert_codes_untouched(db_engine, before)


def test_a_user_without_mfa_gets_a_conflict_and_no_failure(client, db_engine, clock):
    register(client)
    login(client)

    response = post(client, REGENERATE, {"current_password": OTHER, "code": "123456"})

    assert response.status_code == 409
    assert response.headers["cache-control"] == "no-store"
    assert attempt_row(db_engine) is None or attempt_row(db_engine).failures == 0


def test_the_pending_and_enroll_tokens_are_not_a_session_for_this(
    client, db_engine, clock
):
    secret, _ = user_with_mfa(client, db_engine, clock)
    before = stored_hashes(db_engine)
    pending = second_client(client)
    to_pending(pending)
    assert post(pending, REGENERATE, body(secret, clock)).status_code == 401

    make_user(client, db_engine, clock, "boss", role="editor")
    enrolling = second_client(client)
    assert login(enrolling, "boss").json() == {"status": "mfa_enrollment_required"}
    response = post(enrolling, REGENERATE, body(secret, clock))

    assert response.status_code == 401
    assert response.json() == NOT_AUTHENTICATED
    assert_codes_untouched(db_engine, before)


def test_a_request_without_a_session_is_401(client):
    response = client.post(
        REGENERATE,
        json={"current_password": GOOD, "code": "123456"},
        headers=SAME_ORIGIN,
    )

    assert response.status_code == 401


def test_regenerating_needs_same_origin_and_its_csrf_token(client, db_engine, clock):
    secret, _ = user_with_mfa(client, db_engine, clock)
    before = stored_hashes(db_engine)
    sent = body(secret, clock)

    assert post(client, REGENERATE, sent, csrf=None).status_code == 403
    assert post(client, REGENERATE, sent, csrf="nope").status_code == 403
    foreign = post(client, REGENERATE, sent, headers={"Origin": "https://evil.example"})
    assert foreign.status_code == 403
    assert_codes_untouched(db_engine, before)


@pytest.mark.parametrize(
    "sent",
    [
        {},
        {"current_password": GOOD},
        {"code": "123456"},
        {"current_password": GOOD, "code": "12345"},
        {"current_password": GOOD, "code": "1234567"},
        {"current_password": GOOD, "code": "12345a"},
        {"current_password": "", "code": "123456"},
        {"current_password": GOOD, "code": "123456", "extra": 1},
    ],
)
def test_a_malformed_body_is_a_422_that_never_echoes_the_password(
    client, db_engine, clock, sent
):
    user_with_mfa(client, db_engine, clock)
    before = stored_hashes(db_engine)

    response = post(client, REGENERATE, sent)

    assert response.status_code == 422
    assert GOOD not in response.text
    assert_codes_untouched(db_engine, before)


def test_the_event_is_logged_and_no_code_secret_or_password_ever_is(
    client, db_engine, clock, caplog
):
    caplog.set_level(logging.DEBUG)
    secret, old = user_with_mfa(client, db_engine, clock)
    ciphertext = user_row(db_engine)["mfa_secret_ciphertext"]
    wrong = totp(secret, clock, 2)
    post(client, REGENERATE, body(secret, clock, code=wrong))
    good = totp(secret, clock)
    new = post(client, REGENERATE, {"current_password": GOOD, "code": good}).json()[
        "recovery_codes"
    ]
    seen = events(caplog)

    assert "mfa_failure" in seen
    assert "recovery_codes_regenerated" in seen
    for forbidden in (
        secret,
        ciphertext,
        wrong,
        good,
        GOOD,
        OTHER,
        *old,
        *new,
        *(c.replace("-", "") for c in (*old, *new)),
    ):
        assert forbidden not in caplog.text


# --- rechecks under the lock (compare-and-set) ----------------------------


def prepare_interference(monkeypatch, change):
    monkeypatch.setattr(
        auth,
        "decrypt_totp_secret",
        Interfere(auth.decrypt_totp_secret, change),
    )


def test_a_secret_replaced_meanwhile_is_a_counted_failure(
    client, db_engine, clock, monkeypatch
):
    secret, _ = user_with_mfa(client, db_engine, clock)
    before = stored_hashes(db_engine)
    prepare_interference(
        monkeypatch,
        lambda: run_sql(
            db_engine, "UPDATE users SET mfa_secret_ciphertext = 'vault:v1:new'"
        ),
    )

    response = post(client, REGENERATE, body(secret, clock))

    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert attempt_row(db_engine).failures == 1
    assert_codes_untouched(db_engine, before)


def test_mfa_disabled_meanwhile_is_a_conflict_and_changes_nothing(
    client, db_engine, clock, monkeypatch
):
    secret, _ = user_with_mfa(client, db_engine, clock)
    before = stored_hashes(db_engine)
    prepare_interference(
        monkeypatch,
        lambda: run_sql(
            db_engine,
            "UPDATE users SET mfa_enabled_at = NULL, mfa_secret_ciphertext = NULL",
        ),
    )

    response = post(client, REGENERATE, body(secret, clock))

    assert response.status_code == 409
    assert attempt_row(db_engine) is None or attempt_row(db_engine).failures == 0
    assert_codes_untouched(db_engine, before)


def test_a_password_changed_meanwhile_counts_as_a_failure(
    client, db_engine, clock, monkeypatch
):
    secret, _ = user_with_mfa(client, db_engine, clock)
    before = stored_hashes(db_engine)
    monkeypatch.setattr(
        auth,
        "verify_password",
        Interfere(
            auth.verify_password,
            lambda: run_sql(db_engine, "UPDATE users SET password_hash = 'changed'"),
        ),
    )

    response = post(client, REGENERATE, body(secret, clock))

    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert attempt_row(db_engine).failures == 1
    assert_codes_untouched(db_engine, before)


def test_tokens_invalidated_meanwhile_end_the_request(
    client, db_engine, clock, monkeypatch
):
    secret, _ = user_with_mfa(client, db_engine, clock)
    before = stored_hashes(db_engine)
    prepare_interference(
        monkeypatch,
        lambda: run_sql(
            db_engine, "UPDATE users SET token_generation = token_generation + 1"
        ),
    )

    response = post(client, REGENERATE, body(secret, clock))

    assert response.status_code == 401
    assert response.json() == NOT_AUTHENTICATED
    assert_codes_untouched(db_engine, before)


def test_two_regenerations_in_parallel_replace_the_codes_once(
    client, db_engine, clock, monkeypatch
):
    secret, _ = user_with_mfa(client, db_engine, clock)
    before = stored_hashes(db_engine)
    racers = [client, second_client(client)]
    for name in ("__Host-access", "__Host-csrf"):
        racers[1].cookies.set(name, client.cookies.get(name))
    meeting = threading.Barrier(2, timeout=10)
    real = auth.decrypt_totp_secret

    def decrypt(*args, **kwargs):
        result = real(*args, **kwargs)
        meeting.wait()
        return result

    monkeypatch.setattr(auth, "decrypt_totp_secret", decrypt)
    sent = body(secret, clock)
    statuses = []

    def run(racer):
        statuses.append(post(racer, REGENERATE, sent).status_code)

    threads = [threading.Thread(target=run, args=(racer,)) for racer in racers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)

    assert not meeting.broken
    # Both prepared the same step; only one can spend it.
    assert sorted(statuses) == [200, 401]
    assert count(db_engine, "recovery_codes") == 10
    assert stored_hashes(db_engine).isdisjoint(before)


@pytest.mark.parametrize("sqlstate", ["55P03", "40P01", "40001"])
def test_a_busy_user_row_is_a_503_and_counts_nothing(
    client, db_engine, clock, monkeypatch, sqlstate
):
    secret, _ = user_with_mfa(client, db_engine, clock)
    before = stored_hashes(db_engine)
    real_execute = Session.execute

    def execute(self, statement, *args, **kwargs):
        sql = str(statement)
        if "FROM users" in sql and "FOR UPDATE" in sql:
            raise OperationalError("SELECT", {}, DbError(sqlstate))
        return real_execute(self, statement, *args, **kwargs)

    monkeypatch.setattr(Session, "execute", execute)

    response = post(client, REGENERATE, body(secret, clock))

    assert response.status_code == 503
    assert attempt_row(db_engine) is None or attempt_row(db_engine).failures == 0
    assert_codes_untouched(db_engine, before)


def end_session_like_a_logout(client, db_engine, kind):
    """What a concurrent logout leaves behind, whole or in part.

    The generation is not touched: a logout denies the jti and revokes the
    family, nothing else.
    """
    claims = auth.decode_access_token(client.cookies.get("__Host-access"), KEYS)
    if kind in ("jti", "logout"):
        run_sql(
            db_engine,
            "INSERT INTO revoked_jtis (jti, expires_at) "
            "VALUES (:j, now() + interval '1 hour')",
            j=claims["jti"],
        )
    if kind in ("family", "logout"):
        run_sql(db_engine, "UPDATE refresh_families SET revoked_at = now()")


@pytest.mark.parametrize("kind", ["jti", "family", "logout"])
def test_a_logout_meanwhile_ends_the_request_and_changes_nothing(
    client, db_engine, clock, monkeypatch, kind
):
    secret, _ = user_with_mfa(client, db_engine, clock)
    before = stored_hashes(db_engine)
    prepare_interference(
        monkeypatch, lambda: end_session_like_a_logout(client, db_engine, kind)
    )

    response = post(client, REGENERATE, body(secret, clock))

    assert response.status_code == 401
    assert response.json() == NOT_AUTHENTICATED
    assert_codes_untouched(db_engine, before)
    row = attempt_row(db_engine)
    assert row is None or row.failures == 0


def test_a_replayed_step_is_refused_before_any_code_is_hashed(
    client, db_engine, clock, monkeypatch
):
    secret, _ = user_with_mfa(client, db_engine, clock)
    before = stored_hashes(db_engine)
    run_sql(db_engine, "UPDATE users SET mfa_last_step = :s", s=current_step(clock))
    hashed = []
    real = auth.hash_password

    def counting(*args, **kwargs):
        hashed.append(args)
        return real(*args, **kwargs)

    monkeypatch.setattr(auth, "hash_password", counting)

    response = post(client, REGENERATE, body(secret, clock))

    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert attempt_row(db_engine).failures == 1
    assert_codes_untouched(db_engine, before)
    assert hashed == []
