"""POST /api/auth/mfa/disable: a reader removes the second factor (issue #51).

ADR 0004 keeps MFA mandatory for the privileged roles, so only a reader may turn
it off, and only after proving the password and the second factor again. Like
test_mfa these tests use the real OpenBao transit engine and a frozen clock.
"""

import logging
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
    events,
    make_user,
    post,
    second_client,
    to_pending,
    totp,
    user_row,
)

DISABLE = "/api/auth/mfa/disable"
ME = "/api/auth/me"
REFRESH = "/api/auth/refresh"
CLEARED = (
    "mfa_secret_ciphertext",
    "mfa_pending_ciphertext",
    "mfa_enabled_at",
    "mfa_last_step",
    "mfa_enroll_until",
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


def reader_with_mfa(client, db_engine, clock, username="alice"):
    """A reader with MFA and a full session; return the secret and unused codes.

    The session was opened with the first recovery code, and the clock then moves
    one TOTP step on, so the next TOTP is not a replay of the one that confirmed.
    """
    make_user(client, db_engine, clock, username, role="lector", window=False)
    assert login(client, username).json()["role"] == "lector"
    secret = post(client, ENROLL, {"current_password": GOOD}).json()["secret"]
    confirmed = post(client, CONFIRM, {"code": totp(secret, clock)})
    codes = confirmed.json()["recovery_codes"]
    to_pending(client, username)
    assert post(client, LOGIN_MFA, {"code": codes[0]}).status_code == 200
    clock.now += timedelta(seconds=30)
    return secret, codes[1:]


def body(secret, clock, **overrides):
    return {"current_password": GOOD, "code": totp(secret, clock)} | overrides


def current_step(clock):
    return int(clock().timestamp()) // 30


def assert_mfa_untouched(db_engine, codes=9):
    row = user_row(db_engine)
    assert row["mfa_enabled_at"] is not None
    assert row["mfa_secret_ciphertext"] is not None
    assert count(db_engine, "recovery_codes") == codes + 1


def stale_copy(client):
    """Another browser holding the cookies the session has right now."""
    other = second_client(client)
    for name in ("__Host-access", "__Host-csrf"):
        other.cookies.set(name, client.cookies.get(name))
    other.cookies.set(
        "__Secure-refresh",
        client.cookies.get("__Secure-refresh"),
        path="/api/auth/refresh",
    )
    return other


def refresh_with(browser):
    return browser.post(
        REFRESH,
        headers={**SAME_ORIGIN, "X-CSRF-Token": browser.cookies.get("__Host-csrf")},
    )


def test_a_reader_disables_mfa_with_the_password_and_a_totp(client, db_engine, clock):
    secret, _ = reader_with_mfa(client, db_engine, clock)
    old = stale_copy(client)

    response = post(client, DISABLE, body(secret, clock))

    assert response.status_code == 200
    assert response.json()["role"] == "lector"
    assert response.headers["cache-control"] == "no-store"
    row = user_row(db_engine)
    for column in CLEARED:
        assert row[column] is None, column
    assert count(db_engine, "recovery_codes") == 0
    # Every older credential is dead; the session this call returned is not.
    assert old.get(ME).status_code == 401
    assert refresh_with(old).status_code == 401
    assert client.get(ME).status_code == 200
    assert refresh_with(client).status_code == 200


def test_the_other_sessions_of_the_user_end(client, db_engine, clock):
    secret, codes = reader_with_mfa(client, db_engine, clock)
    other = second_client(client)
    login(other)
    assert post(other, LOGIN_MFA, {"code": codes[0]}).status_code == 200
    assert other.get(ME).status_code == 200

    assert post(client, DISABLE, body(secret, clock)).status_code == 200

    assert other.get(ME).status_code == 401
    assert refresh_with(other).status_code == 401
    with db_engine.connect() as conn:
        live = conn.execute(
            text("SELECT count(*) FROM refresh_families WHERE revoked_at IS NULL")
        ).scalar()
    assert live == 1  # only the one issued for this client


def test_the_next_login_does_not_ask_for_a_second_factor(client, db_engine, clock):
    secret, _ = reader_with_mfa(client, db_engine, clock)
    assert post(client, DISABLE, body(secret, clock)).status_code == 200

    fresh = second_client(client)
    response = login(fresh)

    assert response.status_code == 200
    assert response.json()["role"] == "lector"
    assert fresh.get(ME).status_code == 200


def test_a_recovery_code_disables_mfa_too(client, db_engine, clock):
    _, codes = reader_with_mfa(client, db_engine, clock)

    response = post(
        client, DISABLE, {"current_password": GOOD, "code": codes[0].lower()}
    )

    assert response.status_code == 200
    assert user_row(db_engine)["mfa_enabled_at"] is None
    assert count(db_engine, "recovery_codes") == 0
    assert client.get(ME).status_code == 200


def test_a_successful_disable_does_not_reset_the_counter(client, db_engine, clock):
    secret, _ = reader_with_mfa(client, db_engine, clock)
    assert post(client, DISABLE, body(secret, clock, code="000000")).status_code == 401
    assert post(client, DISABLE, body(secret, clock)).status_code == 200

    assert attempt_row(db_engine).failures == 1


def test_a_wrong_password_is_a_counted_failure(client, db_engine, clock):
    secret, _ = reader_with_mfa(client, db_engine, clock)

    response = post(client, DISABLE, body(secret, clock, current_password=OTHER))

    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert attempt_row(db_engine).failures == 1
    assert_mfa_untouched(db_engine)
    assert client.get(ME).status_code == 200


def test_a_wrong_totp_is_a_counted_failure(client, db_engine, clock):
    secret, _ = reader_with_mfa(client, db_engine, clock)

    response = post(client, DISABLE, body(secret, clock, code=totp(secret, clock, 2)))

    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert attempt_row(db_engine).failures == 1
    assert_mfa_untouched(db_engine)


def test_a_replayed_totp_step_is_a_counted_failure(client, db_engine, clock):
    secret, _ = reader_with_mfa(client, db_engine, clock)
    run_sql(db_engine, "UPDATE users SET mfa_last_step = :s", s=current_step(clock))

    response = post(client, DISABLE, body(secret, clock))

    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert attempt_row(db_engine).failures == 1
    assert_mfa_untouched(db_engine)


def test_a_used_or_wrong_recovery_code_is_a_counted_failure(client, db_engine, clock):
    _, codes = reader_with_mfa(client, db_engine, clock)

    wrong = post(client, DISABLE, {"current_password": GOOD, "code": "AAAA-AAAA-AAAA"})
    assert wrong.status_code == 401
    run_sql(db_engine, "UPDATE recovery_codes SET used_at = now()")
    spent = post(client, DISABLE, {"current_password": GOOD, "code": codes[0]})

    assert spent.status_code == 401
    assert spent.json() == LOGIN_FAILED
    assert attempt_row(db_engine).failures == 2
    assert user_row(db_engine)["mfa_enabled_at"] is not None


def test_failures_lock_the_account_and_a_locked_one_verifies_nothing(
    client, db_engine, clock, monkeypatch
):
    secret, _ = reader_with_mfa(client, db_engine, clock)
    for _ in range(4):
        post(client, DISABLE, body(secret, clock, current_password=OTHER))
    assert attempt_row(db_engine).locked_until == clock() + timedelta(minutes=1)

    def boom(*_):
        raise AssertionError("nothing may be verified for a locked account")

    monkeypatch.setattr(auth, "verify_password", boom)
    monkeypatch.setattr(auth, "decrypt_totp_secret", boom)
    response = post(client, DISABLE, body(secret, clock))

    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert_mfa_untouched(db_engine)


@pytest.mark.parametrize("role", ["editor", "auditor", "administrador"])
def test_a_privileged_role_cannot_disable_mfa(client, db_engine, clock, role):
    secret, _ = reader_with_mfa(client, db_engine, clock)
    run_sql(db_engine, "UPDATE users SET role = :r", r=role)

    response = post(client, DISABLE, body(secret, clock))

    assert response.status_code == 403
    assert response.headers["cache-control"] == "no-store"
    assert attempt_row(db_engine).failures == 0
    assert_mfa_untouched(db_engine)
    assert client.get(ME).status_code == 200


def test_a_user_without_mfa_gets_a_conflict_and_no_failure(client, db_engine, clock):
    register(client)
    login(client)

    response = post(client, DISABLE, {"current_password": OTHER, "code": "123456"})

    assert response.status_code == 409
    assert response.headers["cache-control"] == "no-store"
    assert attempt_row(db_engine).failures == 0


def test_the_pending_and_enroll_tokens_are_not_a_session_for_this(
    client, db_engine, clock
):
    secret, _ = reader_with_mfa(client, db_engine, clock)
    pending = second_client(client)
    to_pending(pending)
    assert post(pending, DISABLE, body(secret, clock)).status_code == 401

    make_user(client, db_engine, clock, "boss", role="editor")
    enrolling = second_client(client)
    assert login(enrolling, "boss").json() == {"status": "mfa_enrollment_required"}
    response = post(enrolling, DISABLE, body(secret, clock))

    assert response.status_code == 401
    assert response.json() == NOT_AUTHENTICATED
    assert_mfa_untouched(db_engine)


def test_a_request_without_a_session_is_401(client):
    response = client.post(
        DISABLE,
        json={"current_password": GOOD, "code": "123456"},
        headers=SAME_ORIGIN,
    )

    assert response.status_code == 401


def test_disable_needs_same_origin_and_its_csrf_token(client, db_engine, clock):
    secret, _ = reader_with_mfa(client, db_engine, clock)
    sent = body(secret, clock)

    assert post(client, DISABLE, sent, csrf=None).status_code == 403
    assert post(client, DISABLE, sent, csrf="nope").status_code == 403
    foreign = post(client, DISABLE, sent, headers={"Origin": "https://evil.example"})
    assert foreign.status_code == 403
    assert_mfa_untouched(db_engine)


@pytest.mark.parametrize(
    "sent",
    [
        {},
        {"current_password": GOOD},
        {"code": "123456"},
        {"current_password": GOOD, "code": "12"},
        {"current_password": "", "code": "123456"},
        {"current_password": GOOD, "code": "123456", "extra": 1},
    ],
)
def test_a_malformed_body_is_a_422_that_never_echoes_the_password(
    client, db_engine, clock, sent
):
    reader_with_mfa(client, db_engine, clock)

    response = post(client, DISABLE, sent)

    assert response.status_code == 422
    assert GOOD not in response.text
    assert_mfa_untouched(db_engine)


def test_the_disable_events_are_logged_and_no_secret_ever_is(
    client, db_engine, clock, caplog
):
    caplog.set_level(logging.DEBUG)
    secret, codes = reader_with_mfa(client, db_engine, clock)
    ciphertext = user_row(db_engine)["mfa_secret_ciphertext"]
    wrong = totp(secret, clock, 2)
    post(client, DISABLE, body(secret, clock, code=wrong))
    good = totp(secret, clock)
    post(client, DISABLE, {"current_password": GOOD, "code": codes[0]})
    seen = events(caplog)

    assert "mfa_failure" in seen
    assert "mfa_disabled" in seen
    assert "recovery_code_used" in seen
    for forbidden in (
        secret,
        ciphertext,
        wrong,
        good,
        GOOD,
        OTHER,
        *codes,
        *(c.replace("-", "") for c in codes),
    ):
        assert forbidden not in caplog.text


# --- rechecks under the lock (compare-and-set) ----------------------------


def test_mfa_disabled_meanwhile_is_a_conflict_with_no_double_effect(
    client, db_engine, clock, monkeypatch
):
    secret, _ = reader_with_mfa(client, db_engine, clock)
    monkeypatch.setattr(
        auth,
        "_prepare_second_factor",
        Interfere(
            auth._prepare_second_factor,
            lambda: run_sql(
                db_engine,
                "UPDATE users SET mfa_enabled_at = NULL, mfa_secret_ciphertext = NULL",
            ),
        ),
    )

    response = post(client, DISABLE, body(secret, clock))

    assert response.status_code == 409
    assert attempt_row(db_engine).failures == 0
    assert count(db_engine, "recovery_codes") == 10


def test_a_secret_replaced_meanwhile_is_a_counted_failure(
    client, db_engine, clock, monkeypatch
):
    secret, _ = reader_with_mfa(client, db_engine, clock)
    monkeypatch.setattr(
        auth,
        "_prepare_second_factor",
        Interfere(
            auth._prepare_second_factor,
            lambda: run_sql(
                db_engine, "UPDATE users SET mfa_secret_ciphertext = 'vault:v1:new'"
            ),
        ),
    )

    response = post(client, DISABLE, body(secret, clock))

    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert attempt_row(db_engine).failures == 1
    assert user_row(db_engine)["mfa_enabled_at"] is not None
    assert count(db_engine, "recovery_codes") == 10


def test_a_promotion_meanwhile_is_a_403_and_changes_nothing(
    client, db_engine, clock, monkeypatch
):
    secret, _ = reader_with_mfa(client, db_engine, clock)
    monkeypatch.setattr(
        auth,
        "_prepare_second_factor",
        Interfere(
            auth._prepare_second_factor,
            lambda: run_sql(db_engine, "UPDATE users SET role = 'editor'"),
        ),
    )

    response = post(client, DISABLE, body(secret, clock))

    assert response.status_code == 403
    assert attempt_row(db_engine).failures == 0
    assert_mfa_untouched(db_engine)


def test_a_password_changed_meanwhile_counts_as_a_failure(
    client, db_engine, clock, monkeypatch
):
    secret, _ = reader_with_mfa(client, db_engine, clock)
    monkeypatch.setattr(
        auth,
        "verify_password",
        Interfere(
            auth.verify_password,
            lambda: run_sql(db_engine, "UPDATE users SET password_hash = 'changed'"),
        ),
    )

    response = post(client, DISABLE, body(secret, clock))

    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert attempt_row(db_engine).failures == 1
    assert_mfa_untouched(db_engine)


def test_tokens_invalidated_meanwhile_end_the_request(
    client, db_engine, clock, monkeypatch
):
    secret, _ = reader_with_mfa(client, db_engine, clock)
    monkeypatch.setattr(
        auth,
        "_prepare_second_factor",
        Interfere(
            auth._prepare_second_factor,
            lambda: run_sql(
                db_engine, "UPDATE users SET token_generation = token_generation + 1"
            ),
        ),
    )

    response = post(client, DISABLE, body(secret, clock))

    assert response.status_code == 401
    assert response.json() == NOT_AUTHENTICATED
    assert_mfa_untouched(db_engine)


def test_two_disables_in_parallel_take_effect_once(
    client, db_engine, clock, monkeypatch
):
    secret, _ = reader_with_mfa(client, db_engine, clock)
    racers = [client, stale_copy(client)]
    meeting = threading.Barrier(2, timeout=10)
    real = auth._prepare_second_factor

    def prepare(*args, **kwargs):
        result = real(*args, **kwargs)
        meeting.wait()
        return result

    monkeypatch.setattr(auth, "_prepare_second_factor", prepare)
    sent = body(secret, clock)
    statuses = []

    def run(racer):
        statuses.append(post(racer, DISABLE, sent).status_code)

    threads = [threading.Thread(target=run, args=(racer,)) for racer in racers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)

    assert not meeting.broken
    # The loser finds its session ended by the winner's token bump.
    assert sorted(statuses) == [200, 401]
    assert user_row(db_engine)["mfa_enabled_at"] is None
    assert attempt_row(db_engine).failures == 0


@pytest.mark.parametrize("sqlstate", ["55P03", "40P01", "40001"])
def test_a_busy_user_row_is_a_503_and_counts_nothing(
    client, db_engine, clock, monkeypatch, sqlstate
):
    secret, _ = reader_with_mfa(client, db_engine, clock)
    real_execute = Session.execute

    def execute(self, statement, *args, **kwargs):
        sql = str(statement)
        if "FROM users" in sql and "FOR UPDATE" in sql:
            raise OperationalError("SELECT", {}, DbError(sqlstate))
        return real_execute(self, statement, *args, **kwargs)

    monkeypatch.setattr(Session, "execute", execute)

    response = post(client, DISABLE, body(secret, clock))

    assert response.status_code == 503
    assert attempt_row(db_engine).failures == 0
    assert_mfa_untouched(db_engine)


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
def test_a_logout_meanwhile_ends_the_request_and_opens_no_session(
    client, db_engine, clock, monkeypatch, kind
):
    secret, _ = reader_with_mfa(client, db_engine, clock)
    families = count(db_engine, "refresh_families")
    monkeypatch.setattr(
        auth,
        "_prepare_second_factor",
        Interfere(
            auth._prepare_second_factor,
            lambda: end_session_like_a_logout(client, db_engine, kind),
        ),
    )

    response = post(client, DISABLE, body(secret, clock))

    assert response.status_code == 401
    assert response.json() == NOT_AUTHENTICATED
    assert_mfa_untouched(db_engine)
    assert count(db_engine, "refresh_families") == families
    row = attempt_row(db_engine)
    assert row is None or row.failures == 0
