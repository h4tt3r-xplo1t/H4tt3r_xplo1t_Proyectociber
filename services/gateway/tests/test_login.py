import hashlib
import logging
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from gateway import auth, passwords
from gateway.db import get_engine
from gateway.main import create_app
from gateway.secrets import GatewayKeys
from gateway.tokens import (
    PRE_SESSION_BINDING,
    check_csrf,
    decode_access_token,
    login_attempt_key,
)

# Fake keys and passphrases used only by these tests.
KEYS = GatewayKeys(jwt_kid="kid-1", jwt_key=b"j" * 32, csrf_key=b"c" * 32)
GOOD = "correct horse battery staple"  # noqa: S105
OTHER = "a completely different phrase"  # noqa: S105
SAME_ORIGIN = {"Sec-Fetch-Site": "same-origin"}
LOGIN_FAILED = {"detail": "Login failed; Invalid user ID or password"}


class Clock:
    """Movable 'now' for the lockout tests: no sleeping."""

    def __init__(self):
        self.offset = timedelta(0)

    def __call__(self):
        return datetime.now(UTC) + self.offset


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def app(db_engine, clock):
    app = create_app()
    app.dependency_overrides[auth.get_keys] = lambda: KEYS
    app.dependency_overrides[auth.get_now] = clock
    return app


@pytest.fixture
def client(app):
    # No default headers: each test says what the browser would send.
    yield TestClient(app, base_url="https://testserver")
    get_engine().dispose()


def register(client, username="alice", password=GOOD):
    response = client.post(
        "/api/auth/register",
        json={"username": username, "password": password},
        headers=SAME_ORIGIN,
    )
    assert response.status_code == 201
    return response.json()


def get_csrf(client):
    response = client.get("/api/auth/csrf")
    assert response.status_code == 200
    return response.json()["csrf_token"]


def login(client, username="alice", password=GOOD, *, token=None, headers=SAME_ORIGIN):
    token = get_csrf(client) if token is None else token
    return client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
        headers={**headers, "X-CSRF-Token": token},
    )


def attempt_key(username="alice"):
    return login_attempt_key(username, KEYS.csrf_key)


def attempt_row(db_engine, username="alice"):
    with db_engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT failures, locked_until FROM login_attempts "
                "WHERE attempt_key = :u"
            ),
            {"u": attempt_key(username)},
        ).first()


def set_cookie_lines(response, name):
    return [
        line
        for line in response.headers.get_list("set-cookie")
        if line.startswith(f"{name}=")
    ]


# --- pre-session CSRF endpoint -------------------------------------------


def test_csrf_endpoint_sets_a_short_lived_readable_host_cookie(client):
    response = client.get("/api/auth/csrf")

    (line,) = set_cookie_lines(response, "__Host-csrf")
    attributes = {part.strip().lower() for part in line.split(";")[1:]}
    assert "secure" in attributes
    assert "samesite=strict" in attributes
    assert "path=/" in attributes
    assert "max-age=600" in attributes
    assert "httponly" not in attributes  # the SPA must read it
    assert not any(a.startswith("domain") for a in attributes)
    token = response.json()["csrf_token"]
    assert line.split(";")[0] == f"__Host-csrf={token}"
    assert check_csrf(token, token, PRE_SESSION_BINDING, KEYS.csrf_key)
    assert response.headers["cache-control"] == "no-store"


# --- origin check ---------------------------------------------------------


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Origin": "https://evil.example"},
        {"Origin": "https://testserver.evil.example"},
        {"Sec-Fetch-Site": "cross-site"},
        {"Sec-Fetch-Site": "same-site"},
        {"Sec-Fetch-Site": "none"},
        # A present Sec-Fetch-Site other than same-origin wins over Origin.
        {"Sec-Fetch-Site": "cross-site", "Origin": "https://testserver"},
    ],
)
def test_login_fails_closed_without_a_same_origin_signal(client, headers):
    register(client)

    response = login(client, headers=headers)

    assert response.status_code == 403
    assert response.json() == {"detail": "Forbidden"}
    assert not set_cookie_lines(response, "__Host-access")


def test_login_accepts_the_allowed_origin_when_sec_fetch_site_is_missing(client):
    register(client)

    response = login(client, headers={"Origin": "https://testserver"})

    assert response.status_code == 200


# --- CSRF on login --------------------------------------------------------


def test_login_requires_the_csrf_header(client):
    register(client)
    get_csrf(client)

    response = client.post(
        "/api/auth/login",
        json={"username": "alice", "password": GOOD},
        headers=SAME_ORIGIN,
    )

    assert response.status_code == 403


def test_login_requires_the_csrf_cookie(client, app):
    register(client)
    token = get_csrf(client)
    client.cookies.clear()

    response = login(client, token=token)

    assert response.status_code == 403


def test_login_rejects_a_header_that_differs_from_the_cookie(client):
    register(client)
    get_csrf(client)
    other = TestClient(client.app, base_url="https://testserver")
    foreign = get_csrf(other)

    response = login(client, token=foreign)

    assert response.status_code == 403


def test_login_rejects_a_forged_csrf_token(client):
    register(client)
    forged = "AAAA.0000"
    client.cookies.set("__Host-csrf", forged)

    response = login(client, token=forged)

    assert response.status_code == 403


def test_a_session_bound_csrf_token_is_not_a_pre_session_token(client):
    register(client)
    assert login(client).status_code == 200
    session_token = client.cookies.get("__Host-csrf")

    response = login(client, token=session_token)

    assert response.status_code == 403


def test_csrf_failure_does_not_count_as_a_failed_login(client, db_engine):
    register(client)
    for _ in range(5):
        client.post(
            "/api/auth/login",
            json={"username": "alice", "password": OTHER},
            headers=SAME_ORIGIN,
        )

    assert attempt_row(db_engine) is None
    assert login(client).status_code == 200


def test_pre_session_csrf_token_expires_after_ten_minutes(client, clock):
    register(client)
    token = get_csrf(client)
    clock.offset = timedelta(seconds=601)

    response = login(client, token=token)

    assert response.status_code == 403


def test_pre_session_csrf_token_still_works_just_before_it_expires(client, clock):
    register(client)
    token = get_csrf(client)
    clock.offset = timedelta(seconds=590)

    assert login(client, token=token).status_code == 200


def test_login_rejects_a_pre_session_token_with_a_tampered_timestamp(client, clock):
    register(client)
    token = get_csrf(client)
    random_part, _, mac = token.split(".")
    clock.offset = timedelta(seconds=700)
    fresh_stamp = int((datetime.now(UTC) + clock.offset).timestamp())
    tampered = f"{random_part}.{fresh_stamp}.{mac}"
    client.cookies.set("__Host-csrf", tampered)

    response = login(client, token=tampered)

    assert response.status_code == 403


# --- successful login -----------------------------------------------------


def test_login_returns_public_fields_and_sets_the_cookies(client):
    user = register(client)

    response = login(client)

    assert response.status_code == 200
    assert response.json() == user
    (access,) = set_cookie_lines(response, "__Host-access")
    attributes = {part.strip().lower() for part in access.split(";")[1:]}
    assert {"httponly", "secure", "samesite=strict", "path=/", "max-age=604800"} <= (
        attributes
    )
    assert not any(a.startswith("domain") for a in attributes)
    claims = decode_access_token(client.cookies.get("__Host-access"), KEYS)
    assert claims["sub"] == user["id"]
    assert claims["role"] == "lector"
    assert claims["exp"] - claims["iat"] == 900


def test_login_sets_a_session_csrf_cookie_bound_to_the_sid(client):
    register(client)

    response = login(client)

    (line,) = set_cookie_lines(response, "__Host-csrf")
    attributes = {part.strip().lower() for part in line.split(";")[1:]}
    assert {"secure", "samesite=strict", "path=/"} <= attributes
    assert "httponly" not in attributes
    # It must outlive the 15-minute access cookie: the refresh call needs it.
    assert f"max-age={7 * 24 * 3600}" in attributes
    token = client.cookies.get("__Host-csrf")
    sid = decode_access_token(client.cookies.get("__Host-access"), KEYS)["sid"]
    assert check_csrf(token, token, sid, KEYS.csrf_key)
    assert not check_csrf(token, token, PRE_SESSION_BINDING, KEYS.csrf_key)


def refresh_cookie_value(response):
    (line,) = set_cookie_lines(response, "__Secure-refresh")
    return line.split(";")[0].split("=", 1)[1]


def test_login_creates_a_family_whose_id_is_the_sid(client, db_engine):
    user = register(client)

    login(client)

    claims = decode_access_token(client.cookies.get("__Host-access"), KEYS)
    with db_engine.connect() as conn:
        families = conn.execute(
            text("SELECT id, user_id, revoked_at FROM refresh_families")
        ).all()
    ((family_id, user_id, revoked_at),) = families
    assert claims["sid"] == str(family_id)
    assert str(user_id) == user["id"]
    assert revoked_at is None


def test_login_sets_the_refresh_cookie_scoped_to_the_refresh_path(client):
    register(client)

    response = login(client)

    (line,) = set_cookie_lines(response, "__Secure-refresh")
    attributes = {part.strip().lower() for part in line.split(";")[1:]}
    assert {"httponly", "secure", "samesite=strict"} <= attributes
    assert "path=/api/auth/refresh" in attributes
    assert f"max-age={7 * 24 * 3600}" in attributes
    assert not any(a.startswith("domain") for a in attributes)
    assert len(refresh_cookie_value(response)) >= 43


def test_only_the_sha256_of_the_refresh_token_is_stored(client, db_engine):
    register(client)

    response = login(client)

    token = refresh_cookie_value(response)
    with db_engine.connect() as conn:
        rows = conn.execute(
            text("SELECT token_hash, used_at, family_id FROM refresh_tokens")
        ).all()
        family_id = conn.execute(text("SELECT id FROM refresh_families")).scalar_one()
    ((stored, used_at, token_family),) = rows
    assert stored == hashlib.sha256(token.encode()).hexdigest()
    assert token not in stored
    assert used_at is None
    assert token_family == family_id


def test_session_limits_by_role():
    day = timedelta(days=1)
    assert auth.session_limits("lector") == auth.SessionLimits(
        idle=day, absolute=7 * day
    )
    for role in ("editor", "auditor", "administrador"):
        assert auth.session_limits(role) == auth.SessionLimits(
            idle=timedelta(minutes=30), absolute=timedelta(hours=8)
        )


def test_an_editor_gets_the_shorter_refresh_cookie_lifetime(client, db_engine):
    register(client)
    with db_engine.begin() as conn:
        conn.execute(text("UPDATE users SET role = 'editor'"))

    response = login(client)

    (line,) = set_cookie_lines(response, "__Secure-refresh")
    assert f"max-age={8 * 3600}" in line.lower()


def test_failed_token_issuing_leaves_the_counter_and_tables_untouched(
    app, db_engine, monkeypatch
):
    client = TestClient(
        app, base_url="https://testserver", raise_server_exceptions=False
    )
    register(client)
    login(client, password=OTHER)
    login(client, password=OTHER)
    assert attempt_row(db_engine) == (2, None)

    def boom(*args, **kwargs):
        raise RuntimeError("signing failed")

    monkeypatch.setattr(auth, "issue_access_token", boom)
    response = login(client)

    assert response.status_code == 500
    assert attempt_row(db_engine) == (2, None)
    with db_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM refresh_families")).scalar() == 0
        assert conn.execute(text("SELECT count(*) FROM refresh_tokens")).scalar() == 0
    assert not set_cookie_lines(response, "__Host-access")
    get_engine().dispose()


def test_every_login_starts_a_new_session(client):
    register(client)
    login(client)
    first = decode_access_token(client.cookies.get("__Host-access"), KEYS)
    login(client)
    second = decode_access_token(client.cookies.get("__Host-access"), KEYS)

    assert first["sid"] != second["sid"]
    assert first["jti"] != second["jti"]


def test_login_matches_the_same_password_in_nfc_and_nfd(client):
    # Explicit escapes: an editor that normalizes this file cannot merge them.
    decomposed = "contrase\u0301a-muy-larga-123"  # "e" + combining acute accent
    precomposed = "contrase\u0301a-muy-larga-123".replace("e\u0301", "\u00e9")
    assert decomposed != precomposed
    assert len(decomposed) == len(precomposed) + 1
    assert "\u0301" in decomposed
    assert "\u0301" not in precomposed
    register(client, password=decomposed)

    assert login(client, password=precomposed).status_code == 200


def test_login_body_rejects_extra_fields(client):
    register(client)
    token = get_csrf(client)

    response = client.post(
        "/api/auth/login",
        json={"username": "alice", "password": GOOD, "role": "administrador"},
        headers={**SAME_ORIGIN, "X-CSRF-Token": token},
    )

    assert response.status_code == 422
    assert GOOD not in response.text


# --- identical failures ---------------------------------------------------


def test_wrong_password_unknown_user_and_locked_account_look_the_same(client):
    register(client)
    register(client, username="bob")
    wrong = login(client, password=OTHER)
    unknown = login(client, username="nobody")
    for _ in range(4):
        login(client, username="bob", password=OTHER)
    locked = login(client, username="bob", password=GOOD)

    for response in (wrong, unknown, locked):
        assert response.status_code == 401
        assert response.json() == LOGIN_FAILED
        assert not set_cookie_lines(response, "__Host-access")
    assert wrong.headers["content-type"] == unknown.headers["content-type"]
    assert wrong.headers["content-type"] == locked.headers["content-type"]


def test_unknown_user_costs_a_dummy_verification(client, monkeypatch):
    calls = []
    real_dummy = auth.verify_dummy
    monkeypatch.setattr(
        auth,
        "verify_dummy",
        lambda password: calls.append("dummy") or real_dummy(password),
    )

    response = login(client, username="nobody")

    assert response.status_code == 401
    assert calls == ["dummy"]


# --- lockout --------------------------------------------------------------


@pytest.mark.parametrize(
    ("failures", "minutes"),
    [(1, None), (2, None), (3, None), (4, 1), (5, 5), (6, 15), (7, 30), (50, 30)],
)
def test_lockout_schedule(failures, minutes):
    expected = None if minutes is None else timedelta(minutes=minutes)

    assert auth.lockout_duration(failures) == expected


def test_three_failures_are_free_and_the_fourth_locks_for_a_minute(client, db_engine):
    register(client)
    for _ in range(3):
        login(client, password=OTHER)
    failures, locked_until = attempt_row(db_engine)
    assert (failures, locked_until) == (3, None)

    login(client, password=OTHER)

    failures, locked_until = attempt_row(db_engine)
    assert failures == 4
    remaining = locked_until - datetime.now(UTC)
    assert timedelta(seconds=50) < remaining <= timedelta(seconds=60)


def test_locked_account_rejects_the_right_password_without_verifying_it(
    client, monkeypatch
):
    register(client)
    for _ in range(4):
        login(client, password=OTHER)
    calls = []
    real_dummy = auth.verify_dummy
    monkeypatch.setattr(
        auth,
        "verify_password",
        lambda *a: pytest.fail("a locked account must not be verified"),
    )
    monkeypatch.setattr(
        auth, "verify_dummy", lambda p: calls.append(1) or real_dummy(p)
    )

    response = login(client, password=GOOD)

    assert response.status_code == 401
    assert response.json() == LOGIN_FAILED
    assert calls == [1]  # same cost as any other failure


def test_attempts_while_locked_do_not_extend_the_lock(client, db_engine):
    register(client)
    for _ in range(4):
        login(client, password=OTHER)
    before = attempt_row(db_engine)

    login(client, password=OTHER)

    assert attempt_row(db_engine) == before


def test_login_works_again_after_the_lock_expires_and_resets_the_counter(
    client, db_engine, clock
):
    register(client)
    for _ in range(4):
        login(client, password=OTHER)
    clock.offset = timedelta(seconds=61)

    response = login(client, password=GOOD)

    assert response.status_code == 200
    assert attempt_row(db_engine) == (0, None)


def test_failures_after_a_lock_escalate_to_five_minutes(client, db_engine, clock):
    register(client)
    for _ in range(4):
        login(client, password=OTHER)
    clock.offset = timedelta(seconds=61)

    login(client, password=OTHER)

    failures, locked_until = attempt_row(db_engine)
    assert failures == 5
    remaining = locked_until - (datetime.now(UTC) + clock.offset)
    assert timedelta(minutes=4, seconds=50) < remaining <= timedelta(minutes=5)


def test_success_resets_the_counter(client, db_engine):
    register(client)
    login(client, password=OTHER)
    login(client, password=OTHER)
    assert attempt_row(db_engine)[0] == 2

    assert login(client).status_code == 200

    assert attempt_row(db_engine) == (0, None)


def test_unknown_usernames_are_counted_and_locked_too(client, db_engine):
    for _ in range(4):
        login(client, username="ghost")

    failures, locked_until = attempt_row(db_engine, "ghost")
    assert failures == 4
    assert locked_until is not None
    # A user registered afterwards under that name starts locked: same state.
    register(client, username="ghost")
    assert login(client, username="ghost").status_code == 401


def test_lock_is_per_username(client):
    register(client)
    register(client, username="bob")
    for _ in range(4):
        login(client, password=OTHER)

    assert login(client, username="bob").status_code == 200


# --- concurrency ----------------------------------------------------------


def wait_until_a_backend_waits_on_a_lock(db_engine, timeout=10):
    """Poll PostgreSQL until some backend is blocked on a lock (no fixed sleep)."""
    deadline = time.monotonic() + timeout
    query = text(
        "SELECT count(*) FROM pg_stat_activity "
        "WHERE datname = current_database() AND wait_event_type = 'Lock'"
    )
    while time.monotonic() < deadline:
        with db_engine.connect() as conn:
            if conn.execute(query).scalar_one() > 0:
                return True
        threading.Event().wait(0.02)
    return False


def test_a_login_waiting_on_the_row_lock_survives_a_successful_login(
    client, app, db_engine, monkeypatch
):
    # A holds the row lock while it verifies the right password; B, a wrong
    # password for the same user, queues on that lock. Events, not sleeps,
    # order the steps: A signals when it holds the lock and stays inside the
    # verification until B is seen waiting. When A then succeeds, the row must
    # still be there for B: no 500, a consistent counter.
    register(client)
    login(client, password=OTHER)  # the counter row already exists, committed
    real_verify = auth.verify_password
    a_holds_the_lock = threading.Event()
    b_is_waiting = threading.Event()

    def pause_inside_the_right_password(password_hash, password):
        if password == GOOD:
            a_holds_the_lock.set()
            assert b_is_waiting.wait(10)
        return real_verify(password_hash, password)

    monkeypatch.setattr(auth, "verify_password", pause_inside_the_right_password)
    clients = [
        TestClient(app, base_url="https://testserver", raise_server_exceptions=False)
        for _ in range(2)
    ]
    tokens = [get_csrf(c) for c in clients]
    results = {}

    def run(index, password):
        results[index] = login(clients[index], password=password, token=tokens[index])

    thread_a = threading.Thread(target=run, args=(0, GOOD))
    thread_b = threading.Thread(target=run, args=(1, OTHER))
    thread_a.start()
    assert a_holds_the_lock.wait(10)
    thread_b.start()
    assert wait_until_a_backend_waits_on_a_lock(db_engine)
    b_is_waiting.set()
    thread_a.join()
    thread_b.join()

    assert results[0].status_code == 200
    assert results[1].status_code == 401
    # A reset the counter, then B counted its failure: exactly one.
    assert attempt_row(db_engine) == (1, None)


def test_login_answers_503_when_the_row_lock_is_not_obtained_in_time(
    client, db_engine, monkeypatch
):
    register(client)
    login(client, password=OTHER)  # creates the counter row (failures = 1)
    token = get_csrf(client)
    monkeypatch.setattr(auth, "LOCK_TIMEOUT", "100ms")
    holder = db_engine.connect()
    try:
        holder.execute(
            text("SELECT 1 FROM login_attempts WHERE attempt_key = :u FOR UPDATE"),
            {"u": attempt_key()},
        )
        started = time.monotonic()
        response = login(client, token=token)
        elapsed = time.monotonic() - started
    finally:
        holder.rollback()
        holder.close()

    assert response.status_code == 503
    assert response.json() == {"detail": "Service busy; try again later"}
    assert elapsed < 2
    assert attempt_row(db_engine) == (1, None)  # no failure was counted


def test_row_lock_timeout_is_a_distinct_error_from_hash_saturation():
    assert not issubclass(auth.LoginBusy, passwords.HashingBusy)
    assert not issubclass(passwords.HashingBusy, auth.LoginBusy)


def test_both_503_causes_are_logged_and_look_the_same_to_the_client(
    client, db_engine, monkeypatch, caplog
):
    register(client)
    login(client, password=OTHER)  # creates the counter row
    caplog.set_level(logging.INFO, logger="gateway.auth")

    # Cause 1: no hashing slot.
    token = get_csrf(client)
    monkeypatch.setattr(passwords, "HASH_WAIT_SECONDS", 0.05)
    for _ in range(passwords.MAX_CONCURRENT_HASHES):
        passwords._slots.acquire()
    try:
        saturated = login(client, token=token)
    finally:
        for _ in range(passwords.MAX_CONCURRENT_HASHES):
            passwords._slots.release()

    # Cause 2: the counter row stays locked.
    token = get_csrf(client)
    monkeypatch.setattr(auth, "LOCK_TIMEOUT", "100ms")
    holder = db_engine.connect()
    try:
        holder.execute(
            text("SELECT 1 FROM login_attempts WHERE attempt_key = :u FOR UPDATE"),
            {"u": attempt_key()},
        )
        locked = login(client, token=token)
    finally:
        holder.rollback()
        holder.close()

    assert saturated.status_code == locked.status_code == 503
    assert saturated.json() == locked.json()
    assert saturated.headers["content-type"] == locked.headers["content-type"]
    messages = [r.getMessage() for r in events(caplog)]
    busy = [m for m in messages if "event=service_busy" in m]
    assert len(busy) == 2
    assert "cause=hash_saturated" in busy[0]
    assert "cause=attempt_row_locked" in busy[1]
    assert GOOD not in caplog.text


def test_lock_timeout_is_two_seconds_by_default():
    assert auth.LOCK_TIMEOUT == "2s"


# --- hashing saturation ---------------------------------------------------


def test_login_answers_503_when_hashing_is_saturated_and_does_not_count(
    client, db_engine, monkeypatch
):
    register(client)
    token = get_csrf(client)
    monkeypatch.setattr(passwords, "HASH_WAIT_SECONDS", 0.05)
    for _ in range(passwords.MAX_CONCURRENT_HASHES):
        passwords._slots.acquire()
    try:
        response = login(client, token=token)
    finally:
        for _ in range(passwords.MAX_CONCURRENT_HASHES):
            passwords._slots.release()

    assert response.status_code == 503
    assert response.json() == {"detail": "Service busy; try again later"}
    assert attempt_row(db_engine) is None


# --- current user and /me -------------------------------------------------

NOT_AUTHENTICATED = {"detail": "Not authenticated"}


def forged_access(user_id, *, key=None, exp_delta=timedelta(minutes=15), **claims):
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "role": "lector",
        "sid": "sid-1",
        "jti": "jti-1",
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + exp_delta).timestamp()),
        "iss": "h4tt3r-gateway-test",
        "aud": "h4tt3r-web-test",
        **claims,
    }
    return jwt.encode(
        payload, key or KEYS.jwt_key, algorithm="HS256", headers={"kid": "kid-1"}
    )


def test_me_returns_the_logged_in_user(client):
    user = register(client)
    login(client)

    response = client.get("/api/auth/me")

    assert response.status_code == 200
    assert response.json() == user


def test_me_reads_the_role_from_the_database_not_from_the_token(client, db_engine):
    user = register(client)
    with db_engine.begin() as conn:
        sid = conn.execute(
            text("INSERT INTO refresh_families (user_id) VALUES (:u) RETURNING id"),
            {"u": user["id"]},
        ).scalar_one()
    client.cookies.set(
        "__Host-access", forged_access(user["id"], role="administrador", sid=str(sid))
    )

    response = client.get("/api/auth/me")

    assert response.json()["role"] == "lector"


def test_me_without_cookie_is_401_with_a_fixed_body(client):
    response = client.get("/api/auth/me")

    assert response.status_code == 401
    assert response.json() == NOT_AUTHENTICATED


def test_me_rejects_every_bad_token_with_the_same_response(client, db_engine):
    user = register(client)
    deleted = uuid.uuid4()
    bad = {
        "garbage": "not-a-jwt",
        "bad signature": forged_access(user["id"], key=b"x" * 32),
        "expired": forged_access(user["id"], exp_delta=timedelta(minutes=-5)),
        "wrong audience": forged_access(user["id"], aud="other"),
        "wrong issuer": forged_access(user["id"], iss="other"),
        "sub not a uuid": forged_access("not-a-uuid"),
        "user does not exist": forged_access(deleted),
    }
    for name, token in bad.items():
        client.cookies.clear()
        client.cookies.set("__Host-access", token)

        response = client.get("/api/auth/me")

        assert response.status_code == 401, name
        assert response.json() == NOT_AUTHENTICATED, name


def test_me_is_401_after_the_user_is_deleted(client, db_engine):
    register(client)
    login(client)
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users"))

    assert client.get("/api/auth/me").status_code == 401


# --- Cache-Control --------------------------------------------------------


def test_login_and_me_responses_are_not_cacheable(client):
    register(client)
    wrong = login(client, password=OTHER)
    ok = login(client)
    me_ok = client.get("/api/auth/me")
    client.cookies.clear()
    me_denied = client.get("/api/auth/me")

    assert (wrong.status_code, ok.status_code) == (401, 200)
    assert (me_ok.status_code, me_denied.status_code) == (200, 401)
    for response in (wrong, ok, me_ok, me_denied):
        assert response.headers["cache-control"] == "no-store"


# --- keyed login_attempts keys --------------------------------------------

TYPED_BY_MISTAKE = "hunter2-my.real.pass"  # a password typed in the username box


def test_unknown_username_is_neither_stored_nor_logged(client, db_engine, caplog):
    caplog.set_level(logging.INFO, logger="gateway.auth")

    for _ in range(4):
        login(client, username=TYPED_BY_MISTAKE, password=OTHER)

    with db_engine.connect() as conn:
        keys = (
            conn.execute(text("SELECT attempt_key FROM login_attempts")).scalars().all()
        )
    assert keys == [attempt_key(TYPED_BY_MISTAKE)]
    assert TYPED_BY_MISTAKE not in keys[0]
    assert TYPED_BY_MISTAKE not in caplog.text
    digest = attempt_key(TYPED_BY_MISTAKE)[:16]
    assert f"subject=unknown:{digest} " in caplog.text


def test_known_users_are_also_stored_by_key_and_logged_by_id(client, db_engine, caplog):
    user = register(client)
    caplog.set_level(logging.INFO, logger="gateway.auth")

    login(client, password=OTHER)

    with db_engine.connect() as conn:
        keys = (
            conn.execute(text("SELECT attempt_key FROM login_attempts")).scalars().all()
        )
    assert keys == [attempt_key("alice")]
    assert f"subject={user['id']} " in caplog.text
    assert "unknown:" not in caplog.text


# --- security-event logging -----------------------------------------------


def events(caplog):
    return [r for r in caplog.records if r.name == "gateway.auth"]


def test_login_events_are_logged_without_secrets(client, caplog):
    user = register(client)
    caplog.set_level(logging.INFO, logger="gateway.auth")

    login(client, password=OTHER)
    login(client, username="nobody", password=OTHER)
    ok = login(client)
    client.get("/api/auth/me")

    text_logged = caplog.text
    assert "login_failure" in text_logged
    assert "login_success" in text_logged
    assert user["id"] in text_logged  # who: the user id when it is known
    # No user id for an unknown name: a keyed digest of it, never the name.
    assert "subject=unknown:" in text_logged
    assert "nobody" not in text_logged
    assert "+00:00" in text_logged or "Z" in text_logged  # UTC time
    secrets_seen = [
        GOOD,
        OTHER,
        client.cookies.get("__Host-access"),
        client.cookies.get("__Host-csrf"),
        ok.headers["set-cookie"],
        "$argon2",
    ]
    for value in secrets_seen:
        assert value not in text_logged


def test_lockout_is_logged(client, caplog):
    register(client)
    caplog.set_level(logging.INFO, logger="gateway.auth")

    for _ in range(4):
        login(client, password=OTHER)
    login(client, password=GOOD)

    messages = [r.getMessage() for r in events(caplog)]
    assert sum("account_locked" in m for m in messages) == 1
    assert sum("login_blocked" in m for m in messages) == 1
    assert OTHER not in caplog.text
    assert GOOD not in caplog.text
