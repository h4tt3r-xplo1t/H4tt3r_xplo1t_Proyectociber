import logging
import threading
import time
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from gateway import auth
from gateway.db import get_engine
from gateway.main import create_app
from gateway.tokens import check_csrf, decode_access_token, hash_refresh_token
from tests.test_login import (
    GOOD,
    KEYS,
    NOT_AUTHENTICATED,
    SAME_ORIGIN,
    Clock,
    login,
    refresh_cookie_value,
    register,
    set_cookie_lines,
)

URL = "/api/auth/refresh"
JAR = object()  # "send what the login gave us"


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def client(db_engine, clock):
    app = create_app()
    app.dependency_overrides[auth.get_keys] = lambda: KEYS
    app.dependency_overrides[auth.get_now] = clock
    yield TestClient(app, base_url="https://testserver")
    get_engine().dispose()


class Session:
    """The three cookies a browser holds after login, as plain values."""

    def __init__(self, client, response):
        self.client = client
        self.refresh = refresh_cookie_value(response)
        self.csrf = client.cookies.get("__Host-csrf")
        self.access = client.cookies.get("__Host-access")

    def take(self, response):
        self.refresh = refresh_cookie_value(response)
        self.csrf = self.client.cookies.get("__Host-csrf")
        self.access = self.client.cookies.get("__Host-access")


def start(client, username="alice"):
    register(client, username=username)
    return Session(client, login(client, username=username))


def refresh(client, refresh_token, csrf, *, header=JAR, headers=SAME_ORIGIN):
    """POST the refresh call with exactly the cookies and header given."""
    cookies = []
    if refresh_token is not None:
        cookies.append(f"__Secure-refresh={refresh_token}")
    if csrf is not None:
        cookies.append(f"__Host-csrf={csrf}")
    sent = {**headers, "Cookie": "; ".join(cookies)}
    if header is JAR:
        header = csrf
    if header is not None:
        sent["X-CSRF-Token"] = header
    return client.post(URL, headers=sent)


def family_row(db_engine):
    with db_engine.connect() as conn:
        return conn.execute(
            text("SELECT id, revoked_at, last_used_at FROM refresh_families")
        ).one()


def test_refresh_rotates_the_token_and_returns_the_user(client, db_engine):
    session = start(client)
    old = session.refresh

    response = refresh(client, old, session.csrf)

    assert response.status_code == 200
    assert set(response.json()) == {"id", "username", "role"}
    assert response.json()["username"] == "alice"
    assert response.headers["cache-control"] == "no-store"
    new = refresh_cookie_value(response)
    assert new != old
    with db_engine.connect() as conn:
        rows = conn.execute(
            text("SELECT token_hash, used_at FROM refresh_tokens")
        ).all()
    by_hash = dict(rows)
    assert by_hash[hash_refresh_token(old)] is not None
    assert by_hash[hash_refresh_token(new)] is None
    assert len(by_hash) == 2


def test_refresh_sets_new_cookies_with_the_login_attributes(client):
    session = start(client)

    response = refresh(client, session.refresh, session.csrf)

    for name, path in (
        ("__Host-access", "/"),
        ("__Host-csrf", "/"),
        ("__Secure-refresh", "/api/auth/refresh"),
    ):
        (line,) = set_cookie_lines(response, name)
        attributes = {part.strip().lower() for part in line.split(";")[1:]}
        assert {"secure", "samesite=strict", f"path={path}"} <= attributes
        assert not any(a.startswith("domain") for a in attributes)
    (refresh_line,) = set_cookie_lines(response, "__Secure-refresh")
    assert "httponly" in refresh_line.lower()
    assert f"max-age={7 * 24 * 3600}" in refresh_line.lower()


def test_refresh_keeps_the_sid_and_issues_a_fresh_jti_and_csrf(client):
    session = start(client)
    before = decode_access_token(session.access, KEYS)
    old_csrf = session.csrf

    session.take(refresh(client, session.refresh, session.csrf))

    after = decode_access_token(session.access, KEYS)
    assert after["sid"] == before["sid"]
    assert after["jti"] != before["jti"]
    assert session.csrf != old_csrf
    assert check_csrf(session.csrf, session.csrf, after["sid"], KEYS.csrf_key)


def test_the_new_access_token_works_and_the_old_refresh_token_does_not(client):
    session = start(client)
    old = session.refresh
    response = refresh(client, old, session.csrf)
    session.take(response)

    assert client.get("/api/auth/me").status_code == 200
    # The token that was just rotated is dead; the new one is alive.
    assert refresh(client, session.refresh, session.csrf).status_code == 200


def test_refresh_bumps_the_idle_clock(client, db_engine, clock):
    session = start(client)
    before = family_row(db_engine).last_used_at
    clock.offset = timedelta(hours=1)

    refresh(client, session.refresh, session.csrf)

    assert family_row(db_engine).last_used_at - before >= timedelta(minutes=59)


# --- reuse -------------------------------------------------------------------


def test_reusing_a_rotated_token_revokes_the_whole_family(client, db_engine, caplog):
    session = start(client)
    old = session.refresh
    csrf = session.csrf
    newest = refresh_cookie_value(refresh(client, old, csrf))
    caplog.set_level(logging.INFO, logger="gateway.auth")

    reused = refresh(client, old, csrf)

    assert reused.status_code == 401
    assert reused.json() == NOT_AUTHENTICATED
    assert family_row(db_engine).revoked_at is not None
    assert "event=refresh_reuse" in caplog.text
    # The newest token of the family died with it.
    assert refresh(client, newest, csrf).status_code == 401


def test_a_reuse_attempt_without_csrf_does_not_revoke_anything(client, db_engine):
    session = start(client)
    old = session.refresh
    refresh(client, old, session.csrf)

    response = refresh(client, old, None)

    assert response.status_code == 403
    assert family_row(db_engine).revoked_at is None


# --- failures look the same ---------------------------------------------------


def test_unknown_or_missing_refresh_token_is_401(client):
    session = start(client)

    for token in ("not-a-real-token", None, ""):
        response = refresh(client, token, session.csrf)
        assert response.status_code == 401
        assert response.json() == NOT_AUTHENTICATED
        assert response.headers["cache-control"] == "no-store"


def test_a_revoked_family_is_401(client, db_engine):
    session = start(client)
    with db_engine.begin() as conn:
        conn.execute(text("UPDATE refresh_families SET revoked_at = now()"))

    response = refresh(client, session.refresh, session.csrf)

    assert response.status_code == 401
    assert response.json() == NOT_AUTHENTICATED


def test_a_deleted_user_is_401(client, db_engine):
    session = start(client)
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users"))

    response = refresh(client, session.refresh, session.csrf)

    assert response.status_code == 401
    assert response.json() == NOT_AUTHENTICATED


# --- idle and absolute limits ---------------------------------------------------


@pytest.mark.parametrize(
    ("role", "idle", "absolute"),
    [
        ("lector", timedelta(hours=24), timedelta(days=7)),
        ("editor", timedelta(minutes=30), timedelta(hours=8)),
        ("auditor", timedelta(minutes=30), timedelta(hours=8)),
        ("administrador", timedelta(minutes=30), timedelta(hours=8)),
    ],
)
def test_idle_limit_by_role(client, db_engine, clock, role, idle, absolute):
    session = start(client)
    with db_engine.begin() as conn:
        conn.execute(text("UPDATE users SET role = :r"), {"r": role})

    clock.offset = idle - timedelta(seconds=5)
    ok = refresh(client, session.refresh, session.csrf)
    assert ok.status_code == 200
    session.take(ok)

    # The idle clock restarted at the refresh just made.
    clock.offset += idle + timedelta(seconds=5)
    late = refresh(client, session.refresh, session.csrf)
    assert late.status_code == 401
    assert late.json() == NOT_AUTHENTICATED


@pytest.mark.parametrize(
    ("role", "absolute"),
    [("lector", timedelta(days=7)), ("editor", timedelta(hours=8))],
)
def test_absolute_limit_by_role(client, db_engine, role, absolute):
    session = start(client)
    with db_engine.begin() as conn:
        conn.execute(text("UPDATE users SET role = :r"), {"r": role})

    def age_family(age):
        # Only the total age may trip the limit: last_used_at stays recent.
        with db_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE refresh_families "
                    "SET created_at = now() - make_interval(secs => :s)"
                ),
                {"s": age.total_seconds()},
            )

    age_family(absolute - timedelta(minutes=1))
    ok = refresh(client, session.refresh, session.csrf)
    assert ok.status_code == 200
    session.take(ok)

    age_family(absolute + timedelta(minutes=1))
    response = refresh(client, session.refresh, session.csrf)

    assert response.status_code == 401
    assert response.json() == NOT_AUTHENTICATED


def test_the_role_is_read_from_the_database_at_refresh_time(client, db_engine, clock):
    session = start(client)  # a lector: 24 h idle
    with db_engine.begin() as conn:
        conn.execute(text("UPDATE users SET role = 'editor'"))
    clock.offset = timedelta(hours=1)

    response = refresh(client, session.refresh, session.csrf)

    assert response.status_code == 401  # an editor idles out after 30 minutes


def test_the_refreshed_access_token_carries_the_current_role(client, db_engine):
    session = start(client)
    with db_engine.begin() as conn:
        conn.execute(text("UPDATE users SET role = 'editor'"))

    response = refresh(client, session.refresh, session.csrf)

    assert response.json()["role"] == "editor"
    claims = decode_access_token(client.cookies.get("__Host-access"), KEYS)
    assert claims["role"] == "editor"
    (line,) = set_cookie_lines(response, "__Secure-refresh")
    assert f"max-age={8 * 3600}" in line.lower()


# --- CSRF and origin --------------------------------------------------------------


def test_missing_or_mismatched_csrf_is_403(client):
    session = start(client)
    other = login(client)  # a second session: its CSRF is bound to another sid
    other_csrf = client.cookies.get("__Host-csrf")
    assert other.status_code == 200

    cases = {
        "no cookie": dict(csrf=None, header=session.csrf),
        "no header": dict(csrf=session.csrf, header=None),
        "header differs": dict(csrf=session.csrf, header=session.csrf + "x"),
        "other session": dict(csrf=other_csrf, header=other_csrf),
        "garbage": dict(csrf="a.b.c", header="a.b.c"),
    }
    for name, case in cases.items():
        response = refresh(client, session.refresh, case["csrf"], header=case["header"])
        assert response.status_code == 403, name


def test_a_pre_session_csrf_token_is_not_accepted_for_refresh(client):
    session = start(client)
    pre = client.get("/api/auth/csrf").json()["csrf_token"]

    response = refresh(client, session.refresh, pre)

    assert response.status_code == 403


@pytest.mark.parametrize(
    "headers",
    [{}, {"Origin": "https://evil.example"}, {"Sec-Fetch-Site": "cross-site"}],
)
def test_refresh_fails_closed_without_a_same_origin_signal(client, headers):
    session = start(client)

    response = refresh(client, session.refresh, session.csrf, headers=headers)

    assert response.status_code == 403


def test_a_refresh_that_fails_csrf_does_not_consume_the_token(client):
    session = start(client)

    refresh(client, session.refresh, None)

    assert refresh(client, session.refresh, session.csrf).status_code == 200


# --- cookie scope ------------------------------------------------------------------


def test_the_browser_only_sends_the_refresh_cookie_to_the_refresh_path(client):
    start(client)

    assert client.get("/api/auth/me").status_code == 200
    me_cookies = client.get("/api/auth/me").request.headers.get("cookie", "")
    assert "__Secure-refresh" not in me_cookies


# --- logs and locking -----------------------------------------------------------------


def test_no_token_value_reaches_the_logs(client, caplog):
    caplog.set_level(logging.DEBUG)
    session = start(client)
    old = session.refresh
    csrf = session.csrf
    new = refresh_cookie_value(refresh(client, old, csrf))
    refresh(client, old, csrf)  # reuse: logged

    assert old not in caplog.text
    assert new not in caplog.text
    assert csrf not in caplog.text
    assert session.access not in caplog.text
    assert hash_refresh_token(old) not in caplog.text
    assert GOOD not in caplog.text


def test_refresh_answers_503_when_the_token_row_stays_locked(
    client, db_engine, monkeypatch
):
    session = start(client)
    monkeypatch.setattr(auth, "LOCK_TIMEOUT", "100ms")
    holder = db_engine.connect()
    try:
        holder.execute(
            text("SELECT 1 FROM refresh_tokens WHERE token_hash = :h FOR UPDATE"),
            {"h": hash_refresh_token(session.refresh)},
        )
        started = time.monotonic()
        response = refresh(client, session.refresh, session.csrf)
        elapsed = time.monotonic() - started
    finally:
        holder.rollback()
        holder.close()

    assert response.status_code == 503
    assert response.json() == {"detail": "Service busy; try again later"}
    assert elapsed < 2
    # Nothing was consumed: the same token still works.
    assert refresh(client, session.refresh, session.csrf).status_code == 200


# --- failed refreshes are logged -----------------------------------------------------


def failure_logs(caplog):
    return [
        r.getMessage() for r in caplog.records if "refresh_failed" in r.getMessage()
    ]


def test_every_failed_refresh_is_logged_with_a_short_reason(
    client, db_engine, clock, caplog
):
    caplog.set_level(logging.INFO, logger="gateway.auth")
    session = start(client)
    user_id = decode_access_token(session.access, KEYS)["sub"]

    refresh(client, "not-a-real-token", session.csrf)
    (unknown,) = failure_logs(caplog)
    assert "reason=unknown" in unknown
    assert "subject=unknown" in unknown
    caplog.clear()

    clock.offset = timedelta(hours=25)
    refresh(client, session.refresh, session.csrf)
    (idle,) = failure_logs(caplog)
    assert "reason=idle_expired" in idle
    assert f"subject={user_id}" in idle
    caplog.clear()

    clock.offset = timedelta(0)
    with db_engine.begin() as conn:
        conn.execute(
            text("UPDATE refresh_families SET created_at = now() - interval '8 days'")
        )
    refresh(client, session.refresh, session.csrf)
    (absolute,) = failure_logs(caplog)
    assert "reason=absolute_expired" in absolute
    caplog.clear()

    with db_engine.begin() as conn:
        conn.execute(text("UPDATE refresh_families SET revoked_at = now()"))
    refresh(client, session.refresh, session.csrf)
    (revoked,) = failure_logs(caplog)
    assert "reason=revoked" in revoked
    assert f"subject={user_id}" in revoked
    assert session.refresh not in caplog.text
    assert session.csrf not in caplog.text
    assert hash_refresh_token(session.refresh) not in caplog.text


def test_a_refresh_for_a_missing_user_is_logged_as_user_missing(
    client, db_engine, caplog, monkeypatch
):
    caplog.set_level(logging.INFO, logger="gateway.auth")
    session = start(client)
    # The FK cascade removes the family with the user, so a missing user is only
    # reachable through a race; simulate the lookup coming back empty.
    monkeypatch.setattr(auth.Session, "get", lambda self, *a, **k: None, raising=False)

    response = refresh(client, session.refresh, session.csrf)

    assert response.status_code == 401
    (line,) = failure_logs(caplog)
    assert "reason=user_missing" in line
    assert session.refresh not in caplog.text


def test_a_successful_refresh_logs_no_failure(client, caplog):
    caplog.set_level(logging.INFO, logger="gateway.auth")
    session = start(client)

    refresh(client, session.refresh, session.csrf)

    assert failure_logs(caplog) == []


# --- concurrency ---------------------------------------------------------------------


def wait_for_waiting_backends(db_engine, count, timeout=10):
    """Poll PostgreSQL until `count` backends are blocked on a lock."""
    deadline = time.monotonic() + timeout
    query = text(
        "SELECT count(*) FROM pg_stat_activity "
        "WHERE datname = current_database() AND wait_event_type = 'Lock'"
    )
    while time.monotonic() < deadline:
        with db_engine.connect() as conn:
            if conn.execute(query).scalar_one() >= count:
                return True
        threading.Event().wait(0.02)
    return False


def test_two_simultaneous_refreshes_with_the_same_token_end_in_reuse(client, db_engine):
    session = start(client)
    clients = [
        TestClient(
            client.app, base_url="https://testserver", raise_server_exceptions=False
        )
        for _ in range(2)
    ]
    results = {}

    def run(index):
        results[index] = refresh(clients[index], session.refresh, session.csrf)

    # Hold the family row so that both requests are provably queued on it at the
    # same moment; releasing it lets them race for the rotation.
    holder = db_engine.connect()
    threads = [threading.Thread(target=run, args=(i,)) for i in range(2)]
    try:
        holder.execute(text("SELECT 1 FROM refresh_families FOR UPDATE"))
        for thread in threads:
            thread.start()
        assert wait_for_waiting_backends(db_engine, 2)
    finally:
        holder.rollback()
        holder.close()
    for thread in threads:
        thread.join(timeout=30)

    statuses = sorted(r.status_code for r in results.values())
    assert statuses == [200, 401]
    winner = next(r for r in results.values() if r.status_code == 200)
    loser = next(r for r in results.values() if r.status_code == 401)
    assert loser.json() == NOT_AUTHENTICATED
    # The loser found the token already used: reuse, so the family is revoked
    # and the winner's brand-new token is dead as well.
    assert family_row(db_engine).revoked_at is not None
    assert (
        refresh(client, refresh_cookie_value(winner), session.csrf).status_code == 401
    )
