import logging
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from gateway import auth, tokens
from gateway.db import get_engine
from gateway.main import create_app
from gateway.tokens import decode_access_token, make_csrf
from tests.test_login import (
    KEYS,
    NOT_AUTHENTICATED,
    SAME_ORIGIN,
    Clock,
    forged_access,
    login,
    register,
    set_cookie_lines,
)
from tests.test_refresh import JAR, Session, refresh, start

URL = "/api/auth/logout"


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


def logout(client, access, csrf, *, header=JAR, headers=SAME_ORIGIN):
    """POST logout with exactly the cookies and header given."""
    cookies = []
    if access is not None:
        cookies.append(f"__Host-access={access}")
    if csrf is not None:
        cookies.append(f"__Host-csrf={csrf}")
    sent = {**headers, "Cookie": "; ".join(cookies)}
    if header is JAR:
        header = csrf
    if header is not None:
        sent["X-CSRF-Token"] = header
    return client.post(URL, headers=sent)


def family_id(db_engine):
    with db_engine.connect() as conn:
        return conn.execute(text("SELECT id FROM refresh_families")).scalar_one()


def revoked_at(db_engine):
    with db_engine.connect() as conn:
        return conn.execute(
            text("SELECT revoked_at FROM refresh_families")
        ).scalar_one()


def denied_jtis(db_engine):
    with db_engine.connect() as conn:
        return conn.execute(text("SELECT jti, expires_at FROM revoked_jtis")).all()


def expired_access(user_id, sid, *, jti="old-jti"):
    now = datetime.now(UTC)
    return forged_access(
        user_id,
        sid=str(sid),
        jti=jti,
        iat=int((now - timedelta(minutes=20)).timestamp()),
        nbf=int((now - timedelta(minutes=20)).timestamp()),
        exp_delta=timedelta(minutes=-5),
    )


# --- logout ---------------------------------------------------------------------


def test_logout_revokes_the_session_and_clears_the_three_cookies(client, db_engine):
    session = start(client)

    response = logout(client, session.access, session.csrf)

    assert response.status_code == 204
    assert response.headers["cache-control"] == "no-store"
    assert revoked_at(db_engine) is not None
    for name, path in (
        ("__Host-access", "/"),
        ("__Host-csrf", "/"),
        ("__Secure-refresh", "/api/auth/refresh"),
    ):
        (line,) = set_cookie_lines(response, name)
        attributes = {part.strip().lower() for part in line.split(";")[1:]}
        assert "max-age=0" in attributes, name
        assert f"path={path}" in attributes, name
        assert "secure" in attributes, name
        assert not any(a.startswith("domain") for a in attributes), name


def test_after_logout_the_old_access_and_refresh_tokens_are_dead(client):
    session = start(client)
    assert client.get("/api/auth/me").status_code == 200

    logout(client, session.access, session.csrf)

    client.cookies.set("__Host-access", session.access)
    denied = client.get("/api/auth/me")
    assert denied.status_code == 401
    assert denied.json() == NOT_AUTHENTICATED
    assert refresh(client, session.refresh, session.csrf).status_code == 401


def test_logout_denies_the_jti_until_the_token_expires(client, db_engine):
    session = start(client)
    claims = decode_access_token(session.access, KEYS)

    logout(client, session.access, session.csrf)

    ((jti, expires_at),) = denied_jtis(db_engine)
    assert jti == claims["jti"]
    assert expires_at == datetime.fromtimestamp(claims["exp"], UTC)


def test_logout_works_with_an_expired_but_otherwise_valid_access_token(
    client, db_engine
):
    session = start(client)
    sid = family_id(db_engine)
    user_id = decode_access_token(session.access, KEYS)["sub"]
    stale = expired_access(user_id, sid)
    csrf = make_csrf(str(sid), KEYS.csrf_key)

    response = logout(client, stale, csrf)

    assert response.status_code == 204
    assert revoked_at(db_engine) is not None
    # Already past its exp: nothing to deny.
    assert denied_jtis(db_engine) == []
    assert refresh(client, session.refresh, session.csrf).status_code == 401


def test_double_logout_is_idempotent(client, db_engine):
    session = start(client)

    first = logout(client, session.access, session.csrf)
    stamp = revoked_at(db_engine)
    second = logout(client, session.access, session.csrf)

    assert (first.status_code, second.status_code) == (204, 204)
    assert revoked_at(db_engine) == stamp  # not moved by the second call
    assert len(denied_jtis(db_engine)) == 1


def test_logout_only_ends_its_own_session(client, db_engine):
    first = start(client)
    register(client, username="bob")
    second = Session(client, login(client, username="bob"))

    logout(client, first.access, first.csrf)

    # The jar was cleared by the Set-Cookie deletions; put bob's access back.
    client.cookies.set("__Host-access", second.access)
    assert client.get("/api/auth/me").status_code == 200
    assert refresh(client, second.refresh, second.csrf).status_code == 200


def test_logout_rejects_forged_and_missing_tokens_with_401(client, db_engine):
    session = start(client)
    user_id = decode_access_token(session.access, KEYS)["sub"]
    sid = str(family_id(db_engine))
    bad = {
        "none": None,
        "garbage": "not-a-jwt",
        "bad signature": forged_access(user_id, sid=sid, key=b"x" * 32),
        "wrong audience": forged_access(user_id, sid=sid, aud="other"),
        "wrong issuer": forged_access(user_id, sid=sid, iss="other"),
        "corrupt header": forged_access(user_id, sid=sid).replace(".", "x.", 1),
        "sid not a uuid": forged_access(user_id, sid="sid-1"),
    }
    csrf = make_csrf(sid, KEYS.csrf_key)
    for name, token in bad.items():
        response = logout(client, token, csrf)
        assert response.status_code == 401, name
        assert response.json() == NOT_AUTHENTICATED, name
    assert revoked_at(db_engine) is None
    assert denied_jtis(db_engine) == []


def test_logout_requires_the_session_csrf_bound_to_the_sid(client, db_engine):
    session = start(client)
    other = make_csrf("some-other-sid", KEYS.csrf_key)
    pre = client.get("/api/auth/csrf").json()["csrf_token"]
    cases = {
        "no cookie": dict(csrf=None, header=session.csrf),
        "no header": dict(csrf=session.csrf, header=None),
        "header differs": dict(csrf=session.csrf, header=session.csrf + "x"),
        "other sid": dict(csrf=other, header=other),
        "pre-session": dict(csrf=pre, header=pre),
    }
    for name, case in cases.items():
        response = logout(client, session.access, case["csrf"], header=case["header"])
        assert response.status_code == 403, name
    assert revoked_at(db_engine) is None
    assert denied_jtis(db_engine) == []


@pytest.mark.parametrize(
    "headers",
    [{}, {"Origin": "https://evil.example"}, {"Sec-Fetch-Site": "cross-site"}],
)
def test_logout_fails_closed_without_a_same_origin_signal(client, db_engine, headers):
    session = start(client)

    response = logout(client, session.access, session.csrf, headers=headers)

    assert response.status_code == 403
    assert revoked_at(db_engine) is None


def test_logout_is_logged_without_secrets(client, caplog):
    caplog.set_level(logging.INFO, logger="gateway.auth")
    session = start(client)

    logout(client, session.access, session.csrf)

    assert "event=logout" in caplog.text
    assert session.access not in caplog.text
    assert session.csrf not in caplog.text
    assert session.refresh not in caplog.text


# --- tokens.decode_access_token_allow_expired ---------------------------------------


def test_the_lenient_decoder_ignores_only_expiry(client, db_engine):
    session = start(client)
    claims = decode_access_token(session.access, KEYS)
    stale = expired_access(claims["sub"], claims["sid"])

    assert tokens.decode_access_token_allow_expired(stale, KEYS)["sid"] == claims["sid"]
    with pytest.raises(tokens.InvalidToken):
        decode_access_token(stale, KEYS)
    for bad in (
        forged_access(claims["sub"], key=b"x" * 32, exp_delta=timedelta(minutes=-5)),
        forged_access(claims["sub"], aud="other", exp_delta=timedelta(minutes=-5)),
        forged_access(claims["sub"], iss="other", exp_delta=timedelta(minutes=-5)),
        "garbage",
    ):
        with pytest.raises(tokens.InvalidToken):
            tokens.decode_access_token_allow_expired(bad, KEYS)


def test_the_lenient_decoder_requires_every_claim_and_checks_the_signature(
    monkeypatch,
):
    import jwt

    seen = []
    real = jwt.decode

    def spy(*args, **kwargs):
        seen.append(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(tokens.jwt, "decode", spy)
    token = forged_access("12345678-1234-5678-1234-567812345678")
    tokens.decode_access_token_allow_expired(token, KEYS)
    tokens.decode_access_token_allow_expired(token, KEYS)

    first, second = seen
    assert first["algorithms"] == ["HS256"]
    assert "verify_signature" not in first["options"]
    assert first["options"]["verify_exp"] is False
    assert set(first["options"]["require"]) >= {"sub", "sid", "jti", "iat", "exp"}
    assert first["options"] is not second["options"]  # rebuilt on every call


# --- current_user checks ----------------------------------------------------------


def test_tokens_valid_since_in_the_future_invalidates_the_token(client, db_engine):
    start(client)
    assert client.get("/api/auth/me").status_code == 200
    with db_engine.begin() as conn:
        conn.execute(
            text("UPDATE users SET tokens_valid_since = now() + interval '1 minute'")
        )

    response = client.get("/api/auth/me")

    assert response.status_code == 401
    assert response.json() == NOT_AUTHENTICATED


def test_a_token_issued_in_the_same_second_as_tokens_valid_since_still_works(
    client, db_engine
):
    user = register(client)
    with db_engine.begin() as conn:
        # Whole second of `iat`, microseconds in the column: a plain comparison
        # would reject this token.
        conn.execute(
            text(
                "UPDATE users SET tokens_valid_since = "
                "date_trunc('second', now()) + interval '0.9 seconds'"
            )
        )
        valid_since = conn.execute(
            text("SELECT tokens_valid_since FROM users")
        ).scalar()
        sid = conn.execute(
            text("INSERT INTO refresh_families (user_id) VALUES (:u) RETURNING id"),
            {"u": user["id"]},
        ).scalar_one()
    iat = int(valid_since.timestamp())

    same_second = forged_access(user["id"], iat=iat, nbf=iat, sid=str(sid))
    earlier = forged_access(user["id"], iat=iat - 1, nbf=iat - 1, sid=str(sid))

    client.cookies.set("__Host-access", same_second)
    assert client.get("/api/auth/me").status_code == 200
    client.cookies.set("__Host-access", earlier)
    assert client.get("/api/auth/me").status_code == 401


def test_a_fresh_login_right_after_registration_works(client):
    start(client)

    assert client.get("/api/auth/me").status_code == 200


def test_a_denied_jti_does_not_affect_other_tokens_of_the_user(client, db_engine):
    session = start(client)
    logout(client, session.access, session.csrf)

    login(client)

    assert client.get("/api/auth/me").status_code == 200


# --- current_user rejects tokens of a revoked or missing session -----------------


def test_after_refresh_reuse_the_access_token_of_that_family_is_401(client):
    session = start(client)
    old = session.refresh
    refresh(client, old, session.csrf)
    client.cookies.set("__Host-access", session.access)
    assert client.get("/api/auth/me").status_code == 200

    assert refresh(client, old, session.csrf).status_code == 401  # reuse

    client.cookies.set("__Host-access", session.access)
    response = client.get("/api/auth/me")
    assert response.status_code == 401
    assert response.json() == NOT_AUTHENTICATED


def test_after_logout_another_access_token_of_the_family_is_401(client):
    session = start(client)
    first_access = session.access
    session.take(refresh(client, session.refresh, session.csrf))
    assert session.access != first_access

    logout(client, session.access, session.csrf)

    # first_access was never denied by jti; its family is what died.
    client.cookies.set("__Host-access", first_access)
    response = client.get("/api/auth/me")
    assert response.status_code == 401
    assert response.json() == NOT_AUTHENTICATED


def test_a_validly_signed_token_of_a_nonexistent_family_is_401(client):
    user = register(client)

    client.cookies.set(
        "__Host-access", forged_access(user["id"], sid=str(uuid.uuid4()))
    )

    response = client.get("/api/auth/me")
    assert response.status_code == 401
    assert response.json() == NOT_AUTHENTICATED


@pytest.mark.parametrize("sid", ["sid-1", "", "not-a-uuid", "1" * 200])
def test_a_token_with_a_non_uuid_sid_is_401_not_500(client, sid):
    user = register(client)

    client.cookies.set("__Host-access", forged_access(user["id"], sid=sid))

    response = client.get("/api/auth/me")
    assert response.status_code == 401
    assert response.json() == NOT_AUTHENTICATED


def test_logout_answers_503_when_the_family_row_stays_locked(
    client, db_engine, monkeypatch, caplog
):
    session = start(client)
    caplog.set_level(logging.INFO, logger="gateway.auth")
    monkeypatch.setattr(auth, "LOCK_TIMEOUT", "100ms")
    holder = db_engine.connect()
    results = []
    # In a thread, so that a logout that never gives up fails the test instead
    # of hanging it.
    worker = threading.Thread(
        target=lambda: results.append(logout(client, session.access, session.csrf))
    )
    try:
        holder.execute(text("SELECT 1 FROM refresh_families FOR UPDATE"))
        started = time.monotonic()
        worker.start()
        worker.join(timeout=5)
        elapsed = time.monotonic() - started
    finally:
        holder.rollback()
        holder.close()
    worker.join(timeout=10)

    assert results, "logout never answered while the row was locked"
    (response,) = results
    assert response.status_code == 503
    assert response.json() == {"detail": "Service busy; try again later"}
    assert elapsed < 2
    assert "event=service_busy cause=logout_row_locked" in caplog.text
    assert revoked_at(db_engine) is None
    assert denied_jtis(db_engine) == []
    # Nothing was half done: logging out works once the lock is gone.
    assert logout(client, session.access, session.csrf).status_code == 204


# Validly signed, so they get past the decoder; their claims have the wrong types.
WRONG_TYPES = {
    "int sid": {"sid": 12345},
    "list sid": {"sid": ["a"]},
    "null sid": {"sid": None},
    "int sub": {"sub": 12345},
    "int jti": {"jti": 12345},
}


@pytest.mark.parametrize("claims", WRONG_TYPES.values(), ids=WRONG_TYPES.keys())
def test_a_signed_token_with_wrongly_typed_claims_is_401_on_me(client, claims):
    user = register(client)
    sid = str(uuid.uuid4())
    token = forged_access(claims.get("sub", user["id"]), **{"sid": sid, **claims})
    raising = TestClient(client.app, base_url="https://testserver")
    raising.cookies.set("__Host-access", token)

    response = raising.get("/api/auth/me")

    assert response.status_code == 401
    assert response.json() == NOT_AUTHENTICATED


@pytest.mark.parametrize("claims", WRONG_TYPES.values(), ids=WRONG_TYPES.keys())
def test_a_signed_token_with_wrongly_typed_claims_is_401_on_logout(
    client, db_engine, claims
):
    user = register(client)
    sid = str(uuid.uuid4())
    token = forged_access(claims.get("sub", user["id"]), **{"sid": sid, **claims})
    csrf = make_csrf(sid, KEYS.csrf_key)

    response = logout(client, token, csrf)

    assert response.status_code == 401
    assert response.json() == NOT_AUTHENTICATED


def test_logout_still_works_after_the_access_jwt_expired_in_the_browser(
    client, db_engine, clock
):
    # The access cookie must outlive the 15-minute JWT, or the browser stops
    # sending it and logout cannot find the session. The login happens 20
    # minutes "ago": the JWT is already expired, the cookie's Max-Age is not.
    register(client)
    with db_engine.begin() as conn:
        conn.execute(
            text("UPDATE users SET tokens_valid_since = now() - interval '1 hour'")
        )
    clock.offset = -timedelta(minutes=20)
    response = login(client)
    session = Session(client, response)
    (line,) = set_cookie_lines(response, "__Host-access")
    assert f"max-age={7 * 24 * 3600}" in line.lower()
    clock.offset = timedelta(0)

    assert client.get("/api/auth/me").status_code == 401  # the JWT has expired
    assert "__Host-access" in client.cookies  # but the browser still sends it
    response = logout(client, session.access, session.csrf)

    assert response.status_code == 204
    assert revoked_at(db_engine) is not None


def test_the_access_cookie_lifetime_follows_the_role(client, db_engine):
    register(client)
    with db_engine.begin() as conn:
        conn.execute(text("UPDATE users SET role = 'editor'"))

    response = login(client)

    (line,) = set_cookie_lines(response, "__Host-access")
    assert f"max-age={8 * 3600}" in line.lower()


def test_a_signed_token_with_a_non_numeric_exp_is_401_on_logout(client, db_engine):
    user = register(client)
    sid = str(uuid.uuid4())
    csrf = make_csrf(sid, KEYS.csrf_key)
    for exp in ("tomorrow", [1], None, True):
        token = forged_access(user["id"], sid=sid, exp=exp)
        response = logout(client, token, csrf)
        assert response.status_code == 401, exp
        assert response.json() == NOT_AUTHENTICATED
