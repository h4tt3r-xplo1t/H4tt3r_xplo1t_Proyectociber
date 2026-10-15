"""Guard: every state-changing route of a session refuses a request without CSRF.

ASVS 3.5.x / issue #35. The routes come from the app itself (its OpenAPI paths),
so a route added later cannot slip through: the test fails until the new route
has a case here, and every case must answer 403 to a request that has a valid
session and the right origin but no valid CSRF token bound to that session.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from tests.test_login import GOOD, SAME_ORIGIN, get_csrf, login, register

STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}
# Before any session exists there is nothing to bind a token to: register takes
# no token and login takes the short-lived pre-session one (its own tests cover
# both). Everything else is a state-changing route of a session.
PRE_SESSION = {
    ("POST", "/api/auth/register"),
    ("POST", "/api/auth/login"),
    ("POST", "/api/auth/password-reset"),
}

USERS = "/api/admin/users"
NEW = "an entirely new passphrase"
# (actor, path, body, status when the request does carry a valid token)
CASES = {
    ("POST", "/api/auth/refresh"): ("reader", "/api/auth/refresh", None, 200),
    ("POST", "/api/auth/logout"): ("reader", "/api/auth/logout", None, 204),
    ("POST", "/api/auth/mfa/enroll"): (
        "reader",
        "/api/auth/mfa/enroll",
        {"current_password": GOOD},
        200,
    ),
    ("POST", "/api/auth/mfa/confirm"): (
        "reader",
        "/api/auth/mfa/confirm",
        {"code": "123456"},
        409,  # nothing to confirm: past the CSRF check, refused for its own reason
    ),
    ("POST", "/api/auth/mfa/disable"): (
        "reader",
        "/api/auth/mfa/disable",
        {"current_password": GOOD, "code": "123456"},
        409,  # no MFA to disable: past the CSRF check, refused for its own reason
    ),
    ("POST", "/api/auth/mfa/recovery-codes"): (
        "reader",
        "/api/auth/mfa/recovery-codes",
        {"current_password": GOOD, "code": "123456"},
        409,  # no MFA to regenerate: past the CSRF check, refused for its own reason
    ),
    ("POST", "/api/auth/password"): (
        "reader",
        "/api/auth/password",
        {"current_password": GOOD, "new_password": NEW},
        200,
    ),
    ("POST", "/api/auth/login/mfa"): (
        "mfa-pending",
        "/api/auth/login/mfa",
        {"code": "000000"},
        401,  # a wrong code: the generic login failure, not a CSRF refusal
    ),
    ("PUT", f"{USERS}/{{user_id}}/role"): (
        "admin",
        f"{USERS}/{{target}}/role",
        {"role": "editor"},
        200,
    ),
    ("POST", f"{USERS}/{{user_id}}/enrollment-window"): (
        "admin",
        f"{USERS}/{{target}}/enrollment-window",
        None,
        409,
    ),
    ("POST", f"{USERS}/{{user_id}}/reset-code"): (
        "admin",
        f"{USERS}/{{target}}/reset-code",
        None,
        200,
    ),
    ("POST", f"{USERS}/{{user_id}}/mfa-reset"): (
        "admin",
        f"{USERS}/{{target}}/mfa-reset",
        None,
        409,  # the target has no MFA: past the CSRF check, refused for its own reason
    ),
    ("POST", f"{USERS}/{{user_id}}/mfa-reset/approve"): (
        "admin",
        f"{USERS}/{{target}}/mfa-reset/approve",
        None,
        409,  # no pending request: past the CSRF check, refused for its own reason
    ),
    ("POST", f"{USERS}/{{user_id}}/unlock"): (
        "admin",
        f"{USERS}/{{target}}/unlock",
        None,
        200,
    ),
    ("POST", f"{USERS}/{{user_id}}/sessions/end"): (
        "admin",
        f"{USERS}/{{target}}/sessions/end",
        None,
        200,
    ),
}

SNAPSHOT = {
    "users": "SELECT * FROM users",
    "refresh_families": "SELECT * FROM refresh_families",
    "refresh_tokens": "SELECT * FROM refresh_tokens",
    "revoked_jtis": "SELECT * FROM revoked_jtis",
    "login_attempts": "SELECT * FROM login_attempts",
    "recovery_codes": "SELECT * FROM recovery_codes",
    "password_reset_codes": "SELECT * FROM password_reset_codes",
    "mfa_reset_requests": "SELECT * FROM mfa_reset_requests",
}


def discovered_routes(app):
    """(method, path template) of every state-changing route the app serves."""
    paths = app.openapi()["paths"]
    return {
        (method.upper(), path)
        for path, operations in paths.items()
        for method in operations
        if method.upper() in STATE_CHANGING
    }


def snapshot(db_engine):
    with db_engine.connect() as conn:
        return {
            name: sorted(repr(tuple(row)) for row in conn.execute(text(query)))
            for name, query in SNAPSHOT.items()
        }


def browser(client):
    return TestClient(client.app, base_url="https://testserver")


def sign_in(client, db_engine, username, *, mfa=False, role=None):
    """A browser logged in as a reader; the role and MFA are then set in the DB."""
    c = browser(client)
    register(c, username)
    if mfa:
        with db_engine.begin() as conn:
            conn.execute(
                text("UPDATE users SET mfa_enabled_at = now() WHERE username = :u"),
                {"u": username},
            )
    assert login(c, username).status_code == 200
    if role is not None:
        with db_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE users SET role = :r, mfa_enabled_at = now() "
                    "WHERE username = :u"
                ),
                {"r": role, "u": username},
            )
    return c


def actor_for(kind, client, db_engine):
    if kind == "reader":
        return sign_in(client, db_engine, "alice")
    if kind == "admin":
        return sign_in(client, db_engine, "boss", role="administrador")
    # The password step of a user with MFA: only the mfa-pending token and its
    # session CSRF are set, which is what /login/mfa takes.
    c = browser(client)
    register(c, "carol")
    with db_engine.begin() as conn:
        conn.execute(text("UPDATE users SET mfa_enabled_at = now()"))
    assert login(c, "carol").json() == {"status": "mfa_required"}
    return c


def send(c, method, path, body, *, header, cookie="keep"):
    """The request with the cookies of the session and the CSRF as given."""
    if cookie != "keep":
        valid = c.cookies.get("__Host-csrf")
        c.cookies.delete("__Host-csrf")
        if cookie is not None:
            c.cookies.set("__Host-csrf", cookie)
    sent = dict(SAME_ORIGIN)
    if header is not None:
        sent["X-CSRF-Token"] = header
    try:
        return c.request(method, path, json=body, headers=sent)
    finally:
        if cookie != "keep":
            c.cookies.delete("__Host-csrf")
            c.cookies.set("__Host-csrf", valid)


def test_every_state_changing_route_has_a_csrf_case(client):
    # This is a control, not a spot check: a new state-changing route without a
    # case in CASES (or an entry in PRE_SESSION) fails the suite, so no route can
    # skip the CSRF guard unnoticed.
    assert discovered_routes(client.app) - PRE_SESSION == set(CASES)


def test_the_pre_session_exceptions_are_real_routes(client):
    assert PRE_SESSION <= discovered_routes(client.app)


@pytest.mark.parametrize(("method", "template"), sorted(CASES), ids=lambda v: str(v))
def test_a_request_without_a_valid_session_csrf_is_refused_and_changes_nothing(
    client, db_engine, openbao_env, method, template
):
    kind, path, body, control = CASES[(method, template)]
    c = actor_for(kind, client, db_engine)
    register(browser(client), "target")
    with db_engine.connect() as conn:
        target = conn.execute(
            text("SELECT id FROM users WHERE username = 'target'")
        ).scalar_one()
    path = path.replace("{target}", str(target))
    valid = c.cookies.get("__Host-csrf")
    # A token that is genuine but belongs to no session: the pre-session one.
    foreign = get_csrf(browser(client))
    before = snapshot(db_engine)

    refused = {
        "no header": send(c, method, path, body, header=None),
        "wrong header": send(c, method, path, body, header="not-the-token"),
        "no cookie": send(c, method, path, body, header=valid, cookie=None),
        "cookie differs": send(c, method, path, body, header=valid, cookie=foreign),
        "pre-session token": send(
            c, method, path, body, header=foreign, cookie=foreign
        ),
    }

    for name, response in refused.items():
        assert response.status_code == 403, name
    assert snapshot(db_engine) == before
    # Control: the same request with the right token gets past the CSRF check
    # (any other answer), so the 403s above were the CSRF's and the session,
    # origin and body were fine.
    allowed = send(c, method, path, body, header=valid)
    assert allowed.status_code == control
