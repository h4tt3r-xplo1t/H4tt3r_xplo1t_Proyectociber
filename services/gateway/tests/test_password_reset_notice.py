"""The notice shown on the first full login after an administrator-assisted reset.

ADR 0004, decision 10: the residual risk of a code-only reset is mitigated by
telling the user, once, that their password was reset. Only a login that opens a
full session shows and clears it; a scoped step (second factor due, password
change or MFA enrollment required) and a failed login leave it for later.
"""

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from gateway import auth
from gateway.db import get_engine
from gateway.main import create_app
from tests.helpers import FrozenClock, run_sql
from tests.test_admin import set_user
from tests.test_login import KEYS, OTHER, login
from tests.test_mfa import LOGIN_MFA, make_user, post, totp
from tests.test_mfa import user_row as mfa_user_row
from tests.test_password_change import change
from tests.test_password_reset import (
    NEW,
    browser,
    mfa_reader,
    reader,
    reset,
)

NOTICE = "password_reset_at"
THIRD = "a third passphrase for alice"


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


def notice_column(db_engine, username="alice"):
    return mfa_user_row(db_engine, username)["password_reset_notice_at"]


def test_a_reset_then_the_next_login_shows_the_time_and_clears_it(
    client, db_engine, clock
):
    reader(client, db_engine, clock)
    reset_at = clock()
    assert reset(browser(client)).status_code == 200
    assert notice_column(db_engine) == reset_at

    first = login(browser(client), password=NEW)

    assert first.status_code == 200
    assert first.json()[NOTICE] == reset_at.isoformat().replace("+00:00", "Z")
    assert set(first.json()) == {"id", "username", "role", NOTICE}
    assert notice_column(db_engine) is None
    second = login(browser(client), password=NEW)
    assert second.status_code == 200
    assert second.json()[NOTICE] is None


def test_a_login_with_no_reset_returns_a_null_notice(client, db_engine, clock):
    reader(client, db_engine, clock)

    response = login(browser(client))

    assert response.status_code == 200
    assert response.json()[NOTICE] is None


def test_a_failed_login_leaves_the_notice_set(client, db_engine, clock):
    reader(client, db_engine, clock)
    assert reset(browser(client)).status_code == 200
    before = notice_column(db_engine)

    assert login(browser(client), password=OTHER).status_code == 401

    assert before is not None
    assert notice_column(db_engine) == before
    assert login(browser(client), password=NEW).json()[NOTICE] is not None


def test_the_notice_waits_for_the_second_factor(client, db_engine, clock):
    secret, _ = mfa_reader(client, db_engine, clock)
    reset_at = clock()
    assert reset(browser(client), mfa_code=totp(secret, clock)).status_code == 200
    session = browser(client)

    first = login(session, password=NEW)

    assert first.json() == {"status": "mfa_required"}
    assert notice_column(db_engine) == reset_at
    # A wrong code opens nothing and leaves it too.
    assert post(session, LOGIN_MFA, {"code": "000000"}).status_code == 401
    assert notice_column(db_engine) == reset_at

    # The reset spent this TOTP step; the next one is a fresh code.
    done = post(session, LOGIN_MFA, {"code": totp(secret, clock, 1)})

    assert done.status_code == 200
    assert done.json()[NOTICE] == reset_at.isoformat().replace("+00:00", "Z")
    assert notice_column(db_engine) is None
    run_sql(db_engine, "UPDATE users SET mfa_last_step = NULL")
    again = browser(client)
    assert login(again, password=NEW).json() == {"status": "mfa_required"}
    full = post(again, LOGIN_MFA, {"code": totp(secret, clock, 1)})
    assert full.status_code == 200
    assert full.json()[NOTICE] is None


@pytest.mark.parametrize(
    ("columns", "expected"),
    [
        ({"must_change_password": True}, "password_change_required"),
        (
            {"pending_role": "editor", "mfa_enroll_until": "window"},
            "mfa_enrollment_required",
        ),
    ],
)
def test_a_scoped_login_leaves_the_notice_for_the_full_session(
    client, db_engine, clock, columns, expected
):
    reader(client, db_engine, clock)
    set_user(
        db_engine,
        "alice",
        password_reset_notice_at=clock(),
        **{
            key: (clock() + timedelta(hours=24) if value == "window" else value)
            for key, value in columns.items()
        },
    )

    response = login(browser(client))

    assert response.json() == {"status": expected}
    assert notice_column(db_engine) == clock()


def test_the_notice_survives_the_forced_password_change_and_shows_on_the_full_login(
    client, db_engine, clock
):
    """Path: password change required (a scoped session), then a full login."""
    reader(client, db_engine, clock)
    reset_at = clock()
    assert reset(browser(client)).status_code == 200
    set_user(db_engine, "alice", must_change_password=True)
    scoped = browser(client)

    assert login(scoped, password=NEW).json() == {"status": "password_change_required"}
    assert notice_column(db_engine) == reset_at
    assert change(scoped, current=NEW, new=THIRD).status_code == 200
    assert notice_column(db_engine) == reset_at

    full = login(browser(client), password=THIRD)

    assert full.status_code == 200
    assert full.json()[NOTICE] == reset_at.isoformat().replace("+00:00", "Z")
    assert notice_column(db_engine) is None
    assert login(browser(client), password=THIRD).json()[NOTICE] is None


def test_a_privileged_user_pending_enrollment_keeps_the_notice(
    client, db_engine, clock
):
    make_user(client, db_engine, clock)
    set_user(db_engine, "alice", password_reset_notice_at=clock())

    response = login(client)

    assert response.json() == {"status": "mfa_enrollment_required"}
    assert notice_column(db_engine) == clock()


def test_me_keeps_its_three_fields(client, db_engine, clock):
    session = reader(client, db_engine, clock)
    run_sql(
        db_engine,
        "UPDATE users SET password_reset_notice_at = :t",
        t=clock(),
    )

    response = session.get("/api/auth/me")

    assert response.status_code == 200
    assert set(response.json()) == {"id", "username", "role"}
    assert notice_column(db_engine) == clock()


def test_only_the_login_responses_carry_the_field(client):
    schemas = client.app.openapi()["components"]["schemas"]
    assert NOTICE in schemas["LoginOut"]["properties"]
    assert NOTICE not in schemas["UserOut"]["properties"]
