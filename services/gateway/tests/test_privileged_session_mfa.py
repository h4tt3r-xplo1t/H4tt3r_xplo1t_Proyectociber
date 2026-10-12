"""A full session of a privileged role needs MFA, also one that already exists.

The password login enforces it (see test_mfa); these tests cover the other two
doors: `current_user` (every authenticated route) and the refresh.
"""

import pytest
from sqlalchemy import text

from gateway.auth import PRIVILEGED_ROLES
from tests.test_login import NOT_AUTHENTICATED
from tests.test_refresh import family_row, refresh, start

ME = "/api/auth/me"


def set_role(db_engine, role, *, mfa):
    """Change the role of the only user, as an admin or a past deploy would."""
    with db_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE users SET role = :role, "
                "mfa_enabled_at = CASE WHEN :mfa THEN now() END"
            ),
            {"role": role, "mfa": mfa},
        )


@pytest.mark.parametrize("role", sorted(PRIVILEGED_ROLES))
def test_a_session_of_a_privileged_user_without_mfa_is_401_on_me(
    client, db_engine, role
):
    start(client)
    assert client.get(ME).status_code == 200  # a lector, so far
    set_role(db_engine, role, mfa=False)

    response = client.get(ME)

    assert response.status_code == 401
    assert response.json() == NOT_AUTHENTICATED
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("role", sorted(PRIVILEGED_ROLES))
def test_refresh_of_a_privileged_user_without_mfa_is_401_and_revokes_the_family(
    client, db_engine, role
):
    session = start(client)
    set_role(db_engine, role, mfa=False)

    response = refresh(client, session.refresh, session.csrf)

    assert response.status_code == 401
    assert response.json() == NOT_AUTHENTICATED
    assert family_row(db_engine).revoked_at is not None
    with db_engine.connect() as conn:
        used = conn.execute(text("SELECT count(*) FROM refresh_tokens")).scalar()
        assert used == 1  # nothing rotated
    # The same refresh token is now refused for a revoked family too.
    assert refresh(client, session.refresh, session.csrf).status_code == 401


def test_a_promoted_lector_loses_the_whole_session(client, db_engine):
    session = start(client)
    set_role(db_engine, "editor", mfa=False)

    assert client.get(ME).status_code == 401
    assert refresh(client, session.refresh, session.csrf).status_code == 401
    assert family_row(db_engine).revoked_at is not None


def test_a_privileged_session_seeded_without_mfa_is_401_on_the_next_request(
    client, db_engine
):
    # A session opened before MFA was enforced: the family and the user exist,
    # and nothing in them says "mfa". Seeded directly in the database.
    start(client)
    with db_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE users SET role = 'administrador', mfa_enabled_at = NULL, "
                "mfa_enroll_until = NULL"
            )
        )

    assert client.get(ME).status_code == 401


@pytest.mark.parametrize("role", sorted(PRIVILEGED_ROLES))
def test_a_privileged_user_with_mfa_keeps_the_session_and_the_refresh(
    client, db_engine, role
):
    session = start(client)
    set_role(db_engine, role, mfa=True)

    assert client.get(ME).status_code == 200
    response = refresh(client, session.refresh, session.csrf)

    assert response.status_code == 200
    assert response.json()["role"] == role
    assert family_row(db_engine).revoked_at is None


def test_a_lector_without_mfa_is_unaffected(client, db_engine):
    session = start(client)

    assert client.get(ME).status_code == 200
    assert refresh(client, session.refresh, session.csrf).status_code == 200
    assert family_row(db_engine).revoked_at is None
