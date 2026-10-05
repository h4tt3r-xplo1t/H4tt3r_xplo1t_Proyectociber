import os
import re
import subprocess
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from gateway import maintenance
from gateway.maintenance import ATTEMPT_TTL, purge
from tests.test_refresh import refresh, start

SRC = Path(__file__).resolve().parent.parent / "src"
NOW = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)
TABLES = ("login_attempts", "revoked_jtis", "refresh_families", "refresh_tokens")


def run_purge(db_engine, now=NOW):
    with Session(db_engine) as session:
        return purge(session, now)


def add_user(conn, username, role="lector"):
    return conn.execute(
        text(
            "INSERT INTO users (username, password_hash, role) "
            "VALUES (:u, 'not-a-real-hash', :r) RETURNING id"
        ),
        {"u": username, "r": role},
    ).scalar_one()


def add_family(conn, user_id, created_at, revoked_at=None, tokens=1):
    family_id = uuid.uuid4()
    conn.execute(
        text(
            "INSERT INTO refresh_families (id, user_id, created_at, last_used_at, "
            "revoked_at) VALUES (:id, :u, :c, :c, :r)"
        ),
        {"id": family_id, "u": user_id, "c": created_at, "r": revoked_at},
    )
    for _ in range(tokens):
        conn.execute(
            text(
                "INSERT INTO refresh_tokens (family_id, token_hash, created_at) "
                "VALUES (:f, :h, :c)"
            ),
            {"f": family_id, "h": uuid.uuid4().hex, "c": created_at},
        )
    return family_id


def add_attempt(conn, key, updated_at, locked_until=None):
    conn.execute(
        text(
            "INSERT INTO login_attempts (attempt_key, failures, locked_until, "
            "updated_at) VALUES (:k, 4, :l, :u)"
        ),
        {"k": key, "l": locked_until, "u": updated_at},
    )


def add_jti(conn, jti, expires_at):
    conn.execute(
        text("INSERT INTO revoked_jtis (jti, expires_at) VALUES (:j, :e)"),
        {"j": jti, "e": expires_at},
    )


def column(db_engine, query):
    with db_engine.connect() as conn:
        return {row[0] for row in conn.execute(text(query))}


# --- login_attempts -------------------------------------------------------------


def test_purge_attempts_keeps_recent_and_locked_rows(db_engine):
    old = NOW - ATTEMPT_TTL - timedelta(minutes=1)
    with db_engine.begin() as conn:
        add_attempt(conn, "old-unlocked", old)
        add_attempt(conn, "old-lock-expired", old, NOW - timedelta(seconds=1))
        add_attempt(conn, "old-still-locked", old, NOW + timedelta(minutes=5))
        add_attempt(conn, "recent", NOW - ATTEMPT_TTL + timedelta(minutes=1))

    counts = run_purge(db_engine)

    assert counts["login_attempts"] == 2
    assert column(db_engine, "SELECT attempt_key FROM login_attempts") == {
        "old-still-locked",
        "recent",
    }


# --- revoked_jtis ---------------------------------------------------------------


def test_purge_jtis_deletes_only_expired_ones(db_engine):
    with db_engine.begin() as conn:
        add_jti(conn, "expired", NOW - timedelta(seconds=1))
        add_jti(conn, "live", NOW + timedelta(seconds=1))

    counts = run_purge(db_engine)

    assert counts["revoked_jtis"] == 1
    assert column(db_engine, "SELECT jti FROM revoked_jtis") == {"live"}


# --- refresh families and tokens --------------------------------------------------


def test_purge_families_by_revocation_and_by_role_absolute_limit(db_engine):
    day = timedelta(days=1)
    hour = timedelta(hours=1)
    with db_engine.begin() as conn:
        reader = add_user(conn, "reader")
        editor = add_user(conn, "editor-user", "editor")
        keep = {
            "reader-6d": add_family(conn, reader, NOW - 6 * day),
            "editor-7h": add_family(conn, editor, NOW - 7 * hour),
            "active-now": add_family(conn, reader, NOW),
        }
        gone = {
            "reader-8d": add_family(conn, reader, NOW - 8 * day, tokens=2),
            # An editor's family of 9 h is over the strict limit, while the same
            # age for a reader is fine: the owner's current role decides.
            "editor-9h": add_family(conn, editor, NOW - 9 * hour),
            "revoked-recent": add_family(conn, reader, NOW, revoked_at=NOW),
        }
        # Same 9 h age, but a reader: kept.
        keep["reader-9h"] = add_family(conn, reader, NOW - 9 * hour)

    counts = run_purge(db_engine)

    assert counts["refresh_families"] == len(gone)
    assert counts["refresh_tokens"] == 4  # 2 + 1 + 1
    left = column(db_engine, "SELECT id FROM refresh_families")
    assert left == set(keep.values())
    tokens = column(db_engine, "SELECT family_id FROM refresh_tokens")
    assert tokens == set(keep.values())


def test_purge_uses_the_current_role_of_the_owner(db_engine):
    with db_engine.begin() as conn:
        user = add_user(conn, "promoted")
        family = add_family(conn, user, NOW - timedelta(hours=9))
    assert run_purge(db_engine)["refresh_families"] == 0

    with db_engine.begin() as conn:
        conn.execute(text("UPDATE users SET role = 'auditor'"))
    assert run_purge(db_engine)["refresh_families"] == 1
    assert family not in column(db_engine, "SELECT id FROM refresh_families")


def test_purge_is_idempotent(db_engine):
    old = NOW - ATTEMPT_TTL - timedelta(hours=1)
    with db_engine.begin() as conn:
        user = add_user(conn, "someone")
        add_attempt(conn, "old", old)
        add_jti(conn, "expired", NOW - timedelta(hours=1))
        add_family(conn, user, NOW - timedelta(days=30))

    first = run_purge(db_engine)
    second = run_purge(db_engine)

    assert first == {
        "login_attempts": 1,
        "revoked_jtis": 1,
        "refresh_families": 1,
        "refresh_tokens": 1,
    }
    assert second == dict.fromkeys(TABLES, 0)


# --- a purged session stays dead ---------------------------------------------------


def test_a_purged_expired_family_ends_its_access_and_refresh_tokens(client, db_engine):
    session = start(client)
    with db_engine.begin() as conn:
        conn.execute(
            text("UPDATE refresh_families SET created_at = now() - interval '8 days'")
        )
    # Before the purge the session is still accepted.
    assert client.get("/api/auth/me").status_code == 200

    counts = run_purge(db_engine, datetime.now(UTC))

    assert counts["refresh_families"] == 1
    assert client.get("/api/auth/me").status_code == 401
    assert refresh(client, session.refresh, session.csrf).status_code == 401


def test_a_purged_revoked_family_ends_its_access_and_refresh_tokens(client, db_engine):
    session = start(client)
    with db_engine.begin() as conn:
        conn.execute(text("UPDATE refresh_families SET revoked_at = now()"))

    run_purge(db_engine, datetime.now(UTC))

    assert client.get("/api/auth/me").status_code == 401
    assert refresh(client, session.refresh, session.csrf).status_code == 401


# --- command line -----------------------------------------------------------------


def run_cli(*args):
    return subprocess.run(  # noqa: S603 (fixed interpreter and module, test args)
        [sys.executable, "-m", "gateway.maintenance", *args],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(SRC)},
        timeout=60,
        check=False,
    )


def test_cli_purge_prints_counts_only_and_exits_zero(db_engine):
    visible_name = "visible-name-must-not-print"
    with db_engine.begin() as conn:
        user = add_user(conn, visible_name)
        add_attempt(conn, "attempt-key-must-not-print", NOW - timedelta(days=30))
        add_jti(conn, "jti-must-not-print", NOW - timedelta(days=30))
        add_family(conn, user, NOW - timedelta(days=30))

    result = run_cli("purge")

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "login_attempts=1",
        "revoked_jtis=1",
        "refresh_families=1",
        "refresh_tokens=1",
    ]
    for line in result.stdout.splitlines():
        assert re.fullmatch(r"[a-z_]+=\d+", line)
    everything = result.stdout + result.stderr
    for forbidden in (visible_name, "attempt-key", "jti-must", "not-a-real-hash"):
        assert forbidden not in everything


@pytest.mark.parametrize("args", [(), ("other",), ("purge", "extra")])
def test_cli_rejects_anything_but_purge_with_exit_2(args):
    result = run_cli(*args)

    assert result.returncode == 2
    assert result.stdout == ""
    assert "usage" in result.stderr.lower()


def test_usage_text_is_a_fixed_string():
    assert maintenance.USAGE == "usage: python -m gateway.maintenance purge"
