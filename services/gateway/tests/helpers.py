"""Test helpers shared by several test modules."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from gateway.tokens import decode_access_token


class FrozenClock:
    """A 'now' that only moves when a test says so, set at the start of a step."""

    def __init__(self):
        real = datetime.now(UTC).replace(microsecond=0)
        self.now = real - timedelta(seconds=int(real.timestamp()) % 30)

    def __call__(self):
        return self.now


class Interfere:
    """Runs `change` right after a slow step, as a concurrent request would.

    Wrapped around the last slow call before the lock is taken, so the change
    lands exactly between "prepare" and "consume".
    """

    def __init__(self, real, change):
        self.real = real
        self.change = change

    def __call__(self, *args, **kwargs):
        result = self.real(*args, **kwargs)
        self.change()
        return result


def run_sql(db_engine, sql, **params):
    with db_engine.begin() as conn:
        conn.execute(text(sql), params)


class DbError(Exception):
    """Stands in for the driver's error: only the SQLSTATE is ever read."""

    def __init__(self, sqlstate):
        self.sqlstate = sqlstate


def current_step(clock):
    """The TOTP step the frozen clock is in."""
    return int(clock().timestamp()) // 30


def end_session_like_a_logout(client, db_engine, kind, keys):
    """What a concurrent logout leaves behind, whole or in part.

    The generation is not touched: a logout denies the jti and revokes the
    family, nothing else.
    """
    claims = decode_access_token(client.cookies.get("__Host-access"), keys)
    if kind in ("jti", "logout"):
        run_sql(
            db_engine,
            "INSERT INTO revoked_jtis (jti, expires_at) "
            "VALUES (:j, now() + interval '1 hour')",
            j=claims["jti"],
        )
    if kind in ("family", "logout"):
        run_sql(db_engine, "UPDATE refresh_families SET revoked_at = now()")


def fail_lock(monkeypatch, table, sqlstate):
    real_scalar = Session.scalar

    def scalar(self, statement, *args, **kwargs):
        sql = str(statement)
        if f"FROM {table}" in sql and "FOR UPDATE" in sql:
            raise OperationalError("SELECT", {}, DbError(sqlstate))
        return real_scalar(self, statement, *args, **kwargs)

    monkeypatch.setattr(Session, "scalar", scalar)


def fail_requester_lock(monkeypatch, sqlstate, requester_id):
    """Fail only the `users ... FOR UPDATE` that binds the requester's id.

    Bound by id, not by position, so it cannot pass by failing another lock if
    the lock order changes; `seen` proves the requester lock was really taken.
    """
    real_scalar = Session.scalar
    seen = []

    def scalar(self, statement, *args, **kwargs):
        sql = str(statement)
        if "FROM users" in sql and "FOR UPDATE" in sql:
            bound = {str(v) for v in statement.compile().params.values()}
            if str(requester_id) in bound:
                seen.append(sql)
                raise OperationalError("SELECT", {}, DbError(sqlstate))
        return real_scalar(self, statement, *args, **kwargs)

    monkeypatch.setattr(Session, "scalar", scalar)
    return seen
