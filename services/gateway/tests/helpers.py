"""Test helpers shared by several test modules."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import text


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
