import pytest
from sqlalchemy import event, text
from sqlalchemy.exc import DBAPIError

from gateway.db import get_engine

FAKE_HASH = "$argon2id$v=19$m=19456,t=2,p=1$fake$fake"  # noqa: S105  (not a real hash)


@pytest.fixture
def app_engine(db_engine, database_url, monkeypatch):
    monkeypatch.setenv("GATEWAY_DATABASE_URL", database_url)
    get_engine.cache_clear()
    yield get_engine()
    get_engine().dispose()
    get_engine.cache_clear()


# A value longer than the column fails without PostgreSQL echoing the row, so
# any leak of the hash here comes from SQLAlchemy's own error message.
def test_database_errors_do_not_expose_sql_parameters(app_engine):
    insert = text(
        "INSERT INTO users (id, username, password_hash, role) "
        "VALUES (gen_random_uuid(), 'leaky-user', :h, :r)"
    )

    with pytest.raises(DBAPIError) as excinfo, app_engine.begin() as conn:
        conn.execute(insert, {"h": FAKE_HASH, "r": "r" * 17})

    assert "$argon2id$" not in str(excinfo.value)


def test_engine_sets_a_connect_timeout(app_engine):
    seen = {}

    @event.listens_for(app_engine, "do_connect")
    def capture(dialect, conn_rec, cargs, cparams):
        seen.update(cparams)

    with app_engine.connect():
        pass

    assert seen["connect_timeout"] == 5
