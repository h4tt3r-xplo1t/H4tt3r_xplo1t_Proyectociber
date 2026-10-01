import pytest
from alembic import command
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

from tests.conftest import alembic_config


def test_upgrade_creates_users_and_refresh_families(migrated_db):
    engine = create_engine(migrated_db)
    tables = set(inspect(engine).get_table_names())
    engine.dispose()

    assert {"users", "refresh_families"} <= tables


def test_role_check_constraint_rejects_unknown_role(db_engine):
    insert = text(
        "INSERT INTO users (id, username, password_hash, role) "
        "VALUES (gen_random_uuid(), :u, 'x', :r)"
    )
    with db_engine.begin() as conn:
        conn.execute(insert, {"u": "ok-user", "r": "administrador"})

    with pytest.raises(IntegrityError), db_engine.begin() as conn:
        conn.execute(insert, {"u": "bad-user", "r": "superuser"})


def test_role_defaults_to_lector(db_engine):
    with db_engine.begin() as conn:
        role = conn.execute(
            text(
                "INSERT INTO users (id, username, password_hash) "
                "VALUES (gen_random_uuid(), 'someone', 'x') RETURNING role"
            )
        ).scalar_one()

    assert role == "lector"


def test_downgrade_then_upgrade_works(migrated_db):
    cfg = alembic_config()
    command.downgrade(cfg, "base")
    engine = create_engine(migrated_db)
    assert "users" not in inspect(engine).get_table_names()
    command.upgrade(cfg, "head")
    assert "users" in inspect(engine).get_table_names()
    engine.dispose()
