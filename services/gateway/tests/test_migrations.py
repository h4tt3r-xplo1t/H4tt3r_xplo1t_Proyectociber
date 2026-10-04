import pytest
from alembic import command
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

from gateway.models import ROLES
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
    engine = create_engine(migrated_db)
    try:
        command.downgrade(cfg, "base")
        assert "users" not in inspect(engine).get_table_names()
    finally:
        command.upgrade(cfg, "head")
        assert "users" in inspect(engine).get_table_names()
        engine.dispose()


def test_role_constraint_accepts_exactly_the_model_roles(db_engine):
    insert = text(
        "INSERT INTO users (id, username, password_hash, role) "
        "VALUES (gen_random_uuid(), :u, 'x', :r)"
    )
    for index, role in enumerate(ROLES):
        with db_engine.begin() as conn:
            conn.execute(insert, {"u": f"user-{index}", "r": role})

    with pytest.raises(IntegrityError), db_engine.begin() as conn:
        conn.execute(insert, {"u": "intruder", "r": "not-a-role"})


def test_upgrade_creates_login_attempts(migrated_db):
    engine = create_engine(migrated_db)
    try:
        columns = {c["name"]: c for c in inspect(engine).get_columns("login_attempts")}
        primary_key = inspect(engine).get_pk_constraint("login_attempts")
    finally:
        engine.dispose()

    assert set(columns) == {"attempt_key", "failures", "locked_until", "updated_at"}
    assert primary_key["constrained_columns"] == ["attempt_key"]
    assert columns["locked_until"]["nullable"] is True
    assert columns["failures"]["nullable"] is False


def test_login_attempts_failures_default_to_zero(db_engine):
    with db_engine.begin() as conn:
        failures = conn.execute(
            text(
                "INSERT INTO login_attempts (attempt_key) VALUES ('ghost') "
                "RETURNING failures"
            )
        ).scalar_one()

    assert failures == 0


def test_login_attempts_downgrade_to_previous_revision_drops_only_that_table(
    migrated_db,
):
    cfg = alembic_config()
    engine = create_engine(migrated_db)
    try:
        command.downgrade(cfg, "0001")
        tables = set(inspect(engine).get_table_names())
        assert "login_attempts" not in tables
        assert "users" in tables
    finally:
        command.upgrade(cfg, "head")
        assert "login_attempts" in inspect(engine).get_table_names()
        engine.dispose()
