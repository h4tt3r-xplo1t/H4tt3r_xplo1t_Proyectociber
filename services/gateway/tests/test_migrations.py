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


def test_upgrade_creates_refresh_tokens(migrated_db):
    engine = create_engine(migrated_db)
    try:
        inspector = inspect(engine)
        columns = {c["name"]: c for c in inspector.get_columns("refresh_tokens")}
        foreign_keys = inspector.get_foreign_keys("refresh_tokens")
        unique = inspector.get_unique_constraints("refresh_tokens")
        indexes = inspector.get_indexes("refresh_tokens")
    finally:
        engine.dispose()

    assert set(columns) == {"id", "family_id", "token_hash", "created_at", "used_at"}
    assert columns["used_at"]["nullable"] is True
    assert columns["token_hash"]["nullable"] is False
    (fk,) = foreign_keys
    assert fk["referred_table"] == "refresh_families"
    assert fk["options"]["ondelete"] == "CASCADE"
    assert any(u["column_names"] == ["token_hash"] for u in unique) or any(
        i["column_names"] == ["token_hash"] and i["unique"] for i in indexes
    )
    assert any(i["column_names"] == ["family_id"] for i in indexes)


def test_refresh_token_hash_is_unique_and_cascades_with_the_family(db_engine):
    with db_engine.begin() as conn:
        user_id = conn.execute(
            text(
                "INSERT INTO users (id, username, password_hash) "
                "VALUES (gen_random_uuid(), 'carol', 'x') RETURNING id"
            )
        ).scalar_one()
        family_id = conn.execute(
            text("INSERT INTO refresh_families (user_id) VALUES (:u) RETURNING id"),
            {"u": user_id},
        ).scalar_one()
        conn.execute(
            text(
                "INSERT INTO refresh_tokens (family_id, token_hash) "
                "VALUES (:f, 'hash-1')"
            ),
            {"f": family_id},
        )

    with pytest.raises(IntegrityError), db_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO refresh_tokens (family_id, token_hash) "
                "VALUES (:f, 'hash-1')"
            ),
            {"f": family_id},
        )

    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM refresh_families"))
        remaining = conn.execute(text("SELECT count(*) FROM refresh_tokens")).scalar()
    assert remaining == 0


def test_upgrade_creates_revoked_jtis(migrated_db):
    engine = create_engine(migrated_db)
    try:
        inspector = inspect(engine)
        columns = {c["name"]: c for c in inspector.get_columns("revoked_jtis")}
        primary_key = inspector.get_pk_constraint("revoked_jtis")
        indexes = inspector.get_indexes("revoked_jtis")
    finally:
        engine.dispose()

    assert set(columns) == {"jti", "expires_at"}
    assert primary_key["constrained_columns"] == ["jti"]
    assert columns["expires_at"]["nullable"] is False
    assert any(i["column_names"] == ["expires_at"] for i in indexes)


def test_session_tables_downgrade_to_0002_drops_only_them(migrated_db):
    cfg = alembic_config()
    engine = create_engine(migrated_db)
    try:
        command.downgrade(cfg, "0002")
        tables = set(inspect(engine).get_table_names())
        assert "refresh_tokens" not in tables
        assert "revoked_jtis" not in tables
        assert {"refresh_families", "login_attempts"} <= tables
    finally:
        command.upgrade(cfg, "head")
        tables = set(inspect(engine).get_table_names())
        assert {"refresh_tokens", "revoked_jtis"} <= tables
        engine.dispose()
