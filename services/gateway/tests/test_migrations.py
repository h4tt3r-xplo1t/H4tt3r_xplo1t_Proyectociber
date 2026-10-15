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


MFA_COLUMNS = {
    "mfa_secret_ciphertext",
    "mfa_pending_ciphertext",
    "mfa_enabled_at",
    "mfa_last_step",
    "mfa_enroll_until",
}


def test_upgrade_adds_nullable_mfa_columns_to_users(migrated_db):
    engine = create_engine(migrated_db)
    try:
        columns = {c["name"]: c for c in inspect(engine).get_columns("users")}
    finally:
        engine.dispose()

    assert MFA_COLUMNS <= set(columns)
    for name in MFA_COLUMNS:
        assert columns[name]["nullable"] is True
    assert str(columns["mfa_last_step"]["type"]) == "BIGINT"


def test_new_user_has_no_mfa(db_engine):
    with db_engine.begin() as conn:
        row = conn.execute(
            text(
                "INSERT INTO users (id, username, password_hash) "
                "VALUES (gen_random_uuid(), 'plain', 'x') "
                "RETURNING mfa_secret_ciphertext, mfa_enabled_at, mfa_last_step"
            )
        ).first()

    assert tuple(row) == (None, None, None)


def test_upgrade_creates_recovery_codes(migrated_db):
    engine = create_engine(migrated_db)
    try:
        inspector = inspect(engine)
        columns = {c["name"]: c for c in inspector.get_columns("recovery_codes")}
        indexes = inspector.get_indexes("recovery_codes")
    finally:
        engine.dispose()

    assert set(columns) == {"id", "user_id", "code_hash", "used_at", "created_at"}
    assert columns["code_hash"]["nullable"] is False
    assert columns["used_at"]["nullable"] is True
    assert any(i["column_names"] == ["user_id"] for i in indexes)


def test_recovery_codes_cascade_with_the_user(db_engine):
    with db_engine.begin() as conn:
        user_id = conn.execute(
            text(
                "INSERT INTO users (id, username, password_hash) "
                "VALUES (gen_random_uuid(), 'owner', 'x') RETURNING id"
            )
        ).scalar_one()
        conn.execute(
            text("INSERT INTO recovery_codes (user_id, code_hash) VALUES (:u, 'h')"),
            {"u": user_id},
        )
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users"))
        remaining = conn.execute(text("SELECT count(*) FROM recovery_codes")).scalar()

    assert remaining == 0


def test_mfa_downgrade_to_0003_removes_only_the_mfa_schema(migrated_db):
    cfg = alembic_config()
    engine = create_engine(migrated_db)
    try:
        command.downgrade(cfg, "0003")
        inspector = inspect(engine)
        assert "recovery_codes" not in inspector.get_table_names()
        assert not MFA_COLUMNS & {c["name"] for c in inspector.get_columns("users")}
        assert "revoked_jtis" in inspector.get_table_names()
    finally:
        command.upgrade(cfg, "head")
        assert "recovery_codes" in inspect(engine).get_table_names()
        engine.dispose()


def test_upgrade_adds_password_and_pending_role_columns(migrated_db):
    engine = create_engine(migrated_db)
    try:
        columns = {c["name"]: c for c in inspect(engine).get_columns("users")}
    finally:
        engine.dispose()

    assert columns["must_change_password"]["nullable"] is False
    assert columns["pending_role"]["nullable"] is True


def test_new_user_does_not_have_to_change_password_and_has_no_pending_role(db_engine):
    with db_engine.begin() as conn:
        row = conn.execute(
            text(
                "INSERT INTO users (id, username, password_hash) "
                "VALUES (gen_random_uuid(), 'plain', 'x') "
                "RETURNING must_change_password, pending_role"
            )
        ).first()

    assert tuple(row) == (False, None)


def test_pending_role_constraint_accepts_exactly_the_model_roles_or_null(db_engine):
    insert = text(
        "INSERT INTO users (id, username, password_hash, pending_role) "
        "VALUES (gen_random_uuid(), :u, 'x', :r)"
    )
    for index, role in enumerate((*ROLES, None)):
        with db_engine.begin() as conn:
            conn.execute(insert, {"u": f"pending-{index}", "r": role})

    with pytest.raises(IntegrityError), db_engine.begin() as conn:
        conn.execute(insert, {"u": "intruder", "r": "not-a-role"})


def test_admin_columns_downgrade_to_0004_removes_only_them(migrated_db):
    cfg = alembic_config()
    engine = create_engine(migrated_db)
    try:
        command.downgrade(cfg, "0004")
        names = {c["name"] for c in inspect(engine).get_columns("users")}
        assert not {"must_change_password", "pending_role"} & names
        assert MFA_COLUMNS <= names
    finally:
        command.upgrade(cfg, "head")
        names = {c["name"] for c in inspect(engine).get_columns("users")}
        assert {"must_change_password", "pending_role"} <= names
        engine.dispose()


def test_new_user_starts_at_token_generation_zero(db_engine):
    with db_engine.begin() as conn:
        generation = conn.execute(
            text(
                "INSERT INTO users (id, username, password_hash) "
                "VALUES (gen_random_uuid(), 'plain', 'x') RETURNING token_generation"
            )
        ).scalar_one()
        column = conn.execute(
            text(
                "SELECT is_nullable FROM information_schema.columns "
                "WHERE table_name = 'users' AND column_name = 'token_generation'"
            )
        ).scalar_one()

    assert generation == 0
    assert column == "NO"


def test_token_generation_downgrade_to_0005_removes_only_it(migrated_db):
    cfg = alembic_config()
    engine = create_engine(migrated_db)
    try:
        command.downgrade(cfg, "0005")
        names = {c["name"] for c in inspect(engine).get_columns("users")}
        assert "token_generation" not in names
        assert {"must_change_password", "pending_role"} <= names
    finally:
        command.upgrade(cfg, "head")
        names = {c["name"] for c in inspect(engine).get_columns("users")}
        assert "token_generation" in names
        engine.dispose()


def test_upgrade_creates_mfa_enrollment_attempts(migrated_db):
    engine = create_engine(migrated_db)
    try:
        insp = inspect(engine)
        columns = {c["name"]: c for c in insp.get_columns("mfa_enrollment_attempts")}
        indexes = insp.get_indexes("mfa_enrollment_attempts")
        foreign_keys = insp.get_foreign_keys("mfa_enrollment_attempts")
    finally:
        engine.dispose()

    assert set(columns) == {"id", "user_id", "created_at"}
    assert columns["user_id"]["nullable"] is False
    assert columns["created_at"]["nullable"] is False
    assert any(i["column_names"] == ["user_id", "created_at"] for i in indexes)
    assert foreign_keys[0]["referred_table"] == "users"
    assert foreign_keys[0]["options"]["ondelete"] == "CASCADE"


def test_deleting_a_user_deletes_its_enrollment_attempts(db_engine):
    with db_engine.begin() as conn:
        user_id = conn.execute(
            text(
                "INSERT INTO users (username, password_hash) "
                "VALUES ('someone', 'x') RETURNING id"
            )
        ).scalar_one()
        conn.execute(
            text(
                "INSERT INTO mfa_enrollment_attempts (user_id, created_at) "
                "VALUES (:u, now())"
            ),
            {"u": user_id},
        )
        conn.execute(text("DELETE FROM users WHERE id = :u"), {"u": user_id})
        remaining = conn.execute(
            text("SELECT count(*) FROM mfa_enrollment_attempts")
        ).scalar_one()

    assert remaining == 0


def test_enrollment_attempts_downgrade_to_0006_removes_only_it(migrated_db):
    cfg = alembic_config()
    engine = create_engine(migrated_db)
    try:
        command.downgrade(cfg, "0006")
        tables = set(inspect(engine).get_table_names())
        assert "mfa_enrollment_attempts" not in tables
        assert "users" in tables
        assert "token_generation" in {
            c["name"] for c in inspect(engine).get_columns("users")
        }
    finally:
        command.upgrade(cfg, "head")
        assert "mfa_enrollment_attempts" in inspect(engine).get_table_names()
        engine.dispose()


def test_upgrade_creates_password_reset_codes(migrated_db):
    engine = create_engine(migrated_db)
    try:
        insp = inspect(engine)
        columns = {c["name"]: c for c in insp.get_columns("password_reset_codes")}
        indexes = insp.get_indexes("password_reset_codes")
        uniques = insp.get_unique_constraints("password_reset_codes")
        foreign_keys = {
            fk["constrained_columns"][0]: fk
            for fk in insp.get_foreign_keys("password_reset_codes")
        }
    finally:
        engine.dispose()

    assert set(columns) == {
        "id",
        "user_id",
        "code_hash",
        "issued_by",
        "created_at",
        "expires_at",
    }
    assert columns["issued_by"]["nullable"] is True
    for name in ("user_id", "code_hash", "created_at", "expires_at"):
        assert columns[name]["nullable"] is False
    assert any(u["column_names"] == ["user_id"] for u in uniques)
    assert any(i["column_names"] == ["expires_at"] for i in indexes)
    assert foreign_keys["user_id"]["options"]["ondelete"] == "CASCADE"
    assert foreign_keys["issued_by"]["options"]["ondelete"] == "SET NULL"


def test_a_reset_code_cannot_expire_before_it_is_created(db_engine):
    with db_engine.begin() as conn:
        user_id = conn.execute(
            text(
                "INSERT INTO users (username, password_hash) "
                "VALUES ('someone', 'x') RETURNING id"
            )
        ).scalar_one()
    with pytest.raises(IntegrityError), db_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO password_reset_codes "
                "(user_id, code_hash, created_at, expires_at) "
                "VALUES (:u, 'h', now(), now())"
            ),
            {"u": user_id},
        )


def test_one_live_reset_code_per_user_and_deleting_users_cascades(db_engine):
    insert = text(
        "INSERT INTO password_reset_codes "
        "(user_id, code_hash, issued_by, created_at, expires_at) "
        "VALUES (:u, 'h', :i, now(), now() + interval '15 minutes')"
    )
    with db_engine.begin() as conn:
        user_id, admin_id = (
            conn.execute(
                text(
                    "INSERT INTO users (username, password_hash) "
                    "VALUES (:n, 'x') RETURNING id"
                ),
                {"n": name},
            ).scalar_one()
            for name in ("someone", "issuer")
        )
        conn.execute(insert, {"u": user_id, "i": admin_id})
    with pytest.raises(IntegrityError), db_engine.begin() as conn:
        conn.execute(insert, {"u": user_id, "i": admin_id})
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users WHERE id = :i"), {"i": admin_id})
        issued_by = conn.execute(
            text("SELECT issued_by FROM password_reset_codes")
        ).scalar_one()
        assert issued_by is None
        conn.execute(text("DELETE FROM users WHERE id = :u"), {"u": user_id})
        assert (
            conn.execute(text("SELECT count(*) FROM password_reset_codes")).scalar_one()
            == 0
        )


def test_reset_codes_downgrade_to_0007_removes_only_that_table(migrated_db):
    cfg = alembic_config()
    engine = create_engine(migrated_db)
    try:
        command.downgrade(cfg, "0007")
        tables = set(inspect(engine).get_table_names())
        assert "password_reset_codes" not in tables
        assert "mfa_enrollment_attempts" in tables
    finally:
        command.upgrade(cfg, "head")
        assert "password_reset_codes" in inspect(engine).get_table_names()
        engine.dispose()


def test_users_have_a_nullable_password_reset_notice_column(db_engine):
    columns = {c["name"]: c for c in inspect(db_engine).get_columns("users")}
    column = columns["password_reset_notice_at"]
    assert column["nullable"] is True
    assert column["type"].timezone is True
    with db_engine.begin() as conn:
        notice = conn.execute(
            text(
                "INSERT INTO users (username, password_hash) "
                "VALUES ('someone', 'x') RETURNING password_reset_notice_at"
            )
        ).scalar_one()
    assert notice is None


def test_notice_downgrade_to_0008_removes_only_that_column(migrated_db):
    cfg = alembic_config()
    engine = create_engine(migrated_db)
    try:
        command.downgrade(cfg, "0008")
        columns = {c["name"] for c in inspect(engine).get_columns("users")}
        assert "password_reset_notice_at" not in columns
        assert "mfa_enroll_until" in columns
        assert "password_reset_codes" in inspect(engine).get_table_names()
    finally:
        command.upgrade(cfg, "head")
        columns = {c["name"] for c in inspect(engine).get_columns("users")}
        assert "password_reset_notice_at" in columns
        engine.dispose()


def test_upgrade_creates_mfa_reset_requests(migrated_db):
    engine = create_engine(migrated_db)
    try:
        insp = inspect(engine)
        columns = {c["name"]: c for c in insp.get_columns("mfa_reset_requests")}
        indexes = insp.get_indexes("mfa_reset_requests")
        uniques = insp.get_unique_constraints("mfa_reset_requests")
        foreign_keys = {
            fk["constrained_columns"][0]: fk
            for fk in insp.get_foreign_keys("mfa_reset_requests")
        }
    finally:
        engine.dispose()

    assert set(columns) == {
        "id",
        "target_user_id",
        "requested_by",
        "created_at",
        "expires_at",
    }
    for column in columns.values():
        assert column["nullable"] is False
    assert any(u["column_names"] == ["target_user_id"] for u in uniques)
    assert any(i["column_names"] == ["expires_at"] for i in indexes)
    for name in ("target_user_id", "requested_by"):
        assert foreign_keys[name]["options"]["ondelete"] == "CASCADE"


def test_a_mfa_reset_request_cannot_expire_before_it_is_created(db_engine):
    with db_engine.begin() as conn:
        ids = [
            conn.execute(
                text(
                    "INSERT INTO users (username, password_hash) "
                    "VALUES (:n, 'x') RETURNING id"
                ),
                {"n": name},
            ).scalar_one()
            for name in ("target", "requester")
        ]
    with pytest.raises(IntegrityError), db_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO mfa_reset_requests "
                "(target_user_id, requested_by, created_at, expires_at) "
                "VALUES (:t, :r, now(), now())"
            ),
            {"t": ids[0], "r": ids[1]},
        )


def test_one_live_mfa_reset_request_per_target_and_deleting_users_cascades(db_engine):
    insert = text(
        "INSERT INTO mfa_reset_requests "
        "(target_user_id, requested_by, created_at, expires_at) "
        "VALUES (:t, :r, now(), now() + interval '1 hour')"
    )
    with db_engine.begin() as conn:
        target, requester = (
            conn.execute(
                text(
                    "INSERT INTO users (username, password_hash) "
                    "VALUES (:n, 'x') RETURNING id"
                ),
                {"n": name},
            ).scalar_one()
            for name in ("target", "requester")
        )
        conn.execute(insert, {"t": target, "r": requester})
    with pytest.raises(IntegrityError), db_engine.begin() as conn:
        conn.execute(insert, {"t": target, "r": requester})
    count = text("SELECT count(*) FROM mfa_reset_requests")
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users WHERE id = :i"), {"i": requester})
        assert conn.execute(count).scalar_one() == 0
        conn.execute(text("DELETE FROM users WHERE id = :i"), {"i": target})


def test_mfa_reset_requests_downgrade_to_0009_removes_only_that_table(migrated_db):
    cfg = alembic_config()
    engine = create_engine(migrated_db)
    try:
        command.downgrade(cfg, "0009")
        tables = set(inspect(engine).get_table_names())
        assert "mfa_reset_requests" not in tables
        assert "password_reset_codes" in tables
    finally:
        command.upgrade(cfg, "head")
        assert "mfa_reset_requests" in inspect(engine).get_table_names()
        engine.dispose()
