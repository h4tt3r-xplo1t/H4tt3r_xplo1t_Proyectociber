"""TOTP MFA columns on users and recovery_codes

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-05
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The TOTP secret is stored only as OpenBao transit ciphertext. A pending
    # secret waits here until the user proves a valid code; only then it moves
    # to mfa_secret_ciphertext. mfa_last_step is the last accepted 30 s step
    # (replay protection); mfa_enroll_until is the end of the enrollment window.
    op.add_column(
        "users",
        sa.Column(
            "mfa_secret_ciphertext",
            sa.Text(),
            nullable=True,
            comment="OpenBao transit ciphertext of the active TOTP secret",
        ),
    )
    op.add_column(
        "users",
        sa.Column(
            "mfa_pending_ciphertext",
            sa.Text(),
            nullable=True,
            comment="transit ciphertext of a TOTP secret not yet confirmed",
        ),
    )
    op.add_column(
        "users", sa.Column("mfa_enabled_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("users", sa.Column("mfa_last_step", sa.BigInteger(), nullable=True))
    op.add_column(
        "users",
        sa.Column("mfa_enroll_until", sa.DateTime(timezone=True), nullable=True),
    )
    # One row per recovery code; only the Argon2id hash is stored. `used_at`
    # marks a spent code (single use).
    op.create_table(
        "recovery_codes",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "code_hash",
            sa.Text(),
            nullable=False,
            comment="Argon2id hash of the recovery code, not the code",
        ),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_recovery_codes_user_id"), "recovery_codes", ["user_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_recovery_codes_user_id"), table_name="recovery_codes")
    op.drop_table("recovery_codes")
    op.drop_column("users", "mfa_enroll_until")
    op.drop_column("users", "mfa_last_step")
    op.drop_column("users", "mfa_enabled_at")
    op.drop_column("users", "mfa_pending_ciphertext")
    op.drop_column("users", "mfa_secret_ciphertext")
