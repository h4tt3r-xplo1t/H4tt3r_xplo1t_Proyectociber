"""password_reset_codes

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-15
"""

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # One live code per user: issuing a new one replaces the row. A used code is
    # deleted, so there is no `used_at`. Only the Argon2id hash is stored.
    op.create_table(
        "password_reset_codes",
        sa.Column(
            "id",
            sa.UUID(),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("code_hash", sa.Text(), nullable=False),
        sa.Column("issued_by", sa.UUID(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "expires_at > created_at", name="password_reset_codes_expiry_check"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["issued_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", name="uq_password_reset_codes_user_id"),
    )
    op.create_index(
        "ix_password_reset_codes_expires_at", "password_reset_codes", ["expires_at"]
    )


def downgrade() -> None:
    op.drop_index(
        "ix_password_reset_codes_expires_at", table_name="password_reset_codes"
    )
    op.drop_table("password_reset_codes")
