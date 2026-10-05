"""refresh_tokens and revoked_jtis

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-03
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # One row per refresh token ever issued in a family. Only the SHA-256 of the
    # token is stored (the token is 256 random bits, so a fast hash is enough),
    # never the token. `used_at` marks a rotated token: presenting it again is
    # reuse and revokes the whole family.
    op.create_table(
        "refresh_tokens",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("family_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "token_hash",
            sa.Text(),
            nullable=False,
            comment="hex SHA-256 of the refresh token, not the token",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["family_id"], ["refresh_families.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index(
        op.f("ix_refresh_tokens_family_id"), "refresh_tokens", ["family_id"]
    )
    # Access tokens denied before they expire (logout). A row is useless once
    # `expires_at` has passed, so the index supports a later purge.
    op.create_table(
        "revoked_jtis",
        sa.Column("jti", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("jti"),
    )
    op.create_index(op.f("ix_revoked_jtis_expires_at"), "revoked_jtis", ["expires_at"])


def downgrade() -> None:
    op.drop_index(op.f("ix_revoked_jtis_expires_at"), table_name="revoked_jtis")
    op.drop_table("revoked_jtis")
    op.drop_index(op.f("ix_refresh_tokens_family_id"), table_name="refresh_tokens")
    op.drop_table("refresh_tokens")
