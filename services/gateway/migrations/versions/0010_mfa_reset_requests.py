"""mfa_reset_requests

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-15
"""

import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # One live request per target: a new one replaces the row, an approval deletes
    # it. A request whose requester is deleted is void, so that FK cascades too.
    op.create_table(
        "mfa_reset_requests",
        sa.Column(
            "id",
            sa.UUID(),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("target_user_id", sa.UUID(), nullable=False),
        sa.Column("requested_by", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "expires_at > created_at", name="mfa_reset_requests_expiry_check"
        ),
        sa.ForeignKeyConstraint(["target_user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["requested_by"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "target_user_id", name="mfa_reset_requests_target_user_id_key"
        ),
    )
    op.create_index(
        "ix_mfa_reset_requests_expires_at", "mfa_reset_requests", ["expires_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_mfa_reset_requests_expires_at", table_name="mfa_reset_requests")
    op.drop_table("mfa_reset_requests")
