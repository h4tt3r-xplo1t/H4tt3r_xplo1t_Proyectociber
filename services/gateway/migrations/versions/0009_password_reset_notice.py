"""password_reset_notice

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-15
"""

import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Set when an administrator-issued code resets the password; the next login
    # that opens a full session shows it once and clears it (ADR 0004, decision 10).
    op.add_column(
        "users",
        sa.Column(
            "password_reset_notice_at", sa.DateTime(timezone=True), nullable=True
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "password_reset_notice_at")
