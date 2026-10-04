"""login_attempts

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-03
"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Keyed by the normalized username, not by user id: unknown usernames get a
    # row too, so lockout behaves the same whether or not the account exists.
    op.create_table(
        "login_attempts",
        sa.Column("username", sa.Text(), nullable=False),
        sa.Column("failures", sa.Integer(), server_default="0", nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("username"),
    )


def downgrade() -> None:
    op.drop_table("login_attempts")
