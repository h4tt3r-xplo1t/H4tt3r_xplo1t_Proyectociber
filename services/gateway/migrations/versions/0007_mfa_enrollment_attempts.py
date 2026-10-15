"""mfa_enrollment_attempts

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-12
"""

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # One row per enrollment that passed the password check and reached the
    # transit call; the per-user limit counts the rows inside its window.
    op.create_table(
        "mfa_enrollment_attempts",
        sa.Column(
            "id",
            sa.UUID(),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_mfa_enrollment_attempts_user_id_created_at",
        "mfa_enrollment_attempts",
        ["user_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_mfa_enrollment_attempts_user_id_created_at",
        table_name="mfa_enrollment_attempts",
    )
    op.drop_table("mfa_enrollment_attempts")
