"""must_change_password and pending_role on users

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-11
"""

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Set for an account created by the bootstrap (ADR 0004, decision 11): until
    # the user changes the password, no endpoint but the password change and the
    # MFA enrollment answers.
    op.add_column(
        "users",
        sa.Column(
            "must_change_password",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
    )
    # A privileged role assigned to a user without MFA waits here (decision 11)
    # and becomes `role` when the user confirms the MFA. Same domain as `role`.
    op.add_column(
        "users",
        sa.Column(
            "pending_role",
            sa.String(length=16),
            nullable=True,
            comment="privileged role granted once the MFA enrollment is confirmed",
        ),
    )
    op.create_check_constraint(
        "users_pending_role_check",
        "users",
        "pending_role IS NULL OR pending_role IN "
        "('lector', 'editor', 'auditor', 'administrador')",
    )


def downgrade() -> None:
    op.drop_constraint("users_pending_role_check", "users", type_="check")
    op.drop_column("users", "pending_role")
    op.drop_column("users", "must_change_password")
