"""privileged marker and two-administrator reset codes

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-15
"""

import sqlalchemy as sa
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The first time the account got a privileged role or pending role; never
    # cleared, so a demotion does not lower the bar for recovering the account.
    op.add_column(
        "users", sa.Column("privileged_at", sa.DateTime(timezone=True), nullable=True)
    )
    # `pending_role` only ever holds a privileged role (the CHECK allows any role,
    # but the admin route sets it only for privileged ones); the filter keeps the
    # backfill to exactly those.
    op.execute(
        "UPDATE users SET privileged_at = now() "
        "WHERE role IN ('editor', 'auditor', 'administrador') "
        "OR pending_role IN ('editor', 'auditor', 'administrador')"
    )

    # Requests of two kinds share the table: one live request per target and kind.
    op.add_column(
        "mfa_reset_requests",
        sa.Column("kind", sa.Text(), server_default="mfa_reset", nullable=False),
    )
    op.create_check_constraint(
        "mfa_reset_requests_kind_check",
        "mfa_reset_requests",
        "kind IN ('mfa_reset', 'reset_code')",
    )
    op.drop_constraint(
        "mfa_reset_requests_target_user_id_key", "mfa_reset_requests", type_="unique"
    )
    op.create_unique_constraint(
        "mfa_reset_requests_target_user_id_kind_key",
        "mfa_reset_requests",
        ["target_user_id", "kind"],
    )

    # A code for a privileged account records both administrators: `issued_by`
    # asked for it, `approved_by` approved it and received it.
    op.add_column(
        "password_reset_codes",
        sa.Column("approved_by", sa.UUID(), nullable=True),
    )
    op.create_foreign_key(
        "password_reset_codes_approved_by_fkey",
        "password_reset_codes",
        "users",
        ["approved_by"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(
        "password_reset_codes_approved_by_fkey",
        "password_reset_codes",
        type_="foreignkey",
    )
    op.drop_column("password_reset_codes", "approved_by")

    # A reset-code request has no meaning before this revision, and the old
    # unique constraint could not hold both kinds.
    op.execute("DELETE FROM mfa_reset_requests WHERE kind <> 'mfa_reset'")
    op.drop_constraint(
        "mfa_reset_requests_target_user_id_kind_key",
        "mfa_reset_requests",
        type_="unique",
    )
    op.create_unique_constraint(
        "mfa_reset_requests_target_user_id_key",
        "mfa_reset_requests",
        ["target_user_id"],
    )
    op.drop_constraint(
        "mfa_reset_requests_kind_check", "mfa_reset_requests", type_="check"
    )
    op.drop_column("mfa_reset_requests", "kind")

    op.drop_column("users", "privileged_at")
