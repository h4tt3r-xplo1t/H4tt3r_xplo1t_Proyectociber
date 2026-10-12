"""token_generation on users

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-12
"""

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Every access token carries the generation it was issued under and is
    # accepted only while it equals this column; each change of credentials
    # bumps it. Tokens issued before this migration have no `gen` claim and are
    # refused once (one new login), which is the intended cut-over.
    op.add_column(
        "users",
        sa.Column(
            "token_generation",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "token_generation")
