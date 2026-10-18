"""news_items with least-privilege grants for the worker role

Threats 15 (database access) and 17 (unbounded growth).

The table lives in the worker's own schema `noticias`, so the worker is
isolated from the gateway tables of a shared database. Only the headline, link,
date, short summary, outlet and author are stored, never the article body
(PROJECT_CONTEXT section 8). The CHECK constraints mirror the caps of
`worker_noticias.feeds`, so a bug in the parser cannot store more.

This migration does NOT create the app role: creating roles is an operator
decision (CREATEROLE). It only grants to `worker_noticias`, and fails with a
clear message if the role does not exist yet (see scripts/create_role.sql).
The grant is the minimum: SELECT and INSERT, plus DELETE only for the
retention purge. There is no UPDATE, TRUNCATE or CREATE.

Revision ID: 0001
Revises:
Create Date: 2026-10-16
"""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_roles WHERE rolname = 'worker_noticias'
            ) THEN
                RAISE EXCEPTION 'role worker_noticias does not exist: create it first '
                    '(see services/worker-noticias/scripts/create_role.sql)';
            END IF;
        END
        $$
        """
    )
    op.create_table(
        "news_items",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column("source_id", sa.Text(), nullable=False),
        sa.Column("outlet", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("link", sa.Text(), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("summary", sa.Text()),
        sa.Column("author", sa.Text()),
        sa.Column(
            "fetched_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("link", name="news_items_link_key"),
        sa.CheckConstraint("char_length(title) <= 300", name="news_items_title_len"),
        sa.CheckConstraint(
            "char_length(summary) <= 500", name="news_items_summary_len"
        ),
        sa.CheckConstraint("char_length(author) <= 120", name="news_items_author_len"),
        sa.CheckConstraint("char_length(link) <= 2000", name="news_items_link_len"),
        schema="noticias",
    )
    op.create_index(
        "news_items_published_at_idx", "news_items", ["published_at"], schema="noticias"
    )
    op.execute("REVOKE ALL ON SCHEMA noticias FROM PUBLIC")
    op.execute("REVOKE ALL ON TABLE noticias.news_items FROM PUBLIC")
    op.execute("GRANT USAGE ON SCHEMA noticias TO worker_noticias")
    # DELETE is for the retention purge only. An identity column needs no
    # sequence privilege for INSERT.
    op.execute("GRANT SELECT, INSERT, DELETE ON noticias.news_items TO worker_noticias")


def downgrade() -> None:
    # Dropping the table drops its grants. The schema stays because it holds
    # the Alembic version table; only the role's access to it is removed.
    op.drop_table("news_items", schema="noticias")
    op.execute("REVOKE ALL ON SCHEMA noticias FROM worker_noticias")
