"""Alembic environment of the worker.

Migrations run with an owner/admin URL (WORKER_NOTICIAS_MIGRATION_DATABASE_URL),
never with the app role: the app role has no right to create or alter anything
(threat 15). The version table lives in the worker's own schema `noticias`, so
it never collides with the gateway's `alembic_version` in a shared database.
"""

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool, text

SCHEMA = "noticias"

config = context.config
if config.config_file_name is not None:
    # Keep the logging set up by the caller (tests, CLI) when it exists.
    fileConfig(config.config_file_name, disable_existing_loggers=False)


def get_migration_url() -> str:
    url = os.environ.get("WORKER_NOTICIAS_MIGRATION_DATABASE_URL")
    if not url:
        # Fixed message: never echo environment values.
        raise RuntimeError("WORKER_NOTICIAS_MIGRATION_DATABASE_URL is not set")
    return url


def run_migrations_offline() -> None:
    context.configure(
        url=get_migration_url(),
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        version_table_schema=SCHEMA,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(
        get_migration_url(), poolclass=pool.NullPool, hide_parameters=True
    )
    with engine.connect() as connection:
        # The version table is stored in the schema, so the schema must exist
        # before Alembic creates it. The schema stays after a downgrade to base
        # because it holds the (empty) version table.
        connection.execute(text(f"CREATE SCHEMA IF NOT EXISTS {SCHEMA}"))
        connection.commit()
        context.configure(connection=connection, version_table_schema=SCHEMA)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
