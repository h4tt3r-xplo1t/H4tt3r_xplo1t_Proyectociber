"""PostgreSQL storage of the news (threats 15 and 17).

The worker connects with its own role `worker_noticias` (WORKER_NOTICIAS_DATABASE_URL),
which can only SELECT, INSERT and DELETE on `noticias.news_items`: it cannot
update, truncate, create objects or touch any gateway table. The schema is
created by the migrations, which run with a different, owner URL.

Only the fields of `feeds.NewsItem` are stored, never the article body.
Duplicates are harmless: the link is unique and `save` skips a known link, so
reading a feed twice, or the same piece in the RCN RSS and the RCN sitemap,
keeps one row. `purge` is the retention policy (default 30 days).

Errors are reported with fixed messages and without a chained cause: a database
error can carry the connection URL or the content of the failing row.

Creating the role for development and CI: scripts/create_role.sql.
"""

import os
from collections.abc import Iterable
from datetime import timedelta
from functools import lru_cache

from sqlalchemy import (
    BigInteger,
    Column,
    DateTime,
    Engine,
    MetaData,
    Table,
    Text,
    create_engine,
    delete,
    func,
)
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import SQLAlchemyError

from worker_noticias.feeds import NewsItem

DEFAULT_RETENTION_DAYS = 30
MIN_RETENTION_DAYS = 1
MAX_RETENTION_DAYS = 365
RETENTION_MESSAGE = "WORKER_NOTICIAS_RETENTION_DAYS must be an integer from 1 to 365"

# Declared here, not reflected: reflection needs privileges the role lacks on
# purpose. The tests check the grants against the real table.
news_items = Table(
    "news_items",
    MetaData(schema="noticias"),
    Column("id", BigInteger, primary_key=True),
    Column("source_id", Text, nullable=False),
    Column("outlet", Text, nullable=False),
    Column("title", Text, nullable=False),
    Column("link", Text, nullable=False),
    Column("published_at", DateTime(timezone=True), nullable=False),
    Column("summary", Text),
    Column("author", Text),
)


class ConfigError(Exception):
    """Invalid configuration; the message is fixed and never echoes values."""


class StoreError(Exception):
    """A database operation failed; the message is fixed (no URL, no content)."""


def retention() -> timedelta:
    """Retention from WORKER_NOTICIAS_RETENTION_DAYS (1 to 365, default 30)."""
    raw = os.environ.get("WORKER_NOTICIAS_RETENTION_DAYS")
    if raw is None:
        return timedelta(days=DEFAULT_RETENTION_DAYS)
    raw = raw.strip()
    # isascii: int() also accepts digits of other scripts.
    if not (raw.isascii() and raw.isdigit()):
        raise ConfigError(RETENTION_MESSAGE)
    days = int(raw)
    if not MIN_RETENTION_DAYS <= days <= MAX_RETENTION_DAYS:
        raise ConfigError(RETENTION_MESSAGE)
    return timedelta(days=days)


@lru_cache
def get_engine() -> Engine:
    """Engine of the app role, created on first use."""
    url = os.environ.get("WORKER_NOTICIAS_DATABASE_URL")
    if not url:
        raise ConfigError("WORKER_NOTICIAS_DATABASE_URL is not set")
    try:
        return create_engine(
            url,
            pool_pre_ping=True,
            # Errors must not echo bound parameters: they hold the news content.
            hide_parameters=True,
            connect_args={"connect_timeout": 5},
        )
    except Exception:
        # A malformed URL error can quote the URL, which holds the password.
        raise ConfigError("WORKER_NOTICIAS_DATABASE_URL is not valid") from None


def save(items: Iterable[NewsItem], *, engine: Engine | None = None) -> int:
    """Store the items; returns how many were new (known links are skipped)."""
    rows = [
        {
            "source_id": i.source_id,
            "outlet": i.outlet,
            "title": i.title,
            "link": i.link,
            "published_at": i.published_at,
            "summary": i.summary,
            "author": i.author,
        }
        for i in items
    ]
    if not rows:
        return 0
    statement = (
        insert(news_items)
        .on_conflict_do_nothing(index_elements=["link"])
        .returning(news_items.c.id)
    )
    try:
        with (engine or get_engine()).begin() as conn:
            return len(conn.execute(statement, rows).all())
    except SQLAlchemyError, OSError:
        raise StoreError("could not save the news") from None


def purge(older_than: timedelta, *, engine: Engine | None = None) -> int:
    """Delete the news published before now - older_than; returns the count."""
    if older_than < timedelta(days=MIN_RETENTION_DAYS):
        raise ValueError("retention must be at least one day")
    statement = delete(news_items).where(
        news_items.c.published_at < func.now() - older_than
    )
    try:
        with (engine or get_engine()).begin() as conn:
            return conn.execute(statement).rowcount
    except SQLAlchemyError, OSError:
        raise StoreError("could not purge the news") from None
