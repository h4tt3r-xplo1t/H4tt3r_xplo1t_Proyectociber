from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from gateway.settings import get_database_url


@lru_cache
def get_engine() -> Engine:
    """Create the engine on first use, so the app starts without a database."""
    return create_engine(
        get_database_url(),
        pool_pre_ping=True,
        # Errors must not echo bound parameters: they include password hashes.
        hide_parameters=True,
        # Fail fast when the database is unreachable instead of hanging a worker.
        connect_args={"connect_timeout": 5},
    )


def get_session() -> Iterator[Session]:
    with sessionmaker(get_engine(), expire_on_commit=False)() as session:
        yield session
