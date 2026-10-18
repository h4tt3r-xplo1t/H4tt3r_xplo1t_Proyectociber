"""Constants and helpers shared by the database tests."""

from pathlib import Path

from alembic.config import Config

ALEMBIC_INI = Path(__file__).resolve().parent.parent / "alembic.ini"
APP_ROLE = "worker_noticias"


def alembic_config() -> Config:
    return Config(str(ALEMBIC_INI))
