"""Connecting to the audit database and creating its tables.

Development uses SQLite: one file (data/gateway.db) and no setup at all.
Production can use PostgreSQL by changing GATEWAY_DATABASE_URL. The rest of
the code does not change, because SQLAlchemy hides the differences.

Tables are created by Alembic "migrations" (migrations/versions/), not by
create_all(). A migration is a small numbered script that changes the
tables one step at a time, so a database made with an older version of the
gateway can be upgraded later without losing its data.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, event, inspect
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
EXPECTED_TABLES = {"api_client", "audit_event", "finding_record", "policy_version"}


def create_db_engine(url: str) -> Engine:
    """Open a connection pool to the database at `url`."""
    parsed = make_url(url)
    if parsed.get_backend_name() != "sqlite":
        return create_engine(url, pool_pre_ping=True)

    in_memory = parsed.database in (None, "", ":memory:")
    if not in_memory:
        # SQLite creates the file but not its folder
        Path(str(parsed.database)).parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(
        url,
        # FastAPI handles requests in several threads; each one gets its own
        # session, so sharing the connection pool between threads is fine
        connect_args={"check_same_thread": False},
        # An in-memory database disappears when its connection closes, so
        # every session must share the same single connection
        poolclass=StaticPool if in_memory else None,
    )
    event.listen(engine, "connect", _sqlite_settings)
    return engine


def _sqlite_settings(connection: Any, _record: Any) -> None:
    cursor = connection.cursor()
    # SQLite ignores foreign keys unless this is turned on for each connection
    cursor.execute("PRAGMA foreign_keys = ON")
    # Wait up to 5 seconds if another thread is writing, instead of failing
    cursor.execute("PRAGMA busy_timeout = 5000")
    cursor.close()


def alembic_config() -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    return config


def upgrade_database(engine: Engine) -> None:
    """Create the tables, or upgrade old ones, to the newest version."""
    config = alembic_config()
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")


def is_ready(engine: Engine) -> bool:
    """True when the database can be reached and has all the audit tables."""
    try:
        return EXPECTED_TABLES <= set(inspect(engine).get_table_names())
    except Exception:  # noqa: BLE001 - any failure means "not ready"
        return False


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    # expire_on_commit=False: rows can still be read after the session closes
    return sessionmaker(engine, expire_on_commit=False)
