"""Alembic runs this file to apply migrations.

Two ways in:
  - From the gateway (database.upgrade_database): it passes an open
    connection in config.attributes["connection"].
  - From the command line (`alembic upgrade head` in the project folder):
    the database address is read from GATEWAY_DATABASE_URL, so no password
    ever needs to be written into alembic.ini.
"""

from __future__ import annotations

from alembic import context
from sqlalchemy import Connection

from llm_gateway.audit.database import create_db_engine
from llm_gateway.audit.tables import Base
from llm_gateway.settings import get_settings


def run(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=Base.metadata,
        # SQLite cannot change most things about a table in place; "batch"
        # mode copies the table instead, so future migrations work there too
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    raise SystemExit("Offline (SQL script) mode is not used in this project.")

given = context.config.attributes.get("connection")
if given is not None:
    run(given)
else:
    engine = create_db_engine(get_settings().database_url)
    with engine.begin() as connection:
        run(connection)
    engine.dispose()
