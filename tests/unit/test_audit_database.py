"""Tests for llm_gateway.audit.database and the Alembic migrations."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import Engine, inspect, text
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm import Session

from llm_gateway.audit.database import (
    EXPECTED_TABLES,
    alembic_config,
    create_db_engine,
    is_ready,
    upgrade_database,
)
from llm_gateway.audit.tables import ApiClient, Base


def test_migrations_create_every_table(audit_db: Engine) -> None:
    assert set(inspect(audit_db).get_table_names()) >= EXPECTED_TABLES
    assert is_ready(audit_db)


def test_migrations_match_the_table_classes(audit_db: Engine) -> None:
    """If someone changes tables.py and forgets a migration, this fails."""
    with audit_db.connect() as connection:
        context = MigrationContext.configure(connection, opts={"compare_type": True})
        assert compare_metadata(context, Base.metadata) == []


def test_upgrading_twice_is_harmless(audit_db: Engine) -> None:
    upgrade_database(audit_db)
    assert is_ready(audit_db)


def test_downgrade_removes_the_tables(audit_db: Engine) -> None:
    config = alembic_config()
    with audit_db.begin() as connection:
        config.attributes["connection"] = connection
        command.downgrade(config, "base")
    assert not is_ready(audit_db)


def test_empty_database_is_not_ready() -> None:
    assert not is_ready(create_db_engine("sqlite://"))


def test_unreachable_database_is_not_ready(tmp_path: Path) -> None:
    # tmp_path is a FOLDER, so SQLite cannot open it as a database file
    engine = create_db_engine(f"sqlite:///{tmp_path.as_posix()}")
    assert not is_ready(engine)


def test_folder_for_the_database_file_is_created(tmp_path: Path) -> None:
    path = tmp_path / "new" / "folder" / "gateway.db"
    engine = create_db_engine(f"sqlite:///{path.as_posix()}")
    upgrade_database(engine)
    engine.dispose()
    assert path.exists()


def test_foreign_keys_are_enforced(audit_db: Engine) -> None:
    """SQLite ignores foreign keys unless they are turned on."""
    with pytest.raises(IntegrityError), audit_db.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO finding_record (request_id, direction, detector, "
                "category, confidence, severity, span_start, span_end) "
                "VALUES ('no-such-event', 'input', 'pii', 'x', 1, 'low', 0, 1)"
            )
        )


def test_times_must_have_a_timezone(audit_db: Engine) -> None:
    with pytest.raises(StatementError, match="timezone"), Session(audit_db) as s:
        s.add(
            ApiClient(
                id="c1",
                name="app",
                key_hash="h",
                role="client",
                created_at=datetime(2026, 1, 1),  # noqa: DTZ001 - on purpose
            )
        )
        s.commit()


def test_times_come_back_in_utc(audit_db: Engine) -> None:
    when = datetime(2026, 11, 20, 10, 0, tzinfo=UTC)
    with Session(audit_db) as s:
        s.add(
            ApiClient(id="c1", name="app", key_hash="h", role="client", created_at=when)
        )
        s.commit()
    with Session(audit_db) as s:
        saved = s.get(ApiClient, "c1")
        assert saved is not None
        assert saved.created_at == when
        assert saved.created_at.tzinfo is UTC
