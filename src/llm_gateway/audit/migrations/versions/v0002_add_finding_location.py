"""Add finding_record.location: which part of a request a finding was in.

A chat request has several parts (messages and documents), and each finding's
position only makes sense inside its own part, for example "messages[2]".

Revision ID: 0002
Revises: 0001
Created: 23 November 2026
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # batch mode: SQLite cannot change a table in place, so Alembic copies it
    with op.batch_alter_table("finding_record") as table:
        table.add_column(sa.Column("location", sa.String(30)))


def downgrade() -> None:
    with op.batch_alter_table("finding_record") as table:
        table.drop_column("location")
