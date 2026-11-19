"""Saves every policy version to the database, so history survives restarts.

Each audit event says which policy version decided it. Keeping every
version (and never overwriting one) means an admin can still answer "why
was this request blocked last month?" after the rules have changed.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict
from sqlalchemy import select, update
from sqlalchemy.orm import Session, sessionmaker

from llm_gateway.audit.tables import PolicyVersionRow


class SavedPolicy(BaseModel):
    """A policy version as it is stored (without the full text)."""

    model_config = ConfigDict(frozen=True)

    version: int
    checksum: str
    created_by: str
    source: str
    created_at: datetime
    active: bool


class PolicyHistory:
    """Reads and writes the policy_version table."""

    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self.sessions = sessions

    def save(
        self,
        version: int,
        text: str,
        checksum: str,
        created_by: str,
        source: str,
        created_at: datetime,
    ) -> None:
        """Store a version and mark it as the active one.

        Saving a version that is already stored (same number and checksum)
        only marks it active again. That happens after a restart with an
        unchanged policy file. The same number with DIFFERENT text is a bug,
        so it is refused instead of overwriting history.
        """
        with self.sessions.begin() as session:
            existing = session.get(PolicyVersionRow, version)
            if existing is not None and existing.checksum != checksum:
                raise ValueError(
                    f"policy version {version} is already saved with other text"
                )
            session.execute(update(PolicyVersionRow).values(active=False))
            if existing is not None:
                existing.active = True
            else:
                session.add(
                    PolicyVersionRow(
                        version=version,
                        created_at=created_at,
                        created_by=created_by,
                        source=source,
                        policy_yaml=text,
                        checksum=checksum,
                        active=True,
                    )
                )

    def latest(self) -> SavedPolicy | None:
        """The newest saved version, or None for a new, empty database."""
        with self.sessions() as session:
            row = session.scalar(
                select(PolicyVersionRow).order_by(PolicyVersionRow.version.desc())
            )
            return _saved(row) if row is not None else None

    def list(self, limit: int = 50) -> list[SavedPolicy]:
        """Saved versions, newest first."""
        with self.sessions() as session:
            rows = session.scalars(
                select(PolicyVersionRow)
                .order_by(PolicyVersionRow.version.desc())
                .limit(limit)
            )
            return [_saved(row) for row in rows]

    def text_of(self, version: int) -> str | None:
        """The exact policy text of one version."""
        with self.sessions() as session:
            row = session.get(PolicyVersionRow, version)
            return row.policy_yaml if row is not None else None


def _saved(row: PolicyVersionRow) -> SavedPolicy:
    return SavedPolicy(
        version=row.version,
        checksum=row.checksum,
        created_by=row.created_by,
        source=row.source,
        created_at=row.created_at,
        active=row.active,
    )
