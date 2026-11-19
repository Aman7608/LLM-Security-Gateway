"""The audit database tables (section 8 of docs/02-system-architecture.md).

    api_client      one row per app that uses the gateway (keys are hashes)
    audit_event     one row per request: decisions, counts and timings
    finding_record  one row per finding: type, position and fingerprint
    policy_version  every policy the gateway has used, never overwritten

What is NOT here, on purpose: the prompt, the answer, and the real value of
any secret or personal data. `redacted_prompt` stays empty unless an admin
turns it on, and even then it only holds the redacted version (FR-46).

If you change a table, also add an Alembic migration in migrations/versions/.
A test checks that the migrations and these classes still match.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Dialect,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    TypeDecorator,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class UTCDateTime(TypeDecorator[datetime]):
    """Saves times in UTC and always gives them back with the UTC timezone.

    SQLite forgets timezones, so without this a time read back from the
    database could not be compared with datetime.now(UTC).
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> Any:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("times saved to the audit log must have a timezone")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: Any, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        assert isinstance(value, datetime)  # noqa: S101 - DateTime gives datetimes
        return value.replace(tzinfo=UTC)


class Base(DeclarativeBase):
    pass


class ApiClient(Base):
    """An app allowed to use the gateway. Logins are added in Phase 13."""

    __tablename__ = "api_client"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    key_hash: Mapped[str] = mapped_column(String(128), unique=True)
    role: Mapped[str] = mapped_column(String(10))  # "client" or "admin"
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime)


class PolicyVersionRow(Base):
    """One version of the policy. A change adds a row; old rows stay."""

    __tablename__ = "policy_version"

    version: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime)
    created_by: Mapped[str] = mapped_column(String(100))
    source: Mapped[str] = mapped_column(String(30))
    policy_yaml: Mapped[str] = mapped_column(Text)
    checksum: Mapped[str] = mapped_column(String(64))
    active: Mapped[bool] = mapped_column(Boolean, default=False)


class AuditEvent(Base):
    """One request through the gateway. No prompt, no answer, no secrets."""

    __tablename__ = "audit_event"

    request_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    client_id: Mapped[str | None] = mapped_column(
        ForeignKey("api_client.id"), index=True
    )
    policy_version: Mapped[int | None] = mapped_column(
        ForeignKey("policy_version.version")
    )
    provider: Mapped[str | None] = mapped_column(String(30))
    model: Mapped[str | None] = mapped_column(String(100))
    input_action: Mapped[str] = mapped_column(String(10))
    output_action: Mapped[str | None] = mapped_column(String(10))
    risk_level: Mapped[str] = mapped_column(String(10), index=True)
    status: Mapped[str] = mapped_column(String(20))
    input_chars: Mapped[int] = mapped_column(Integer)
    output_chars: Mapped[int] = mapped_column(Integer)
    scan_ms: Mapped[float] = mapped_column(Float)
    provider_ms: Mapped[float] = mapped_column(Float)
    total_ms: Mapped[float] = mapped_column(Float)
    redacted_prompt: Mapped[str | None] = mapped_column(Text)

    findings: Mapped[list[FindingRecord]] = relationship(
        back_populates="event",
        cascade="all, delete-orphan",
        order_by="FindingRecord.id",
    )


class FindingRecord(Base):
    """One finding: what type, where, and a one-way fingerprint of the value."""

    __tablename__ = "finding_record"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    request_id: Mapped[str] = mapped_column(
        ForeignKey("audit_event.request_id", ondelete="CASCADE"), index=True
    )
    direction: Mapped[str] = mapped_column(String(10))
    detector: Mapped[str] = mapped_column(String(30))
    category: Mapped[str] = mapped_column(String(50))
    entity_type: Mapped[str | None] = mapped_column(String(50))
    rule_id: Mapped[str | None] = mapped_column(String(100))
    confidence: Mapped[float] = mapped_column(Float)
    severity: Mapped[str] = mapped_column(String(10))
    span_start: Mapped[int] = mapped_column(Integer)
    span_end: Mapped[int] = mapped_column(Integer)
    fingerprint: Mapped[str | None] = mapped_column(String(32), index=True)

    event: Mapped[AuditEvent] = relationship(back_populates="findings")
