"""The audit logger: saves one safe record per request, and searches them.

What happens if the database is down?
  The gateway should not stop protecting people just because logging broke.
  So by default the record is written to the normal (console) log instead,
  the failure is counted, and the request carries on. If the admin sets
  GATEWAY_AUDIT_REQUIRED=true, a failed write raises AuditWriteError and
  the API answers 503 instead (some companies must log every request).
  Either way the console copy has the same safe fields only: no prompt, no
  answer, no secret values.
"""

from __future__ import annotations

import logging
import math
import threading
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field
from sqlalchemy import Select, delete, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, selectinload, sessionmaker

from llm_gateway.audit.records import AuditEntry, EventStatus, FindingEntry
from llm_gateway.audit.tables import AuditEvent, FindingRecord
from llm_gateway.models import Action, Direction, RiskLevel

logger = logging.getLogger(__name__)

MAX_PAGE_SIZE = 500
MAX_TIMELINE_POINTS = 400


class AuditWriteError(Exception):
    """The audit record could not be saved, and saving is required."""


class EventFilter(BaseModel):
    """Search options for the audit log (FR-48). Every field is optional."""

    model_config = ConfigDict(frozen=True)

    # Times must say their timezone (e.g. 2026-11-20T10:00:00Z), so a search
    # never silently means "local time" on one machine and UTC on another
    since: AwareDatetime | None = None
    until: AwareDatetime | None = None
    min_risk: RiskLevel | None = None  # this level or higher
    action: Action | None = None  # matches the prompt OR the answer decision
    finding_type: str | None = None  # e.g. "EMAIL_ADDRESS" or "jailbreak"
    client_id: str | None = None
    status: EventStatus | None = None
    limit: int = Field(default=50, ge=1, le=MAX_PAGE_SIZE)
    offset: int = Field(default=0, ge=0)


class AuditStats(BaseModel):
    """Counts for the dashboard."""

    model_config = ConfigDict(frozen=True)

    total_events: int
    by_status: dict[str, int]
    by_risk: dict[str, int]
    by_input_action: dict[str, int]
    by_output_action: dict[str, int]
    by_finding_type: dict[str, int]
    # How many events had at least one finding from each detector,
    # e.g. {"injection": 3, "pii": 10, "secret": 2}
    events_by_detector: dict[str, int]
    failed_writes: int  # since the gateway started


class TimelinePoint(BaseModel):
    """How many events started in one hour or one day, per risk level."""

    model_config = ConfigDict(frozen=True)

    start: datetime
    total: int
    by_risk: dict[str, int]  # every risk level is listed, 0 if none


class AuditLogger:
    """Saves and reads audit records. Safe to use from many threads."""

    def __init__(self, sessions: sessionmaker[Session], required: bool = False):
        self.sessions = sessions
        self.required = required
        self._failed_writes = 0
        self._count_lock = threading.Lock()

    @property
    def failed_writes(self) -> int:
        return self._failed_writes

    # ---------- writing ----------

    def record(self, entry: AuditEntry) -> bool:
        """Save one record. Returns False if it went to the console instead."""
        try:
            with self.sessions.begin() as session:
                session.add(_to_row(entry))
        except SQLAlchemyError as error:
            with self._count_lock:
                self._failed_writes += 1
            # Only the error TYPE: database messages can quote the values
            logger.error(
                "Audit record could not be saved to the database (%s); "
                "the safe record follows",
                type(error).__name__,
                extra={"audit_event": entry.model_dump(mode="json")},
            )
            if self.required:
                raise AuditWriteError("the audit record could not be saved") from None
            return False
        return True

    def delete_older_than(self, days: int, now: datetime | None = None) -> int:
        """Delete events (and their findings) older than `days`. Returns how many.

        Keeping logs only as long as needed is part of privacy (NFR-04).
        """
        if days < 1:
            raise ValueError("days must be at least 1")
        cutoff = (now or datetime.now(UTC)) - timedelta(days=days)
        old_events = select(AuditEvent.request_id).where(AuditEvent.timestamp < cutoff)
        with self.sessions.begin() as session:
            session.execute(
                delete(FindingRecord).where(FindingRecord.request_id.in_(old_events))
            )
            result = session.execute(
                delete(AuditEvent).where(AuditEvent.timestamp < cutoff)
            )
        deleted = int(getattr(result, "rowcount", 0) or 0)
        if deleted:
            logger.info("Deleted %s audit events older than %s days", deleted, days)
        return deleted

    # ---------- reading ----------

    def get(self, request_id: str) -> AuditEntry | None:
        with self.sessions() as session:
            row = session.get(
                AuditEvent, request_id, options=[selectinload(AuditEvent.findings)]
            )
            return _from_row(row) if row is not None else None

    def search(self, filters: EventFilter | None = None) -> list[AuditEntry]:
        """Matching events, newest first."""
        filters = filters or EventFilter()
        query = (
            _apply(select(AuditEvent), filters)
            .options(selectinload(AuditEvent.findings))
            .order_by(AuditEvent.timestamp.desc(), AuditEvent.request_id)
            .limit(filters.limit)
            .offset(filters.offset)
        )
        with self.sessions() as session:
            return [_from_row(row) for row in session.scalars(query)]

    def count(self, filters: EventFilter | None = None) -> int:
        """How many events match (ignores limit and offset), for paging."""
        query = _apply(select(func.count(AuditEvent.request_id)), filters)
        with self.sessions() as session:
            return int(session.scalar(query) or 0)

    def stats(self, since: datetime | None = None) -> AuditStats:
        with self.sessions() as session:
            events = select(AuditEvent)
            if since is not None:
                events = events.where(AuditEvent.timestamp >= since)
            sub = events.subquery()

            def counts(column: str) -> dict[str, int]:
                col = sub.c[column]
                rows = session.execute(
                    select(col, func.count()).where(col.is_not(None)).group_by(col)
                )
                return {str(key): int(n) for key, n in rows}

            label = func.coalesce(FindingRecord.entity_type, FindingRecord.category)
            finding_rows = session.execute(
                select(label, func.count())
                .where(FindingRecord.request_id.in_(select(sub.c.request_id)))
                .group_by(label)
            )
            detector_rows = session.execute(
                select(
                    FindingRecord.detector,
                    func.count(func.distinct(FindingRecord.request_id)),
                )
                .where(FindingRecord.request_id.in_(select(sub.c.request_id)))
                .group_by(FindingRecord.detector)
            )
            return AuditStats(
                total_events=int(
                    session.scalar(select(func.count()).select_from(sub)) or 0
                ),
                by_status=counts("status"),
                by_risk=counts("risk_level"),
                by_input_action=counts("input_action"),
                by_output_action=counts("output_action"),
                by_finding_type=dict(
                    Counter({str(k): int(n) for k, n in finding_rows}).most_common()
                ),
                events_by_detector={str(k): int(n) for k, n in detector_rows},
                failed_writes=self.failed_writes,
            )

    def timeline(
        self, start: datetime, end: datetime, step: timedelta
    ) -> list[TimelinePoint]:
        """Events per time step between start and end, for the risk chart.

        Steps with no events are included with zeros, so a chart shows the
        quiet times too. Counting happens in Python (not SQL) because each
        database groups dates differently. Only two small columns are read,
        which is fine for the numbers this project handles.
        """
        if step <= timedelta(0) or end <= start:
            raise ValueError("step must be positive and end must be after start")
        points = math.ceil((end - start) / step)
        if points > MAX_TIMELINE_POINTS:
            raise ValueError(
                f"that would be {points} points; the most is {MAX_TIMELINE_POINTS}"
            )
        counts = [Counter[str]() for _ in range(points)]
        query = select(AuditEvent.timestamp, AuditEvent.risk_level).where(
            AuditEvent.timestamp >= start, AuditEvent.timestamp < end
        )
        with self.sessions() as session:
            for timestamp, risk in session.execute(query):
                counts[int((timestamp - start) // step)][str(risk)] += 1
        return [
            TimelinePoint(
                start=start + n * step,
                total=sum(found.values()),
                by_risk={level.value: found[level.value] for level in RiskLevel},
            )
            for n, found in enumerate(counts)
        ]


def _apply(query: Select[Any], filters: EventFilter | None) -> Select[Any]:
    """Add the WHERE parts for the chosen filters."""
    if filters is None:
        return query
    conditions = []
    if filters.since is not None:
        conditions.append(AuditEvent.timestamp >= filters.since)
    if filters.until is not None:
        conditions.append(AuditEvent.timestamp < filters.until)
    if filters.min_risk is not None:
        levels = [lvl.value for lvl in RiskLevel if lvl.rank >= filters.min_risk.rank]
        conditions.append(AuditEvent.risk_level.in_(levels))
    if filters.action is not None:
        conditions.append(
            (AuditEvent.input_action == filters.action.value)
            | (AuditEvent.output_action == filters.action.value)
        )
    if filters.finding_type is not None:
        conditions.append(
            AuditEvent.findings.any(
                (FindingRecord.entity_type == filters.finding_type)
                | (FindingRecord.category == filters.finding_type)
            )
        )
    if filters.client_id is not None:
        conditions.append(AuditEvent.client_id == filters.client_id)
    if filters.status is not None:
        conditions.append(AuditEvent.status == filters.status.value)
    return query.where(*conditions) if conditions else query


def _to_row(entry: AuditEntry) -> AuditEvent:
    return AuditEvent(
        request_id=entry.request_id,
        timestamp=entry.timestamp,
        client_id=entry.client_id,
        policy_version=entry.policy_version,
        provider=entry.provider,
        model=entry.model,
        input_action=entry.input_action.value,
        output_action=entry.output_action.value if entry.output_action else None,
        risk_level=entry.risk_level.value,
        status=entry.status.value,
        input_chars=entry.input_chars,
        output_chars=entry.output_chars,
        scan_ms=entry.scan_ms,
        provider_ms=entry.provider_ms,
        total_ms=entry.total_ms,
        redacted_prompt=entry.redacted_prompt,
        findings=[
            FindingRecord(
                direction=f.direction.value,
                location=f.location,
                detector=f.detector,
                category=f.category,
                entity_type=f.entity_type,
                rule_id=f.rule_id,
                confidence=f.confidence,
                severity=f.severity.value,
                span_start=f.span_start,
                span_end=f.span_end,
                fingerprint=f.fingerprint,
            )
            for f in entry.findings
        ],
    )


def _from_row(row: AuditEvent) -> AuditEntry:
    return AuditEntry(
        request_id=row.request_id,
        timestamp=row.timestamp,
        client_id=row.client_id,
        policy_version=row.policy_version,
        provider=row.provider,
        model=row.model,
        input_action=Action(row.input_action),
        output_action=Action(row.output_action) if row.output_action else None,
        risk_level=RiskLevel(row.risk_level),
        status=EventStatus(row.status),
        input_chars=row.input_chars,
        output_chars=row.output_chars,
        scan_ms=row.scan_ms,
        provider_ms=row.provider_ms,
        total_ms=row.total_ms,
        redacted_prompt=row.redacted_prompt,
        findings=tuple(
            FindingEntry(
                direction=Direction(f.direction),
                location=f.location,
                detector=f.detector,
                category=f.category,
                entity_type=f.entity_type,
                rule_id=f.rule_id,
                confidence=f.confidence,
                severity=RiskLevel(f.severity),
                span_start=f.span_start,
                span_end=f.span_end,
                fingerprint=f.fingerprint,
            )
            for f in row.findings
        ),
    )
