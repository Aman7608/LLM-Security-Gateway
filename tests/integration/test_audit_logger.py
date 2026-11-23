"""The audit logger with a real SQLite database."""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import Engine, func, select, text
from sqlalchemy.orm import Session, sessionmaker

from llm_gateway.audit.logger import AuditLogger, AuditWriteError, EventFilter
from llm_gateway.audit.records import AuditEntry, EventStatus, FindingEntry
from llm_gateway.audit.tables import ApiClient, FindingRecord
from llm_gateway.models import Action, Direction, RiskLevel

NOW = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)


def finding(entity: str | None, category: str = "personal_data") -> FindingEntry:
    return FindingEntry(
        direction=Direction.INPUT,
        detector="pii" if entity else "injection",
        category=category,
        entity_type=entity,
        rule_id=None,
        confidence=0.9,
        severity=RiskLevel.MEDIUM,
        span_start=0,
        span_end=5,
        fingerprint="fp_0123456789abcdef",
    )


def entry(request_id: str, **overrides: object) -> AuditEntry:
    values: dict[str, object] = {
        "request_id": request_id,
        "timestamp": NOW,
        "input_action": Action.ALLOW,
        "output_action": Action.ALLOW,
        "risk_level": RiskLevel.NONE,
        "status": EventStatus.COMPLETED,
        "input_chars": 20,
        "output_chars": 40,
        "provider": "mock",
        "model": "mock-echo-1",
        "scan_ms": 12.5,
        "provider_ms": 3.0,
        "total_ms": 16.0,
    }
    values.update(overrides)
    return AuditEntry.model_validate(values)


@pytest.fixture
def filled(audit_logger: AuditLogger) -> AuditLogger:
    """Five events at different times, risks and decisions."""
    events = [
        entry("e1", timestamp=NOW - timedelta(hours=4)),
        entry(
            "e2",
            timestamp=NOW - timedelta(hours=3),
            input_action=Action.REDACT,
            risk_level=RiskLevel.MEDIUM,
            findings=(finding("EMAIL_ADDRESS"), finding("PHONE_NUMBER")),
        ),
        entry(
            "e3",
            timestamp=NOW - timedelta(hours=2),
            input_action=Action.BLOCK,
            output_action=None,
            risk_level=RiskLevel.CRITICAL,
            status=EventStatus.INPUT_BLOCKED,
            findings=(finding(None, "jailbreak"),),
        ),
        entry(
            "e4",
            timestamp=NOW - timedelta(hours=1),
            output_action=Action.BLOCK,
            risk_level=RiskLevel.HIGH,
            status=EventStatus.OUTPUT_BLOCKED,
            findings=(finding("AWS_ACCESS_KEY", "secret"),),
        ),
        entry("e5", timestamp=NOW, output_action=Action.WARN, risk_level=RiskLevel.LOW),
    ]
    for event in events:
        assert audit_logger.record(event)
    return audit_logger


def ids(entries: list[AuditEntry]) -> list[str]:
    return [e.request_id for e in entries]


# ---------- saving and reading ----------


def test_saved_record_comes_back_the_same(audit_logger: AuditLogger) -> None:
    original = entry("req-1", findings=(finding("EMAIL_ADDRESS"),))
    assert audit_logger.record(original) is True
    assert audit_logger.get("req-1") == original


def test_unknown_request_id(audit_logger: AuditLogger) -> None:
    assert audit_logger.get("nope") is None


def test_saving_the_same_request_twice_fails_safely(audit_logger: AuditLogger) -> None:
    assert audit_logger.record(entry("req-1"))
    assert audit_logger.record(entry("req-1")) is False
    assert audit_logger.failed_writes == 1


def test_unknown_client_is_refused(audit_logger: AuditLogger) -> None:
    """The client must exist (foreign key). Phase 13 adds the clients."""
    assert audit_logger.record(entry("req-1", client_id="ghost")) is False


def test_known_client(
    audit_logger: AuditLogger, audit_sessions: sessionmaker[Session]
) -> None:
    with audit_sessions.begin() as session:
        session.add(
            ApiClient(
                id="app-1", name="App", key_hash="h", role="client", created_at=NOW
            )
        )
    assert audit_logger.record(entry("req-1", client_id="app-1"))
    assert audit_logger.search(EventFilter(client_id="app-1"))[0].request_id == "req-1"


# ---------- when the database fails ----------


def break_database(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE finding_record"))
        connection.execute(text("DROP TABLE audit_event"))


def test_database_failure_goes_to_the_console(
    audit_logger: AuditLogger, audit_db: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    break_database(audit_db)
    with caplog.at_level(logging.ERROR, logger="llm_gateway.audit.logger"):
        assert audit_logger.record(entry("req-1")) is False
    (log,) = caplog.records
    assert "OperationalError" in log.getMessage()
    assert log.audit_event["request_id"] == "req-1"  # type: ignore[attr-defined]
    assert audit_logger.failed_writes == 1


def test_database_failure_can_be_required_to_stop_the_request(
    audit_sessions: sessionmaker[Session], audit_db: Engine
) -> None:
    strict = AuditLogger(audit_sessions, required=True)
    break_database(audit_db)
    with pytest.raises(AuditWriteError):
        strict.record(entry("req-1"))


# ---------- searching (FR-48) ----------


def test_newest_first(filled: AuditLogger) -> None:
    assert ids(filled.search()) == ["e5", "e4", "e3", "e2", "e1"]


def test_paging(filled: AuditLogger) -> None:
    assert ids(filled.search(EventFilter(limit=2))) == ["e5", "e4"]
    assert ids(filled.search(EventFilter(limit=2, offset=2))) == ["e3", "e2"]
    assert filled.count(EventFilter(limit=2)) == 5  # count ignores paging


def test_filter_by_time(filled: AuditLogger) -> None:
    window = EventFilter(since=NOW - timedelta(hours=3), until=NOW - timedelta(hours=1))
    assert ids(filled.search(window)) == ["e3", "e2"]


def test_filter_by_minimum_risk(filled: AuditLogger) -> None:
    assert ids(filled.search(EventFilter(min_risk=RiskLevel.HIGH))) == ["e4", "e3"]


def test_filter_by_action_checks_prompt_and_answer(filled: AuditLogger) -> None:
    assert ids(filled.search(EventFilter(action=Action.BLOCK))) == ["e4", "e3"]
    assert ids(filled.search(EventFilter(action=Action.WARN))) == ["e5"]


def test_filter_by_finding_type(filled: AuditLogger) -> None:
    assert ids(filled.search(EventFilter(finding_type="EMAIL_ADDRESS"))) == ["e2"]
    assert ids(filled.search(EventFilter(finding_type="jailbreak"))) == ["e3"]


def test_filter_by_status(filled: AuditLogger) -> None:
    only = EventFilter(status=EventStatus.OUTPUT_BLOCKED)
    assert ids(filled.search(only)) == ["e4"]


def test_filters_combine(filled: AuditLogger) -> None:
    both = EventFilter(min_risk=RiskLevel.MEDIUM, action=Action.REDACT)
    assert ids(filled.search(both)) == ["e2"]


def test_page_size_is_limited() -> None:
    with pytest.raises(ValueError, match="less than or equal to 500"):
        EventFilter(limit=10_000)


# ---------- statistics ----------


def test_stats(filled: AuditLogger) -> None:
    stats = filled.stats()
    assert stats.total_events == 5
    assert stats.by_status == {"completed": 3, "input_blocked": 1, "output_blocked": 1}
    assert stats.by_risk["critical"] == 1
    assert stats.by_input_action == {"allow": 3, "redact": 1, "block": 1}
    assert stats.by_output_action == {"allow": 2, "block": 1, "warn": 1}
    assert stats.by_finding_type == {
        "EMAIL_ADDRESS": 1,
        "PHONE_NUMBER": 1,
        "jailbreak": 1,
        "AWS_ACCESS_KEY": 1,
    }
    # e2 has two PII findings but is one event; e4's test finding is "pii" too
    assert stats.events_by_detector == {"pii": 2, "injection": 1}
    assert stats.failed_writes == 0


def test_stats_since(filled: AuditLogger) -> None:
    stats = filled.stats(since=NOW - timedelta(hours=1))
    assert stats.total_events == 2
    assert stats.by_finding_type == {"AWS_ACCESS_KEY": 1}


def test_stats_of_an_empty_log(audit_logger: AuditLogger) -> None:
    assert audit_logger.stats().total_events == 0


def test_timeline_per_hour(filled: AuditLogger) -> None:
    start = NOW - timedelta(hours=5)
    points = filled.timeline(start, NOW + timedelta(hours=1), timedelta(hours=1))
    assert [p.start for p in points] == [start + timedelta(hours=n) for n in range(6)]
    assert [p.total for p in points] == [0, 1, 1, 1, 1, 1]
    assert points[3].by_risk["critical"] == 1  # e3, two hours before NOW
    assert set(points[0].by_risk) == {level.value for level in RiskLevel}


def test_timeline_end_is_not_included(filled: AuditLogger) -> None:
    points = filled.timeline(NOW - timedelta(hours=1), NOW, timedelta(hours=1))
    assert [p.total for p in points] == [1]  # e4 only; e5 is exactly at NOW


def test_timeline_per_day(filled: AuditLogger) -> None:
    day = datetime(2026, 11, 20, tzinfo=UTC)
    points = filled.timeline(day, day + timedelta(days=1), timedelta(days=1))
    assert [p.total for p in points] == [5]


@pytest.mark.parametrize(
    ("start", "step", "problem"),
    [
        (NOW - timedelta(days=30), timedelta(hours=1), "720 points"),
        (NOW, timedelta(hours=1), "end must be after start"),
        (NOW - timedelta(hours=1), timedelta(0), "step must be positive"),
    ],
)
def test_timeline_limits(
    audit_logger: AuditLogger, start: datetime, step: timedelta, problem: str
) -> None:
    with pytest.raises(ValueError, match=problem):
        audit_logger.timeline(start, NOW, step)


# ---------- deleting old events (NFR-04) ----------


def test_old_events_and_their_findings_are_deleted(
    filled: AuditLogger, audit_sessions: sessionmaker[Session]
) -> None:
    # cutoff = now - 1 day = NOW - 1.5 hours
    removed = filled.delete_older_than(days=1, now=NOW + timedelta(hours=22.5))
    assert removed == 3  # e1, e2, e3 are older than the cutoff
    assert ids(filled.search()) == ["e5", "e4"]
    with audit_sessions() as session:
        left = session.scalar(select(func.count()).select_from(FindingRecord))
    assert left == 1  # only e4's finding is left


def test_nothing_to_delete(filled: AuditLogger) -> None:
    assert filled.delete_older_than(days=30, now=NOW) == 0


def test_keep_at_least_one_day(audit_logger: AuditLogger) -> None:
    with pytest.raises(ValueError, match="at least 1"):
        audit_logger.delete_older_than(days=0)


# ---------- many threads at once ----------


def test_many_threads_can_write_at_once(audit_logger: AuditLogger) -> None:
    """The API handles requests in several threads at the same time."""

    def write(thread: int) -> None:
        for n in range(20):
            assert audit_logger.record(entry(f"t{thread}-{n}"))

    threads = [threading.Thread(target=write, args=(t,)) for t in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert audit_logger.count() == 120
    assert audit_logger.failed_writes == 0
