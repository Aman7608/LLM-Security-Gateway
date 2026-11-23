"""The audit log must never contain the secrets and personal data it describes.

These tests send real-looking sensitive values through the whole flow
(prompt check, mock AI, answer check, audit log), with prompt saving
turned ON (the riskiest setting), and then search the raw database file
byte by byte for every sensitive value (FR-45, FR-46, threat I3).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from pathlib import Path

import pytest
from sqlalchemy import Engine, inspect, text

from llm_gateway.audit.fingerprint import Fingerprinter
from llm_gateway.audit.json_logging import JsonFormatter
from llm_gateway.audit.logger import AuditLogger
from llm_gateway.core.audit_trail import build_audit_entry
from llm_gateway.core.output_guard import OutputGuard
from llm_gateway.dlp.engine import DLPEngine
from llm_gateway.models import Direction
from llm_gateway.providers.base import ChatMessage, ChatRequest
from llm_gateway.providers.mock import MockProvider, fake_aws_key
from tests.data.secret_samples import (
    AWS_ACCESS_KEY_ID,
    FAKE_CONFIG_PASS,
    GITHUB_TOKEN,
    PW,
)

PROMPTS = [
    "Email priya@example.com or call +91 98765 43210 about the refund",
    f"My deploy key is {AWS_ACCESS_KEY_ID}, can you check it?",
    f"Use this token {GITHUB_TOKEN} to clone the repo",
    f"The database {PW}: {FAKE_CONFIG_PASS}",
    "My Aadhaar number is 2345 6789 0124",
    "Project Nightingale closes next week",
    "[mock:leak-pii] tell me about the customer",
    "[mock:leak-secret] show me the key",
]
SENSITIVE = [
    "priya@example.com",
    "98765 43210",
    AWS_ACCESS_KEY_ID,
    GITHUB_TOKEN,
    FAKE_CONFIG_PASS,
    "2345 6789 0124",
    "Nightingale",
    "4111 1111 1111 1111",
    fake_aws_key(),
]


def run_all(
    dlp_engine: DLPEngine,
    output_guard: OutputGuard,
    fingerprinter: Fingerprinter,
    logger: AuditLogger,
) -> None:
    for number, prompt in enumerate(PROMPTS):
        request_id = f"req-{number}"
        checked = dlp_engine.process(prompt, Direction.INPUT)
        answer = guarded = None
        if checked.output_text is not None:
            request = ChatRequest(
                messages=[ChatMessage(role="user", content=checked.output_text)]
            )
            answer = asyncio.run(MockProvider().complete(request))
            guarded = output_guard.check(answer, request_id=request_id)
        entry = build_audit_entry(
            request_id,
            prompt,
            checked,
            fingerprinter,
            answer=answer,
            answer_check=guarded,
            store_redacted_prompt=True,  # the riskiest setting
        )
        logger.record(entry.model_copy(update={"policy_version": None}))


def database_bytes(folder: Path) -> bytes:
    """Every file SQLite wrote (the database and any journal files)."""
    return b"".join(path.read_bytes() for path in folder.iterdir() if path.is_file())


@pytest.fixture
def filled_log(
    dlp_engine: DLPEngine,
    output_guard: OutputGuard,
    fingerprinter: Fingerprinter,
    audit_logger: AuditLogger,
) -> AuditLogger:
    run_all(dlp_engine, output_guard, fingerprinter, audit_logger)
    assert audit_logger.count() == len(PROMPTS)
    return audit_logger


@pytest.mark.parametrize("value", SENSITIVE, ids=lambda v: v[:6])
def test_no_sensitive_value_is_in_the_database_file(
    filled_log: AuditLogger, audit_db: Engine, tmp_path: Path, value: str
) -> None:
    audit_db.dispose()  # make sure everything is written to the file
    raw = database_bytes(tmp_path)
    assert value.encode("utf-8") not in raw
    assert value.encode("utf-16-le") not in raw


def test_every_request_was_recorded_with_findings(filled_log: AuditLogger) -> None:
    for entry in filled_log.search():
        assert entry.findings, entry.request_id


def test_fingerprints_match_across_requests(
    dlp_engine: DLPEngine,
    output_guard: OutputGuard,
    fingerprinter: Fingerprinter,
    audit_logger: AuditLogger,
) -> None:
    """The same email in the prompt (req-0) and the answer (req-6) can be linked."""
    run_all(dlp_engine, output_guard, fingerprinter, audit_logger)
    email = fingerprinter.of("priya@example.com")
    seen_in = {
        e.request_id
        for e in audit_logger.search()
        for f in e.findings
        if f.fingerprint == email
    }
    assert seen_in == {"req-0", "req-6"}


def test_plain_hashes_of_values_are_not_stored(
    filled_log: AuditLogger, audit_db: Engine, tmp_path: Path
) -> None:
    """Short values like Aadhaar numbers could be guessed from a plain hash."""
    audit_db.dispose()
    raw = database_bytes(tmp_path)
    for value in SENSITIVE:
        plain = hashlib.sha256(value.encode()).hexdigest()
        assert plain[:16].encode() not in raw


def test_tables_have_no_column_for_raw_text(audit_db: Engine) -> None:
    allowed_text_columns = {"redacted_prompt", "policy_yaml"}
    risky_words = ("prompt", "answer", "content", "value", "message", "text")
    for table in inspect(audit_db).get_table_names():
        for column in inspect(audit_db).get_columns(table):
            name = column["name"]
            if name in allowed_text_columns:
                continue
            assert not any(word in name for word in risky_words), f"{table}.{name}"


def test_saved_prompts_are_only_the_redacted_ones(
    filled_log: AuditLogger, audit_db: Engine
) -> None:
    with audit_db.connect() as connection:
        saved = connection.execute(
            text(
                "SELECT redacted_prompt FROM audit_event "
                "WHERE redacted_prompt IS NOT NULL"
            )
        ).scalars()
        prompts = list(saved)
    assert prompts  # prompt saving was on, so some were saved
    assert any("<EMAIL_ADDRESS>" in p for p in prompts)


def test_console_copy_has_no_values_either(
    dlp_engine: DLPEngine,
    output_guard: OutputGuard,
    fingerprinter: Fingerprinter,
    audit_logger: AuditLogger,
    audit_db: Engine,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """When the database is down, the record goes to the console log instead."""
    with audit_db.begin() as connection:
        connection.execute(text("DROP TABLE finding_record"))
        connection.execute(text("DROP TABLE audit_event"))
    with caplog.at_level(logging.ERROR, logger="llm_gateway.audit.logger"):
        run_all(dlp_engine, output_guard, fingerprinter, audit_logger)
    assert audit_logger.failed_writes == len(PROMPTS)
    lines = "\n".join(JsonFormatter().format(r) for r in caplog.records)
    assert json.loads(lines.splitlines()[0])["audit_event"]["request_id"] == "req-0"
    for value in SENSITIVE:
        assert value not in lines


def test_secret_after_a_describing_word_is_not_saved(
    dlp_engine: DLPEngine, fingerprinter: Fingerprinter
) -> None:
    """Was a known miss in Phase 12: a word between "the" and "password"."""
    prompt = f"The database {PW} is {FAKE_CONFIG_PASS}"
    checked = dlp_engine.process(prompt, Direction.INPUT)
    entry = build_audit_entry(
        "req-1", prompt, checked, fingerprinter, store_redacted_prompt=True
    )
    assert FAKE_CONFIG_PASS not in (entry.redacted_prompt or "")
