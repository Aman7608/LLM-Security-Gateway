"""Tests for llm_gateway.audit.json_logging."""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Iterator

import pytest

from llm_gateway.audit.json_logging import JsonFormatter, configure_logging


def make_record(**extra: object) -> logging.LogRecord:
    record = logging.LogRecord(
        "llm_gateway.test", logging.WARNING, __file__, 1, "Saved %s rows", (3,), None
    )
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def test_each_line_is_json_with_the_main_fields() -> None:
    line = JsonFormatter().format(make_record())
    data = json.loads(line)
    assert data["level"] == "WARNING"
    assert data["logger"] == "llm_gateway.test"
    assert data["message"] == "Saved 3 rows"
    assert data["time"].endswith("Z")
    assert "\n" not in line  # one event per line


def test_extra_fields_become_json_fields() -> None:
    data = json.loads(
        JsonFormatter().format(make_record(request_id="req-1", audit_event={"a": 1}))
    )
    assert data["request_id"] == "req-1"
    assert data["audit_event"] == {"a": 1}


def test_errors_include_their_type() -> None:
    try:
        raise TimeoutError("slow")
    except TimeoutError:
        record = make_record()
        record.exc_info = sys.exc_info()
    data = json.loads(JsonFormatter().format(record))
    assert data["error_type"] == "TimeoutError"
    assert "Traceback" in data["traceback"]


@pytest.fixture
def restore_root_logger() -> Iterator[None]:
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    yield
    root.handlers, root.level = handlers, level


@pytest.mark.usefixtures("restore_root_logger")
def test_configure_logging_can_be_called_twice() -> None:
    configure_logging("DEBUG")
    configure_logging("INFO")
    root = logging.getLogger()
    assert len(root.handlers) == 1
    assert isinstance(root.handlers[0].formatter, JsonFormatter)
    assert root.level == logging.INFO
