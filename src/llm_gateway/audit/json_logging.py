"""Application logs in JSON format (FR-47).

Normal log lines are written for people:

    WARNING llm_gateway.audit.logger Audit record could not be saved ...

JSON lines are just as readable, and log tools (Docker, Grafana Loki,
Elasticsearch...) can search them by field without guessing the format:

    {"time": "2026-11-20T10:15:02.123Z", "level": "WARNING",
     "logger": "llm_gateway.audit.logger", "message": "...",
     "audit_event": {...}}

Anything passed with `extra={...}` becomes its own field.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

# Fields every LogRecord has. Anything else came from `extra={...}`.
_STANDARD_FIELDS = set(
    vars(logging.LogRecord("x", logging.INFO, "x", 0, "x", None, None))
) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    """Turns each log record into one line of JSON."""

    def format(self, record: logging.LogRecord) -> str:
        data: dict[str, Any] = {
            "time": datetime.fromtimestamp(record.created, UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in vars(record).items():
            if key not in _STANDARD_FIELDS and not key.startswith("_"):
                data[key] = value
        if record.exc_info and record.exc_info[0] is not None:
            data["error_type"] = record.exc_info[0].__name__
            data["traceback"] = self.formatException(record.exc_info)
        return json.dumps(data, default=str, ensure_ascii=False)


def configure_logging(level: str = "INFO") -> None:
    """Send all logs to the console (stderr) as JSON. Safe to call twice."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
