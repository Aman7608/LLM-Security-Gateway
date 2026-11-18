"""Tests for the "part of a longer token" check in the PII detector.

Found in Phase 8: the last 12 digits of a UUID can pass the Aadhaar check
digit by chance, so ID numbers glued to other letters or digits are ignored.
"""

from __future__ import annotations

import pytest

from llm_gateway.detectors.pii import STANDALONE_ENTITIES, _part_of_longer_token


@pytest.mark.parametrize(
    "text, start, end, expected",
    [
        ("x 2345 y", 2, 6, False),  # spaces around: on its own
        ("(2345)", 1, 5, False),  # brackets around: on its own
        ("id:2345", 3, 7, False),  # after a colon: on its own
        ("2345", 0, 4, False),  # the whole text
        ("2345- b", 0, 4, False),  # dash then space: not joined
        ("a2345 ", 1, 5, True),  # letter right before
        ("2345b", 0, 4, True),  # letter right after
        ("a-2345 ", 2, 6, True),  # joined by a dash, as in a UUID
        ("2345_b", 0, 4, True),  # joined by an underscore
    ],
)
def test_part_of_longer_token(text: str, start: int, end: int, expected: bool) -> None:
    assert _part_of_longer_token(text, start, end) is expected


def test_names_and_emails_are_not_affected() -> None:
    """Only number-like IDs get this check; names and emails do not."""
    assert "PERSON" not in STANDALONE_ENTITIES
    assert "EMAIL_ADDRESS" not in STANDALONE_ENTITIES
    assert "IN_AADHAAR" in STANDALONE_ENTITIES
