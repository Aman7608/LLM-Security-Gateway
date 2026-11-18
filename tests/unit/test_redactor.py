"""Tests for llm_gateway.dlp.redactor."""

from __future__ import annotations

import pytest

from llm_gateway.dlp.redactor import RedactionMode, redact
from llm_gateway.models import Finding, RiskLevel

TEXT = "Email priya@example.com or call +91 98765 43210."
EMAIL = (6, 23)
PHONE = (32, 47)


def finding(
    start: int,
    end: int,
    entity_type: str | None = "EMAIL_ADDRESS",
    confidence: float = 0.9,
    category: str = "pii",
) -> Finding:
    return Finding(
        detector="pii",
        category=category,
        entity_type=entity_type,
        start=start,
        end=end,
        confidence=confidence,
        severity=RiskLevel.MEDIUM,
    )


def test_spans_in_the_sample_text_are_right() -> None:
    assert TEXT[slice(*EMAIL)] == "priya@example.com"
    assert TEXT[slice(*PHONE)] == "+91 98765 43210"


def test_label_mode_is_the_default() -> None:
    result = redact(TEXT, [finding(*EMAIL), finding(*PHONE, "PHONE_NUMBER")])
    assert result == "Email <EMAIL_ADDRESS> or call <PHONE_NUMBER>."


def test_mask_mode_keeps_the_length() -> None:
    result = redact(TEXT, [finding(*EMAIL)], RedactionMode.MASK)
    assert result == "Email " + "*" * 17 + " or call +91 98765 43210."
    assert len(result) == len(TEXT)


def test_remove_mode_hides_the_type() -> None:
    result = redact(TEXT, [finding(*EMAIL)], RedactionMode.REMOVE)
    assert result == "Email [REDACTED] or call +91 98765 43210."


def test_no_findings_changes_nothing() -> None:
    assert redact(TEXT, []) == TEXT


def test_order_of_findings_does_not_matter() -> None:
    both = [finding(*PHONE, "PHONE_NUMBER"), finding(*EMAIL)]
    assert redact(TEXT, both) == redact(TEXT, list(reversed(both)))


def test_overlapping_findings_are_replaced_once() -> None:
    text = "card 4111 1111 1111 1111 ok"
    card = finding(5, 24, "CREDIT_CARD", confidence=1.0)
    phone = finding(10, 24, "PHONE_NUMBER", confidence=0.4)
    assert redact(text, [phone, card]) == "card <CREDIT_CARD> ok"


def test_merged_span_covers_both_findings() -> None:
    text = "abcdefghij"
    result = redact(text, [finding(0, 5, "A", 0.9), finding(3, 8, "B", 0.5)])
    assert result == "<A>ij"


def test_touching_findings_stay_separate() -> None:
    text = "AAABBB"
    result = redact(text, [finding(0, 3, "A"), finding(3, 6, "B")])
    assert result == "<A><B>"


def test_label_falls_back_to_category() -> None:
    result = redact("key=abc123", [finding(4, 10, None, category="secret")])
    assert result == "key=<SECRET>"


def test_works_with_non_english_text() -> None:
    text = "नाम: राहुल, ईमेल a@example.com"
    start = text.index("a@")
    result = redact(text, [finding(start, len(text))])
    assert result == "नाम: राहुल, ईमेल <EMAIL_ADDRESS>"


def test_finding_outside_the_text_is_an_error() -> None:
    with pytest.raises(ValueError, match="outside the text"):
        redact("short", [finding(2, 50)])
