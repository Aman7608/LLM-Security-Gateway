"""Tests for llm_gateway.audit.fingerprint."""

from __future__ import annotations

import hashlib
import logging
import re
from collections.abc import Callable

import pytest

from llm_gateway.audit.fingerprint import Fingerprinter
from llm_gateway.settings import Settings
from tests.conftest import TEST_FINGERPRINT_KEY

MakeSettings = Callable[..., Settings]


def test_same_value_gives_the_same_fingerprint(fingerprinter: Fingerprinter) -> None:
    assert fingerprinter.of("priya@example.com") == fingerprinter.of(
        "priya@example.com"
    )


def test_different_values_give_different_fingerprints(
    fingerprinter: Fingerprinter,
) -> None:
    values = [f"2345 6789 {n:04d}" for n in range(1000)]
    assert len({fingerprinter.of(v) for v in values}) == 1000


def test_fingerprint_format(fingerprinter: Fingerprinter) -> None:
    assert re.fullmatch(r"fp_[0-9a-f]{16}", fingerprinter.of("anything"))


def test_fingerprint_is_not_a_plain_hash(fingerprinter: Fingerprinter) -> None:
    """Without the key, nobody can rebuild a fingerprint by guessing values."""
    value = "2345 6789 0124"
    plain = hashlib.sha256(value.encode()).hexdigest()[:16]
    assert fingerprinter.of(value) != "fp_" + plain


def test_another_key_gives_other_fingerprints() -> None:
    first = Fingerprinter(TEST_FINGERPRINT_KEY)
    second = Fingerprinter(TEST_FINGERPRINT_KEY + "-other")
    assert first.of("value") != second.of("value")


def test_short_key_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least 32"):
        Fingerprinter("too-short")


def test_key_is_never_shown(fingerprinter: Fingerprinter) -> None:
    assert TEST_FINGERPRINT_KEY not in repr(fingerprinter)
    assert TEST_FINGERPRINT_KEY not in str(fingerprinter)


def test_key_from_settings_gives_stable_fingerprints(
    make_settings: MakeSettings,
) -> None:
    """Two gateways (or one after a restart) with the same key agree."""
    settings = make_settings(fingerprint_key=TEST_FINGERPRINT_KEY)
    first = Fingerprinter.from_settings(settings)
    second = Fingerprinter.from_settings(settings)
    assert first.of("value") == second.of("value")


def test_no_key_uses_a_random_one_and_warns(
    make_settings: MakeSettings, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        first = Fingerprinter.from_settings(make_settings())
        second = Fingerprinter.from_settings(make_settings())
    assert first.of("value") != second.of("value")
    assert "change after a restart" in caplog.text


def test_settings_reject_a_short_key(make_settings: MakeSettings) -> None:
    with pytest.raises(ValueError, match="at least 32 characters"):
        make_settings(fingerprint_key="short")
