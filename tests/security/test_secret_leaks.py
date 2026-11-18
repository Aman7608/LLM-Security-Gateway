"""Security tests: every fake secret is found and fully hidden.

All secrets here are FAKE and built at runtime (see tests/data/secret_samples.py).
Test ids show only the secret type, not the value.
"""

from __future__ import annotations

import time

import pytest

from llm_gateway.detectors.secrets import SecretDetector
from llm_gateway.dlp.redactor import RedactionMode, redact
from tests.data.secret_samples import KNOWN_MISSES, NO_SECRETS, SECRET_SAMPLES


@pytest.mark.parametrize(
    "text, secret_type, value",
    SECRET_SAMPLES,
    ids=[
        f"{i:02d}-{secret_type}" for i, (_, secret_type, _) in enumerate(SECRET_SAMPLES)
    ],
)
def test_secret_is_found_and_fully_hidden(
    secret_detector: SecretDetector, text: str, secret_type: str, value: str
) -> None:
    findings = secret_detector.scan_text(text)
    assert secret_type in {f.entity_type for f in findings}
    for mode in RedactionMode:
        assert value not in redact(text, findings, mode)


@pytest.mark.parametrize("text", NO_SECRETS)
def test_text_without_secrets_is_clean(
    secret_detector: SecretDetector, text: str
) -> None:
    assert secret_detector.scan_text(text) == []


def test_many_secrets_in_one_message(secret_detector: SecretDetector) -> None:
    """A whole .env file pasted at once: nothing may survive redaction."""
    text = "\n".join(text for text, _, _ in SECRET_SAMPLES)
    hidden = redact(text, secret_detector.scan_text(text))
    for _, secret_type, value in SECRET_SAMPLES:
        assert value not in hidden, secret_type


@pytest.mark.parametrize(
    "text, value",
    [
        pytest.param(text, value, marks=pytest.mark.xfail(strict=True, reason=why))
        for text, value, why in KNOWN_MISSES
    ],
)
def test_known_misses_are_still_missed(
    secret_detector: SecretDetector, text: str, value: str
) -> None:
    """These fail on purpose. If one starts passing, move it to SECRET_SAMPLES."""
    assert value not in redact(text, secret_detector.scan_text(text))


SLOW_INPUTS = {
    "many key headers, no end": ("-----BEGIN " + "PRIVATE KEY-----\n") * 1200,
    "one huge word": "A" * 60_000,
    "repeated assignments": "password=" * 3000,
    "repeated url starts": "postgres://a:" * 3000,
    "repeated bearer": "Bearer " * 5000,
    "repeated jwt starts": "eyJabcdefghij." * 3000,
    "long base64 run": ("Ab3dEf9h" * 2500),
}


@pytest.mark.parametrize("name", sorted(SLOW_INPUTS))
def test_patterns_stay_fast_on_crafted_input(
    secret_detector: SecretDetector, name: str
) -> None:
    """Protects against ReDoS: input crafted to make regexes take very long."""
    started = time.perf_counter()
    secret_detector.scan_text(SLOW_INPUTS[name])
    assert time.perf_counter() - started < 2.0
