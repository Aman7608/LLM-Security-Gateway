"""Fingerprints: a short one-way code for a secret or personal value.

The audit log never saves the real value of what a detector found (FR-45).
It saves a fingerprint instead:

    "priya@example.com"  ->  "fp_3c9a1f0e8b7d6a52"

  - The same value always gives the same fingerprint, so an admin can see
    "this AWS key appeared in 14 requests" without ever seeing the key.
  - It cannot be turned back into the value.

Why HMAC with a secret key, and not a plain SHA-256 hash?
  Many values are easy to guess. An Aadhaar number has only 12 digits, so
  someone with a plain hash could try every possible number until one gives
  the same hash. With HMAC, nobody can do that without our secret key
  (GATEWAY_FINGERPRINT_KEY), which is never stored in the database.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets

from llm_gateway.settings import Settings

logger = logging.getLogger(__name__)

PREFIX = "fp_"
LENGTH = 16  # hex characters = 64 bits, plenty to tell values apart
MIN_KEY_CHARS = 32


class Fingerprinter:
    """Makes fingerprints with one secret key."""

    def __init__(self, key: str) -> None:
        if len(key) < MIN_KEY_CHARS:
            raise ValueError(
                f"the fingerprint key must be at least {MIN_KEY_CHARS} characters"
            )
        self._key = key.encode("utf-8")

    @classmethod
    def from_settings(cls, settings: Settings) -> Fingerprinter:
        """Use GATEWAY_FINGERPRINT_KEY, or a random key outside production.

        A random key works, but fingerprints then change every time the
        gateway restarts, so the same secret can no longer be matched across
        restarts. Production refuses to start without a key (see settings.py).
        """
        if settings.fingerprint_key is not None:
            return cls(settings.fingerprint_key.get_secret_value())
        logger.warning(
            "GATEWAY_FINGERPRINT_KEY is not set, so a random key is used. "
            "Fingerprints will change after a restart."
        )
        return cls(secrets.token_hex(32))

    def of(self, value: str) -> str:
        digest = hmac.new(self._key, value.encode("utf-8"), hashlib.sha256)
        return PREFIX + digest.hexdigest()[:LENGTH]

    def __repr__(self) -> str:
        return "Fingerprinter(key=**********)"  # never show the key
