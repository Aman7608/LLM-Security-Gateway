"""The shared interface that every detector follows.

A detector looks at text and returns a list of findings. It never blocks or
changes anything. Deciding what to do is the policy engine's job (Phase 9).
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from llm_gateway.detectors.normalizer import NormalizedText, normalize
from llm_gateway.models import Finding


class DetectorConfigError(ValueError):
    """A detector's config file is missing or has mistakes."""


class Detector(ABC):
    """Base class for the injection, PII and secret detectors."""

    #: Short name stored in each finding, e.g. "injection".
    name: str = "detector"

    @abstractmethod
    def scan(self, text: NormalizedText) -> list[Finding]:
        """Return everything found in the text, sorted by position.

        The DLP engine (Phase 8) normalizes the text once and passes the same
        NormalizedText to every detector, so the work is not repeated.
        """

    def scan_text(self, text: str) -> list[Finding]:
        """Shortcut that normalizes the text first. Handy for tests and scripts."""
        return self.scan(normalize(text))
