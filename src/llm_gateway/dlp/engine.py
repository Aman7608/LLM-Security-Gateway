"""The DLP engine: one place that checks a piece of text and acts on it.

For each text it does three steps:
    1. SCAN    clean the text once (normalize), run every detector on it,
               collect all findings, time each detector, catch crashes
    2. DECIDE  ask the policy what to do (allow, warn, redact or block)
    3. APPLY   return the text unchanged, with secrets and PII hidden, or
               nothing at all if it is blocked

The engine does not know the policy rules. It is given an object with a
decide() method (the PolicyEngine in normal use, a simple fake in tests).
This is called dependency injection: it keeps the engine easy to test and
lets the policy change without touching the engine.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Sequence
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from llm_gateway.detectors.base import Detector
from llm_gateway.detectors.normalizer import normalize
from llm_gateway.dlp.redactor import RedactionMode, redact
from llm_gateway.models import (
    Action,
    Decision,
    Direction,
    Finding,
    RiskLevel,
    ScanResult,
)

logger = logging.getLogger(__name__)


class DecisionMaker(Protocol):
    """Anything with this method can be the engine's policy."""

    def decide(self, scan: ScanResult) -> Decision: ...


class DLPResult(BaseModel):
    """Everything the engine found, decided and did for one text."""

    model_config = ConfigDict(frozen=True)

    direction: Direction
    scan: ScanResult
    decision: Decision
    output_text: str | None  # what may be passed on; None when blocked
    duration_ms: float

    @property
    def action(self) -> Action:
        return self.decision.action

    @property
    def blocked(self) -> bool:
        return self.decision.action is Action.BLOCK

    @property
    def warnings(self) -> tuple[Finding, ...]:
        return self.decision.findings_with(Action.WARN)


class DLPEngine:
    """Runs all detectors on a text, asks the policy, and applies the decision."""

    def __init__(
        self,
        detectors: Sequence[Detector],
        policy: DecisionMaker,
        redaction_mode: RedactionMode = RedactionMode.LABEL,
        max_chars: int = 20_000,
    ) -> None:
        names = [d.name for d in detectors]
        if len(set(names)) != len(names):
            raise ValueError(f"detector names must be unique: {names}")
        self.detectors = list(detectors)
        self.policy = policy
        self.redaction_mode = redaction_mode
        self.max_chars = max_chars

    def scan(self, text: str, direction: Direction) -> ScanResult:
        """Step 1: run every detector on the text and collect what they find."""
        started = time.perf_counter()
        cleaned = normalize(text)  # done ONCE and shared by every detector
        findings: list[Finding] = []
        timings: dict[str, float] = {}
        errors: list[str] = []

        for detector in self.detectors:
            detector_started = time.perf_counter()
            try:
                findings += detector.scan(cleaned)
            except Exception as error:  # noqa: BLE001 - one broken detector must not crash the gateway
                # Log only the error TYPE: the message could contain the text.
                logger.error(
                    "detector %r failed: %s", detector.name, type(error).__name__
                )
                errors.append(detector.name)
            timings[detector.name] = _ms_since(detector_started)

        return ScanResult(
            direction=direction,
            findings=tuple(
                sorted(findings, key=lambda f: (f.start, f.end, f.detector))
            ),
            duration_ms=_ms_since(started),
            detector_ms=timings,
            errors=tuple(errors),
        )

    def process(self, text: str, direction: Direction) -> DLPResult:
        """Scan, decide and apply. This is what the rest of the gateway calls."""
        started = time.perf_counter()

        if len(text) > self.max_chars:
            # Too long to scan safely. Block without running any detector, so a
            # huge input cannot be used to slow the gateway down.
            return DLPResult(
                direction=direction,
                scan=ScanResult(direction=direction),
                decision=Decision(
                    action=Action.BLOCK,
                    risk_level=RiskLevel.MEDIUM,
                    reasons=(
                        f"text is {len(text)} characters, more than the limit "
                        f"of {self.max_chars}",
                    ),
                ),
                output_text=None,
                duration_ms=_ms_since(started),
            )

        scan = self.scan(text, direction)
        decision = self.policy.decide(scan)

        return DLPResult(
            direction=direction,
            scan=scan,
            decision=decision,
            output_text=self._apply(text, decision),
            duration_ms=_ms_since(started),
        )

    def _apply(self, text: str, decision: Decision) -> str | None:
        """Step 3: turn the decision into the text that may be passed on."""
        if decision.action is Action.BLOCK:
            return None
        to_hide = decision.findings_with(Action.REDACT)
        if to_hide:
            return redact(text, to_hide, self.redaction_mode)
        return text  # ALLOW and WARN pass the text on unchanged


def _ms_since(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 3)
