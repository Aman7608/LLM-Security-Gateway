"""Builds the gateway's parts from the settings.

This is the one place that knows which concrete classes to use. Everything
else receives its parts ready-made (dependency injection), which is why
tests can swap in fake detectors or a different policy easily.
"""

from __future__ import annotations

from llm_gateway.detectors.base import Detector
from llm_gateway.detectors.injection import InjectionDetector
from llm_gateway.detectors.pii import PIIDetector
from llm_gateway.detectors.secrets import SecretDetector
from llm_gateway.dlp.engine import DLPEngine
from llm_gateway.dlp.redactor import RedactionMode
from llm_gateway.policy.engine import PolicyEngine
from llm_gateway.policy.store import PolicyStore
from llm_gateway.settings import Settings


def build_detectors(settings: Settings) -> list[Detector]:
    """Load the three detectors. Slow (the PII model takes 1 to 3 seconds)."""
    return [
        InjectionDetector.from_file(settings.injection_rules_file),
        PIIDetector.from_file(settings.pii_entities_file),
        SecretDetector.from_file(settings.secret_patterns_file),
    ]


def build_dlp_engine(
    settings: Settings, detectors: list[Detector] | None = None
) -> DLPEngine:
    """Create the DLP engine with the policy and limits from the settings.

    Pass `detectors` to reuse ones that are already loaded (tests do this so
    the PII model is only loaded once).

    If the policy file is broken, the strict built-in policy is used and the
    problem is logged (see policy/store.py). The gateway never runs without one.
    """
    store = PolicyStore(settings.policy_file)
    store.load()
    policy = PolicyEngine(store, fail_mode=settings.fail_mode)
    return DLPEngine(
        detectors=detectors if detectors is not None else build_detectors(settings),
        policy=policy,
        redaction_mode=RedactionMode(policy.policy.redaction_mode),
        max_chars=settings.max_prompt_chars,
    )
