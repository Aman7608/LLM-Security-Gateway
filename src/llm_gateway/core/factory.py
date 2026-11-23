"""Builds the gateway's parts from the settings.

This is the one place that knows which concrete classes to use. Everything
else receives its parts ready-made (dependency injection), which is why
tests can swap in fake detectors or a different policy easily.
"""

from __future__ import annotations

from typing import Any

from llm_gateway.audit.clients import ApiKeys
from llm_gateway.audit.database import (
    create_db_engine,
    make_session_factory,
    upgrade_database,
)
from llm_gateway.audit.fingerprint import Fingerprinter
from llm_gateway.audit.logger import AuditLogger
from llm_gateway.audit.parts import AuditParts
from llm_gateway.audit.policy_history import PolicyHistory
from llm_gateway.core.gateway import Gateway
from llm_gateway.core.output_guard import OutputGuard
from llm_gateway.detectors.base import Detector
from llm_gateway.detectors.confidential import ConfidentialDetector
from llm_gateway.detectors.injection import InjectionDetector
from llm_gateway.detectors.pii import PIIDetector
from llm_gateway.detectors.secrets import SecretDetector
from llm_gateway.dlp.engine import DLPEngine
from llm_gateway.dlp.redactor import RedactionMode
from llm_gateway.policy.engine import PolicyEngine
from llm_gateway.policy.store import PolicyStore, PolicyVersion
from llm_gateway.providers.registry import ProviderRegistry
from llm_gateway.settings import Settings


def build_detectors(settings: Settings) -> list[Detector]:
    """Load the four detectors. Slow (the PII model takes 1 to 3 seconds)."""
    return [
        InjectionDetector.from_file(settings.injection_rules_file),
        PIIDetector.from_file(settings.pii_entities_file),
        SecretDetector.from_file(settings.secret_patterns_file),
        ConfidentialDetector.from_file(settings.confidential_terms_file),
    ]


def build_dlp_engine(
    settings: Settings,
    detectors: list[Detector] | None = None,
    policy_history: PolicyHistory | None = None,
) -> DLPEngine:
    """Create the DLP engine with the policy and limits from the settings.

    Pass `detectors` to reuse ones that are already loaded (tests do this so
    the PII model is only loaded once).

    Pass `policy_history` to save every policy version to the database and
    carry on the version numbers from the last run.

    If the policy file is broken, the strict built-in policy is used and the
    problem is logged (see policy/store.py). The gateway never runs without one.
    """
    store = _policy_store(settings, policy_history)
    store.load()
    policy = PolicyEngine(store, fail_mode=settings.fail_mode)
    return DLPEngine(
        detectors=detectors if detectors is not None else build_detectors(settings),
        policy=policy,
        redaction_mode=RedactionMode(policy.policy.redaction_mode),
        max_chars=settings.max_prompt_chars,
    )


def build_output_guard(settings: Settings, engine: DLPEngine) -> OutputGuard:
    """The output scanner for AI answers, using the same DLP engine."""
    return OutputGuard(engine, blocked_message=settings.output_blocked_message)


def _policy_store(settings: Settings, history: PolicyHistory | None) -> PolicyStore:
    if history is None:
        return PolicyStore(settings.policy_file)
    latest = history.latest()

    def save(version: PolicyVersion) -> None:
        history.save(
            version.version,
            version.text,
            version.checksum,
            version.created_by,
            version.source,
            version.created_at,
        )

    return PolicyStore(
        settings.policy_file,
        on_change=save,
        resume=(latest.version, latest.checksum) if latest is not None else None,
    )


def build_audit(settings: Settings, create_tables: bool = True) -> AuditParts:
    """Connect to the audit database and (by default) create or upgrade its tables."""
    engine = create_db_engine(settings.database_url)
    if create_tables:
        upgrade_database(engine)
    sessions = make_session_factory(engine)
    return AuditParts(
        engine=engine,
        logger=AuditLogger(sessions, required=settings.audit_required),
        policy_history=PolicyHistory(sessions),
        fingerprinter=Fingerprinter.from_settings(settings),
        api_keys=ApiKeys(sessions),
    )


def build_gateway(
    settings: Settings,
    detectors: list[Detector] | None = None,
    audit: AuditParts | None = None,
    http_client: Any = None,
) -> Gateway:
    """Build the whole gateway: detectors, policy, providers and audit log.

    Slow the first time (the PII model loads). Tests pass ready-made
    `detectors` and a test `audit` database to stay fast.
    """
    audit = audit or build_audit(settings)
    engine = build_dlp_engine(settings, detectors, policy_history=audit.policy_history)
    assert isinstance(engine.policy, PolicyEngine)  # noqa: S101 - built just above
    return Gateway(
        settings=settings,
        engine=engine,
        output_guard=build_output_guard(settings, engine),
        registry=ProviderRegistry.from_settings(settings, http_client),
        audit=audit,
        policy_store=engine.policy.store,
    )
