"""Everything the audit log needs, built together by core/factory.py."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import Engine

from llm_gateway.audit.clients import ApiKeys
from llm_gateway.audit.fingerprint import Fingerprinter
from llm_gateway.audit.logger import AuditLogger
from llm_gateway.audit.policy_history import PolicyHistory


@dataclass(frozen=True)
class AuditParts:
    engine: Engine
    logger: AuditLogger
    policy_history: PolicyHistory
    fingerprinter: Fingerprinter
    api_keys: ApiKeys
