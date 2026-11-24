"""Shared test setup. pytest loads this file automatically."""

from __future__ import annotations

import shutil
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from llm_gateway.audit.database import (
    create_db_engine,
    make_session_factory,
    upgrade_database,
)
from llm_gateway.audit.fingerprint import Fingerprinter
from llm_gateway.audit.logger import AuditLogger
from llm_gateway.core.factory import (
    build_dlp_engine,
    build_gateway,
    build_output_guard,
)
from llm_gateway.core.gateway import Gateway
from llm_gateway.core.output_guard import OutputGuard
from llm_gateway.detectors.confidential import ConfidentialDetector
from llm_gateway.detectors.injection import InjectionDetector
from llm_gateway.detectors.pii import PIIDetector
from llm_gateway.detectors.secrets import SecretDetector
from llm_gateway.dlp.engine import DLPEngine
from llm_gateway.main import create_app
from llm_gateway.settings import Settings

TESTS_DIR = Path(__file__).parent
PROJECT_ROOT = TESTS_DIR.parent
INJECTION_RULES_FILE = PROJECT_ROOT / "config" / "injection_rules.yaml"
PII_CONFIG_FILE = PROJECT_ROOT / "config" / "pii_entities.yaml"
SECRET_PATTERNS_FILE = PROJECT_ROOT / "config" / "secret_patterns.yaml"
CONFIDENTIAL_TERMS_FILE = PROJECT_ROOT / "config" / "confidential_terms.yaml"
TEST_GROUPS = ("unit", "integration", "security", "e2e")

# Only for tests. Long enough to pass the 32-character check.
TEST_FINGERPRINT_KEY = "test-only-fingerprint-key-" + "x" * 16


@pytest.fixture(scope="session")
def injection_detector() -> InjectionDetector:
    """The injection detector with the real rule file. Loaded once for all tests."""
    return InjectionDetector.from_file(INJECTION_RULES_FILE)


@pytest.fixture(scope="session")
def pii_detector() -> PIIDetector:
    """The PII detector with the real config.

    Loading the language model takes a few seconds, so it is done ONCE for
    the whole test run and shared by every test that asks for it.
    """
    return PIIDetector.from_file(PII_CONFIG_FILE)


@pytest.fixture(scope="session")
def secret_detector() -> SecretDetector:
    """The secret detector with the real pattern file. Loaded once for all tests."""
    return SecretDetector.from_file(SECRET_PATTERNS_FILE)


@pytest.fixture(scope="session")
def confidential_detector() -> ConfidentialDetector:
    """The confidential-terms detector with the real terms file."""
    return ConfidentialDetector.from_file(CONFIDENTIAL_TERMS_FILE)


@pytest.fixture(scope="session")
def dlp_engine(
    injection_detector: InjectionDetector,
    pii_detector: PIIDetector,
    secret_detector: SecretDetector,
    confidential_detector: ConfidentialDetector,
) -> DLPEngine:
    """The full DLP engine with the real detectors and config/policy.yaml.

    It reuses the detectors above, so the PII model is still loaded only once.
    """
    settings = Settings(
        _env_file=None, policy_file=PROJECT_ROOT / "config" / "policy.yaml"
    )
    return build_dlp_engine(
        settings,
        detectors=[
            injection_detector,
            pii_detector,
            secret_detector,
            confidential_detector,
        ],
    )


@pytest.fixture(scope="session")
def output_guard(dlp_engine: DLPEngine) -> OutputGuard:
    """The output scanner, using the shared DLP engine."""
    return build_output_guard(Settings(_env_file=None), dlp_engine)


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Mark each test by its folder, so `pytest -m unit` runs only unit tests."""
    for item in items:
        folder = Path(item.fspath).relative_to(TESTS_DIR).parts[0]
        if folder in TEST_GROUPS:
            item.add_marker(getattr(pytest.mark, folder))


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove any GATEWAY_ variables from the real environment.

    This stops settings on the developer's computer from changing test results.
    """
    import os

    for name in list(os.environ):
        if name.startswith("GATEWAY_"):
            monkeypatch.delenv(name)


@pytest.fixture
def make_settings() -> Callable[..., Settings]:
    """Build Settings for a test, without reading any .env file."""

    def _make(**overrides: Any) -> Settings:
        return Settings(_env_file=None, **overrides)

    return _make


# ---------- the whole gateway and its API (Phase 13) ----------


@pytest.fixture
def gateway_settings(tmp_path: Path) -> Settings:
    """Settings for one test: its own database and its own copy of the policy.

    The policy is copied because PUT /v1/policies/active writes the file,
    and tests must never change the real config/policy.yaml.
    """
    policy_file = tmp_path / "policy.yaml"
    shutil.copy(PROJECT_ROOT / "config" / "policy.yaml", policy_file)
    return Settings(
        _env_file=None,
        environment="test",
        database_url=f"sqlite:///{(tmp_path / 'gateway.db').as_posix()}",
        policy_file=policy_file,
        fingerprint_key=TEST_FINGERPRINT_KEY,
        provider_max_retries=0,  # no waiting between retries in tests
        rate_limit_per_minute=10_000,
        dashboard_dir=None,  # tests that need it make their own (see test_whole_system)
    )


@pytest.fixture
def gateway(
    gateway_settings: Settings,
    injection_detector: InjectionDetector,
    pii_detector: PIIDetector,
    secret_detector: SecretDetector,
    confidential_detector: ConfidentialDetector,
) -> Iterator[Gateway]:
    """A full gateway that reuses the detectors loaded once for all tests."""
    built = build_gateway(
        gateway_settings,
        detectors=[
            injection_detector,
            pii_detector,
            secret_detector,
            confidential_detector,
        ],
    )
    yield built
    built.audit.engine.dispose()


@pytest.fixture
def client(gateway_settings: Settings, gateway: Gateway) -> Iterator[TestClient]:
    """Sends requests to the app without starting a real server."""
    with TestClient(create_app(gateway_settings, gateway)) as test_client:
        yield test_client


@pytest.fixture
def api_keys(gateway: Gateway) -> dict[str, dict[str, str]]:
    """Headers with a fresh client key and a fresh admin key."""
    _, client_key = gateway.audit.api_keys.create("Test app")
    _, admin_key = gateway.audit.api_keys.create("Test admin", role="admin")
    return {"client": {"X-API-Key": client_key}, "admin": {"X-API-Key": admin_key}}


# ---------- audit database (Phase 12) ----------


@pytest.fixture
def audit_db(tmp_path: Path) -> Iterator[Engine]:
    """A new, empty audit database (a SQLite file) with all tables created."""
    engine = create_db_engine(f"sqlite:///{(tmp_path / 'audit.db').as_posix()}")
    upgrade_database(engine)
    yield engine
    engine.dispose()  # close the file, so Windows can delete the folder


@pytest.fixture
def audit_sessions(audit_db: Engine) -> sessionmaker[Session]:
    return make_session_factory(audit_db)


@pytest.fixture
def audit_logger(audit_sessions: sessionmaker[Session]) -> AuditLogger:
    return AuditLogger(audit_sessions)


@pytest.fixture
def fingerprinter() -> Fingerprinter:
    return Fingerprinter(TEST_FINGERPRINT_KEY)
