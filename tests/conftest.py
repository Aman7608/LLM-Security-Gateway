"""Shared test setup. pytest loads this file automatically."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from llm_gateway.core.factory import build_dlp_engine, build_output_guard
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


@pytest.fixture
def client(make_settings: Callable[..., Settings]) -> Iterator[TestClient]:
    """A test client that sends requests to the app without starting a server."""
    app = create_app(make_settings(environment="test"))
    with TestClient(app) as test_client:
        yield test_client
