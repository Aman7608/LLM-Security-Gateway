"""Shared test setup. pytest loads this file automatically."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from llm_gateway.detectors.injection import InjectionDetector
from llm_gateway.detectors.pii import PIIDetector
from llm_gateway.main import create_app
from llm_gateway.settings import Settings

TESTS_DIR = Path(__file__).parent
PROJECT_ROOT = TESTS_DIR.parent
INJECTION_RULES_FILE = PROJECT_ROOT / "config" / "injection_rules.yaml"
PII_CONFIG_FILE = PROJECT_ROOT / "config" / "pii_entities.yaml"
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
