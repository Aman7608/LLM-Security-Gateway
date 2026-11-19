"""Policy versions saved in the database, and surviving a restart."""

from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from llm_gateway.audit.policy_history import PolicyHistory
from llm_gateway.core.factory import build_dlp_engine
from llm_gateway.detectors.secrets import SecretDetector
from llm_gateway.models import Direction
from llm_gateway.settings import Settings
from tests.conftest import PROJECT_ROOT

NOW = datetime(2026, 11, 20, tzinfo=UTC)


@pytest.fixture
def history(audit_sessions: sessionmaker[Session]) -> PolicyHistory:
    return PolicyHistory(audit_sessions)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    policy_file = tmp_path / "policy.yaml"
    shutil.copy(PROJECT_ROOT / "config" / "policy.yaml", policy_file)
    return Settings(_env_file=None, policy_file=policy_file)


def start_gateway(
    settings: Settings, history: PolicyHistory, secret_detector: SecretDetector
) -> int:
    """Build the engine like the gateway does at startup; return its version."""
    engine = build_dlp_engine(settings, [secret_detector], policy_history=history)
    version = engine.policy.store.current.version  # type: ignore[attr-defined]
    assert isinstance(version, int)
    return version


def test_save_and_read_back(history: PolicyHistory) -> None:
    history.save(1, "version: 1 text", "abc", "startup", "file", NOW)
    latest = history.latest()
    assert latest is not None
    assert (latest.version, latest.checksum, latest.active) == (1, "abc", True)
    assert history.text_of(1) == "version: 1 text"
    assert history.text_of(99) is None


def test_only_the_newest_is_active(history: PolicyHistory) -> None:
    history.save(1, "a", "c1", "startup", "file", NOW)
    history.save(2, "b", "c2", "admin", "update", NOW)
    assert [(p.version, p.active) for p in history.list()] == [(2, True), (1, False)]


def test_old_versions_are_never_overwritten(history: PolicyHistory) -> None:
    history.save(1, "a", "c1", "startup", "file", NOW)
    with pytest.raises(ValueError, match="already saved"):
        history.save(1, "other text", "c2", "startup", "file", NOW)
    assert history.text_of(1) == "a"


def test_empty_database_has_no_versions(history: PolicyHistory) -> None:
    assert history.latest() is None
    assert history.list() == []


def test_startup_saves_the_policy(
    settings: Settings, history: PolicyHistory, secret_detector: SecretDetector
) -> None:
    assert start_gateway(settings, history, secret_detector) == 1
    assert history.text_of(1) == settings.policy_file.read_text(encoding="utf-8")


def test_restart_with_the_same_policy_keeps_its_number(
    settings: Settings, history: PolicyHistory, secret_detector: SecretDetector
) -> None:
    start_gateway(settings, history, secret_detector)
    assert start_gateway(settings, history, secret_detector) == 1
    assert len(history.list()) == 1


def test_restart_after_the_file_changed_adds_a_version(
    settings: Settings, history: PolicyHistory, secret_detector: SecretDetector
) -> None:
    start_gateway(settings, history, secret_detector)
    with settings.policy_file.open("a", encoding="utf-8") as file:
        file.write("# changed by hand\n")
    assert start_gateway(settings, history, secret_detector) == 2
    assert [p.active for p in history.list()] == [True, False]


def test_admin_update_is_saved_with_who_made_it(
    settings: Settings, history: PolicyHistory, secret_detector: SecretDetector
) -> None:
    engine = build_dlp_engine(settings, [secret_detector], policy_history=history)
    new_text = settings.policy_file.read_text(encoding="utf-8") + "# tuned\n"
    engine.policy.store.update(new_text, created_by="aman")  # type: ignore[attr-defined]
    latest = history.latest()
    assert latest is not None
    assert (latest.version, latest.created_by, latest.source) == (2, "aman", "update")


def test_decisions_name_the_saved_version(
    settings: Settings, history: PolicyHistory, secret_detector: SecretDetector
) -> None:
    """An audit event can always be matched to the exact rules that decided it."""
    start_gateway(settings, history, secret_detector)
    engine = build_dlp_engine(settings, [secret_detector], policy_history=history)
    result = engine.process("hello", Direction.INPUT)
    assert result.decision.policy_version == 1
    assert history.text_of(1) is not None
