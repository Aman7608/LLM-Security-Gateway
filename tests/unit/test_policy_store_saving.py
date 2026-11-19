"""PolicyStore with `on_change` (saving each version) and `resume` (numbering)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from llm_gateway.policy.schema import PolicyError
from llm_gateway.policy.store import PolicyStore, PolicyVersion, checksum
from tests.conftest import PROJECT_ROOT

POLICY_FILE = PROJECT_ROOT / "config" / "policy.yaml"


@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    path = tmp_path / "policy.yaml"
    shutil.copy(POLICY_FILE, path)
    return path


def edited(path: Path) -> str:
    """The same rules plus a comment line, so the checksum changes."""
    return path.read_text(encoding="utf-8") + "# edited\n"


def test_every_new_version_is_passed_to_on_change(policy_file: Path) -> None:
    seen: list[PolicyVersion] = []
    store = PolicyStore(policy_file, on_change=seen.append)
    store.load()
    store.update(edited(policy_file), created_by="admin")
    assert [v.version for v in seen] == [1, 2]
    assert seen[0].text == POLICY_FILE.read_text(encoding="utf-8")
    assert seen[1].checksum == checksum(seen[1].text)
    assert seen[1].created_by == "admin"


def test_restart_with_the_same_file_keeps_the_number(policy_file: Path) -> None:
    text = policy_file.read_text(encoding="utf-8")
    store = PolicyStore(policy_file, resume=(7, checksum(text)))
    assert store.load().version == 7


def test_restart_with_a_changed_file_carries_on_counting(policy_file: Path) -> None:
    store = PolicyStore(policy_file, resume=(7, "an-older-checksum"))
    assert store.load().version == 8
    assert store.update(edited(policy_file), created_by="admin").version == 9


def test_failed_save_at_startup_is_not_hidden(policy_file: Path) -> None:
    """A database error must not look like a broken policy file."""

    def broken(_version: PolicyVersion) -> None:
        raise ConnectionError("database down")

    store = PolicyStore(policy_file, on_change=broken)
    with pytest.raises(PolicyError, match="could not be saved"):
        store.load()
    assert store.last_error is None  # the FILE was fine


def test_failed_save_changes_nothing(policy_file: Path) -> None:
    calls = 0

    def fails_second_time(_version: PolicyVersion) -> None:
        nonlocal calls
        calls += 1
        if calls > 1:
            raise ConnectionError("database down")

    store = PolicyStore(policy_file, on_change=fails_second_time)
    store.load()
    before = policy_file.read_text(encoding="utf-8")
    with pytest.raises(PolicyError, match="ConnectionError"):
        store.update(edited(policy_file), created_by="admin")
    assert store.current.version == 1  # the old policy is still active
    assert policy_file.read_text(encoding="utf-8") == before  # file not touched
    assert "database down" not in str(store.history)


def test_built_in_fallback_is_saved_too(tmp_path: Path) -> None:
    seen: list[PolicyVersion] = []
    store = PolicyStore(tmp_path / "missing.yaml", on_change=seen.append)
    store.load()
    assert seen[0].source == "built-in default"
    assert seen[0].text  # its JSON form, so the exact rules are on record
