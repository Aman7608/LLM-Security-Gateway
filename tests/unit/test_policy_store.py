"""Tests for llm_gateway.policy.store: versions, reloading and safe updates."""

from __future__ import annotations

import logging
import threading
from pathlib import Path

import pytest

from llm_gateway.policy.schema import BUILT_IN_DEFAULT_POLICY, PolicyError
from llm_gateway.policy.store import MAX_HISTORY, PolicyStore, checksum

GOOD = """\
version: 1
input:
  rules:
    - id: warn-pii
      description: d
      when: { detector: pii }
      action: warn
output: { rules: [] }
"""
GOOD_2 = GOOD.replace("action: warn", "action: redact")
BROKEN = "version: 1\ninput: {rules: [{id: oops}]}\noutput: {rules: []}\n"


def store_with(tmp_path: Path, text: str) -> PolicyStore:
    path = tmp_path / "policy.yaml"
    path.write_text(text, encoding="utf-8")
    return PolicyStore(path)


def test_load_a_good_file(tmp_path: Path) -> None:
    store = store_with(tmp_path, GOOD)
    version = store.load()
    assert version.version == 1
    assert version.source == "file"
    assert version.checksum == checksum(GOOD)
    assert store.current is version
    assert store.last_error is None


@pytest.mark.parametrize("text", [BROKEN, "not: [valid", ""])
def test_broken_file_at_startup_uses_the_built_in_policy(
    tmp_path: Path, text: str, caplog: pytest.LogCaptureFixture
) -> None:
    store = store_with(tmp_path, text)
    with caplog.at_level(logging.CRITICAL):
        version = store.load()
    assert version.source == "built-in default"
    assert version.policy == BUILT_IN_DEFAULT_POLICY
    assert store.last_error
    assert "BUILT-IN policy is active" in caplog.text


def test_missing_file_at_startup_uses_the_built_in_policy(tmp_path: Path) -> None:
    store = PolicyStore(tmp_path / "does-not-exist.yaml")
    assert store.load().source == "built-in default"


def test_reload_without_changes_keeps_the_same_version(tmp_path: Path) -> None:
    store = store_with(tmp_path, GOOD)
    first = store.load()
    assert store.reload() is first
    assert len(store.history) == 1


def test_reload_picks_up_a_changed_file(tmp_path: Path) -> None:
    store = store_with(tmp_path, GOOD)
    store.load()
    store.path.write_text(GOOD_2, encoding="utf-8")  # type: ignore[union-attr]
    version = store.reload()
    assert version.version == 2
    assert version.source == "file"
    assert version.policy.input.rules[0].action.value == "redact"


def test_broken_reload_keeps_the_last_good_policy(tmp_path: Path) -> None:
    store = store_with(tmp_path, GOOD)
    good = store.load()
    store.path.write_text(BROKEN, encoding="utf-8")  # type: ignore[union-attr]
    with pytest.raises(PolicyError):
        store.reload()
    assert store.current is good
    assert store.last_error


def test_update_checks_saves_and_activates(tmp_path: Path) -> None:
    store = store_with(tmp_path, GOOD)
    store.load()
    version = store.update(GOOD_2, created_by="aman")
    assert version.version == 2
    assert version.created_by == "aman"
    assert version.source == "update"
    assert store.path.read_text(encoding="utf-8") == GOOD_2  # type: ignore[union-attr]
    assert store.current is version


def test_broken_update_changes_nothing(tmp_path: Path) -> None:
    store = store_with(tmp_path, GOOD)
    good = store.load()
    with pytest.raises(PolicyError):
        store.update(BROKEN, created_by="aman")
    assert store.current is good
    assert store.path.read_text(encoding="utf-8") == GOOD  # type: ignore[union-attr]


@pytest.mark.parametrize("who", ["", "   ", "x" * 101])
def test_update_needs_a_sensible_author(tmp_path: Path, who: str) -> None:
    store = store_with(tmp_path, GOOD)
    store.load()
    with pytest.raises(PolicyError, match="created_by"):
        store.update(GOOD_2, created_by=who)


def test_update_leaves_no_temporary_files(tmp_path: Path) -> None:
    store = store_with(tmp_path, GOOD)
    store.load()
    store.update(GOOD_2, created_by="aman")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["policy.yaml"]


def test_validate_is_a_dry_run(tmp_path: Path) -> None:
    store = store_with(tmp_path, GOOD)
    good = store.load()
    policy = store.validate(GOOD_2)
    assert policy.input.rules[0].action.value == "redact"
    assert store.current is good  # nothing changed
    with pytest.raises(PolicyError, match="new policy has mistakes"):
        store.validate(BROKEN)


def test_history_is_limited(tmp_path: Path) -> None:
    store = store_with(tmp_path, GOOD)
    store.load()
    for number in range(MAX_HISTORY + 10):
        store.update(GOOD if number % 2 else GOOD_2, created_by="aman")
    assert len(store.history) == MAX_HISTORY
    assert store.current.version == MAX_HISTORY + 11  # numbers keep counting up


def test_store_without_a_file() -> None:
    store = PolicyStore.from_policy(BUILT_IN_DEFAULT_POLICY)
    assert store.current.version == 1
    assert store.current.source == "code"
    with pytest.raises(PolicyError, match="no policy file"):
        store.reload()


def test_current_before_load_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="no policy has been loaded"):
        _ = PolicyStore(tmp_path / "p.yaml").current


def test_updates_from_many_threads_get_unique_versions(tmp_path: Path) -> None:
    store = store_with(tmp_path, GOOD)
    store.load()

    def work() -> None:
        for _ in range(5):
            store.update(GOOD_2, created_by="thread")

    threads = [threading.Thread(target=work) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    numbers = [v.version for v in store.history]
    assert numbers == sorted(set(numbers))  # no number used twice
    assert store.current.version == 1 + 4 * 5
