"""Tests for llm_gateway.audit.clients with a real database."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from llm_gateway.audit.clients import ApiKeys, hash_key


@pytest.fixture
def keys(audit_sessions: sessionmaker[Session]) -> ApiKeys:
    return ApiKeys(audit_sessions)


def test_new_key_looks_right(keys: ApiKeys) -> None:
    client, key = keys.create("My app")
    assert re.fullmatch(r"lsg_[A-Za-z0-9_\-]{43}", key)
    assert client.name == "My app" and client.role == "client" and client.active
    assert client.id.startswith("app_")


def test_keys_are_unique(keys: ApiKeys) -> None:
    assert len({keys.create("app")[1] for _ in range(50)}) == 50


def test_the_right_key_is_accepted(keys: ApiKeys) -> None:
    client, key = keys.create("My app", role="admin")
    found = keys.verify(key)
    assert found is not None
    assert found.id == client.id and found.is_admin


@pytest.mark.parametrize(
    "wrong", ["", "lsg_", "lsg_wrong", "not-our-format", "lsg_" + "a" * 500]
)
def test_wrong_keys_are_refused(keys: ApiKeys, wrong: str) -> None:
    keys.create("My app")
    assert keys.verify(wrong) is None


def test_a_slightly_changed_key_is_refused(keys: ApiKeys) -> None:
    _, key = keys.create("My app")
    changed = key[:-1] + ("A" if key[-1] != "A" else "B")
    assert keys.verify(changed) is None


def test_turned_off_key_is_refused_and_can_come_back(keys: ApiKeys) -> None:
    client, key = keys.create("My app")
    assert keys.set_active(client.id, False)
    assert keys.verify(key) is None
    assert keys.set_active(client.id, True)
    assert keys.verify(key) is not None


def test_unknown_client_cannot_be_turned_off(keys: ApiKeys) -> None:
    assert keys.set_active("app_nobody", False) is False


def test_only_the_hash_is_stored(
    keys: ApiKeys, audit_db: Engine, tmp_path: Path
) -> None:
    _, key = keys.create("My app")
    audit_db.dispose()
    raw = b"".join(p.read_bytes() for p in tmp_path.iterdir() if p.is_file())
    assert key.encode() not in raw
    assert hash_key(key).encode() in raw


def test_list_never_shows_keys(keys: ApiKeys) -> None:
    _, key = keys.create("First")
    keys.create("Second", role="admin")
    listed = keys.list()
    assert [c.name for c in listed] == ["First", "Second"]
    assert key not in str(listed)


@pytest.mark.parametrize(("name", "role"), [("", "client"), ("x" * 101, "client")])
def test_bad_names_are_refused(keys: ApiKeys, name: str, role: str) -> None:
    with pytest.raises(ValueError, match="name"):
        keys.create(name, role)  # type: ignore[arg-type]


def test_bad_role_is_refused(keys: ApiKeys) -> None:
    with pytest.raises(ValueError, match="role"):
        keys.create("app", role="root")  # type: ignore[arg-type]
