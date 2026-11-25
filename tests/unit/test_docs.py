"""Checks that keep the documents correct (Phase 18).

Docs go out of date quietly. These tests catch the common cases: a setting
added to the code but not documented, a wrong default, a broken link, or a
guide missing from the README.
"""

from __future__ import annotations

import re
from enum import Enum
from pathlib import Path
from typing import Any

import pytest

from llm_gateway.settings import Settings

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
MARKDOWN = [
    ROOT / "README.md",
    *sorted(DOCS.glob("*.md")),
    ROOT / "config" / "README.md",
    ROOT / "SECURITY.md",
]
SETTINGS_DOC = DOCS / "settings.md"


def env_name(field: str) -> str:
    return "GATEWAY_" + field.upper()


def as_env_text(value: Any) -> str:
    """A default value written the way you would put it in .env."""
    if value is None:
        return "not set"
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, Enum):
        return str(value.value)
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def documented_defaults() -> dict[str, str]:
    """{setting: default} from the tables in docs/settings.md."""
    rows = re.findall(
        r"^\| `(GATEWAY_[A-Z_]+)` \| (?:`([^`]*)`|not set) \|",
        SETTINGS_DOC.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    return {name: default if default else "not set" for name, default in rows}


# ---------- settings ----------


def test_every_setting_is_documented_with_its_default() -> None:
    documented = documented_defaults()
    for field, info in Settings.model_fields.items():
        name = env_name(field)
        assert name in documented, f"{name} is missing from docs/settings.md"
        assert documented[name] == as_env_text(info.default), name


def test_settings_doc_lists_nothing_that_does_not_exist() -> None:
    real = {env_name(field) for field in Settings.model_fields}
    assert set(documented_defaults()) == real


def test_every_setting_is_in_the_env_example() -> None:
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    for field in Settings.model_fields:
        assert re.search(rf"^{env_name(field)}=", example, re.MULTILINE), field


# ---------- links and the list of guides ----------


def links(path: Path) -> list[str]:
    """Relative links in a Markdown file, without #anchors."""
    found = re.findall(r"\]\(([^)\s]+)\)", path.read_text(encoding="utf-8"))
    return [
        link.split("#")[0]
        for link in found
        if not link.startswith(("http://", "https://", "mailto:", "#"))
    ]


@pytest.mark.parametrize("path", MARKDOWN, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_relative_links_point_to_real_files(path: Path) -> None:
    for link in links(path):
        target = (path.parent / link).resolve()
        assert target.exists(), f"{path.name} links to missing {link}"


def test_readme_lists_every_guide() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for doc in sorted(DOCS.glob("*.md")):
        assert f"docs/{doc.name}" in readme, f"README does not list {doc.name}"


# ---------- writing style ----------


@pytest.mark.parametrize("path", MARKDOWN, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_no_em_dashes(path: Path) -> None:
    """The project's writing style: plain sentences, no em dashes."""
    assert "—" not in path.read_text(encoding="utf-8")
