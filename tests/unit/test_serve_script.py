"""The checks in scripts/serve.py, the start command (Phase 17)."""

from __future__ import annotations

import importlib.util
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

from llm_gateway.settings import get_settings

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "serve.py"


@pytest.fixture
def serve(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[ModuleType]:
    """The script as a module, run in an empty folder (so no .env is read)."""
    monkeypatch.chdir(tmp_path)
    for name in ("GATEWAY_ENVIRONMENT", "GATEWAY_FINGERPRINT_KEY"):
        monkeypatch.delenv(name, raising=False)
    spec = importlib.util.spec_from_file_location("serve", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    get_settings.cache_clear()
    yield module
    get_settings.cache_clear()


def test_production_without_a_fingerprint_key_does_not_start(
    serve: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("GATEWAY_ENVIRONMENT", "production")
    assert serve.load_settings() is None
    out = capsys.readouterr().out
    assert "GATEWAY_FINGERPRINT_KEY" in out
    assert "secrets.token_hex(32)" in out  # says how to make one


def test_production_with_a_key_starts(
    serve: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GATEWAY_ENVIRONMENT", "production")
    monkeypatch.setenv("GATEWAY_FINGERPRINT_KEY", "k" * 64)
    settings = serve.load_settings()
    assert settings is not None and settings.environment == "production"


@pytest.mark.parametrize(
    ("make_index", "expected"),
    [(True, "served from"), (False, "not built yet")],
)
def test_dashboard_check(
    serve: ModuleType,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    make_index: bool,
    expected: str,
) -> None:
    folder = tmp_path / "dist"
    folder.mkdir()
    if make_index:
        (folder / "index.html").write_text("<div></div>", encoding="utf-8")
    serve.check_dashboard(folder)
    assert expected in capsys.readouterr().out


def test_dashboard_turned_off(
    serve: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    serve.check_dashboard(None)
    assert "turned off" in capsys.readouterr().out
