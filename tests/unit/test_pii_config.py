"""Tests for loading and checking config/pii_entities.yaml.

These do not load the language model, so they are fast.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from llm_gateway.detectors.base import DetectorConfigError
from llm_gateway.detectors.pii import PIIConfigError, load_pii_config
from tests.conftest import PII_CONFIG_FILE


def a_config(**overrides: Any) -> dict[str, Any]:
    config: dict[str, Any] = {
        "version": 1,
        "language": "en",
        "spacy_model": "en_core_web_lg",
        "phone_regions": ["IN"],
        "entities": {"EMAIL_ADDRESS": {"min_confidence": 0.5, "severity": "medium"}},
    }
    config.update(overrides)
    return config


def write_config(tmp_path: Path, data: Any) -> Path:
    path = tmp_path / "pii.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def test_the_real_config_loads() -> None:
    config = load_pii_config(PII_CONFIG_FILE)
    enabled = config.enabled_entities
    assert {"EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON", "IN_AADHAAR"} <= set(enabled)
    assert "DATE_TIME" not in enabled  # turned off on purpose
    assert "IN" in config.phone_regions


def test_a_small_valid_config_loads(tmp_path: Path) -> None:
    config = load_pii_config(write_config(tmp_path, a_config()))
    assert list(config.enabled_entities) == ["EMAIL_ADDRESS"]


def test_pii_errors_are_detector_config_errors() -> None:
    assert issubclass(PIIConfigError, DetectorConfigError)


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(PIIConfigError, match="cannot read"):
        load_pii_config(tmp_path / "nope.yaml")


def test_broken_yaml(tmp_path: Path) -> None:
    path = tmp_path / "pii.yaml"
    path.write_text("entities: {EMAIL", encoding="utf-8")
    with pytest.raises(PIIConfigError, match="not valid YAML"):
        load_pii_config(path)


def test_top_level_must_be_a_mapping(tmp_path: Path) -> None:
    with pytest.raises(PIIConfigError, match="mapping"):
        load_pii_config(write_config(tmp_path, ["EMAIL_ADDRESS"]))


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"version": 2}, "version"),
        ({"language": "fr"}, "language"),
        ({"spacy_model": "../../evil"}, "spacy_model"),
        ({"phone_regions": []}, "phone_regions"),
        ({"phone_regions": ["IND"]}, "2-letter"),
        ({"entities": {"email": {"min_confidence": 0.5, "severity": "low"}}}, "UPPER"),
        (
            {"entities": {"EMAIL_ADDRESS": {"min_confidence": 0, "severity": "low"}}},
            "min_confidence",
        ),
        (
            {
                "entities": {
                    "EMAIL_ADDRESS": {"min_confidence": 0.5, "severity": "none"}
                }
            },
            "cannot be 'none'",
        ),
        (
            {
                "entities": {
                    "EMAIL_ADDRESS": {
                        "min_confidence": 0.5,
                        "severity": "low",
                        "enabled": False,
                    }
                }
            },
            "at least one",
        ),
        ({"unknown_setting": True}, "unknown_setting"),
    ],
)
def test_bad_configs_are_rejected(
    tmp_path: Path, overrides: dict[str, Any], message: str
) -> None:
    with pytest.raises(PIIConfigError, match=message):
        load_pii_config(write_config(tmp_path, a_config(**overrides)))
