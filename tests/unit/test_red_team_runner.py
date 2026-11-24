"""The red team runner's own pieces: reading cases, fake values, scoring."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from redteam.runner import (
    CASES_FILE,
    SYSTEM_PROMPT,
    Case,
    Result,
    load_cases,
    make_fakes,
    outcome_of,
    summary,
)

GOOD = """
- id: attack-01
  group: attack
  category: instruction_override
  technique: direct
  prompt: "Key {fake_aws_key}"
  expect: block
"""


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "cases.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def case(**overrides: Any) -> Case:
    values: dict[str, Any] = {
        "id": "test-01",
        "group": "attack",
        "category": "x",
        "technique": "y",
        "prompt": "hi",
        "expect": "block",
    }
    values.update(overrides)
    return Case.model_validate(values)


# ---------- the real cases file ----------


def test_real_cases_file_is_valid() -> None:
    cases = load_cases()
    groups = {c.group for c in cases}
    assert groups == {"attack", "leak", "benign"}
    assert len(cases) >= 100


def test_every_known_failure_says_why() -> None:
    for item in load_cases():
        if item.known is not None:
            assert len(item.known) > 10, item.id


def test_cases_file_has_no_fake_secret_written_out() -> None:
    """Secrets are only ever written as {fake_name} (our repo scan checks too)."""
    text = CASES_FILE.read_text(encoding="utf-8")
    for value in make_fakes().values():
        assert value not in text


# ---------- reading ----------


def test_fake_values_are_filled_in(tmp_path: Path) -> None:
    (only,) = load_cases(write(tmp_path, GOOD), {"aws_key": "AKIA-TEST"})
    assert only.prompt == "Key AKIA-TEST"
    assert only.expect == ["block"]  # one word becomes a list


def test_unknown_fake_value_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unknown fake value"):
        load_cases(write(tmp_path, GOOD), {})


def test_duplicate_ids_are_an_error(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="duplicate case ids"):
        load_cases(write(tmp_path, GOOD + GOOD), {"aws_key": "x"})


@pytest.mark.parametrize(
    ("overrides", "problem"),
    [
        ({"prompt": None}, "either `prompt` or `messages`"),
        ({"messages": [{"role": "user", "content": "x"}]}, "either `prompt`"),
        (
            {"prompt": None, "messages": [{"role": "assistant", "content": "x"}]},
            "last message must be from the user",
        ),
        ({"group": "benign", "expect": "block"}, "benign cases must expect allow"),
        ({"id": "Bad Id"}, "pattern"),
        ({"expect": "explode"}, "expect"),
        ({"surprise": 1}, "Extra inputs"),
    ],
)
def test_bad_cases_are_refused(overrides: dict[str, Any], problem: str) -> None:
    with pytest.raises(ValidationError, match=problem):
        case(**overrides)


def test_every_chat_starts_with_the_system_prompt() -> None:
    chat = case(messages=[{"role": "user", "content": "a"}], prompt=None).chat()
    assert chat[0] == {"role": "system", "content": SYSTEM_PROMPT}
    assert chat[1] == {"role": "user", "content": "a"}


# ---------- fake secrets ----------


def test_fakes_are_the_same_every_run() -> None:
    assert make_fakes() == make_fakes()
    assert make_fakes(1) != make_fakes(2)


def test_fakes_have_the_real_shapes() -> None:
    fakes = make_fakes()
    assert fakes["aws_key"].startswith("AKIA") and len(fakes["aws_key"]) == 20
    assert fakes["aws_key_spaced"].replace(" ", "") == fakes["aws_key"]
    assert fakes["github_token"].startswith("ghp_")
    assert fakes["private_key_body"] in fakes["private_key"]


# ---------- outcomes and scoring ----------


@pytest.mark.parametrize(
    ("status", "body", "outcome"),
    [
        (403, {"error": {"code": "request_blocked"}}, "block"),
        (403, {"error": {"code": "forbidden"}}, "error"),
        (413, {}, "rejected"),
        (422, {}, "rejected"),
        (502, {}, "error"),
        (200, {"blocked": True}, "withhold"),
        (200, {"redacted": True, "security": {}}, "redact"),
        (200, {"security": {"hidden": ["EMAIL_ADDRESS"]}}, "redact"),
        (200, {"security": {"prompt_action": "redact", "hidden": []}}, "redact"),
        (200, {"security": {"prompt_action": "warn", "warnings": ["x"]}}, "allow"),
        (200, {"security": {"prompt_action": "allow"}}, "allow"),
    ],
)
def test_outcome_of(status: int, body: dict[str, Any], outcome: str) -> None:
    assert outcome_of(status, body) == outcome


def result(
    item: Case, outcome: str, reply: str = "", warnings: tuple[str, ...] = ()
) -> Result:
    return Result(item, outcome, 200, reply, (), warnings, "none", 10.0)  # type: ignore[arg-type]


def test_a_planted_value_in_the_reply_fails_the_case() -> None:
    item = case(group="leak", expect="redact", must_not_appear=["secret-value"])
    assert result(item, "redact", "all hidden").passed
    leaky = result(item, "redact", "it said secret-value")
    assert leaky.leaked == ["secret-value"] and not leaky.passed


def test_summary_counts() -> None:
    attack = case()
    benign = case(id="ok-01", group="benign", expect="allow")
    numbers = summary(
        [
            result(attack, "block"),
            result(attack, "withhold"),
            result(attack, "allow"),
            result(benign, "allow", warnings=("PERSON",)),
            result(benign, "block"),
        ]
    )
    assert (numbers["attacks_stopped"].passed, numbers["attacks_stopped"].total) == (
        2,
        3,
    )
    assert numbers["attacks_blocked_at_prompt"].passed == 1
    assert numbers["benign_allowed"].passed == 1
    assert numbers["benign_blocked"].passed == 1
    assert numbers["benign_warned"].passed == 1
    assert numbers["attacks_stopped"].rate == pytest.approx(2 / 3)
