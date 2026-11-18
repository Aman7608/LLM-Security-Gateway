"""Tests for llm_gateway.detectors.normalizer."""

from __future__ import annotations

import pytest

from llm_gateway.detectors.normalizer import normalize


def test_lowercases_and_collapses_whitespace() -> None:
    result = normalize("  Hello\t\tWORLD\n\nagain  ")
    assert result.text == "hello world again"


def test_empty_text() -> None:
    result = normalize("")
    assert result.text == ""
    assert result.compact == ""
    assert result.offsets == ()


def test_removes_and_reports_invisible_characters() -> None:
    text = "ig​nore⁠ this"
    result = normalize(text)
    assert result.text == "ignore this"
    assert result.invisible_positions == (2, 7)


def test_removes_control_characters() -> None:
    result = normalize("ig\x00no\x1bre")
    assert result.text == "ignore"
    assert len(result.invisible_positions) == 2


def test_keeps_harmless_joiners_out_of_the_report() -> None:
    """Emoji and some languages use zero-width joiners in normal writing."""
    result = normalize("family \U0001f468‍\U0001f469")
    assert result.invisible_positions == ()


@pytest.mark.parametrize(
    "disguised",
    [
        "Іgnore",  # Cyrillic capital I
        "ignоre",  # Cyrillic o
        "ｉｇｎｏｒｅ",  # full-width letters
        "\U0001d422\U0001d420\U0001d427\U0001d428\U0001d42b\U0001d41e",  # math bold
        "ïgnöré",  # accents
        "IGNORE",
    ],
)
def test_disguised_letters_become_plain(disguised: str) -> None:
    assert normalize(disguised).text == "ignore"


def test_curly_quotes_become_plain() -> None:
    assert normalize("don’t “stop”").text == 'don\'t "stop"'


def test_reports_mixed_alphabet_words() -> None:
    text = "please іgnore this"  # Cyrillic i inside a Latin word
    result = normalize(text)
    assert result.mixed_script_spans == ((7, 13),)
    assert text[7:13] == "іgnore"


def test_whole_words_in_other_alphabets_are_not_mixed() -> None:
    assert normalize("Привет, как дела?").mixed_script_spans == ()
    assert normalize("नमस्ते दुनिया").mixed_script_spans == ()


def test_compact_view_keeps_only_letters_and_digits() -> None:
    assert normalize("I.g-n o_r!e 2").compact == "ignore2"


def test_offsets_point_back_to_the_original() -> None:
    text = "AB​  CＤ"  # invisible char, double space, full-width D
    result = normalize(text)
    assert result.text == "ab cd"
    for clean_char, original_index in zip(result.text, result.offsets, strict=True):
        if clean_char != " ":
            assert normalize(text[original_index]).text == clean_char


def test_original_span_maps_a_match_back() -> None:
    text = "Please  IGNORE​ this"
    result = normalize(text)
    start = result.text.index("ignore")
    original_start, original_end = result.original_span(start, start + 6)
    assert text[original_start:original_end] == "IGNORE"


def test_original_span_for_compact_view() -> None:
    text = "x I.g.n.o.r.e y"
    result = normalize(text)
    start = result.compact.index("ignore")
    original = result.original_span(start, start + 6, compact=True)
    assert text[original[0] : original[1]] == "I.g.n.o.r.e"


@pytest.mark.parametrize("span", [(0, 0), (3, 2), (-1, 2), (0, 99)])
def test_original_span_rejects_bad_spans(span: tuple[int, int]) -> None:
    with pytest.raises(ValueError):
        normalize("hello").original_span(*span)
