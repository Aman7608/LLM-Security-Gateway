"""Makes a cleaned-up copy of text so tricks cannot hide attacks from detectors.

Attackers often disguise text, for example:
    "Ign<zero-width space>ore"   invisible characters inside words
    "Іgnore" with a Cyrillic "І"  letters that look the same but are different
    "ＩＧＮＯＲＥ"                  full-width or fancy Unicode letters
    "I.g.n.o.r.e"                punctuation between letters

normalize() undoes these tricks and returns a NormalizedText. The cleaned text
is ONLY used for scanning. The text sent to the AI is never changed here.

Every character of the cleaned text remembers which character of the original
text it came from (the "offsets"). That way, when a detector finds something
in the cleaned text, we can point to the exact place in the original text.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

# Invisible characters that appear in normal writing (emoji sequences, Persian,
# Hindi). They are removed from the scan view but not reported as suspicious.
HARMLESS_INVISIBLE = frozenset({"‌", "‍"})

# Letters from other alphabets that look like Latin letters, plus fancy quotes.
# Keys are lowercase, because text is lowercased before this table is used.
HOMOGLYPHS: dict[str, str] = {
    # Cyrillic
    "а": "a",
    "в": "b",
    "е": "e",
    "ё": "e",
    "к": "k",
    "м": "m",
    "н": "h",
    "о": "o",
    "р": "p",
    "с": "c",
    "т": "t",
    "у": "y",
    "х": "x",
    "ѕ": "s",
    "і": "i",
    "ї": "i",
    "ј": "j",
    "ԁ": "d",
    "ԛ": "q",
    "ԝ": "w",
    "һ": "h",
    "ӏ": "l",
    # Greek
    "α": "a",
    "β": "b",
    "ε": "e",
    "ι": "i",
    "κ": "k",
    "ν": "v",
    "ο": "o",
    "ρ": "p",
    "τ": "t",
    "υ": "u",
    "χ": "x",
    # Other Latin look-alikes
    "ɡ": "g",
    # Curly quotes and backticks become plain quotes
    "‘": "'",
    "’": "'",
    "‚": "'",
    "‛": "'",
    "`": "'",
    "“": '"',
    "”": '"',
    "„": '"',
    "‟": '"',
}

_LOOKALIKE_LETTERS = frozenset(
    key for key, value in HOMOGLYPHS.items() if value.isalpha()
)
_WORD = re.compile(r"\w+")


@dataclass(frozen=True)
class NormalizedText:
    """The original text plus cleaned-up views of it for scanning.

    text:      lowercase, look-alike letters replaced, invisible characters
               removed, accents removed, all whitespace turned into one space.
    compact:   the same, but with ONLY letters and digits kept. "I.g.n.o.r.e"
               becomes "ignore". Used for short phrase checks.
    offsets / compact_offsets: for each character in text / compact, the
               position in the original text it came from.
    invisible_positions: where hidden characters were found in the original.
    mixed_script_spans: words that mix Latin letters with look-alike letters
               from other alphabets, like "Іgnore". Normal text rarely does this.
    """

    original: str
    text: str
    offsets: tuple[int, ...]
    compact: str
    compact_offsets: tuple[int, ...]
    invisible_positions: tuple[int, ...]
    mixed_script_spans: tuple[tuple[int, int], ...]

    def original_span(
        self, start: int, end: int, *, compact: bool = False
    ) -> tuple[int, int]:
        """Turn a span in the cleaned text into a span in the original text."""
        offsets = self.compact_offsets if compact else self.offsets
        if not 0 <= start < end <= len(offsets):
            raise ValueError(f"span {start}:{end} is outside the cleaned text")
        return offsets[start], offsets[end - 1] + 1


def normalize(text: str) -> NormalizedText:
    """Build the cleaned views of text. See the module docstring for why."""
    # Each item is (cleaned character, position in the original text).
    chars: list[tuple[str, int]] = []
    invisible: list[int] = []

    for index, char in enumerate(text):
        # Format (Cf) and control (Cc) characters are invisible. Keep normal
        # whitespace like spaces, tabs and newlines.
        if unicodedata.category(char) in ("Cf", "Cc") and not char.isspace():
            if char not in HARMLESS_INVISIBLE:
                invisible.append(index)
            continue

        # NFKD splits fancy letters into plain ones ("Ｉ" -> "I", "é" -> "e" +
        # an accent mark). We then drop the accent marks.
        for piece in unicodedata.normalize("NFKD", char):
            if unicodedata.combining(piece):
                continue
            # casefold() is a stronger lower() that also handles letters like "ß".
            for small in piece.casefold():
                chars.append((HOMOGLYPHS.get(small, small), index))

    chars = _collapse_whitespace(chars)
    compact = [(char, index) for char, index in chars if char.isalnum()]

    return NormalizedText(
        original=text,
        text="".join(char for char, _ in chars),
        offsets=tuple(index for _, index in chars),
        compact="".join(char for char, _ in compact),
        compact_offsets=tuple(index for _, index in compact),
        invisible_positions=tuple(invisible),
        mixed_script_spans=_find_mixed_script_words(text),
    )


def _collapse_whitespace(chars: list[tuple[str, int]]) -> list[tuple[str, int]]:
    """Turn every run of spaces, tabs and newlines into a single space."""
    result: list[tuple[str, int]] = []
    for char, index in chars:
        if char.isspace():
            if result and result[-1][0] != " ":
                result.append((" ", index))
        else:
            result.append((char, index))
    if result and result[-1][0] == " ":
        result.pop()
    return result


def _find_mixed_script_words(text: str) -> tuple[tuple[int, int], ...]:
    """Find words that mix Latin letters with look-alike letters, like "Іgnore"."""
    spans = []
    for match in _WORD.finditer(text):
        word = match.group()
        has_latin = any("a" <= char <= "z" for char in word.lower())
        has_lookalike = any(char.casefold() in _LOOKALIKE_LETTERS for char in word)
        if has_latin and has_lookalike:
            spans.append((match.start(), match.end()))
    return tuple(spans)
