"""Print how well the injection detector does on the test samples.

Run from the project folder:
    .\\.venv\\Scripts\\python.exe scripts\\injection_report.py

It shows, for the samples in tests/data/injection_samples.py:
  - how many attacks were detected (right category found)
  - how many attacks would be blocked (confidence 0.7 or more)
  - how many normal prompts got a warning, and how many would be blocked
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))  # so we can import tests.data

from llm_gateway.detectors.injection import InjectionDetector  # noqa: E402
from tests.data.injection_samples import BENIGN, KNOWN_MISSES, MALICIOUS  # noqa: E402

BLOCK_THRESHOLD = 0.7


def main() -> None:
    detector = InjectionDetector.from_file(PROJECT_ROOT / "config/injection_rules.yaml")

    def top(text: str) -> float:
        return max((f.confidence for f in detector.scan_text(text)), default=0.0)

    detected = sum(
        category in {f.category for f in detector.scan_text(text)}
        for text, category in MALICIOUS
    )
    blocked = sum(top(text) >= BLOCK_THRESHOLD for text, _ in MALICIOUS)
    benign_warned = sum(0 < top(text) < BLOCK_THRESHOLD for text in BENIGN)
    benign_blocked = sum(top(text) >= BLOCK_THRESHOLD for text in BENIGN)
    misses_caught = sum(bool(detector.scan_text(text)) for text, _ in KNOWN_MISSES)

    def line(label: str, count: int, total: int) -> None:
        print(f"{label:<42} {count:>3} / {total:<3} ({count / total:6.1%})")

    print(f"Block threshold: {BLOCK_THRESHOLD}\n")
    line("Attacks detected (right category)", detected, len(MALICIOUS))
    line("Attacks that would be blocked", blocked, len(MALICIOUS))
    line("Normal prompts with a warning only", benign_warned, len(BENIGN))
    line("Normal prompts that would be blocked", benign_blocked, len(BENIGN))
    line("Known-miss attacks caught", misses_caught, len(KNOWN_MISSES))

    print("\nAttacks found but NOT blocked (only warned):")
    for text, _ in MALICIOUS:
        if 0 < top(text) < BLOCK_THRESHOLD:
            print(f"  {top(text):.2f}  {text[:75]}")

    print("\nNormal prompts that would be blocked (false positives):")
    for text in BENIGN:
        if top(text) >= BLOCK_THRESHOLD:
            print(f"  {top(text):.2f}  {text[:75]}")


if __name__ == "__main__":
    main()
