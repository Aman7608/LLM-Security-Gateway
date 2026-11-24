r"""Run the red team test set and write the report (Phase 16, FR-61).

Run from the project folder:
    .\.venv\Scripts\python.exe scripts\red_team.py

It sends every case in redteam/cases.yaml through the whole gateway (with the
offline mock AI), prints a summary, and writes docs/red-team-report.md.
Use --no-write to only print.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))  # so we can import redteam

from redteam.runner import (  # noqa: E402
    Result,
    Score,
    by_category,
    load_cases,
    run_all,
    summary,
)

REPORT = PROJECT_ROOT / "docs" / "red-team-report.md"


def pct(score: Score) -> str:
    return f"{score.passed} / {score.total} ({score.rate:.0%})"


def words(value: str) -> str:
    return value.replace("_", " ")


def cell(text: str) -> str:
    """Make text safe inside a Markdown table cell."""
    return text.replace("|", "\\|").replace("\n", " ").replace("<", "&lt;")[:110]


def build_report(results: list[Result], when: datetime) -> str:
    numbers = summary(results)
    attacks = [r for r in results if r.case.group == "attack"]
    lines = [
        "# Red Team Report",
        "",
        "This file is written by `scripts/red_team.py`. Don't edit it by hand: "
        "run the script again. How the test works and what the results mean "
        "is explained in [16-red-team.md](16-red-team.md).",
        "",
        f"- **Run on:** {when:%d %B %Y, %H:%M} UTC",
        f"- **Cases:** {len(results)} "
        f"({len(attacks)} attacks, "
        f"{sum(r.case.group == 'leak' for r in results)} data leaks, "
        f"{sum(r.case.group == 'benign' for r in results)} normal requests)",
        "- **Setup:** the whole gateway (API, detectors, default policy, "
        "audit log) with the offline mock AI",
        "",
        "## Summary",
        "",
        "| Measure | Result |",
        "|---|---|",
        f"| Attacks stopped (prompt blocked or answer withheld) | "
        f"**{pct(numbers['attacks_stopped'])}** |",
        f"| ...of those, blocked before the AI saw them | "
        f"{pct(numbers['attacks_blocked_at_prompt'])} |",
        f"| Data leaks prevented | **{pct(numbers['leaks_prevented'])}** |",
        f"| Normal requests let through | **{pct(numbers['benign_allowed'])}** |",
        f"| Normal requests wrongly blocked (false positives) | "
        f"**{pct(numbers['benign_blocked'])}** |",
        f"| Normal requests wrongly changed (hidden parts) | "
        f"{pct(numbers['benign_changed'])} |",
        f"| Normal requests with a warning in the log | "
        f"{pct(numbers['benign_warned'])} |",
        f"| Time per request (median / slowest) | "
        f"{numbers['median_ms']:.0f} ms / {numbers['slowest_ms']:.0f} ms |",
        "",
        "## Attacks by category",
        "",
        "| Category | Stopped |",
        "|---|---|",
    ]
    lines += [
        f"| {words(name)} | {pct(score)} |"
        for name, score in by_category(results, "attack")
    ]
    lines += [
        "",
        "## Data leaks by category",
        "",
        "| Category | Prevented |",
        "|---|---|",
    ]
    lines += [
        f"| {words(name)} | {pct(score)} |"
        for name, score in by_category(results, "leak")
    ]

    got_through = [r for r in attacks if not r.stopped]
    lines += [
        "",
        f"## Attacks that got through ({len(got_through)})",
        "",
        "These reached the AI. A real AI might or might not follow them, but "
        "the gateway did not stop them.",
        "",
        "| Case | Technique | What it said | Why it was missed | Warned |",
        "|---|---|---|---|---|",
    ]
    for r in got_through:
        said = r.case.prompt or r.case.messages[-1].content
        if r.case.documents:
            said = f"(in a document) {r.case.documents[0].content}"
        warning_text = ", ".join(r.warnings) or "no"
        lines.append(
            f"| `{r.case.id}` | {r.case.technique} | {cell(said)} | "
            f"{cell(r.case.known or 'NEW: not explained yet')} | {cell(warning_text)} |"
        )

    second_line = [r for r in attacks if r.outcome == "withhold"]
    lines += [
        "",
        f"## Caught only by the answer check ({len(second_line)})",
        "",
        "The prompt got through, the AI (a test AI that leaks on purpose) "
        "repeated its hidden instructions, and the answer check withheld it.",
        "",
    ]
    lines += [f"- `{r.case.id}`: {r.case.technique}" for r in second_line]

    leak_failures = [r for r in results if r.case.group == "leak" and not r.passed]
    lines += ["", f"## Data leaks not prevented ({len(leak_failures)})", ""]
    lines += [
        f"- `{r.case.id}` ({r.case.technique}): "
        f"{r.case.known or 'NEW: not explained yet'}"
        for r in leak_failures
    ]

    benign = [r for r in results if r.case.group == "benign"]
    wrong = [r for r in benign if r.outcome != "allow"]
    warned = [r for r in benign if r.outcome == "allow" and r.warnings]
    lines += ["", "## Normal requests", ""]
    if wrong:
        lines += [f"- **Not allowed:** `{r.case.id}` got {r.outcome}" for r in wrong]
    else:
        lines.append("None was blocked or changed.")
    lines += ["", "Allowed, but with a warning in the audit log:", ""]
    lines += [
        f"- `{r.case.id}` ({r.case.technique}): {', '.join(r.warnings)}" for r in warned
    ]

    unexpected = [r for r in results if not r.passed and not r.case.known]
    lines += ["", "## Changes since the cases were marked", ""]
    newly = [r for r in results if r.passed and r.case.known]
    if not unexpected and not newly:
        lines.append("None: every case did what its notes say.")
    lines += [f"- **New failure:** `{r.case.id}` got {r.outcome}" for r in unexpected]
    lines += [
        f"- **Now passes:** `{r.case.id}` (remove its `known:` note)" for r in newly
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0] if __doc__ else ""
    )
    parser.add_argument(
        "--no-write", action="store_true", help="only print the summary"
    )
    args = parser.parse_args()

    cases = load_cases()
    print(
        f"Running {len(cases)} cases through the gateway (loading the models first)..."
    )
    results = run_all(cases)
    numbers = summary(results)
    for label, key in [
        ("Attacks stopped", "attacks_stopped"),
        ("  blocked before the AI", "attacks_blocked_at_prompt"),
        ("Data leaks prevented", "leaks_prevented"),
        ("Normal requests let through", "benign_allowed"),
        ("Normal requests wrongly blocked", "benign_blocked"),
        ("Cases that did what their notes say", "all_as_expected"),
    ]:
        print(f"{label:<38} {pct(numbers[key])}")
    surprises = [r.case.id for r in results if r.passed == bool(r.case.known)]
    if surprises:
        print(f"\nCases that changed since they were marked: {', '.join(surprises)}")
    if not args.no_write:
        # newline="\n": the same line endings on every computer
        REPORT.write_text(
            build_report(results, datetime.now(UTC)), encoding="utf-8", newline="\n"
        )
        print(f"\nReport written to {REPORT.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
