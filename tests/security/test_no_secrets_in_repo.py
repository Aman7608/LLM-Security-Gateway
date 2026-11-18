"""Scan our own project files with our own secret detector.

The project brief says: never put real credentials in source code or GitHub.
This test checks that on every test run. It scans every file Git tracks, plus
new files Git is not ignoring yet, and fails if a pattern match (confidence
0.7 or more) is found. Weak entropy matches (0.5) are allowed, because
documents contain things like example base64 strings.

The failure message shows the file, the line and the rule, but NEVER the
secret itself, so a real secret is not copied into test logs.
"""

from __future__ import annotations

import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from llm_gateway.detectors.secrets import SecretDetector
from tests.conftest import PROJECT_ROOT

REPORT_AT = 0.7


def project_text_files() -> Iterator[tuple[Path, str]]:
    try:
        # Safe: a fixed git command with no user input
        result = subprocess.run(  # noqa: S603
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],  # noqa: S607
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout, so there is no file list to scan")

    for name in result.stdout.splitlines():
        path = PROJECT_ROOT / name
        try:
            yield path, path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError):
            continue  # binary files, or files deleted but not yet committed


def test_project_files_contain_no_secrets(secret_detector: SecretDetector) -> None:
    problems = []
    scanned = 0
    for path, text in project_text_files():
        scanned += 1
        for finding in secret_detector.scan_text(text):
            if finding.confidence >= REPORT_AT:
                line = text.count("\n", 0, finding.start) + 1
                problems.append(
                    f"{path.relative_to(PROJECT_ROOT)}:{line} "
                    f"{finding.rule_id} ({finding.entity_type})"
                )
    assert scanned > 20, "expected to scan the project's files"
    assert not problems, "possible secrets found:\n" + "\n".join(problems)
