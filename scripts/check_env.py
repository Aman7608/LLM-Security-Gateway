"""Check that the development environment is set up correctly.

Run it from the project folder:
    .\\.venv\\Scripts\\python.exe scripts\\check_env.py

Each check prints PASS, WARN or FAIL. WARN is for tools we only need in
later phases. The script exits with code 1 if anything FAILs.
It only reads information and never changes anything.
"""

from __future__ import annotations

import importlib.metadata
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MIN_PYTHON = (3, 12)
REQUIRED_PACKAGES = (
    "fastapi",
    "uvicorn",
    "pydantic",
    "pydantic-settings",
    "PyYAML",
    "httpx",
    "pytest",
    "pytest-cov",
    "ruff",
    "mypy",
)


class Report:
    """Prints check results and counts how many failed."""

    def __init__(self) -> None:
        self.failures = 0

    def add(self, status: str, name: str, detail: str = "") -> None:
        if status == "FAIL":
            self.failures += 1
        print(f"[{status:4}] {name:<26} {detail}")


def run(cmd: list[str]) -> tuple[int, str]:
    """Run a command and return (exit code, output). Never raises an error."""
    try:
        result = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
            cwd=PROJECT_ROOT,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return 1, str(error)
    return result.returncode, (result.stdout + result.stderr).strip()


def check_python(report: Report) -> None:
    version = ".".join(str(part) for part in sys.version_info[:3])
    if sys.version_info[:2] >= MIN_PYTHON:
        report.add("PASS", "Python version", version)
    else:
        report.add("FAIL", "Python version", f"{version} (need 3.12 or newer)")


def check_venv(report: Report) -> None:
    # Inside a venv, sys.prefix points to the venv and sys.base_prefix
    # points to the real Python install.
    expected = (PROJECT_ROOT / ".venv").resolve()
    if sys.prefix == sys.base_prefix:
        report.add("FAIL", "Virtual environment", "not running inside .venv")
    elif Path(sys.prefix).resolve() == expected:
        report.add("PASS", "Virtual environment", str(expected))
    else:
        report.add("WARN", "Virtual environment", f"a different venv: {sys.prefix}")


def check_packages(report: Report) -> None:
    for package in REQUIRED_PACKAGES:
        try:
            version = importlib.metadata.version(package)
            report.add("PASS", f"package {package}", version)
        except importlib.metadata.PackageNotFoundError:
            report.add("FAIL", f"package {package}", "not installed")


def check_git(report: Report) -> None:
    if not shutil.which("git"):
        report.add("FAIL", "Git", "not found")
        return

    # The git repo must start at this project folder, not a parent folder.
    code, top = run(["git", "rev-parse", "--show-toplevel"])
    if code == 0 and Path(top).resolve() == PROJECT_ROOT:
        report.add("PASS", "Git repo root", top)
    else:
        report.add("FAIL", "Git repo root", top or "not a git repo")

    # .env holds real secrets, so it must never be tracked by git.
    _, tracked = run(["git", "ls-files", ".env"])
    if tracked:
        report.add("FAIL", ".env not in git", ".env is tracked by git!")
    else:
        report.add("PASS", ".env not in git")


def check_later_tools(report: Report) -> None:
    """Tools for later phases. Missing ones are warnings, not failures."""
    if shutil.which("gh"):
        code, _ = run(["gh", "auth", "status"])
        signed_in = code == 0
    else:
        signed_in = False
    report.add(
        "PASS" if signed_in else "WARN",
        "GitHub CLI signed in",
        "yes" if signed_in else "gh missing or not signed in",
    )

    if shutil.which("docker"):
        code, version = run(["docker", "info", "--format", "{{.ServerVersion}}"])
        running = code == 0 and bool(version)
        report.add(
            "PASS" if running else "WARN",
            "Docker engine running",
            version if running else "start Docker Desktop (needed in Phase 15)",
        )
    else:
        report.add("WARN", "Docker", "not installed (needed in Phase 15)")

    if shutil.which("node"):
        report.add("PASS", "Node.js", run(["node", "--version"])[1])
    else:
        report.add("WARN", "Node.js", "not installed (needed in Phase 14)")


def main() -> int:
    print(f"Project folder: {PROJECT_ROOT}\n")
    report = Report()
    check_python(report)
    check_venv(report)
    check_packages(report)
    check_git(report)
    check_later_tools(report)

    if report.failures:
        print(f"\nFAILED: {report.failures} check(s) failed")
        return 1
    print("\nOK: all required checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
