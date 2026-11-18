"""Checks that our packages only import what the architecture allows.

From docs/02-system-architecture.md: arrows only point one way. For example,
detectors must never import from the API or the pipeline. This test reads
the import lines of every file, so a wrong import fails right away instead
of slowly turning the code into a tangle.
"""

from __future__ import annotations

import ast
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parents[2] / "src" / "llm_gateway"

# Which parts each part may import from (besides itself).
ALLOWED_IMPORTS: dict[str, set[str]] = {
    "models": set(),
    "settings": set(),
    "detectors": {"models", "settings"},
    "dlp": {"models", "settings", "detectors"},
    "policy": {"models", "settings"},
    "providers": {"models", "settings"},
    "audit": {"models", "settings"},
    "core": {
        "models",
        "settings",
        "detectors",
        "dlp",
        "policy",
        "providers",
        "audit",
    },
    "api": {"models", "settings", "core", "policy", "providers", "audit"},
    "main": {"settings", "api", "core", "audit", "providers", "policy"},
}


def part_name(path: Path) -> str:
    """'detectors/base.py' -> 'detectors', 'models.py' -> 'models'."""
    relative = path.relative_to(PACKAGE_DIR)
    return relative.parts[0] if len(relative.parts) > 1 else relative.stem


def imported_parts(path: Path) -> set[str]:
    """Return the llm_gateway parts that a file imports."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module]
        for name in names:
            pieces = name.split(".")
            if pieces[0] == "llm_gateway" and len(pieces) > 1:
                found.add(pieces[1])
    return found


def test_every_part_has_an_import_rule() -> None:
    """A new package or module must be added to ALLOWED_IMPORTS on purpose."""
    parts = {part_name(p) for p in PACKAGE_DIR.rglob("*.py")} - {"__init__"}
    assert parts <= set(ALLOWED_IMPORTS), parts - set(ALLOWED_IMPORTS)


def test_imports_follow_the_architecture() -> None:
    problems = []
    for path in PACKAGE_DIR.rglob("*.py"):
        part = part_name(path)
        if part == "__init__":
            continue
        allowed = ALLOWED_IMPORTS[part] | {part}
        for target in imported_parts(path) - allowed:
            problems.append(f"{path.relative_to(PACKAGE_DIR)} imports {target}")
    assert not problems, "\n".join(problems)
