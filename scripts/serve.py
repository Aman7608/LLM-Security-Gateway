r"""Start the whole gateway (API + dashboard) the way it runs for real.

Run from the project folder:
    .\.venv\Scripts\python.exe scripts\serve.py
    .\.venv\Scripts\python.exe scripts\serve.py --build    # build the dashboard first

Then open http://127.0.0.1:8000 for the dashboard, or /docs for the API docs.

Before it starts, it checks the things people forget:
  - production mode needs GATEWAY_FINGERPRINT_KEY (in .env)
  - the dashboard must be built (npm run build), or it is left out
  - an admin key is needed to sign in to the dashboard
It runs ONE worker on purpose: the rate limiter counts in memory, and the
language model takes about 1 GB per worker.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

from pydantic import ValidationError

from llm_gateway.settings import Settings, get_settings

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND = PROJECT_ROOT / "frontend"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0] if __doc__ else ""
    )
    parser.add_argument(
        "--build", action="store_true", help="build the dashboard first"
    )
    parser.add_argument(
        "--development",
        action="store_true",
        help="development mode (a fingerprint key is not required)",
    )
    args = parser.parse_args()

    os.chdir(PROJECT_ROOT)  # the config paths in the settings are relative
    # Real runs use production mode. A value set in the shell wins over .env,
    # so this applies even if .env says development (use --development for that)
    os.environ.setdefault(
        "GATEWAY_ENVIRONMENT", "development" if args.development else "production"
    )

    settings = load_settings()
    if settings is None:
        return 1
    if args.build and not build_dashboard():
        return 1
    check_dashboard(settings.dashboard_dir)
    check_admin_key()

    import uvicorn  # imported late: only needed once the checks pass

    print(f"\nStarting at http://{settings.host}:{settings.port}  (Ctrl+C to stop)\n")
    uvicorn.run(
        "llm_gateway.main:app",
        host=settings.host,
        port=settings.port,
        workers=1,
        access_log=False,  # the gateway writes its own log, without query strings
        server_header=False,
    )
    return 0


def load_settings() -> Settings | None:
    try:
        return get_settings()
    except ValidationError as error:
        print("The settings are not valid:\n")
        for problem in error.errors():
            print(f"  - {problem['msg']}")
        if "FINGERPRINT_KEY" in str(error):
            print(
                "\nProduction mode needs a secret fingerprint key. Make one with:\n"
                '  .\\.venv\\Scripts\\python.exe -c "import secrets; '
                'print(secrets.token_hex(32))"\n'
                "and put it in .env as GATEWAY_FINGERPRINT_KEY=...\n"
                "(Or try it out with --development.)"
            )
        return None


def build_dashboard() -> bool:
    npm = shutil.which("npm")
    if npm is None:
        print("npm was not found. Install Node.js, or build the dashboard elsewhere.")
        return False
    for step in (["ci", "--no-fund", "--no-audit"], ["run", "build"]):
        print(f"> npm {' '.join(step)}")
        if subprocess.run([npm, *step], cwd=FRONTEND, check=False).returncode != 0:  # noqa: S603
            print("Building the dashboard failed.")
            return False
    return True


def check_dashboard(folder: Path | None) -> None:
    if folder is None:
        print("Dashboard: turned off (GATEWAY_DASHBOARD_DIR is empty)")
    elif (folder / "index.html").is_file():
        print(f"Dashboard: served from {folder}")
    else:
        print(
            f"Dashboard: not built yet, so only the API runs. Build it with:\n"
            f"  {sys.executable} scripts\\serve.py --build"
        )


def check_admin_key() -> None:
    from llm_gateway.core.factory import build_audit  # slow import: only here

    audit = build_audit(get_settings())  # also creates or upgrades the tables
    try:
        admins = [c for c in audit.api_keys.list() if c.role == "admin" and c.active]
    finally:
        audit.engine.dispose()
    if not admins:
        print(
            "No admin key yet. To sign in to the dashboard, make one with:\n"
            "  .\\.venv\\Scripts\\python.exe scripts\\manage_keys.py "
            'create "Me" --role admin'
        )


if __name__ == "__main__":
    sys.exit(main())
