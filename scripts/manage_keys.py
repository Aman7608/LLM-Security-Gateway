r"""Create, list and turn off API keys for the gateway.

Run from the project folder with .\.venv\Scripts\python.exe:

    python scripts\manage_keys.py create "My chat app"            # a client key
    python scripts\manage_keys.py create "Aman" --role admin      # an admin key
    python scripts\manage_keys.py list
    python scripts\manage_keys.py disable app_1a2b3c4d5e6f
    python scripts\manage_keys.py enable app_1a2b3c4d5e6f

A new key is printed ONCE. Only its hash is stored, so it cannot be shown
again: copy it somewhere safe (a password manager), never into git.

This needs access to the database itself (GATEWAY_DATABASE_URL), so only
someone who runs the gateway can make keys. There is no API route for it,
so a stolen admin key cannot make more keys.
"""

from __future__ import annotations

import argparse

from llm_gateway.core.factory import build_audit
from llm_gateway.settings import get_settings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="make a new key")
    create.add_argument("name", help="who or what the key is for")
    create.add_argument("--role", choices=["client", "admin"], default="client")
    commands.add_parser("list", help="show all clients (never their keys)")
    for name in ("disable", "enable"):
        cmd = commands.add_parser(name, help=f"{name} a key")
        cmd.add_argument("client_id")
    args = parser.parse_args()

    audit = build_audit(get_settings())
    keys = audit.api_keys
    try:
        if args.command == "create":
            client, key = keys.create(args.name, args.role)
            print(f"Created {client.role} key for {client.name!r} (id {client.id}).")
            print()
            print(f"    {key}")
            print()
            print("This is the only time the key is shown. Store it safely.")
        elif args.command == "list":
            for c in keys.list():
                state = "active" if c.active else "OFF"
                made = f"{c.created_at:%Y-%m-%d}"
                print(f"{c.id}  {c.role:<6}  {state:<6}  {made}  {c.name}")
        else:
            found = keys.set_active(args.client_id, args.command == "enable")
            print(
                f"{args.command}d {args.client_id}" if found else "No such client id."
            )
            return 0 if found else 1
    finally:
        audit.engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
