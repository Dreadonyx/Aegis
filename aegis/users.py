"""Manage Aegis accounts. Passwords are read interactively (or from stdin with --password-stdin), never from
arguments, so they do not land in shell history or process listings.

    python -m aegis.users add alice --role analyst
    python -m aegis.users list
    python -m aegis.users set-role alice admin
    python -m aegis.users disable alice
    python -m aegis.users reset-password alice
"""
import argparse
import getpass
import os
import re
import sqlite3
import sys

from aegis.auth import ROLES, hash_password
from aegis.store import Store

NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")


def read_password(stdin):
    if stdin:
        return sys.stdin.readline().rstrip("\n")
    first = getpass.getpass("Password (12+ characters): ")
    if first != getpass.getpass("Repeat password: "):
        raise ValueError("Passwords do not match")
    return first


def main(argv=None):
    parser = argparse.ArgumentParser(description="Manage Aegis accounts.")
    parser.add_argument("--db", default=os.environ.get("AEGIS_DB", "data/aegis.sqlite3"))
    commands = parser.add_subparsers(dest="command", required=True)
    add = commands.add_parser("add")
    add.add_argument("username")
    add.add_argument("--role", choices=ROLES, default="viewer")
    add.add_argument("--password-stdin", action="store_true")
    commands.add_parser("list")
    role = commands.add_parser("set-role")
    role.add_argument("username")
    role.add_argument("role", choices=ROLES)
    for name in ("disable", "enable"):
        commands.add_parser(name).add_argument("username")
    reset = commands.add_parser("reset-password")
    reset.add_argument("username")
    reset.add_argument("--password-stdin", action="store_true")
    args = parser.parse_args(argv)
    store = Store(args.db)
    try:
        if args.command == "add":
            if not NAME.match(args.username):
                raise ValueError("Usernames are 2-64 lowercase letters, digits, '.', '_' or '-'")
            store.add_user(args.username, hash_password(read_password(args.password_stdin)), args.role)
            print(f"Added {args.username} ({args.role}).")
        elif args.command == "list":
            for u in store.users():
                print(f"{u['username']:24s} {u['role']:8s} {'disabled' if u['disabled'] else 'active':9s} last login {u['last_login_at'] or 'never'}")
        elif args.command == "set-role":
            store.update_user(args.username, role=args.role)
            print(f"{args.username} is now {args.role}.")
        elif args.command in ("disable", "enable"):
            store.update_user(args.username, disabled=int(args.command == "disable"))
            print(f"{args.username} {args.command}d.")
        else:
            store.update_user(args.username, password_hash=hash_password(read_password(args.password_stdin)))
            print(f"Password reset for {args.username}.")
    except sqlite3.IntegrityError:
        print(f"An account named {args.username} already exists.", file=sys.stderr)
        return 2
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
