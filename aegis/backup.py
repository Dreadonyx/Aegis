"""Consistent backups, verification, and restore for the Aegis database.

    python -m aegis.backup create --db data/aegis.sqlite3 --out backups/aegis-2026-10-11.sqlite3
    python -m aegis.backup verify backups/aegis-2026-10-11.sqlite3
    python -m aegis.backup restore backups/aegis-2026-10-11.sqlite3 --to data/aegis.sqlite3

Backups use SQLite's online backup API, so they are consistent while the collector writes. Each backup has
a manifest (<file>.json) with its SHA-256, schema version, row counts, and evidence-chain head. Verification
never writes to the backup: it checks the digest, runs integrity_check, and re-verifies the hash chain."""
import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from aegis.store import verify_chain_db

COUNTED = ("events", "raw_events", "findings", "incidents", "activity", "session_labels", "users")


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def inspect(path):
    """Read-only facts about a database file."""
    db = sqlite3.connect(f"file:{Path(path).resolve()}?mode=ro&immutable=1", uri=True)
    try:
        integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        version = db.execute("SELECT max(version) FROM schema_migrations").fetchone()[0] if "schema_migrations" in tables else None
        counts = {t: db.execute(f"SELECT count(*) FROM {t}").fetchone()[0] for t in COUNTED if t in tables}
        chain = verify_chain_db(db) if "raw_events" in tables else None
    finally:
        db.close()
    return {"integrity": integrity, "schema_version": version, "counts": counts, "chain": chain}


def create(db_path, out):
    out = Path(out)
    if out.exists():
        raise ValueError(f"{out} already exists; backups never overwrite")
    out.parent.mkdir(parents=True, exist_ok=True)
    source = sqlite3.connect(f"file:{Path(db_path).resolve()}?mode=ro", uri=True)
    target = sqlite3.connect(out)
    try:
        source.backup(target)
        target.execute("PRAGMA journal_mode=DELETE")  # one self-contained file, no WAL sidecar to lose or tamper with
    finally:
        target.close()
        source.close()
    os.chmod(out, 0o600)  # contains raw evidence, including attempted passwords
    facts = inspect(out)
    if facts["integrity"] != "ok" or (facts["chain"] and not facts["chain"]["valid"]):
        out.unlink()
        raise ValueError(f"The backup failed verification ({facts['integrity']}, chain {facts['chain']}); nothing was kept")
    manifest = {"created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "source": Path(db_path).name,
                "sha256": sha256(out), "bytes": out.stat().st_size, **facts}
    manifest_path = Path(f"{out}.json")
    manifest_path.write_text(json.dumps(manifest, indent=2))
    os.chmod(manifest_path, 0o600)
    return manifest


def verify(path):
    path = Path(path)
    manifest_path = Path(f"{path}.json")
    if not path.is_file() or not manifest_path.is_file():
        raise ValueError("Backup or its manifest is missing")
    manifest = json.loads(manifest_path.read_text())
    problems = []
    if sha256(path) != manifest.get("sha256"):
        problems.append("SHA-256 does not match the manifest (the file changed after backup)")
    for sidecar in ("-wal", "-journal"):
        if Path(f"{path}{sidecar}").exists():
            problems.append(f"unexpected {sidecar} file next to the backup; backups are single self-contained files")
    try:
        facts = inspect(path)
    except sqlite3.DatabaseError as error:
        problems.append(f"database is unreadable or malformed ({error})")
        return {"valid": False, "problems": problems, "manifest": manifest, "observed": None}
    if facts["integrity"] != "ok":
        problems.append(f"integrity_check: {facts['integrity']}")
    if facts["chain"] and not facts["chain"]["valid"]:
        problems.append(f"evidence chain: {facts['chain']['reason']} at record {facts['chain']['first_invalid_seq']}")
    if facts["counts"] != manifest.get("counts"):
        problems.append("row counts differ from the manifest")
    return {"valid": not problems, "problems": problems, "manifest": manifest, "observed": facts}


def restore(path, target):
    target = Path(target)
    if target.exists() or Path(f"{target}-wal").exists():
        raise ValueError(f"{target} exists. Stop Aegis and move the current database aside first; restore never overwrites")
    result = verify(path)
    if not result["valid"]:
        raise ValueError("Backup failed verification: " + "; ".join(result["problems"]))
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = Path(f"{target}.restoring")
    shutil.copyfile(path, partial)
    os.chmod(partial, 0o600)
    if sha256(partial) != result["manifest"]["sha256"]:
        partial.unlink()
        raise ValueError("Copy did not match the backup digest; nothing was restored")
    partial.rename(target)
    return {"restored_to": str(target), **result["manifest"]["chain"]} if result["manifest"].get("chain") else {"restored_to": str(target)}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Back up, verify, and restore the Aegis database.")
    commands = parser.add_subparsers(dest="command", required=True)
    c = commands.add_parser("create")
    c.add_argument("--db", default=os.environ.get("AEGIS_DB", "data/aegis.sqlite3"))
    c.add_argument("--out", required=True)
    commands.add_parser("verify").add_argument("backup")
    r = commands.add_parser("restore")
    r.add_argument("backup")
    r.add_argument("--to", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            result = create(args.db, args.out)
        elif args.command == "verify":
            result = verify(args.backup)
        else:
            result = restore(args.backup, args.to)
    except (ValueError, OSError, sqlite3.Error) as error:
        print(f"{args.command} failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0 if result.get("valid", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
