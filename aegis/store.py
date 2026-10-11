import hashlib
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime, timezone

EVENT_LIMIT = 50000
ERROR_LIMIT = 1000  # quarantined lines retained per source; oldest are trimmed
GENESIS = "0" * 64

# Ordered, append-only. Never edit an applied migration; add a new one.
MIGRATIONS = [
    (1, "Baseline v0.2 schema", [
        "CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, source TEXT NOT NULL, body TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS workflow(id TEXT PRIMARY KEY, status TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS events_source ON events(source)",
        """CREATE TABLE IF NOT EXISTS activity(
            id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL,
            timestamp TEXT NOT NULL, kind TEXT NOT NULL, body TEXT NOT NULL)""",
        "CREATE INDEX IF NOT EXISTS activity_incident ON activity(incident_id, id)",
    ]),
    (2, "Hash-chained raw evidence, source checkpoints, quarantined lines", [
        # raw holds the original record bytes and may contain attempted passwords.
        # No API returns it. purge_raw() clears it while keeping the chain verifiable.
        """CREATE TABLE raw_events(
            seq INTEGER PRIMARY KEY,
            source_event_key TEXT NOT NULL UNIQUE,
            event_id TEXT NOT NULL,
            ingestion_mode TEXT NOT NULL CHECK(ingestion_mode IN ('synthetic', 'import', 'live')),
            source_id TEXT NOT NULL,
            source_type TEXT NOT NULL,
            file_id TEXT,
            locator TEXT,
            ingested_at TEXT NOT NULL,
            parser_version TEXT NOT NULL,
            schema_version INTEGER NOT NULL,
            raw BLOB,
            raw_sha256 TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            chain_hash TEXT NOT NULL UNIQUE)""",
        "CREATE INDEX raw_events_event ON raw_events(event_id)",
        """CREATE TABLE sources(
            source_id TEXT PRIMARY KEY,
            source_type TEXT NOT NULL,
            ingestion_mode TEXT NOT NULL,
            file_id TEXT,
            file_offset INTEGER NOT NULL DEFAULT 0,
            discarding INTEGER NOT NULL DEFAULT 0,
            last_event_time TEXT,
            last_commit_at TEXT NOT NULL,
            events_total INTEGER NOT NULL DEFAULT 0,
            duplicates_total INTEGER NOT NULL DEFAULT 0,
            malformed_total INTEGER NOT NULL DEFAULT 0,
            rotations_total INTEGER NOT NULL DEFAULT 0,
            truncations_total INTEGER NOT NULL DEFAULT 0)""",
        """CREATE TABLE ingest_errors(
            id INTEGER PRIMARY KEY,
            source_id TEXT NOT NULL,
            file_id TEXT,
            locator TEXT,
            ingested_at TEXT NOT NULL,
            reason TEXT NOT NULL,
            line_sha256 TEXT,
            line_bytes INTEGER)""",
        "CREATE INDEX ingest_errors_source ON ingest_errors(source_id, id)",
    ]),
]

RAW_COLUMNS = ("seq", "source_event_key", "event_id", "ingestion_mode", "source_id", "source_type", "file_id",
               "locator", "ingested_at", "parser_version", "schema_version", "raw_sha256")


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def chain_link(prev_hash, row):
    """Each link commits to the previous link, the raw digest, and all provenance metadata."""
    fields = [prev_hash] + [row[k] for k in RAW_COLUMNS]
    return hashlib.sha256(json.dumps(fields, separators=(",", ":")).encode()).hexdigest()


class Store:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = str(path)
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
        self.migrate()

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        try:
            with db:
                yield db
        finally:
            db.close()

    def migrate(self):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)")
            applied = {r[0] for r in db.execute("SELECT version FROM schema_migrations")}
            for version, name, statements in MIGRATIONS:
                if version in applied:
                    continue
                for statement in statements:
                    db.execute(statement)
                db.execute("INSERT INTO schema_migrations VALUES (?, ?, ?)", (version, name, utcnow()))

    def schema_version(self):
        with self.connect() as db:
            return db.execute("SELECT max(version) FROM schema_migrations").fetchone()[0]

    def ingest(self, events):
        """Store canonical events without raw evidence (tests and pre-2.0 callers)."""
        return self.commit([{"event": e} for e in events])["inserted"]

    def commit(self, records=(), origin=None, errors=(), checkpoint=None):
        """Write one batch in a single transaction: canonical events, hash-chained raw evidence,
        quarantined lines, and the source checkpoint. Nothing is kept unless everything is."""
        now = utcnow()
        inserted = 0
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            head = db.execute("SELECT seq, chain_hash FROM raw_events ORDER BY seq DESC LIMIT 1").fetchone()
            seq, prev = head if head else (0, GENESIS)
            for record in records:
                event = record["event"]
                inserted += db.execute("INSERT OR IGNORE INTO events VALUES (?, ?, ?)",
                                       (event["id"], event["source"], json.dumps(event))).rowcount
                if record.get("raw") is None or db.execute("SELECT 1 FROM raw_events WHERE source_event_key=?", (record["key"],)).fetchone():
                    continue
                seq += 1
                row = dict(seq=seq, source_event_key=record["key"], event_id=event["id"],
                           ingestion_mode=origin["mode"], source_id=origin["source_id"], source_type=origin["source_type"],
                           file_id=origin.get("file_id"), locator=record.get("locator"), ingested_at=now,
                           parser_version=record["parser_version"], schema_version=record["schema_version"],
                           raw_sha256=record["raw_sha256"])
                link = chain_link(prev, row)
                db.execute(f"INSERT INTO raw_events({','.join(RAW_COLUMNS)}, raw, prev_hash, chain_hash) VALUES ({','.join('?' * (len(RAW_COLUMNS) + 3))})",
                           [row[k] for k in RAW_COLUMNS] + [record["raw"], prev, link])
                prev = link
            if db.execute("SELECT count(*) FROM events").fetchone()[0] > EVENT_LIMIT:
                raise ValueError(f"Lab storage limit reached ({EVENT_LIMIT:,} events). Archive the database before continuing.")
            if origin:
                self._record_errors(db, origin, errors, now)
                self._update_source(db, origin, records, inserted, len(errors), checkpoint or {}, now)
        return dict(inserted=inserted, duplicates=len(records) - inserted, malformed=len(errors))

    def _record_errors(self, db, origin, errors, now):
        if not errors:
            return
        db.executemany("INSERT INTO ingest_errors(source_id, file_id, locator, ingested_at, reason, line_sha256, line_bytes) VALUES (?,?,?,?,?,?,?)",
                       [(origin["source_id"], e.get("file_id", origin.get("file_id")), e.get("locator"), now, e["reason"][:200],
                         e.get("line_sha256"), e.get("line_bytes")) for e in errors])
        db.execute("DELETE FROM ingest_errors WHERE source_id=? AND id NOT IN (SELECT id FROM ingest_errors WHERE source_id=? ORDER BY id DESC LIMIT ?)",
                   (origin["source_id"], origin["source_id"], ERROR_LIMIT))

    def _update_source(self, db, origin, records, inserted, malformed, checkpoint, now):
        old = db.execute("SELECT last_event_time, events_total, duplicates_total, malformed_total, rotations_total, truncations_total, file_id, file_offset, discarding FROM sources WHERE source_id=?",
                         (origin["source_id"],)).fetchone() or (None, 0, 0, 0, 0, 0, None, 0, 0)
        times = [r["event"]["timestamp"] for r in records] + ([old[0]] if old[0] else [])
        db.execute("""INSERT INTO sources VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(source_id) DO UPDATE SET
            source_type=excluded.source_type, ingestion_mode=excluded.ingestion_mode, file_id=excluded.file_id,
            file_offset=excluded.file_offset, discarding=excluded.discarding, last_event_time=excluded.last_event_time,
            last_commit_at=excluded.last_commit_at, events_total=excluded.events_total, duplicates_total=excluded.duplicates_total,
            malformed_total=excluded.malformed_total, rotations_total=excluded.rotations_total, truncations_total=excluded.truncations_total""",
            (origin["source_id"], origin["source_type"], origin["mode"],
             checkpoint.get("file_id", old[6]), checkpoint.get("offset", old[7]), int(checkpoint.get("discarding", old[8])),
             max(times) if times else None, now, old[1] + inserted, old[2] + len(records) - inserted, old[3] + malformed,
             old[4] + checkpoint.get("rotations", 0), old[5] + checkpoint.get("truncations", 0)))

    def sources(self):
        with self.connect() as db:
            db.row_factory = sqlite3.Row
            return [dict(r) for r in db.execute("SELECT * FROM sources ORDER BY source_id")]

    def source(self, source_id):
        return next((s for s in self.sources() if s["source_id"] == source_id), None)

    def errors(self, source_id, limit=50):
        with self.connect() as db:
            db.row_factory = sqlite3.Row
            return [dict(r) for r in db.execute("SELECT id, file_id, locator, ingested_at, reason, line_sha256, line_bytes FROM ingest_errors WHERE source_id=? ORDER BY id DESC LIMIT ?",
                                                (source_id, limit))]

    def verify_chain(self):
        """Recompute every digest and link. Detects altered, reordered, or removed records, except
        removal of the newest records: compare head_hash with a copy kept elsewhere to cover that."""
        prev, count, purged = GENESIS, 0, 0
        with self.connect() as db:
            db.row_factory = sqlite3.Row
            for row in db.execute(f"SELECT {','.join(RAW_COLUMNS)}, raw, prev_hash, chain_hash FROM raw_events ORDER BY seq"):
                problem = None
                if row["raw"] is None:
                    purged += 1
                elif hashlib.sha256(row["raw"]).hexdigest() != row["raw_sha256"]:
                    problem = "raw bytes do not match their recorded digest"
                if not problem and row["prev_hash"] != prev:
                    problem = "link to the previous record is broken (a record was removed or reordered)"
                if not problem and chain_link(prev, row) != row["chain_hash"]:
                    problem = "record metadata or digest was altered"
                if problem:
                    return dict(valid=False, records=count, purged=purged, first_invalid_seq=row["seq"], reason=problem)
                prev, count = row["chain_hash"], count + 1
            head_seq = db.execute("SELECT max(seq) FROM raw_events").fetchone()[0]
        return dict(valid=True, records=count, purged=purged, head_seq=head_seq, head_hash=prev)

    def purge_raw(self, ingested_before):
        """Retention: drop raw bytes older than a UTC ISO timestamp. Digests and links remain."""
        with self.connect() as db:
            return db.execute("UPDATE raw_events SET raw=NULL WHERE raw IS NOT NULL AND ingested_at < ?", (ingested_before,)).rowcount

    def events(self, source):
        with self.connect() as db:
            return [json.loads(r[0]) for r in db.execute("SELECT body FROM events WHERE source=?", (source,))]

    def statuses(self):
        with self.connect() as db:
            return dict(db.execute("SELECT id,status FROM workflow"))

    def set_status(self, incident_id, status):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT status FROM workflow WHERE id=?", (incident_id,)).fetchone()
            previous = row[0] if row else "open"
            if previous == status:
                return
            db.execute("INSERT INTO workflow VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET status=excluded.status", (incident_id, status))
            db.execute("INSERT INTO activity(incident_id,timestamp,kind,body) VALUES (?,?,?,?)",
                       (incident_id, datetime.now(timezone.utc).isoformat(), "status", f"{previous} → {status}"))

    def activity(self, incident_id):
        with self.connect() as db:
            return [dict(zip(("id", "timestamp", "kind", "body"), row)) for row in db.execute(
                "SELECT id,timestamp,kind,body FROM activity WHERE incident_id=? ORDER BY id DESC", (incident_id,))]

    def add_note(self, incident_id, text):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            count = db.execute("SELECT count(*) FROM activity WHERE incident_id=? AND kind='note'", (incident_id,)).fetchone()[0]
            if count >= 100:
                raise ValueError("This incident has reached the lab limit of 100 notes.")
            db.execute("INSERT INTO activity(incident_id,timestamp,kind,body) VALUES (?,?,?,?)",
                       (incident_id, datetime.now(timezone.utc).isoformat(), "note", text))

    def raw_count(self):
        with self.connect() as db:
            return db.execute("SELECT count(*) FROM raw_events").fetchone()[0]

    def usage(self):
        with self.connect() as db:
            return {"events": db.execute("SELECT count(*) FROM events").fetchone()[0], "limit": EVENT_LIMIT}
