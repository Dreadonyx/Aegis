import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime, timezone

EVENT_LIMIT = 50000


class Store:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = str(path)
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, source TEXT NOT NULL, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS workflow(id TEXT PRIMARY KEY, status TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS events_source ON events(source);
                CREATE TABLE IF NOT EXISTS activity(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL, kind TEXT NOT NULL, body TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS activity_incident ON activity(incident_id, id);
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        try:
            with db:
                yield db
        finally:
            db.close()

    def ingest(self, events):
        with self.connect() as db:
            before = db.total_changes
            db.executemany("INSERT OR IGNORE INTO events VALUES (?, ?, ?)", [(e["id"], e["source"], json.dumps(e)) for e in events])
            count = db.execute("SELECT count(*) FROM events").fetchone()[0]
            if count > EVENT_LIMIT:
                raise ValueError(f"Lab storage limit reached ({EVENT_LIMIT:,} events). Archive the database before continuing.")
            return db.total_changes - before

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

    def usage(self):
        with self.connect() as db:
            return {"events": db.execute("SELECT count(*) FROM events").fetchone()[0], "limit": EVENT_LIMIT}
