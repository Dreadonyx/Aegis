import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path


class Store:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = str(path)
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, source TEXT NOT NULL, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS workflow(id TEXT PRIMARY KEY, status TEXT NOT NULL);
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
            count = db.execute("SELECT count(*) FROM events").fetchone()[0]
            if count + len(events) > 50000:
                raise ValueError("Lab storage limit reached (50,000 events). Archive the database before continuing.")
            before = db.total_changes
            db.executemany("INSERT OR IGNORE INTO events VALUES (?, ?, ?)", [(e["id"], e["source"], json.dumps(e)) for e in events])
            return db.total_changes - before

    def events(self, source):
        with self.connect() as db:
            return [json.loads(r[0]) for r in db.execute("SELECT body FROM events WHERE source=?", (source,))]

    def statuses(self):
        with self.connect() as db:
            return dict(db.execute("SELECT id,status FROM workflow"))

    def set_status(self, incident_id, status):
        with self.connect() as db:
            db.execute("INSERT INTO workflow VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET status=excluded.status", (incident_id, status))
