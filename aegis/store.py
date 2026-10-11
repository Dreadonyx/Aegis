import hashlib
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime, timezone

from aegis.canonical import event_type

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



def _backfill_event_columns(db):
    rows = db.execute("SELECT id, body FROM events").fetchall()
    db.executemany("UPDATE events SET event_time=?, eventid=?, event_type=?, session=?, sensor=?, src_ip=? WHERE id=?",
                   [event_columns(json.loads(body)) + (event_id,) for event_id, body in rows])


def _backfill_status_values(db):
    rows = db.execute("SELECT id, body FROM activity WHERE kind='status'").fetchall()
    db.executemany("UPDATE activity SET before_value=?, after_value=? WHERE id=?",
                   [tuple(body.split(" → ", 1)) + (row_id,) for row_id, body in rows if " → " in body])


MIGRATIONS.append((3, "Indexed canonical event columns, persisted findings and incidents, audited workflow", [
    *[f"ALTER TABLE events ADD COLUMN {column} TEXT" for column in ("event_time", "eventid", "event_type", "session", "sensor", "src_ip")],
    _backfill_event_columns,
    "CREATE INDEX events_time ON events(source, event_time, id)",
    "CREATE INDEX events_session ON events(source, session)",
    "CREATE INDEX events_src ON events(source, src_ip)",
    "CREATE INDEX events_type ON events(source, event_type)",
    "ALTER TABLE activity ADD COLUMN actor TEXT NOT NULL DEFAULT 'local-analyst'",
    "ALTER TABLE activity ADD COLUMN before_value TEXT",
    "ALTER TABLE activity ADD COLUMN after_value TEXT",
    _backfill_status_values,
    """CREATE TABLE findings(
        finding_id TEXT PRIMARY KEY,
        dataset TEXT NOT NULL,
        incident_id TEXT,
        engine TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        rule_version TEXT NOT NULL,
        severity TEXT NOT NULL,
        src_ip TEXT NOT NULL,
        session_key TEXT NOT NULL,
        observed_at TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('active', 'superseded')),
        body TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL)""",
    "CREATE INDEX findings_incident ON findings(dataset, incident_id)",
    "CREATE INDEX findings_src ON findings(dataset, src_ip)",
    "CREATE INDEX findings_status ON findings(dataset, status, observed_at)",
    """CREATE TABLE incidents(
        incident_id TEXT PRIMARY KEY,
        dataset TEXT NOT NULL,
        src_ip TEXT NOT NULL,
        severity TEXT NOT NULL,
        severity_rank INTEGER NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        merged_into TEXT,
        body TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL)""",
    "CREATE INDEX incidents_queue ON incidents(dataset, active, severity_rank, last_seen)",
    "CREATE INDEX incidents_src ON incidents(dataset, src_ip)",
    "CREATE INDEX incidents_merged ON incidents(merged_into)",
    """CREATE TABLE detection_state(
        dataset TEXT PRIMARY KEY,
        fingerprint TEXT,
        computed_at TEXT,
        dirty INTEGER NOT NULL DEFAULT 0,
        last_error TEXT)""",
]))

MIGRATIONS.append((4, "Statistical baseline state", [
    """CREATE TABLE stats_state(
        dataset TEXT PRIMARY KEY,
        fingerprint TEXT,
        computed_at TEXT,
        event_count INTEGER,
        baselines TEXT,
        dirty INTEGER NOT NULL DEFAULT 0,
        last_error TEXT)""",
    "CREATE INDEX findings_engine ON findings(dataset, engine, status)",
]))

MIGRATIONS.append((5, "ML scoring state", [
    """CREATE TABLE ml_state(
        dataset TEXT PRIMARY KEY,
        fingerprint TEXT,
        computed_at TEXT,
        event_count INTEGER,
        baselines TEXT,
        dirty INTEGER NOT NULL DEFAULT 0,
        last_error TEXT)""",
]))
SIGNAL_TABLES = {"statistical": "stats_state", "ml": "ml_state"}

MIGRATIONS.append((6, "Analyst session labels with history", [
    """CREATE TABLE session_labels(
        dataset TEXT NOT NULL,
        session_key TEXT NOT NULL,
        session TEXT NOT NULL,
        sensor TEXT NOT NULL,
        label TEXT NOT NULL CHECK(label IN ('malicious', 'benign')),
        types TEXT NOT NULL,
        note TEXT,
        actor TEXT NOT NULL,
        labeled_at TEXT NOT NULL,
        PRIMARY KEY(dataset, session_key))""",
    """CREATE TABLE session_label_history(
        id INTEGER PRIMARY KEY,
        dataset TEXT NOT NULL,
        session_key TEXT NOT NULL,
        actor TEXT NOT NULL,
        changed_at TEXT NOT NULL,
        before_value TEXT,
        after_value TEXT)""",
    "CREATE INDEX session_label_history_key ON session_label_history(dataset, session_key, id)",
]))
MIGRATIONS.append((7, "Accounts, persisted settings, and settings history", [
    """CREATE TABLE users(
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('viewer', 'analyst', 'admin')),
        disabled INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        last_login_at TEXT)""",
    """CREATE TABLE settings(
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        actor TEXT NOT NULL)""",
    """CREATE TABLE settings_history(
        id INTEGER PRIMARY KEY,
        key TEXT NOT NULL,
        actor TEXT NOT NULL,
        changed_at TEXT NOT NULL,
        before_value TEXT,
        after_value TEXT)""",
]))
LABEL_TYPES = ("credential_access", "discovery", "transfer", "intrusion_sequence", "anomaly")

RANK = {"low": 1, "medium": 2, "high": 3}
# Validated workflow. Closed cases (resolved, false_positive) are reopened before changing outcome.
TRANSITIONS = {
    "open": {"investigating", "resolved", "false_positive"},
    "investigating": {"open", "resolved", "false_positive"},
    "resolved": {"open", "investigating"},
    "false_positive": {"open", "investigating"},
}
CHUNK = 500


class TransitionError(ValueError):
    pass


def event_columns(event):
    return (event.get("timestamp"), event.get("eventid"), event.get("event_type") or event_type(event.get("eventid") or ""),
            event.get("session"), event.get("sensor"), event.get("src_ip"))


def chunks(values):
    values = list(values)
    for start in range(0, len(values), CHUNK):
        yield values[start:start + CHUNK]


def marks(values):
    return ",".join("?" * len(values))


RAW_COLUMNS = ("seq", "source_event_key", "event_id", "ingestion_mode", "source_id", "source_type", "file_id",
               "locator", "ingested_at", "parser_version", "schema_version", "raw_sha256")


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def chain_link(prev_hash, row):
    """Each link commits to the previous link, the raw digest, and all provenance metadata."""
    fields = [prev_hash] + [row[k] for k in RAW_COLUMNS]
    return hashlib.sha256(json.dumps(fields, separators=(",", ":")).encode()).hexdigest()


def verify_chain_db(db):
    """Recompute every raw-evidence digest and link over any connection (read-only is enough)."""
    prev, count, purged = GENESIS, 0, 0
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
            db.row_factory = None
            return dict(valid=False, records=count, purged=purged, first_invalid_seq=row["seq"], reason=problem)
        prev, count = row["chain_hash"], count + 1
    db.row_factory = None
    head_seq = db.execute("SELECT max(seq) FROM raw_events").fetchone()[0]
    return dict(valid=True, records=count, purged=purged, head_seq=head_seq, head_hash=prev)


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
                    statement(db) if callable(statement) else db.execute(statement)
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
                inserted += db.execute("INSERT OR IGNORE INTO events(id, source, body, event_time, eventid, event_type, session, sensor, src_ip) VALUES (?,?,?,?,?,?,?,?,?)",
                                       (event["id"], event["source"], json.dumps(event)) + event_columns(event)).rowcount
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
        with self.connect() as db:
            return verify_chain_db(db)

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

    def set_status(self, incident_id, status, actor="local-analyst"):
        if status not in TRANSITIONS:
            raise ValueError(f"Choose {', '.join(TRANSITIONS)}")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT status FROM workflow WHERE id=?", (incident_id,)).fetchone()
            previous = row[0] if row else "open"
            if previous == status:
                return
            if status not in TRANSITIONS[previous]:
                raise TransitionError(f"A {previous.replace('_', ' ')} incident must be reopened before it can become {status.replace('_', ' ')}.")
            db.execute("INSERT INTO workflow VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET status=excluded.status", (incident_id, status))
            db.execute("INSERT INTO activity(incident_id,timestamp,kind,body,actor,before_value,after_value) VALUES (?,?,?,?,?,?,?)",
                       (incident_id, utcnow(), "status", f"{previous} → {status}", actor, previous, status))

    def _lineage(self, db, incident_id):
        """The incident and every case merged into it, directly or transitively."""
        ids, frontier = [incident_id], [incident_id]
        while frontier:
            frontier = [r[0] for r in db.execute(f"SELECT incident_id FROM incidents WHERE merged_into IN ({marks(frontier)})", frontier)
                        if r[0] not in ids]
            ids.extend(frontier)
        return ids

    def activity(self, incident_id):
        with self.connect() as db:
            ids = self._lineage(db, incident_id)
            return [dict(zip(("id", "timestamp", "kind", "body", "actor", "before", "after"), row)) for row in db.execute(
                f"SELECT id,timestamp,kind,body,actor,before_value,after_value FROM activity WHERE incident_id IN ({marks(ids)}) ORDER BY id DESC", ids)]

    def add_note(self, incident_id, text, actor="local-analyst"):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            count = db.execute("SELECT count(*) FROM activity WHERE incident_id=? AND kind='note'", (incident_id,)).fetchone()[0]
            if count >= 100:
                raise ValueError("This incident has reached the lab limit of 100 notes.")
            db.execute("INSERT INTO activity(incident_id,timestamp,kind,body,actor) VALUES (?,?,?,?,?)",
                       (incident_id, utcnow(), "note", text, actor))

    # --- Detection results ------------------------------------------------------------------

    def replace_detection(self, dataset, src_ips, compute, fingerprint):
        """Recompute detection for some source addresses (all when src_ips is None) and store the result.
        Reading events, computing, and writing happen in one write transaction, so concurrent ingestion
        can never interleave with a stale result."""
        now = utcnow()
        full = src_ips is None
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if full:
                bodies = [r[0] for r in db.execute("SELECT body FROM events WHERE source=?", (dataset,))]
            else:
                src_ips = sorted(set(src_ips))
                bodies = [r[0] for part in chunks(src_ips)
                          for r in db.execute(f"SELECT body FROM events WHERE source=? AND src_ip IN ({marks(part)})", [dataset, *part])]
            incidents = compute([json.loads(b) for b in bodies])

            def scoped(sql, extra=()):
                if full:
                    return list(db.execute(sql, (dataset, *extra)))
                return [r for part in chunks(src_ips) for r in db.execute(sql + f" AND src_ip IN ({marks(part)})", (dataset, *extra, *part))]
            previous = {r[0] for r in scoped("SELECT incident_id FROM incidents WHERE dataset=? AND active=1")}
            old_findings = {r[0] for r in scoped("SELECT finding_id FROM findings WHERE dataset=? AND status='active' AND engine IN ('rule', 'sequence')")}
            if full:  # v0.2 cases have workflow or notes but no incident row yet
                previous |= {r[0] for r in db.execute("SELECT id FROM workflow UNION SELECT incident_id FROM activity")} - \
                            {r[0] for r in db.execute("SELECT incident_id FROM incidents")}
            new_findings = set()
            for incident in incidents:
                for f in incident["findings"]:
                    new_findings.add(f["finding_id"])
                    db.execute("""INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,'active',?,?,?) ON CONFLICT(finding_id) DO UPDATE SET
                        incident_id=excluded.incident_id, severity=excluded.severity, observed_at=excluded.observed_at, status='active',
                        body=excluded.body, updated_at=excluded.updated_at""",
                        (f["finding_id"], dataset, incident["id"], f["engine"], f["rule_id"], f["rule_version"], f["severity"], f["src_ip"],
                         f["session_key"], f["observed_at"], json.dumps(f), now, now))
                body = {k: v for k, v in incident.items() if k not in ("findings", "events", "status", "activity")}
                body.update(finding_ids=[f["finding_id"] for f in incident["findings"]], fingerprint=fingerprint)
                db.execute("""INSERT INTO incidents VALUES (?,?,?,?,?,?,?,1,NULL,?,?,?) ON CONFLICT(incident_id) DO UPDATE SET
                    dataset=excluded.dataset, src_ip=excluded.src_ip, severity=excluded.severity, severity_rank=excluded.severity_rank,
                    first_seen=excluded.first_seen, last_seen=excluded.last_seen, active=1, merged_into=NULL, body=excluded.body, updated_at=excluded.updated_at""",
                    (incident["id"], dataset, incident["src_ip"], incident["severity"], RANK[incident["severity"]], incident["first_seen"],
                     incident["last_seen"], json.dumps(body), now, now))
            stale = sorted(old_findings - new_findings)
            for part in chunks(stale):
                db.execute(f"UPDATE findings SET status='superseded', updated_at=? WHERE finding_id IN ({marks(part)})", [now, *part])
            merged = self._retire(db, dataset, previous - {i["id"] for i in incidents}, incidents, now)
            if full:
                db.execute("""INSERT INTO detection_state VALUES (?,?,?,0,NULL) ON CONFLICT(dataset) DO UPDATE SET
                    fingerprint=excluded.fingerprint, computed_at=excluded.computed_at, dirty=0, last_error=NULL""", (dataset, fingerprint, now))
        return dict(incidents=len(incidents), findings=len(new_findings), superseded=len(stale), merged=merged)

    def _retire(self, db, dataset, gone, incidents, now):
        """Cases that no longer exist are merged into the incident that now holds their session, carrying
        their workflow status and leaving an audit entry; otherwise they are retired."""
        merged = 0
        statuses = dict(db.execute("SELECT id, status FROM workflow"))
        for old in sorted(gone):
            target = next((i for i in incidents if old in i["session_keys"]), None)
            if not target:
                db.execute("UPDATE incidents SET active=0, updated_at=? WHERE incident_id=?", (now, old))
                continue
            db.execute("""INSERT INTO incidents VALUES (?,?,?,?,?,?,?,0,?,'{}',?,?) ON CONFLICT(incident_id) DO UPDATE SET
                active=0, merged_into=excluded.merged_into, updated_at=excluded.updated_at""",
                (old, dataset, target["src_ip"], target["severity"], RANK[target["severity"]], target["first_seen"], target["last_seen"], target["id"], now, now))
            carried = statuses.get(old, "open")
            note = f"Detection update merged case {old[:8]} (status: {carried.replace('_', ' ')}) into this case."
            if carried != "open" and target["id"] not in statuses:
                db.execute("INSERT INTO workflow VALUES (?, ?)", (target["id"], carried))
                statuses[target["id"]] = carried
                note += " Its status was carried over."
            db.execute("INSERT INTO activity(incident_id,timestamp,kind,body,actor,before_value,after_value) VALUES (?,?,?,?,?,?,?)",
                       (target["id"], now, "merge", note, "aegis", old, target["id"]))
            merged += 1
        return merged

    def replace_signals(self, dataset, compute, fingerprint, engine="statistical"):
        """Recompute one signal engine's findings (statistical or ml) for a whole dataset. They are stored
        without an incident: an anomaly alone is a signal, not a case."""
        table = SIGNAL_TABLES[engine]
        now = utcnow()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            events = [json.loads(r[0]) for r in db.execute("SELECT body FROM events WHERE source=?", (dataset,))]
            result = compute(events)
            old = {r[0] for r in db.execute("SELECT finding_id FROM findings WHERE dataset=? AND engine=? AND status='active'", (dataset, engine))}
            new = set()
            for f in result["findings"]:
                new.add(f["finding_id"])
                db.execute("""INSERT INTO findings VALUES (?,?,NULL,?,?,?,?,?,?,?,'active',?,?,?) ON CONFLICT(finding_id) DO UPDATE SET
                    severity=excluded.severity, observed_at=excluded.observed_at, status='active', body=excluded.body, updated_at=excluded.updated_at""",
                    (f["finding_id"], dataset, f["engine"], f["rule_id"], f["rule_version"], f["severity"], f["src_ip"], f["session_key"],
                     f["observed_at"], json.dumps(f), now, now))
            stale = sorted(old - new)
            for part in chunks(stale):
                db.execute(f"UPDATE findings SET status='superseded', updated_at=? WHERE finding_id IN ({marks(part)})", [now, *part])
            state = {k: v for k, v in result.items() if k != "findings"}
            db.execute(f"""INSERT INTO {table} VALUES (?,?,?,?,?,0,NULL) ON CONFLICT(dataset) DO UPDATE SET fingerprint=excluded.fingerprint,
                computed_at=excluded.computed_at, event_count=excluded.event_count, baselines=excluded.baselines, dirty=0, last_error=NULL""",
                (dataset, fingerprint, now, len(events), json.dumps(state)))
        return dict(findings=len(new), superseded=len(stale))

    def stats_state(self, dataset):
        return self.signal_state(dataset, "statistical")

    def signal_state(self, dataset, engine):
        with self.connect() as db:
            row = db.execute(f"SELECT fingerprint, computed_at, event_count, baselines, dirty, last_error FROM {SIGNAL_TABLES[engine]} WHERE dataset=?", (dataset,)).fetchone()
        if not row:
            return None
        return dict(fingerprint=row[0], computed_at=row[1], event_count=row[2], **(json.loads(row[3]) if row[3] else {}), dirty=row[4], last_error=row[5])

    def mark_stats_dirty(self, dataset, error):
        self.mark_signal_dirty(dataset, error, "statistical")

    def mark_signal_dirty(self, dataset, error, engine):
        with self.connect() as db:
            db.execute(f"""INSERT INTO {SIGNAL_TABLES[engine]}(dataset, dirty, last_error) VALUES (?,1,?) ON CONFLICT(dataset) DO UPDATE SET
                dirty=1, last_error=excluded.last_error""", (dataset, error[:200]))

    def event_count(self, dataset):
        with self.connect() as db:
            return db.execute("SELECT count(*) FROM events WHERE source=?", (dataset,)).fetchone()[0]

    def signals_for(self, incident):
        """Active statistical findings that share this incident's session, source address, or sensor and overlap
        its time span. Related, not merged."""
        with self.connect() as db:
            rows = [json.loads(r[0]) for r in db.execute(
                "SELECT body FROM findings WHERE dataset=? AND engine IN ('statistical', 'ml') AND status='active'", (incident["source"],))]
        keys, sensors = set(incident.get("session_keys", [])), set(incident.get("sensors", [incident.get("sensor")]))

        def related(f):
            scope = f.get("scope", {})
            matches = (scope.get("type") == "session" and scope.get("session_key") in keys) or \
                      (scope.get("type") == "source" and scope.get("src_ip") == incident["src_ip"]) or \
                      (scope.get("type") == "sensor" and scope.get("sensor") in sensors)
            return matches and f["first_seen"] <= incident["last_seen"] and f["last_seen"] >= incident["first_seen"]
        return [f for f in rows if related(f)]

    def events_between(self, dataset, since=None, until=None):
        where, args = ["source=?"], [dataset]
        if since:
            where.append("event_time >= ?")
            args.append(since)
        if until:
            where.append("event_time < ?")
            args.append(until)
        with self.connect() as db:
            return [json.loads(r[0]) for r in db.execute(f"SELECT body FROM events WHERE {' AND '.join(where)} ORDER BY event_time, id", args)]

    def finding_counts(self, dataset):
        with self.connect() as db:
            rows = db.execute("SELECT engine, severity, count(*) FROM findings WHERE dataset=? AND status='active' GROUP BY engine, severity", (dataset,)).fetchall()
        return [{"engine": e, "severity": s, "count": c} for e, s, c in rows]

    def detection_state(self, dataset):
        with self.connect() as db:
            row = db.execute("SELECT fingerprint, computed_at, dirty, last_error FROM detection_state WHERE dataset=?", (dataset,)).fetchone()
        return dict(zip(("fingerprint", "computed_at", "dirty", "last_error"), row)) if row else None

    def mark_dirty(self, dataset, error):
        with self.connect() as db:
            db.execute("""INSERT INTO detection_state(dataset, dirty, last_error) VALUES (?,1,?) ON CONFLICT(dataset) DO UPDATE SET
                dirty=1, last_error=excluded.last_error""", (dataset, error[:200]))

    def _events_by_id(self, db, ids):
        found = {}
        for part in chunks(ids):
            found.update((r[0], json.loads(r[1])) for r in db.execute(f"SELECT id, body FROM events WHERE id IN ({marks(part)})", part))
        return found

    def _findings_by_id(self, db, ids):
        found = {}
        for part in chunks(ids):
            found.update((r[0], json.loads(r[1])) for r in db.execute(f"SELECT finding_id, body FROM findings WHERE finding_id IN ({marks(part)})", part))
        return found

    def incidents(self, dataset, status=None, severity=None, limit=None, offset=0):
        """Active incidents in queue order, with findings and workflow status."""
        where, args = ["i.dataset=?", "i.active=1"], [dataset]
        if status:
            where.append("COALESCE(w.status, 'open')=?")
            args.append(status)
        if severity:
            where.append("i.severity=?")
            args.append(severity)
        sql = f"FROM incidents i LEFT JOIN workflow w ON w.id=i.incident_id WHERE {' AND '.join(where)}"
        page = f" LIMIT {int(limit)} OFFSET {int(offset)}" if limit else ""
        with self.connect() as db:
            total = db.execute(f"SELECT count(*) {sql}", args).fetchone()[0]
            rows = db.execute(f"SELECT i.body, COALESCE(w.status, 'open') {sql} ORDER BY i.severity_rank DESC, i.last_seen DESC, i.incident_id DESC{page}", args).fetchall()
            incidents = [{**json.loads(body), "status": state} for body, state in rows]
            findings = self._findings_by_id(db, [f for i in incidents for f in i["finding_ids"]])
        for incident in incidents:
            incident["findings"] = [findings[f] for f in incident["finding_ids"] if f in findings]
        return total, incidents

    def incident(self, dataset, incident_id):
        """One incident with findings, annotated events, and the activity of every case merged into it.
        A merged case ID resolves to the incident that absorbed it."""
        with self.connect() as db:
            for _ in range(100):
                row = db.execute("SELECT dataset, active, merged_into, body FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
                if not row or row[0] != dataset:
                    return None
                if row[1]:
                    break
                if not row[2]:
                    return None
                incident_id = row[2]
            else:
                return None
            incident = json.loads(row[3])
            state = db.execute("SELECT status FROM workflow WHERE id=?", (incident_id,)).fetchone()
            findings = self._findings_by_id(db, incident["finding_ids"])
            events = self._events_by_id(db, [r["id"] for r in incident["event_refs"]])
        incident.update(status=state[0] if state else "open", findings=[findings[f] for f in incident["finding_ids"] if f in findings],
                        events=[{**events[r["id"]], "relationship": r["relationship"], "link": r["link"]} for r in incident["event_refs"] if r["id"] in events],
                        activity=self.activity(incident_id))
        return incident

    def findings(self, dataset, filters, limit, offset):
        where, args = ["dataset=?"], [dataset]
        for column in ("engine", "rule_id", "severity", "status", "incident_id"):
            if filters.get(column):
                where.append(f"{column}=?")
                args.append(filters[column])
        sql = " AND ".join(where)
        with self.connect() as db:
            total = db.execute(f"SELECT count(*) FROM findings WHERE {sql}", args).fetchone()[0]
            rows = db.execute(f"SELECT body, status, created_at, updated_at FROM findings WHERE {sql} ORDER BY observed_at DESC, finding_id LIMIT ? OFFSET ?",
                              [*args, limit, offset]).fetchall()
        return total, [{**json.loads(b), "status": st, "created_at": c, "updated_at": u} for b, st, c, u in rows]

    def query_events(self, dataset, q="", filters=None, limit=50, offset=0):
        where, args = ["source=?"], [dataset]
        if q:
            where.append("body LIKE ? ESCAPE '\\'")
            args.append("%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
        for column in ("id", "event_type", "eventid", "session", "sensor", "src_ip"):
            if (filters or {}).get(column):
                where.append(f"{column}=?")
                args.append(filters[column])
        if (filters or {}).get("since"):
            where.append("event_time >= ?")
            args.append(filters["since"])
        if (filters or {}).get("until"):
            where.append("event_time < ?")
            args.append(filters["until"])
        sql = " AND ".join(where)
        with self.connect() as db:
            total = db.execute(f"SELECT count(*) FROM events WHERE {sql}", args).fetchone()[0]
            rows = db.execute(f"SELECT body FROM events WHERE {sql} ORDER BY event_time DESC, id DESC LIMIT ? OFFSET ?", [*args, limit, offset]).fetchall()
        return total, [json.loads(r[0]) for r in rows]

    def overview(self, dataset):
        with self.connect() as db:
            events, sources, sensors = db.execute("SELECT count(*), count(DISTINCT src_ip), count(DISTINCT sensor) FROM events WHERE source=?", (dataset,)).fetchone()
            bins = db.execute("SELECT substr(event_time, 1, 16) AS minute, count(*) FROM events WHERE source=? GROUP BY minute ORDER BY minute DESC LIMIT 40",
                              (dataset,)).fetchall()
        return dict(events=events, sources=sources, sensors=sensors, timeline=[{"time": m, "count": c} for m, c in reversed(bins)])

    def session_timeline(self, dataset, session, sensor=None, limit=2000):
        where, args = ["source=?", "session=?"], [dataset, session]
        if sensor:
            where.append("sensor=?")
            args.append(sensor)
        with self.connect() as db:
            rows = db.execute(f"SELECT body FROM events WHERE {' AND '.join(where)} ORDER BY event_time, id LIMIT ?", [*args, limit + 1]).fetchall()
            events = [json.loads(r[0]) for r in rows]
            ids = {e["id"] for e in events[:limit]}
            src_ips = sorted({e["src_ip"] for e in events})
            candidates = [json.loads(r[0]) for part in chunks(src_ips) for r in db.execute(
                f"SELECT body FROM findings WHERE dataset=? AND status='active' AND src_ip IN ({marks(part)})", [dataset, *part])]
        findings = [f for f in candidates if ids & set(f["evidence_event_ids"])]
        return dict(events=events[:limit], truncated=len(events) > limit, findings=findings,
                    incident_ids=sorted({f.get("incident_id") for f in findings} - {None}))

    # --- Accounts and settings -----------------------------------------------------------------

    def user(self, username):
        with self.connect() as db:
            db.row_factory = sqlite3.Row
            row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(row) if row else None

    def users(self):
        with self.connect() as db:
            db.row_factory = sqlite3.Row
            return [dict(r) for r in db.execute("SELECT username, role, disabled, created_at, last_login_at FROM users ORDER BY username")]

    def add_user(self, username, password_hash, role):
        with self.connect() as db:
            db.execute("INSERT INTO users(username, password_hash, role, created_at) VALUES (?,?,?,?)", (username, password_hash, role, utcnow()))

    def update_user(self, username, **fields):
        allowed = {"password_hash", "role", "disabled", "last_login_at"}
        if not fields or not set(fields) <= allowed:
            raise ValueError("Unknown account field")
        with self.connect() as db:
            changed = db.execute(f"UPDATE users SET {', '.join(f'{k}=?' for k in fields)} WHERE username=?", [*fields.values(), username]).rowcount
        if not changed:
            raise ValueError(f"No account named {username}")

    def count_users(self):
        with self.connect() as db:
            return db.execute("SELECT count(*) FROM users WHERE disabled=0").fetchone()[0]

    def setting(self, key):
        with self.connect() as db:
            row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def set_setting(self, key, value, actor):
        now = utcnow()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            after = json.dumps(value, sort_keys=True)
            if row and row[0] == after:
                return
            db.execute("INSERT INTO settings VALUES (?,?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at, actor=excluded.actor",
                       (key, after, now, actor))
            db.execute("INSERT INTO settings_history(key, actor, changed_at, before_value, after_value) VALUES (?,?,?,?,?)",
                       (key, actor, now, row[0] if row else None, after))

    def settings_history(self, key, limit=50):
        with self.connect() as db:
            return [{"actor": a, "changed_at": t, "before": json.loads(b) if b else None, "after": json.loads(v)}
                    for a, t, b, v in db.execute("SELECT actor, changed_at, before_value, after_value FROM settings_history WHERE key=? ORDER BY id DESC LIMIT ?", (key, limit))]

    # --- Analyst labels ----------------------------------------------------------------------

    def label(self, dataset, session_key):
        with self.connect() as db:
            db.row_factory = sqlite3.Row
            row = db.execute("SELECT * FROM session_labels WHERE dataset=? AND session_key=?", (dataset, session_key)).fetchone()
            history = [dict(r) for r in db.execute("SELECT actor, changed_at, before_value, after_value FROM session_label_history "
                                                   "WHERE dataset=? AND session_key=? ORDER BY id DESC", (dataset, session_key))]
        label = dict(row) if row else None
        if label:
            label["types"] = json.loads(label["types"])
        for h in history:
            h["before"], h["after"] = (json.loads(h.pop(k)) if h.get(k) else None for k in ("before_value", "after_value"))
        return label, history

    def set_label(self, dataset, session_key, session, sensor, label, types, note, actor):
        """Set or clear (label=None) one session's label; every change is kept in the history."""
        now = utcnow()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT label, types, note FROM session_labels WHERE dataset=? AND session_key=?", (dataset, session_key)).fetchone()
            before = {"label": row[0], "types": json.loads(row[1]), "note": row[2]} if row else None
            after = {"label": label, "types": sorted(types), "note": note} if label else None
            if before == after:
                return
            if after:
                db.execute("""INSERT INTO session_labels VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(dataset, session_key) DO UPDATE SET
                    label=excluded.label, types=excluded.types, note=excluded.note, actor=excluded.actor, labeled_at=excluded.labeled_at""",
                    (dataset, session_key, session, sensor, label, json.dumps(sorted(types)), note, actor, now))
            else:
                db.execute("DELETE FROM session_labels WHERE dataset=? AND session_key=?", (dataset, session_key))
            db.execute("INSERT INTO session_label_history(dataset, session_key, actor, changed_at, before_value, after_value) VALUES (?,?,?,?,?,?)",
                       (dataset, session_key, actor, now, json.dumps(before) if before else None, json.dumps(after) if after else None))

    def labels(self, dataset, limit=None, offset=0):
        with self.connect() as db:
            db.row_factory = sqlite3.Row
            counts = dict(db.execute("SELECT label, count(*) FROM session_labels WHERE dataset=? GROUP BY label", (dataset,)).fetchall())
            page = f" LIMIT {int(limit)} OFFSET {int(offset)}" if limit else ""
            rows = [dict(r) for r in db.execute(f"SELECT * FROM session_labels WHERE dataset=? ORDER BY labeled_at DESC, session_key{page}", (dataset,))]
        for r in rows:
            r["types"] = json.loads(r["types"])
        return {"malicious": counts.get("malicious", 0), "benign": counts.get("benign", 0)}, rows

    def raw_records(self, event_ids):
        """Original record bytes per event (first record when several map to one event). Callers redact."""
        found = {}
        with self.connect() as db:
            for part in chunks(sorted(set(event_ids))):
                for event_id, raw in db.execute(f"SELECT event_id, raw FROM raw_events WHERE event_id IN ({marks(part)}) ORDER BY seq", part):
                    found.setdefault(event_id, raw)
        return found

    def provenance(self, event_ids):
        """Raw-evidence provenance per event (never the raw bytes)."""
        columns = ("seq", "event_id", "ingestion_mode", "source_id", "source_type", "file_id", "locator", "ingested_at",
                   "parser_version", "schema_version", "raw_sha256", "chain_hash")
        found = {}
        with self.connect() as db:
            for part in chunks(sorted(set(event_ids))):
                for row in db.execute(f"SELECT {','.join(columns)} FROM raw_events WHERE event_id IN ({marks(part)}) ORDER BY seq", part):
                    record = dict(zip(columns, row))
                    found.setdefault(record.pop("event_id"), []).append(record)
        return found

    def chain_head(self):
        with self.connect() as db:
            row = db.execute("SELECT seq, chain_hash FROM raw_events ORDER BY seq DESC LIMIT 1").fetchone()
        return dict(head_seq=row[0], head_hash=row[1]) if row else dict(head_seq=None, head_hash=None)

    def raw_count(self):
        with self.connect() as db:
            return db.execute("SELECT count(*) FROM raw_events").fetchone()[0]

    def usage(self):
        with self.connect() as db:
            return {"events": db.execute("SELECT count(*) FROM events").fetchone()[0], "limit": EVENT_LIMIT}
