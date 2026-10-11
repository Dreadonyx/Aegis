import io
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from app import create_app
from aegis.demo import demo_records
from aegis.ingestion import Collector, make_record
from aegis.store import MIGRATIONS, Store

LATEST = MIGRATIONS[-1][0]

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def line(n, **fields):
    record = dict(timestamp=(BASE + timedelta(seconds=n)).isoformat(), eventid="cowrie.session.connect",
                  sensor="sensor-a", session=f"s{n}", src_ip="192.0.2.1") | fields
    return (json.dumps(record) + "\n").encode()


def lines(*ns):
    return b"".join(line(n) for n in ns)


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "aegis.sqlite3")


def drain(collector, polls=20):
    for _ in range(polls):
        collector.poll()


def live_count(store):
    return len(store.events("live"))


# --- Evidence records and the hash chain -------------------------------------------------

def test_raw_bytes_preserved_but_passwords_stay_out_of_canonical_events():
    raw = json.dumps(demo_records()[1] | {"password": "hunter2"}).encode()
    record = make_record(raw, "imported")
    assert record["raw"] == raw
    assert "hunter2" not in json.dumps(record["event"])
    reformatted = json.dumps(json.loads(raw), indent=2).encode()
    assert make_record(reformatted, "imported")["key"] == record["key"]
    assert make_record(raw, "demo")["key"] != record["key"]


def test_chain_verifies_and_detects_tampering(store):
    records = [make_record(line(n)[:-1], "imported", f"line:{n}") for n in range(5)]
    store.commit(records, dict(mode="import", source_id="upload", source_type="cowrie"))
    good = store.verify_chain()
    assert good["valid"] and good["records"] == 5 and good["head_seq"] == 5

    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE raw_events SET raw=? WHERE seq=3", (b'{"edited":true}',))
    bad = store.verify_chain()
    assert not bad["valid"] and bad["first_invalid_seq"] == 3 and "digest" in bad["reason"]


@pytest.mark.parametrize("statement,reason", [
    ("UPDATE raw_events SET source_id='forged' WHERE seq=2", "altered"),
    ("DELETE FROM raw_events WHERE seq=2", "removed"),
])
def test_chain_detects_metadata_edits_and_removal(store, statement, reason):
    store.commit([make_record(line(n)[:-1], "imported") for n in range(4)], dict(mode="import", source_id="upload", source_type="cowrie"))
    with sqlite3.connect(store.path) as db:
        db.execute(statement)
    result = store.verify_chain()
    assert not result["valid"] and reason in result["reason"]


def test_retention_purge_keeps_chain_verifiable(store):
    store.commit([make_record(line(n)[:-1], "imported") for n in range(3)], dict(mode="import", source_id="upload", source_type="cowrie"))
    assert store.purge_raw("9999-01-01T00:00:00+00:00") == 3
    result = store.verify_chain()
    assert result["valid"] and result["purged"] == 3


def test_migrations_upgrade_a_v02_database(tmp_path):
    path = tmp_path / "old.sqlite3"
    with sqlite3.connect(path) as db:  # schema exactly as v0.2 created it
        db.executescript("""CREATE TABLE events(id TEXT PRIMARY KEY, source TEXT NOT NULL, body TEXT NOT NULL);
            CREATE TABLE workflow(id TEXT PRIMARY KEY, status TEXT NOT NULL);
            CREATE TABLE activity(id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL, timestamp TEXT NOT NULL, kind TEXT NOT NULL, body TEXT NOT NULL);
            INSERT INTO events VALUES ('legacy', 'imported', '{"id":"legacy","source":"imported"}');""")
    store = Store(path)
    assert store.schema_version() == LATEST
    assert store.events("imported") == [{"id": "legacy", "source": "imported"}]
    Store(path)  # reopening applies nothing twice
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT count(*) FROM schema_migrations").fetchone()[0] == LATEST


# --- Live collector -------------------------------------------------------------------------

def test_collector_commits_and_resumes_after_restart(tmp_path, store):
    log = tmp_path / "cowrie.json"
    log.write_bytes(lines(1, 2, 3))
    drain(Collector(store, log))
    assert live_count(store) == 3
    saved = store.source("cowrie-live")
    assert saved["file_offset"] == log.stat().st_size and saved["events_total"] == 3

    with log.open("ab") as f:
        f.write(line(4))
    restarted = Collector(store, log)
    restarted.poll()
    assert restarted.offset == log.stat().st_size
    assert live_count(store) == 4
    assert store.source("cowrie-live")["duplicates_total"] == 0  # resumed, did not reread
    assert store.verify_chain()["records"] == 4


def test_partial_line_waits_for_writer(tmp_path, store):
    log = tmp_path / "cowrie.json"
    full = line(1)
    log.write_bytes(full[:20])
    collector = Collector(store, log)
    collector.poll()
    assert live_count(store) == 0 and collector.offset == 0
    log.write_bytes(full)
    collector.poll()
    assert live_count(store) == 1


def test_malformed_lines_are_quarantined_and_processing_continues(tmp_path, store):
    log = tmp_path / "cowrie.json"
    secret = b'{"eventid":"cowrie.login.failed","password":"hunter2"'
    log.write_bytes(line(1) + secret + b"\n" + b"x" * 70000 + b"\n" + line(2))
    drain(Collector(store, log))
    assert live_count(store) == 2
    errors = store.errors("cowrie-live")
    assert {e["reason"] for e in errors} >= {"Line exceeds 64 KiB"}
    assert len(errors) == 2 and all(e["locator"].startswith("offset:") and e["line_sha256"] for e in errors)
    assert "hunter2" not in json.dumps(errors)
    assert store.source("cowrie-live")["malformed_total"] == 2


def test_rename_rotation_drains_old_file_before_switching(tmp_path, store):
    log = tmp_path / "cowrie.json"
    log.write_bytes(lines(1, 2))
    collector = Collector(store, log)
    collector.poll()
    with log.open("ab") as f:  # written after the last poll, then rotated away
        f.write(line(3) + b'{"partial":')
    os.rename(log, tmp_path / "cowrie.json.2026_01_01")
    log.write_bytes(lines(4, 5))
    drain(collector)
    assert live_count(store) == 5
    source = store.source("cowrie-live")
    assert source["rotations_total"] == 1 and source["malformed_total"] == 1
    assert "Incomplete final line" in store.errors("cowrie-live")[0]["reason"]


def test_restart_after_rotation_finds_previous_file_by_identity(tmp_path, store):
    log = tmp_path / "cowrie.json"
    log.write_bytes(lines(1))
    Collector(store, log).poll()
    with log.open("ab") as f:
        f.write(line(2))  # unread when the process stops
    os.rename(log, tmp_path / "cowrie.json.2026_01_01")
    log.write_bytes(lines(3))
    drain(Collector(store, log))
    assert live_count(store) == 3


def test_truncation_restarts_from_the_beginning(tmp_path, store):
    log = tmp_path / "cowrie.json"
    log.write_bytes(lines(1, 2, 3))
    collector = Collector(store, log)
    collector.poll()
    log.write_bytes(lines(9))  # same inode, smaller size
    drain(collector)
    assert live_count(store) == 4
    assert store.source("cowrie-live")["truncations_total"] == 1


def test_storage_outage_does_not_advance_checkpoint(tmp_path, store, monkeypatch):
    log = tmp_path / "cowrie.json"
    log.write_bytes(lines(1, 2))
    collector = Collector(store, log)
    real = store.commit

    def outage(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")
    monkeypatch.setattr(store, "commit", outage)
    with pytest.raises(sqlite3.OperationalError):
        collector.poll()
    assert collector.offset == 0 and live_count(store) == 0

    monkeypatch.setattr(store, "commit", real)
    drain(collector)
    assert live_count(store) == 2
    assert store.source("cowrie-live")["duplicates_total"] == 0


def test_worker_reports_storage_failure_and_recovers(tmp_path, store, monkeypatch):
    import aegis.ingestion as module
    log = tmp_path / "cowrie.json"
    log.write_bytes(lines(1))
    collector = Collector(store, log)
    calls = []

    def flaky(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise sqlite3.OperationalError("disk I/O error")
        collector.stop_event.set()
        return real(*args, **kwargs)
    real = store.commit
    monkeypatch.setattr(store, "commit", flaky)
    monkeypatch.setattr(module, "MAX_BACKOFF", 0)
    states = []
    original = collector._failed

    def record(state, *args):
        states.append(state)
        return original(state, *args)
    monkeypatch.setattr(collector, "_failed", record)
    collector.run()
    assert states == ["storage_unavailable"]
    assert collector.status["state"] == "running" and collector.failures == 0
    assert live_count(store) == 1


def test_replaying_the_same_file_twice_is_idempotent(tmp_path, store):
    log = tmp_path / "cowrie.json"
    log.write_bytes(lines(1, 2, 3))
    drain(Collector(store, log))
    store.commit([], dict(mode="live", source_id="cowrie-live", source_type="cowrie"), checkpoint=dict(file_id=None, offset=0))
    drain(Collector(store, log))  # checkpoint lost: rereads everything
    assert live_count(store) == 3
    assert store.verify_chain()["records"] == 3
    assert store.source("cowrie-live")["duplicates_total"] == 3


# --- API --------------------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path):
    app = create_app(tmp_path / "aegis.sqlite3")
    app.config["TESTING"] = True
    with app.test_client() as client:
        client.get("/")
        with client.session_transaction() as session:
            client.environ_base["HTTP_X_AEGIS_CSRF"] = session["csrf"]
        yield client


def test_import_and_replay_record_provenance_without_exposing_passwords(client):
    raw = json.dumps(demo_records()[2] | {"password": "hunter2"})
    assert client.post("/api/import", data={"file": (io.BytesIO(raw.encode()), "a.jsonl")}).get_json()["inserted"] == 1
    client.post("/api/replay")
    sources = {s["source_id"]: s for s in client.get("/api/v1/sources").get_json()["sources"]}
    assert sources["upload"]["ingestion_mode"] == "import" and sources["upload"]["events_total"] == 1
    assert sources["demo-replay"]["ingestion_mode"] == "synthetic" and sources["demo-replay"]["events_total"] == 18
    assert client.get("/api/v1/evidence/verify").get_json()["records"] == 19
    store = client.application.extensions["store"]
    with sqlite3.connect(store.path) as db:
        # raw is a BLOB; compare bytes directly (SQL LIKE on BLOBs differs between SQLite builds)
        assert sum(b"hunter2" in raw for (raw,) in db.execute("SELECT raw FROM raw_events WHERE raw IS NOT NULL")) == 1
    incident = client.get("/api/overview?source=imported").get_json()
    responses = [json.dumps(incident), client.get("/api/events?source=imported").text]
    responses += [client.get(f"/api/incidents/{i['id']}/evidence?source=imported").text for i in incident["incidents"]]
    assert all("hunter2" not in r for r in responses)


def test_failed_import_writes_no_evidence(client):
    body = json.dumps(demo_records()[0]) + "\n{}"
    assert client.post("/api/import", data={"file": (io.BytesIO(body.encode()), "bad.jsonl")}).status_code == 400
    assert client.get("/api/v1/evidence/verify").get_json()["records"] == 0
    assert client.get("/api/v1/sources").get_json()["sources"] == []


def test_live_dataset_is_separate(client, tmp_path):
    log = tmp_path / "cowrie.json"
    log.write_bytes(lines(1, 2))
    drain(Collector(client.application.extensions["store"], log))
    assert client.get("/api/overview?source=live").get_json()["events"] == 2
    assert client.get("/api/overview?source=imported").get_json()["events"] == 0
    health = client.get("/api/v1/sources/cowrie-live/health").get_json()
    assert health["ingestion_mode"] == "live" and health["seconds_since_last_event"] > 0
    assert client.get("/api/v1/sources/missing/health").status_code == 404


def test_readiness_reflects_collector_and_database(client, tmp_path, monkeypatch):
    assert client.get("/api/v1/health/live").status_code == 200
    assert client.get("/api/v1/health/ready").get_json()["checks"]["schema_version"] == LATEST
    collector = Collector(client.application.extensions["store"], tmp_path / "cowrie.json")
    client.application.extensions["collector"] = collector
    collector.status["state"] = "storage_unavailable"
    assert client.get("/api/v1/health/ready").status_code == 503
    assert "Storage unavailable" in client.get("/api/overview").get_json()["collector"]
    collector.status["state"] = "running"

    def down():
        raise sqlite3.OperationalError("private path")
    monkeypatch.setattr(client.application.extensions["store"], "usage", down)
    response = client.get("/api/v1/health/ready")
    assert response.status_code == 503 and "private path" not in response.text


def test_versioned_aliases_and_bounded_error_listing(client):
    client.post("/api/v1/replay")
    assert client.get("/api/v1/overview").get_json()["events"] == 18
    assert client.get("/api/v1/events?limit=5").get_json()["pages"] == 4
    assert client.get("/api/v1/sources/cowrie-live/errors?limit=201").status_code == 400
    assert client.get("/api/v1/sources/cowrie-live/errors").get_json() == {"errors": []}


# --- Configuration, metrics, shutdown ---------------------------------------------------------

@pytest.mark.parametrize("name,source_id,message", [
    ("cowrie.log", "cowrie-live", "diagnostic text log"),
    ("cowrie.json", "Bad ID!", "AEGIS_SOURCE_ID"),
    ("missing-dir/cowrie.json", "cowrie-live", "directory does not exist"),
])
def test_invalid_source_configuration_fails_startup(tmp_path, name, source_id, message):
    from aegis.ingestion import validate_source
    with pytest.raises(ValueError, match=message):
        validate_source(tmp_path / name, source_id)
    assert validate_source(tmp_path / "cowrie.json", "cowrie-live") == tmp_path / "cowrie.json"


def test_metrics_expose_ingestion_counters(client, tmp_path):
    log = tmp_path / "cowrie.json"
    log.write_bytes(lines(1, 2) + b"not json\n")
    collector = Collector(client.application.extensions["store"], log)
    client.application.extensions["collector"] = collector
    drain(collector)
    text = client.get("/api/v1/metrics").text
    assert 'aegis_source_events_total{source_id="cowrie-live",mode="live"} 2' in text
    assert 'aegis_source_malformed_total{source_id="cowrie-live",mode="live"} 1' in text
    assert 'aegis_collector_lines_read_total{source_id="cowrie-live"} 3' in text
    assert 'aegis_collector_up{source_id="cowrie-live"} 1' in text
    assert "aegis_raw_evidence_records 2" in text
    assert "# TYPE aegis_collector_bytes_behind gauge" in text


def test_sigterm_stops_server_and_collector_cleanly(tmp_path):
    import socket
    import subprocess
    import sys
    import time
    import urllib.request
    from pathlib import Path
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    log = tmp_path / "cowrie.json"
    log.write_bytes(lines(1, 2, 3))
    env = dict(os.environ, AEGIS_DB=str(tmp_path / "db.sqlite3"), AEGIS_COWRIE_LOG=str(log), AEGIS_PORT=str(port))
    root = Path(__file__).resolve().parent.parent
    server = subprocess.Popen([sys.executable, "app.py"], cwd=root, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 15
        while True:
            try:
                sources = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/sources", timeout=1))["sources"]
                if sources and sources[0]["events_total"] == 3:
                    break
            except OSError:
                pass
            assert time.monotonic() < deadline, "server did not ingest the log"
            time.sleep(0.2)
        server.send_signal(15)
        assert server.wait(timeout=10) == 0
    finally:
        server.kill()
    assert b"Traceback" not in server.stderr.read()
    assert Store(tmp_path / "db.sqlite3").verify_chain()["records"] == 3


def test_misconfigured_collector_exits_with_message(tmp_path):
    import subprocess
    import sys
    from pathlib import Path
    env = dict(os.environ, AEGIS_DB=str(tmp_path / "db.sqlite3"), AEGIS_COWRIE_LOG=str(tmp_path / "cowrie.log"))
    result = subprocess.run([sys.executable, "app.py"], cwd=Path(__file__).resolve().parent.parent, env=env,
                            capture_output=True, timeout=20)
    assert result.returncode == 1 and b"diagnostic text log" in result.stderr
