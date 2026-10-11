import json
import os
import sqlite3
import stat
import threading
from datetime import datetime, timedelta, timezone

import pytest

from app import create_app
from aegis import backup
from aegis.ingestion import make_record
from aegis.maintenance import Retention
from aegis.store import Store

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def record(n):
    raw = dict(timestamp=(BASE + timedelta(seconds=n)).isoformat(), eventid="cowrie.session.connect", sensor="hp", session=f"s{n}", src_ip="192.0.2.5")
    return make_record(json.dumps(raw).encode(), "imported", f"line:{n}")


def populated(tmp_path):
    store = Store(tmp_path / "live.sqlite3")
    store.commit([record(n) for n in range(200)], dict(mode="import", source_id="upload", source_type="cowrie"))
    return store


def test_backup_while_writing_is_consistent_and_verifiable(tmp_path):
    store = populated(tmp_path)
    stop = threading.Event()

    def writer():
        n = 1000
        while not stop.is_set():
            store.commit([record(n)], dict(mode="import", source_id="upload", source_type="cowrie"))
            n += 1
    thread = threading.Thread(target=writer)
    thread.start()
    try:
        manifest = backup.create(store.path, tmp_path / "b" / "aegis.sqlite3")
    finally:
        stop.set()
        thread.join()
    assert manifest["integrity"] == "ok" and manifest["chain"]["valid"]
    assert manifest["counts"]["events"] == manifest["counts"]["raw_events"] >= 200  # events and evidence captured together
    assert stat.S_IMODE(os.stat(tmp_path / "b" / "aegis.sqlite3").st_mode) == 0o600
    assert backup.verify(tmp_path / "b" / "aegis.sqlite3")["valid"]
    with pytest.raises(ValueError, match="never overwrite"):
        backup.create(store.path, tmp_path / "b" / "aegis.sqlite3")


def test_verification_catches_file_tampering(tmp_path):
    store = populated(tmp_path)
    path = tmp_path / "b.sqlite3"
    backup.create(store.path, path)
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0xFF
    path.write_bytes(bytes(data))
    result = backup.verify(path)
    assert not result["valid"] and any("SHA-256" in p for p in result["problems"])


def test_verification_catches_evidence_edits_even_with_a_forged_manifest(tmp_path):
    store = populated(tmp_path)
    path = tmp_path / "b.sqlite3"
    backup.create(store.path, path)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE raw_events SET raw=? WHERE seq=50", (b'{"forged": true}',))
    manifest = json.loads((tmp_path / "b.sqlite3.json").read_text())
    manifest["sha256"] = backup.sha256(path)  # the attacker also updates the digest
    (tmp_path / "b.sqlite3.json").write_text(json.dumps(manifest))
    result = backup.verify(path)
    assert not result["valid"] and any("evidence chain" in p and "50" in p for p in result["problems"])


def test_restore_verifies_and_never_overwrites(tmp_path):
    app = create_app(tmp_path / "live.sqlite3")
    client = app.test_client()
    client.get("/")
    with client.session_transaction() as session:
        client.environ_base["HTTP_X_AEGIS_CSRF"] = session["csrf"]
    client.post("/api/replay")
    path = tmp_path / "b.sqlite3"
    assert backup.main(["create", "--db", str(tmp_path / "live.sqlite3"), "--out", str(path)]) == 0
    assert backup.main(["restore", str(path), "--to", str(tmp_path / "live.sqlite3")]) == 2  # refuses to overwrite
    assert backup.main(["restore", str(path), "--to", str(tmp_path / "restored" / "aegis.sqlite3")]) == 0
    restored = create_app(tmp_path / "restored" / "aegis.sqlite3").test_client()
    assert restored.get("/api/overview").get_json()["events"] == 18
    assert restored.get("/api/v1/evidence/verify").get_json()["valid"]
    path.write_bytes(path.read_bytes() + b"x")
    assert backup.main(["restore", str(path), "--to", str(tmp_path / "other.sqlite3")]) == 2
    assert not (tmp_path / "other.sqlite3").exists() and not (tmp_path / "other.sqlite3.restoring").exists()
    assert backup.main(["verify", str(path)]) == 1


def test_retention_purges_old_raw_bytes_and_keeps_the_chain(tmp_path):
    store = populated(tmp_path)
    retention = Retention(store, 30)
    assert retention.run_once() == 0  # nothing is 30 days old yet
    assert retention.run_once(now=datetime.now(timezone.utc) + timedelta(days=31)) == 200
    chain = store.verify_chain()
    assert chain["valid"] and chain["purged"] == 200
    assert retention.status["purged_total"] == 200
    for bad in (0, -1, "7"):
        with pytest.raises(ValueError, match="AEGIS_RAW_RETENTION_DAYS"):
            Retention(store, bad)


def test_retention_metric(tmp_path):
    app = create_app(tmp_path / "aegis.sqlite3")
    retention = Retention(app.extensions["store"], 7)
    app.extensions["retention"] = retention
    retention.run_once()
    assert "aegis_raw_purged_total 0" in app.test_client().get("/api/v1/metrics").text


def test_backups_are_self_contained(tmp_path):
    store = populated(tmp_path)
    path = tmp_path / "b.sqlite3"
    backup.create(store.path, path)
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as db:
        assert db.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
    (tmp_path / "b.sqlite3-wal").write_bytes(b"stray")
    result = backup.verify(path)
    assert not result["valid"] and any("-wal" in p for p in result["problems"])
