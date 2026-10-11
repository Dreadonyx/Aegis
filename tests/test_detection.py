import io
import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from app import create_app
from aegis.canonical import normalize
from aegis.engine import detect, fingerprint, session_key, validate_config
from aegis.ingestion import Collector

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def raw(n=0, **fields):
    return dict(timestamp=(BASE + timedelta(seconds=n)).isoformat(), eventid="cowrie.login.failed", sensor="sensor-a",
                session="s", src_ip="192.0.2.1") | fields


def ev(n=0, source="imported", **fields):
    return normalize(raw(n, **fields), source)


def jsonl(*records):
    return ("\n".join(json.dumps(r) for r in records) + "\n").encode()


def make_client(path, config=None):
    app = create_app(path, detection_config=config)
    app.config["TESTING"] = True
    client = app.test_client()
    client.get("/")
    with client.session_transaction() as session:
        client.environ_base["HTTP_X_AEGIS_CSRF"] = session["csrf"]
    return client


@pytest.fixture
def client(tmp_path):
    return make_client(tmp_path / "aegis.sqlite3")


def upload(client, *records):
    return client.post("/api/import", data={"file": (io.BytesIO(jsonl(*records)), "x.jsonl")})


# --- Canonical events --------------------------------------------------------------------------

def test_canonical_fields_follow_cowrie_reference():
    connect = ev(eventid="cowrie.session.connect", src_port=50122, dst_ip="198.51.100.5", dst_port=22, protocol="ssh")
    assert connect["event_type"] == "session_start"
    assert (connect["src_port"], connect["dst_ip"], connect["dst_port"], connect["protocol"]) == (50122, "198.51.100.5", 22, "ssh")
    assert ev(eventid="cowrie.session.closed", duration_ms=1500)["duration_ms"] == 1500
    assert ev(eventid="cowrie.session.closed", duration="2.5")["duration_ms"] == 2500  # pre-3.x seconds
    assert ev(eventid="cowrie.client.version", version="SSH-2.0-Go")["client_version"] == "SSH-2.0-Go"
    assert ev(eventid="cowrie.client.kex", hassh="a" * 32)["hassh"] == "a" * 32
    assert "hassh" not in ev(eventid="cowrie.client.kex", hassh="not-hex")
    upload_event = ev(eventid="cowrie.session.file_upload", filename="x.sh", shasum="c" * 64)
    assert (upload_event["filename"], upload_event["shasum"], upload_event["event_type"]) == ("x.sh", "c" * 64, "file_upload")
    assert ev(eventid="cowrie.weird.new")["event_type"] == "other"


def test_invalid_optional_fields_are_dropped_not_fatal():
    event = ev(eventid="cowrie.session.connect", src_port=99999, dst_ip="not-an-ip", protocol=7, late=True)
    assert {"src_port", "dst_ip", "protocol"}.isdisjoint(event) and event["late"] is True


def test_identity_is_stable_across_schema_versions():
    plain = ev(eventid="cowrie.session.connect")
    enriched = ev(eventid="cowrie.session.connect", src_port=1, dst_ip="198.51.100.1", dst_port=22, protocol="ssh")
    assert plain["id"] == enriched["id"]


def test_command_events_require_input():
    with pytest.raises(ValueError, match="input is required"):
        ev(eventid="cowrie.command.input")


# --- Configuration -----------------------------------------------------------------------------

@pytest.mark.parametrize("overrides,message", [
    ({"auth_failure_threshold": 1}, "auth_failure_threshold"),
    ({"auth_failure_window_seconds": True}, "auth_failure_window_seconds"),
    ({"discovery_commands": ["rm -rf"]}, "discovery_commands"),
    ({"disabled_rules": ["NOPE-1"]}, "disabled_rules"),
    ({"auth_group_by": "actor"}, "auth_group_by"),
    ({"surprise": 1}, "Unknown detection settings"),
])
def test_invalid_detection_settings_are_rejected(overrides, message):
    with pytest.raises(ValueError, match=message):
        validate_config(overrides)


def test_configured_thresholds_commands_grouping_and_disabling():
    assert fingerprint(validate_config({})) != fingerprint(validate_config({"auth_failure_threshold": 3}))
    three = [ev(n) for n in range(3)]
    assert not detect(three)
    assert detect(three, validate_config({"auth_failure_threshold": 3}))
    whoami = [ev(eventid="cowrie.command.input", input="whoami")]
    assert not detect(whoami)
    assert detect(whoami, validate_config({"discovery_commands": ["whoami"]}))[0]["findings"][0]["rationale"]["facts"]["commands_matched"] == ["whoami"]
    sensors = [ev(n, sensor=f"sensor-{n}", session=f"s{n}") for n in range(5)]
    assert not detect(sensors)
    assert detect(sensors, validate_config({"auth_group_by": "source"}))
    assert not detect([ev(eventid="cowrie.command.input", input="uname")], validate_config({"disabled_rules": ["DISC-001"]}))


# --- Findings contract -------------------------------------------------------------------------

def test_findings_carry_contract_fields_and_stable_ids():
    events = [ev(n, session=f"g{n}") for n in range(6)]
    first, again = detect(events), detect(list(reversed(events)))
    finding = first[0]["findings"][0]
    for field in ("finding_id", "engine", "rule_id", "rule_version", "title", "description", "category", "severity", "observed_at",
                  "evidence_event_ids", "rationale", "score", "score_type", "dedup_key", "status"):
        assert field in finding
    assert finding["score"] is None and finding["score_type"] is None
    assert finding["rationale"]["facts"]["failures"] == 6 and finding["rationale"]["facts"]["sessions"] == 6
    assert finding["finding_id"] == again[0]["findings"][0]["finding_id"]
    assert len(first) == 1 and len(first[0]["findings"]) == 1  # one burst, one finding, one incident


def test_separate_bursts_are_separate_findings():
    events = [ev(n) for n in range(5)] + [ev(1000 + n) for n in range(5)]
    assert len(detect(events)[0]["findings"]) == 2


# --- Persistence and the live pipeline ---------------------------------------------------------

def test_findings_and_incidents_persist_with_stable_identity(client):
    client.post("/api/replay")
    first = client.get("/api/v1/findings").get_json()
    assert first["total"] >= 6 and all(f["created_at"] and f["status"] == "active" for f in first["findings"])
    client.post("/api/replay")
    second = client.get("/api/v1/findings").get_json()
    assert {(f["finding_id"], f["created_at"]) for f in first["findings"]} == {(f["finding_id"], f["created_at"]) for f in second["findings"]}
    sequences = client.get("/api/v1/findings?engine=sequence").get_json()["findings"]
    assert [f["rule_id"] for f in sequences] == ["SEQ-002"]


def live_collector(client, path):
    app = client.application
    return Collector(app.extensions["store"], path, on_commit=app.extensions["analyzer"].after_commit)


def test_live_detection_runs_after_each_commit_and_handles_late_events(client, tmp_path):
    log = tmp_path / "cowrie.json"
    log.write_bytes(jsonl(raw(30, eventid="cowrie.login.success", session="entry"), raw(35, eventid="cowrie.command.input", input="echo hi", session="entry")))
    collector = live_collector(client, log)
    collector.poll()
    assert client.get("/api/overview?source=live").get_json()["incidents"] == []
    with log.open("ab") as f:  # earlier failures arrive late
        f.write(jsonl(*[raw(n * 5, session=f"g{n}") for n in range(5)]))
    collector.poll()
    incidents = client.get("/api/overview?source=live").get_json()["incidents"]
    assert len(incidents) == 1
    assert {f["id"] for f in incidents[0]["findings"]} == {"AUTH-001", "AUTH-002", "SEQ-002"}


def test_merged_case_keeps_status_and_audit_trail(client, tmp_path):
    log = tmp_path / "cowrie.json"
    log.write_bytes(jsonl(raw(100, eventid="cowrie.command.input", input="uname -a", session="X")))
    collector = live_collector(client, log)
    collector.poll()
    original = client.get("/api/overview?source=live").get_json()["incidents"][0]["id"]
    assert client.patch(f"/api/incidents/{original}?source=live", json={"status": "investigating"}).status_code == 200
    with log.open("ab") as f:  # a burst that includes a failure from session X, anchored in another session
        f.write(jsonl(raw(0, session="X"), *[raw(n * 5, session=f"g{n}") for n in range(1, 5)]))
    collector.poll()
    incidents = client.get("/api/overview?source=live").get_json()["incidents"]
    assert len(incidents) == 1 and incidents[0]["id"] != original
    detail = client.get(f"/api/incidents/{original}?source=live").get_json()  # old ID resolves
    assert detail["id"] == incidents[0]["id"] and detail["status"] == "investigating"
    kinds = [a["kind"] for a in detail["activity"]]
    assert kinds == ["merge", "status"] and detail["activity"][0]["actor"] == "aegis"


def test_configuration_change_supersedes_old_findings(tmp_path):
    path = tmp_path / "aegis.sqlite3"
    make_client(path).post("/api/replay")
    client = make_client(path, {"disabled_rules": ["DISC-001"]})
    active = {f["rule_id"] for f in client.get("/api/v1/findings").get_json()["findings"]}
    superseded = {f["rule_id"] for f in client.get("/api/v1/findings?status=superseded").get_json()["findings"]}
    assert "DISC-001" not in active and "DISC-001" in superseded
    assert client.get("/api/v1/detection").get_json()["config"]["disabled_rules"] == ["DISC-001"]


def test_detection_failure_never_blocks_ingestion(client, monkeypatch):
    store = client.application.extensions["store"]
    real = store.replace_detection

    def broken(*args, **kwargs):
        raise RuntimeError("detector bug")
    monkeypatch.setattr(store, "replace_detection", broken)
    assert upload(client, *[raw(n) for n in range(5)]).status_code == 200
    assert store.usage()["events"] == 5
    assert store.detection_state("imported")["dirty"] == 1
    monkeypatch.setattr(store, "replace_detection", real)
    overview = client.get("/api/overview?source=imported").get_json()  # recomputes the dirty dataset
    assert len(overview["incidents"]) == 1 and overview["detection"]["dirty"] == 0


def test_v02_database_upgrade_merges_split_cases(tmp_path):
    path = tmp_path / "old.sqlite3"
    events = [ev(n * 5, session=f"s{n}") for n in range(6)]
    old_split = session_key(events[5])  # v0.2 raised a second AUTH-001 case for the sixth failure
    with sqlite3.connect(path) as db:
        db.executescript("""CREATE TABLE events(id TEXT PRIMARY KEY, source TEXT NOT NULL, body TEXT NOT NULL);
            CREATE TABLE workflow(id TEXT PRIMARY KEY, status TEXT NOT NULL);
            CREATE TABLE activity(id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL, timestamp TEXT NOT NULL, kind TEXT NOT NULL, body TEXT NOT NULL);""")
        db.executemany("INSERT INTO events VALUES (?,?,?)", [(e["id"], e["source"], json.dumps({k: v for k, v in e.items() if k != "event_type"})) for e in events])
        db.execute("INSERT INTO workflow VALUES (?, 'resolved')", (old_split,))
        db.execute("INSERT INTO activity(incident_id,timestamp,kind,body) VALUES (?, '2026-01-02T00:00:00+00:00', 'status', 'open → resolved')", (old_split,))
    client = make_client(path)
    incidents = client.get("/api/overview?source=imported").get_json()["incidents"]
    assert len(incidents) == 1 and incidents[0]["status"] == "resolved"
    activity = client.get(f"/api/incidents/{old_split}?source=imported").get_json()["activity"]
    assert [a["kind"] for a in activity] == ["merge", "status"]
    assert activity[1]["before"] == "open" and activity[1]["after"] == "resolved"  # backfilled audit values
    assert client.get("/api/events?source=imported&event_type=auth_failure").get_json()["total"] == 6  # backfilled columns


# --- Workflow and queries -----------------------------------------------------------------------

def test_workflow_transitions_are_validated_and_audited(client):
    client.post("/api/replay")
    incident = client.get("/api/overview").get_json()["incidents"][0]["id"]
    path = f"/api/incidents/{incident}"
    assert client.patch(path, json={"status": "resolved"}).status_code == 200
    response = client.patch(path, json={"status": "false_positive"})
    assert response.status_code == 409 and "reopened" in response.get_json()["error"]
    assert client.patch(path, json={"status": "open"}).status_code == 200
    assert client.patch(path, json={"status": "false_positive"}).status_code == 200
    overview = client.get("/api/overview").get_json()
    assert overview["open_incidents"] == len(overview["incidents"]) - 1
    status = [a for a in client.get(path).get_json()["activity"] if a["kind"] == "status"]
    assert [(a["before"], a["after"], a["actor"]) for a in status][0] == ("open", "false_positive", "local-analyst")
    listed = client.get("/api/v1/incidents?status=false_positive").get_json()
    assert listed["total"] == 1 and listed["incidents"][0]["id"] == incident


def test_event_filters_and_bounds(client):
    client.post("/api/replay")
    assert client.get("/api/events?event_type=auth_failure").get_json()["total"] == 6
    assert client.get("/api/events?session=demo-auth").get_json()["total"] == 8
    assert client.get("/api/events?since=2026-10-05T14:31:00Z").get_json()["total"] == 10
    assert client.get("/api/events?since=2026-10-05T14:31:00Z&until=2026-10-05T14:31:30Z").get_json()["total"] == 3
    assert client.get("/api/events?q=100%25").get_json()["total"] == 0  # % is literal
    for bad in ("since=yesterday", "since=2026-10-05T14:31:00", "session=" + "x" * 201):
        assert client.get("/api/events?" + bad).status_code == 400
    assert client.get("/api/v1/incidents?limit=201").status_code == 400
    assert client.get("/api/v1/incidents?status=closed").status_code == 400


def test_session_timeline(client):
    client.post("/api/replay")
    timeline = client.get("/api/v1/sessions/demo-auth/timeline").get_json()
    assert len(timeline["events"]) == 8 and not timeline["truncated"]
    assert {f["rule_id"] for f in timeline["findings"]} == {"AUTH-001", "AUTH-002", "DISC-001", "SEQ-002"}
    assert [e["timestamp"] for e in timeline["events"]] == sorted(e["timestamp"] for e in timeline["events"])
    assert client.get("/api/v1/sessions/missing/timeline").status_code == 404


def test_reports_label_synthetic_data_and_provenance(client):
    client.post("/api/replay")
    incident = next(i for i in client.get("/api/overview").get_json()["incidents"] if len(i["findings"]) > 1)
    text = client.get(f"/api/incidents/{incident['id']}/report").text
    assert "synthetic replay; these are not observed attacks" in text
    assert "contains no observed attacker activity" in text
    assert "Ingested from: synthetic:demo-replay (parser 2.0.0)" in text
    assert "Why:" in text and "SEQ-002 v1 (sequence)" in text


def test_imported_report_has_no_synthetic_disclaimer_and_marks_weak_links(client):
    upload(client, *[raw(n * 5, session=f"g{n}") for n in range(5)], raw(30, eventid="cowrie.login.success", session="entry"))
    incident = client.get("/api/overview?source=imported").get_json()["incidents"][0]
    text = client.get(f"/api/incidents/{incident['id']}/report?source=imported").text
    assert "synthetic" not in text.lower()
    assert "address-linked" in text and "does not establish a single actor" in text


def test_real_world_client_version_shapes():
    # Shapes seen on the AWS honeypot: scanners send HTTP or TLS bytes where an SSH version belongs.
    http = ev(eventid="cowrie.client.version", version="GET / HTTP/1.1")
    binary = ev(eventid="cowrie.client.version", version="\x16\x03\x01\x02\x00\x01")
    assert http["client_version"] == "GET / HTTP/1.1"
    assert binary["client_version"] == "\x16\x03\x01\x02\x00\x01"  # kept as observed; the UI shows control characters escaped
    assert "client_version" not in ev(eventid="cowrie.client.version", version="")
    assert "uuid" not in ev(eventid="cowrie.session.connect", uuid="00000000-0000-4000-8000-000000000000")  # undocumented field stays in raw evidence only
