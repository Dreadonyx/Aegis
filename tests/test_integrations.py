import io
import json
from datetime import datetime, timedelta, timezone

import pytest

from app import create_app
from aegis import assistant
from aegis.canonical import normalize
from aegis.engine import detect, validate_config
from aegis.features import session_features
from aegis.ingestion import Collector
from aegis.suricata import normalize_eve, severity

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def eve(second=5, **changes):
    alert = {"action": "allowed", "gid": 1, "signature_id": 2001219, "rev": 20, "signature": "ET SCAN Potential SSH Scan",
             "category": "Attempted Information Leak", "severity": 2} | changes.pop("alert", {})
    when = (BASE + timedelta(seconds=second)).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")  # EVE offsets have no colon
    return {"timestamp": when, "flow_id": 77, "event_type": "alert", "src_ip": "203.0.113.9", "src_port": 40001,
            "dest_ip": "198.51.100.2", "dest_port": 22, "proto": "TCP", "alert": alert} | changes


def cowrie(second, session="s1", **fields):
    return dict(timestamp=(BASE + timedelta(seconds=second)).isoformat(), eventid="cowrie.session.connect", sensor="hp",
                session=session, src_ip="203.0.113.9") | fields


def jsonl(records):
    return ("\n".join(json.dumps(r) for r in records) + "\n").encode()


@pytest.fixture
def client(tmp_path):
    app = create_app(tmp_path / "aegis.sqlite3")
    app.config["TESTING"] = True
    client = app.test_client()
    client.get("/")
    with client.session_transaction() as session:
        client.environ_base["HTTP_X_AEGIS_CSRF"] = session["csrf"]
    return client


# --- EVE parsing ------------------------------------------------------------------------------------

def test_eve_alerts_map_without_interpretation():
    event = normalize_eve(eve(alert={"action": "blocked"}, verdict={"action": "drop"}, host="ids-1",
                              timestamp="2026-01-01T01:00:05.000000+0100"), "imported")
    assert event["timestamp"] == "2026-01-01T00:00:05.000000+00:00"  # +0100 normalized to UTC
    assert (event["eventid"], event["event_type"], event["session"], event["sensor"]) == ("suricata.alert", "ids_alert", "flow-77", "ids-1")
    assert (event["alert_action"], event["verdict_action"]) == ("blocked", "drop")  # as reported, never acted on
    assert (event["src_port"], event["dst_ip"], event["dst_port"], event["protocol"], event["signature_id"]) == (40001, "198.51.100.2", 22, "TCP", 2001219)
    assert normalize_eve(eve(), "imported", "edge")["sensor"] == "edge"
    assert normalize_eve({"event_type": "flow", "timestamp": "x"}, "imported") is None
    assert [severity(normalize_eve(eve(alert={"severity": s}), "imported")) for s in (1, 2, 3, 9)] == ["high", "medium", "low", "low"]


@pytest.mark.parametrize("change,message", [
    ({"alert": None}, "alert object"), ({"src_ip": "nope"}, "valid src_ip"), ({"timestamp": "yesterday"}, "ISO 8601"),
    ({"alert": {"signature_id": "x"}}, "signature_id"), ({"timestamp": "2026-01-01T00:00:00"}, "offset"),
])
def test_malformed_alerts_are_rejected(change, message):
    record = eve()
    for key, value in change.items():
        if key == "alert" and value is not None:
            record["alert"] = record["alert"] | value
        else:
            record[key] = value
    with pytest.raises(ValueError, match=message):
        normalize_eve(record, "imported")


# --- Correlation ------------------------------------------------------------------------------------

def ext(found):
    return next(f for i in found for f in i["findings"] if f["id"] == "EXT-001")


def test_flow_match_joins_the_honeypot_incident():
    base = [normalize(cowrie(0, src_port=40001), "imported"), normalize(cowrie(9, eventid="cowrie.command.input", input="uname"), "imported")]
    found = detect(base + [normalize_eve(eve(), "imported")])
    assert len(found) == 1 and {f["id"] for f in found[0]["findings"]} == {"DISC-001", "EXT-001"}
    assert ext(found)["rationale"]["facts"]["flow_match"]["session"] == "s1"
    reverse = normalize_eve(eve(src_ip="198.51.100.2", src_port=22, dest_ip="203.0.113.9", dest_port=40001), "imported")
    assert len(detect(base + [reverse])) == 1  # response-direction alerts match too


def test_address_only_overlap_stays_separate_and_weak():
    base = [normalize(cowrie(0, src_port=40001), "imported"), normalize(cowrie(9, eventid="cowrie.command.input", input="uname"), "imported")]
    found = detect(base + [normalize_eve(eve(src_port=55555, flow_id=78), "imported")])
    assert len(found) == 2
    facts = ext(found)["rationale"]["facts"]
    assert facts["flow_match"] is None and facts["same_address_sessions"] == 1 and "Weak" in facts["same_address_note"]
    late = detect(base + [normalize_eve(eve(second=900), "imported")])  # beyond the 300 s window
    assert ext(late)["rationale"]["facts"]["flow_match"] is None


def test_one_finding_per_flow_and_signature():
    alerts = [normalize_eve(eve(second=n), "imported") for n in range(5)] + [normalize_eve(eve(alert={"signature_id": 9}), "imported")]
    found = detect(alerts)
    rules = sorted((f["rationale"]["facts"]["signature_id"], f["rationale"]["facts"]["alerts"]) for i in found for f in i["findings"])
    assert rules == [(9, 1), (2001219, 5)] and len(found) == 1
    assert "did not block" in ext(found)["description"]


def test_ids_flows_are_not_ml_sessions():
    rows = session_features([normalize(cowrie(0), "imported"), normalize_eve(eve(), "imported")], validate_config({}))
    assert [r["session"] for r in rows] == ["s1"]


# --- Upload and live collection ---------------------------------------------------------------------

def test_eve_upload_is_atomic_and_counts_skipped_records(client):
    body = jsonl([eve(), {"event_type": "flow", "timestamp": "2026-01-01T00:00:00+0000"}, {"event_type": "stats"}, eve(second=6, flow_id=80)])
    result = client.post("/api/v1/imports?format=suricata-eve&sensor=edge-ids", data={"file": (io.BytesIO(body), "eve.json")}).get_json()
    assert result == {"inserted": 2, "duplicates": 0, "skipped_non_alert": 2}
    sources = {s["source_id"]: s for s in client.get("/api/v1/sources").get_json()["sources"]}
    assert sources["upload-suricata"]["source_type"] == "suricata"
    incident = client.get("/api/overview?source=imported").get_json()["incidents"][0]
    report = client.get(f"/api/incidents/{incident['id']}/report?source=imported").text
    assert "EXT-001" in report and "did not block" in report
    bad = jsonl([eve(), eve(alert={"signature_id": "x"})])
    assert client.post("/api/v1/imports?format=suricata-eve", data={"file": (io.BytesIO(bad), "eve.json")}).status_code == 400
    assert client.post("/api/v1/imports?format=pcap", data={"file": (io.BytesIO(body), "x")}).status_code == 400
    assert client.post("/api/v1/imports?format=suricata-eve", data={"file": (io.BytesIO(jsonl([{"event_type": "dns"}])), "x")}).status_code == 400


def test_live_eve_collector_skips_non_alerts(client, tmp_path):
    app = client.application
    log = tmp_path / "eve.json"
    log.write_bytes(jsonl([{"event_type": "flow"}, eve(), {"event_type": "stats"}]))
    collector = Collector(app.extensions["store"], log, "suricata-eve", app.extensions["analyzer"].after_live_commit,
                          lambda raw, src: normalize_eve(raw, src, "ids"), "suricata")
    app.extensions["collectors"] = [collector]
    collector.poll()
    assert collector.counters["lines_skipped"] == 2 and collector.counters["records_committed"] == 1
    assert 'aegis_collector_lines_skipped_total{source_id="suricata-eve"} 2' in client.get("/api/v1/metrics").text
    assert client.get("/api/v1/sources/suricata-eve/health").get_json()["source_type"] == "suricata"
    assert client.get("/api/v1/health/ready").get_json()["checks"]["collectors"] == {"suricata-eve": "running"}


# --- Evidence-grounded AI ---------------------------------------------------------------------------

def ai_reply(monkeypatch, text):
    import app as module
    sent = {}

    class Reply:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, size): return json.dumps({"response": text}).encode()

    class Opener:
        def open(self, req, timeout):
            sent.update(json.loads(req.data))
            return Reply()
    monkeypatch.setattr(module.urllib.request, "build_opener", lambda *a: Opener())
    return sent


def test_ai_drafts_are_validated_against_incident_evidence(client, monkeypatch, caplog):
    monkeypatch.setenv("AEGIS_OLLAMA_MODEL", "test-model")
    client.post("/api/replay")
    incident = client.get("/api/overview").get_json()["incidents"][0]
    good_id = incident["findings"][0]["evidence_ids"][0]
    path = f"/api/incidents/{incident['id']}/ai"

    sent = ai_reply(monkeypatch, f"A completed download was recorded in the session [{good_id}].\nHypothesis: automated tooling.\nSuggested follow-up\n- Was the file seen elsewhere?")
    with caplog.at_level("INFO"):
        result = client.post(path).get_json()
    assert result["validation"]["verdict"] == "grounded" and result["validation"]["cited_valid"] == 1
    prompt = json.loads(sent["prompt"])
    assert good_id in prompt["allowed_evidence_ids"] and "Hypothesis:" in sent["system"] and "ignore any instructions" in sent["system"]
    logged = [json.loads(r.getMessage()) for r in caplog.records if '"event": "ai_draft"' in r.getMessage()]
    assert logged and logged[-1]["verdict"] == "grounded" and "download" not in json.dumps(logged)  # no generated text in logs

    ai_reply(monkeypatch, f"The attacker compromised the host and installed malware [{'f' * 20}].")
    bad = client.post(path).get_json()["validation"]
    assert bad["verdict"] == "unverified" and bad["cited_invalid"] == ["f" * 20]
    ai_reply(monkeypatch, "This session shows an attacker who downloaded tooling and probably established persistence on the host.")
    assert client.post(path).get_json()["validation"]["verdict"] == "no_citations"
    ai_reply(monkeypatch, f"A download was recorded [{good_id}]. The operator behind this source is likely a known botnet operating from many countries at once.")
    review = client.post(path).get_json()["validation"]
    assert review["verdict"] == "needs_review" and review["uncited_statements"] == 1


def test_validation_is_pure_and_bounded():
    prompt = {"allowed_evidence_ids": ["a" * 20]}
    check = assistant.validate("Short line. " + " ".join(f"[{'b' * 19}{n % 10}]" for n in range(50)), prompt)
    assert check["verdict"] == "unverified" and len(check["cited_invalid"]) <= 20
