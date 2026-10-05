import io
import json
from datetime import datetime, timedelta, timezone

import pytest

from app import create_app, read_log_batch
from aegis.demo import demo_records
from aegis.engine import detect, normalize


def event(seconds=0, **changes):
    raw = dict(timestamp=(datetime(2026, 1, 1, tzinfo=timezone.utc)+timedelta(seconds=seconds)).isoformat(),
        eventid="cowrie.login.failed", sensor="sensor-a", session="session-a", src_ip="192.0.2.1")
    raw.update(changes)
    return normalize(raw, "imported")


def test_failure_window_and_boundary():
    assert detect([event(n*10) for n in range(4)]) == []
    assert detect([event(n*15) for n in range(5)])[0]["findings"][0]["id"] == "AUTH-001"
    assert detect([event(n*16) for n in range(5)]) == []


def test_cross_session_detection_and_evidence():
    events = [event(n*5, session=f"s{n}") for n in range(5)]
    events.append(event(30, session="success", eventid="cowrie.login.success"))
    incidents = detect(list(reversed(events)))
    success = next(i for i in incidents if i["session"] == "success")
    assert success["findings"][0]["id"] == "AUTH-002"
    assert len(success["events"]) == 6
    assert set(success["findings"][0]["evidence_ids"]) == {e["id"] for e in success["events"]}


@pytest.mark.parametrize("field,other", [("sensor", "sensor-b"), ("src_ip", "192.0.2.2"), ("source", "demo")])
def test_correlation_boundaries(field, other):
    events = [event(n*5) for n in range(4)]
    fifth = event(25)
    fifth[field] = other
    assert not detect(events + [fifth])


def test_login_correlation_expires():
    events = [event(n*5) for n in range(5)] + [event(400, eventid="cowrie.login.success")]
    assert {f["id"] for i in detect(events) for f in i["findings"]} == {"AUTH-001"}


def test_redaction_and_canonical_hash():
    raw = demo_records()[1] | {"password": "sensitive", "message": "password=sensitive", "key": "private"}
    clean = normalize(raw, "imported")
    assert "sensitive" not in json.dumps(clean)
    raw["timestamp"] = raw["timestamp"].replace("+00:00", "Z")
    assert normalize(raw, "imported")["id"] == clean["id"]


@pytest.mark.parametrize("command,expected", [("uname -a", True), ("/bin/hostname", True), ("echo uname", False), ("hostnamething", False)])
def test_discovery_is_command_not_keyword(command, expected):
    assert bool(detect([event(eventid="cowrie.command.input", input=command)])) == expected


@pytest.fixture
def client(tmp_path):
    app = create_app(tmp_path / "aegis.sqlite3")
    app.config["TESTING"] = True
    with app.test_client() as client:
        client.get("/")
        with client.session_transaction() as session:
            client.environ_base["HTTP_X_AEGIS_CSRF"] = session["csrf"]
        yield client


def test_replay_idempotent_and_sources_separate(client):
    first = client.post("/api/replay").get_json()
    assert first["inserted"] == 18
    assert first["evaluation"] | {} == dict(true_positives=3, false_positives=0, false_negatives=0, true_negatives=2, scope="Five synthetic sessions only; not an estimate of real-world performance.")
    assert client.post("/api/replay").get_json()["inserted"] == 0
    assert client.get("/api/overview?source=imported").get_json()["events"] == 0


def test_atomic_import_and_duplicate_handling(client):
    line = json.dumps(demo_records()[0])
    response = client.post("/api/import", data={"file": (io.BytesIO((line+'\n{}').encode()), "bad.jsonl")})
    assert response.status_code == 400
    assert client.get("/api/overview?source=imported").get_json()["events"] == 0
    response = client.post("/api/import", data={"file": (io.BytesIO((line+'\n'+line).encode()), "good.jsonl")})
    assert response.get_json() == {"inserted": 1, "duplicates": 1}


def test_workflow_report_and_ai_disabled(client, monkeypatch):
    monkeypatch.delenv("AEGIS_OLLAMA_MODEL", raising=False)
    client.post("/api/replay")
    incident = client.get("/api/overview").get_json()["incidents"][0]
    path = f"/api/incidents/{incident['id']}"
    assert client.patch(path, json={"status": "resolved"}).status_code == 200
    assert client.get(path).get_json()["status"] == "resolved"
    report = client.get(path+"/report").text
    assert "not AI" in report
    assert incident["findings"][0]["evidence_ids"][0] in report
    assert client.patch(path, json={"status": "nonsense"}).status_code == 400
    assert client.post(path+"/ai").status_code == 503


def test_request_boundaries(client):
    assert client.post("/api/replay", headers={"X-Aegis-CSRF": "bad"}).status_code == 403
    assert client.post("/api/replay", headers={"Origin": "https://other.example"}).status_code == 403
    assert client.get("/", headers={"Host": "other.example"}).status_code == 400
    assert client.get("/api/overview?source=anything").status_code == 400
    assert client.get("/api/incidents/missing").status_code == 404


def test_ai_uses_only_rule_findings(client, monkeypatch):
    import app as module
    monkeypatch.setenv("AEGIS_OLLAMA_MODEL", "test-model")
    client.post("/api/replay")
    incident = client.get("/api/overview").get_json()["incidents"][0]
    class Reply:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, size): return b'{"response":"Review the cited observations."}'
    class Opener:
        def open(self, req, timeout):
            payload = json.loads(req.data)
            assert "uname" not in payload["prompt"]
            assert incident["findings"][0]["evidence_ids"][0] in payload["prompt"]
            assert payload["stream"] is False
            return Reply()
    monkeypatch.setattr(module.urllib.request, "build_opener", lambda *a: Opener())
    path = f"/api/incidents/{incident['id']}/ai"
    assert client.post(path).get_json()["text"] == "Review the cited observations."
    monkeypatch.setenv("AEGIS_OLLAMA_URL", "http://example.com")
    assert client.post(path).status_code == 503


def test_collector_partial_lines_and_oversized_records(tmp_path):
    path = tmp_path / "cowrie.json"
    line = json.dumps(demo_records()[0]).encode()
    path.write_bytes(line)
    assert read_log_batch(path) == ([], 0, False, 0)
    path.write_bytes(line + b"\n" + b"x" * 150000 + b"\n" + line + b"\n")
    batch, offset, discarding, rejected = read_log_batch(path)
    assert len(batch) == 2
    assert offset == path.stat().st_size
    assert not discarding
    assert rejected == 1
    assert read_log_batch(path, offset)[0] == []
