import io
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

pytest.importorskip("sklearn")

from app import create_app
from aegis import labeled_eval, ml
from aegis.canonical import normalize
from aegis.engine import validate_config
from aegis.features import FEATURE_VERSION, NAMES, session_features

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def raw(second, session, **fields):
    return dict(timestamp=(BASE + timedelta(seconds=second)).isoformat(), eventid="cowrie.session.connect", sensor="hp",
                session=session, src_ip="192.0.2.60") | fields


def normal_sessions(count=80, start=0, seed=7):
    """Scanner-like and short interactive sessions with some natural variation."""
    rng, records = random.Random(seed), []
    for n in range(count):
        t, s = start + n * 600, f"n{start}-{n}"
        records += [raw(t, s), raw(t + 1, s, eventid="cowrie.client.version", version="SSH-2.0-Go")]
        if n % 4 == 0:
            records += [raw(t + 2, s, eventid="cowrie.login.success", username="root"),
                        raw(t + 3, s, eventid="cowrie.command.input", input=f"echo {rng.randint(1, 9)}")]
        records.append(raw(t + 5, s, eventid="cowrie.session.closed", duration_ms=rng.randint(200, 4000)))
    return records


def outlier(start):
    s = "intruder"
    records = [raw(start, s), raw(start + 1, s, eventid="cowrie.login.success", username="root")]
    records += [raw(start + 2 + k, s, eventid="cowrie.command.input", input=f"uname -a; cat /proc/cpuinfo #{k}") for k in range(40)]
    records += [raw(start + 50 + k, s, eventid="cowrie.session.file_download", shasum=f"{k:064x}") for k in range(5)]
    records.append(raw(start + 900, s, eventid="cowrie.session.closed", duration_ms=900000))
    return records


def jsonl(records):
    return ("\n".join(json.dumps(r) for r in records) + "\n").encode()


def make_client(path, config=None, model_dir=None):
    app = create_app(path, detection_config=config, model_dir=model_dir)
    app.config["TESTING"] = True
    client = app.test_client()
    client.get("/")
    with client.session_transaction() as session:
        client.environ_base["HTTP_X_AEGIS_CSRF"] = session["csrf"]
    return client


def upload(client, records):
    response = client.post("/api/import", data={"file": (io.BytesIO(jsonl(records)), "x.jsonl")})
    assert response.status_code == 200, response.get_json()


@pytest.fixture
def trained(tmp_path):
    """A model trained from an imported (non-synthetic) dataset through the CLI, as an operator would."""
    db = tmp_path / "train.sqlite3"
    upload(make_client(db), normal_sessions())
    out = tmp_path / "model"
    assert ml.main(["train", "--db", str(db), "--dataset", "imported", "--until", "2026-02-01T00:00:00Z", "--out", str(out)]) == 0
    return out


ENABLED = {"ml_enabled": True}


# --- Features and training ------------------------------------------------------------------------

def test_session_features_are_explicit_and_versioned():
    events = [normalize(r, "imported") for r in outlier(0)]
    row = session_features(events, validate_config({}))[0]
    v = row["values"]
    assert list(v) == list(NAMES) and FEATURE_VERSION == "1"
    assert (v["commands"], v["distinct_commands"], v["discovery_commands"], v["downloads"], v["auth_successes"]) == (40, 40, 40, 5, 1)
    assert v["duration_s"] == 900.0 and v["events"] == 48


def test_training_manifest_records_provenance(trained):
    manifest = json.loads((trained / "model.json").read_text())
    assert manifest["model_version"].startswith("if-") and manifest["model_sha256"] == ml.sha256_file(trained / "model.joblib")
    expected = {"source": "database", "dataset": "imported", "until": "2026-02-01T00:00:00.000000+00:00", "synthetic": False, "sessions": 80}
    assert expected.items() <= manifest["training"].items()
    assert manifest["params"]["random_state"] == 42 and manifest["feature_version"] == FEATURE_VERSION
    assert manifest["threshold"]["quantile"] == 0.99 and "not a probability" in manifest["interpretation"].lower()
    assert manifest["libraries"]["scikit-learn"]
    assert ml.main(["inspect", str(trained)]) == 0


def test_training_guards(tmp_path, capsys):
    db = tmp_path / "db.sqlite3"
    client = make_client(db)
    client.post("/api/replay")
    upload(client, normal_sessions(20))
    assert ml.main(["train", "--db", str(db), "--dataset", "demo", "--until", "2027-01-01T00:00:00Z", "--out", str(tmp_path / "a")]) == 2
    assert "--allow-synthetic" in capsys.readouterr().err
    assert ml.main(["train", "--db", str(db), "--dataset", "imported", "--out", str(tmp_path / "b")]) == 2
    assert "explicit --until" in capsys.readouterr().err
    assert ml.main(["train", "--db", str(db), "--dataset", "imported", "--until", "2027-01-01T00:00:00Z", "--out", str(tmp_path / "c")]) == 2
    assert "at least 50 sessions" in capsys.readouterr().err
    (tmp_path / "exists").mkdir()
    upload(client, normal_sessions(60, start=100000))
    assert ml.main(["train", "--db", str(db), "--dataset", "imported", "--until", "2027-01-01T00:00:00Z", "--out", str(tmp_path / "exists")]) == 2
    assert "exists" in capsys.readouterr().err  # never overwrites a model


def test_training_window_excludes_later_events(tmp_path):
    db = tmp_path / "db.sqlite3"
    upload(make_client(db), normal_sessions(60) + normal_sessions(60, start=10_000_000))
    assert ml.main(["train", "--db", str(db), "--dataset", "imported", "--until", "2026-03-01T00:00:00Z", "--out", str(tmp_path / "m")]) == 0
    assert json.loads((tmp_path / "m" / "model.json").read_text())["training"]["sessions"] == 60


# --- Fail closed ----------------------------------------------------------------------------------

def test_load_failures_are_explicit(trained, tmp_path, monkeypatch):
    def status(path, dataset=None, age=90):
        with pytest.raises(ml.ModelUnavailable) as caught:
            ml.load(path, age, dataset)
        return caught.value.status
    assert status(None) == "missing" and status(tmp_path / "nowhere") == "missing"

    tampered = tmp_path / "tampered"
    tampered.mkdir()
    (tampered / "model.json").write_text((trained / "model.json").read_text())
    (tampered / "model.joblib").write_bytes((trained / "model.joblib").read_bytes() + b"x")
    import joblib
    monkeypatch.setattr(joblib, "load", lambda *a: pytest.fail("an unverified model file was unpickled"))
    assert status(tampered) == "integrity"
    monkeypatch.undo()

    def edited(change):
        target = tmp_path / f"edited-{len(list(tmp_path.iterdir()))}"
        target.mkdir()
        (target / "model.joblib").write_bytes((trained / "model.joblib").read_bytes())
        manifest = json.loads((trained / "model.json").read_text())
        change(manifest)
        (target / "model.json").write_text(json.dumps(manifest))
        return target
    assert status(edited(lambda m: m["threshold"].update(score=99.0))) == "integrity"
    assert status(edited(lambda m: m["training"].update(synthetic=True))) == "integrity"
    assert status(edited(lambda m: m.update(feature_version="0"))) == "stale"
    assert status(edited(lambda m: m["libraries"].update({"scikit-learn": "0.1"}))) == "incompatible"


def test_old_model_is_stale(trained, monkeypatch):
    class Later(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.now(tz) + timedelta(days=91)
    monkeypatch.setattr(ml, "datetime", Later)
    with pytest.raises(ml.ModelUnavailable, match="91 days old"):
        ml.load(trained, 90)


def test_missing_dependency_fails_closed(tmp_path, trained, monkeypatch):
    def missing():
        raise ml.ModelUnavailable("dependency", "scikit-learn is not installed")
    monkeypatch.setattr(ml, "_libraries", missing)
    client = make_client(tmp_path / "db.sqlite3", ENABLED, trained)
    upload(client, outlier(0))
    status = client.get("/api/v1/ml?source=imported").get_json()
    assert status["status"] == "dependency" and status["signals"] == 0
    assert client.get("/api/overview?source=imported").get_json()["incidents"]  # rules unaffected


# --- Runtime --------------------------------------------------------------------------------------

def test_ml_is_off_by_default(tmp_path, trained):
    client = make_client(tmp_path / "db.sqlite3", None, trained)
    upload(client, outlier(0))
    status = client.get("/api/v1/ml?source=imported").get_json()
    assert status["enabled"] is False and status["status"] == "disabled" and status["signals"] == 0
    assert not any(r["engine"] == "ml" for r in client.get("/api/overview").get_json()["rules"])


def test_enabled_model_flags_the_outlier_as_a_signal(tmp_path, trained):
    client = make_client(tmp_path / "db.sqlite3", ENABLED, trained)
    upload(client, normal_sessions(40, start=5_000_000, seed=11) + outlier(9_000_000))
    status = client.get("/api/v1/ml?source=imported").get_json()
    assert status["status"] == "ok" and status["scored_sessions"] == 41
    findings = client.get("/api/v1/findings?source=imported&engine=ml").get_json()["findings"]
    flagged = {f["session"] for f in findings}
    assert "intruder" in flagged and len(flagged) <= 3  # at most a few ordinary sessions cross a 99th-percentile threshold
    f = next(f for f in findings if f["session"] == "intruder")
    assert (f["severity"], f["score_type"], f["rule_id"]) == ("low", "isolation_forest_anomaly", "ML-001")
    facts = f["rationale"]["facts"]
    assert facts["training_percentile"] == 100.0 and facts["model_version"] == status["model"]["model_version"]
    assert facts["largest_deviations"] and "does not attribute" in facts["deviation_note"]
    incidents = client.get("/api/overview?source=imported").get_json()["incidents"]
    intruder = next(i for i in incidents if i["session"] == "intruder")
    assert all(x["engine"] != "ml" for x in intruder["findings"])  # never part of an incident's findings
    detail = client.get(f"/api/incidents/{intruder['id']}?source=imported").get_json()
    assert any(s["rule_id"] == "ML-001" for s in detail["signals"])


def test_synthetic_model_cannot_score_observed_telemetry(tmp_path):
    db = tmp_path / "db.sqlite3"
    client = make_client(db)
    client.post("/api/replay")
    # The demo has five sessions; train a synthetic model from a larger synthetic import instead.
    labeled = tmp_path / "synthetic"
    labeled.mkdir()
    (labeled / "manifest.json").write_text(json.dumps({"name": "synthetic", "version": "1", "synthetic": True}))
    (labeled / "events.jsonl").write_bytes(jsonl(normal_sessions()))
    (labeled / "labels.jsonl").write_text(json.dumps({"session": "n0-0", "label": "benign"}))
    assert ml.main(["train", "--labeled", str(labeled), "--out", str(tmp_path / "x")]) == 2
    assert ml.main(["train", "--labeled", str(labeled), "--allow-synthetic", "--out", str(tmp_path / "syn")]) == 0
    client = make_client(db, ENABLED, tmp_path / "syn")
    upload(client, outlier(0))
    status = client.get("/api/v1/ml?source=imported").get_json()
    assert status["status"] == "rejected" and status["signals"] == 0
    assert client.get("/api/v1/ml?source=demo").get_json()["status"] == "ok"  # synthetic models may score synthetic data


def test_losing_the_model_supersedes_its_findings(tmp_path, trained):
    client = make_client(tmp_path / "db.sqlite3", ENABLED, trained)
    upload(client, outlier(9_000_000))
    assert client.get("/api/v1/ml?source=imported").get_json()["signals"] >= 1
    (trained / "model.joblib").unlink()
    status = client.get("/api/v1/ml?source=imported").get_json()
    assert status["status"] == "missing" and status["signals"] == 0
    assert client.get("/api/v1/findings?source=imported&engine=ml&status=superseded").get_json()["total"] >= 1


def test_scoring_errors_are_isolated(tmp_path, trained, monkeypatch):
    def broken(self, rows):
        raise RuntimeError("model bug")
    monkeypatch.setattr(ml.Model, "score", broken)
    client = make_client(tmp_path / "db.sqlite3", ENABLED, trained)
    upload(client, outlier(0) + normal_sessions(5))
    status = client.get("/api/v1/ml?source=imported").get_json()
    assert status["dirty"] == 1 and "RuntimeError" in status["last_error"]
    assert client.get("/api/overview?source=imported").get_json()["incidents"]
    assert not client.get("/api/v1/statistics?source=imported").get_json()["dirty"]


# --- Evaluation -----------------------------------------------------------------------------------

def test_labeled_evaluation_includes_ml_and_reports_leakage(tmp_path, trained):
    data = tmp_path / "eval"
    data.mkdir()
    (data / "manifest.json").write_text(json.dumps({"name": "eval", "version": "1", "synthetic": True}))
    records = normal_sessions(30, start=0, seed=3) + outlier(9_000_000)
    (data / "events.jsonl").write_bytes(jsonl(records))
    labels = [{"session": f"n0-{n}", "label": "benign"} for n in range(30)] + [{"session": "intruder", "label": "malicious"}]
    (data / "labels.jsonl").write_text("\n".join(json.dumps(l) for l in labels))
    result = labeled_eval.evaluate_dataset(data, validate_config({}), None, trained)
    assert result["detectors"]["engine:ml"]["confusion"]["tp"] == 1
    assert result["model"]["model_version"].startswith("if-")
    assert any("possible leakage" in item for item in result["limitations"])
    clean = labeled_eval.evaluate_dataset(data, validate_config({}), "2026-03-01T00:00:00Z", trained)
    assert not any("leakage" in item for item in clean["limitations"])
    assert labeled_eval.main([str(data), "--model", str(tmp_path / "missing")]) == 2
