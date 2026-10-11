import io
import json
from datetime import datetime, timedelta, timezone

import pytest
from urllib.parse import urlencode

from app import create_app
from aegis import labeled_eval, statistics
from aegis.engine import validate_config
from aegis.evaluate import RATES
from aegis.ingestion import Collector

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)
HOUR = 3600


def raw(second, **fields):
    return dict(timestamp=(BASE + timedelta(seconds=second)).isoformat(), eventid="cowrie.session.connect", sensor="hp",
                session=f"x{second}", src_ip="192.0.2.50") | fields


def spike(final=100, extra=()):
    records = [raw(hour * HOUR + n, session=f"h{hour}-{n}") for hour, count in enumerate(RATES + [final]) for n in range(count)]
    return records + list(extra)


def jsonl(records):
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


def upload(client, records):
    response = client.post("/api/import", data={"file": (io.BytesIO(jsonl(records)), "x.jsonl")})
    assert response.status_code == 200, response.get_json()
    return response


# --- Persistence and API -----------------------------------------------------------------------

def test_statistical_signal_is_stored_explained_and_never_an_incident(client):
    upload(client, spike())
    status = client.get("/api/v1/statistics?source=imported").get_json()
    assert status["signals"] == 1 and not status["dirty"]
    sensor = next(b for b in status["baselines"] if b["metric"] == "STAT-001")
    assert sensor["state"] == "established" and sensor["sample_size"] >= sensor["required"]
    finding = client.get("/api/v1/findings?source=imported&engine=statistical").get_json()["findings"][0]
    assert (finding["rule_id"], finding["severity"], finding["score_type"]) == ("STAT-001", "low", "robust_z")
    facts = finding["rationale"]["facts"]
    for key in ("observed", "robust_z", "threshold", "min_excess", "method", "baseline", "evidence_total", "evidence_selector"):
        assert key in facts
    assert {"window_start", "window_end", "sample_size", "median", "mad", "scale_source"} <= set(facts["baseline"])
    assert facts["baseline"]["window_end"] == facts["bucket_start"]  # baseline ends where the judged bucket begins
    assert client.get("/api/overview?source=imported").get_json()["incidents"] == []
    selector = facts["evidence_selector"]
    events = client.get("/api/events?" + urlencode({"source": "imported", "limit": 500, **selector})).get_json()
    assert events["total"] == facts["evidence_total"] == 100


def test_signals_attach_to_related_incidents_and_reports(client):
    upload(client, spike(extra=[raw(20 * HOUR + 500, eventid="cowrie.command.input", input="uname -a", session="h20-0")]))
    incident = client.get("/api/overview?source=imported").get_json()["incidents"][0]
    detail = client.get(f"/api/incidents/{incident['id']}?source=imported").get_json()
    assert [s["rule_id"] for s in detail["signals"]] == ["STAT-001"]
    assert detail["severity"] == "low" and [f["rule_id"] for f in detail["findings"]] == ["DISC-001"]  # signals do not change severity
    report = client.get(f"/api/incidents/{incident['id']}/report?source=imported").text
    assert "Related statistical signals" in report and "not evidence of malicious intent" in report
    bundle = client.get(f"/api/incidents/{incident['id']}/evidence?source=imported").get_json()
    assert bundle["incident"]["signals"][0]["score_type"] == "robust_z"


def test_cold_start_is_reported_not_alerted(client):
    client.post("/api/replay")
    status = client.get("/api/v1/statistics").get_json()
    assert status["cold_start"] is True and status["signals"] == 0
    assert all(b["state"] == "insufficient_baseline" for b in status["baselines"])
    assert client.get("/api/overview").get_json()["statistics"]["cold_start"] is True


def test_baselines_never_mix_datasets(client):
    client.post("/api/replay")
    upload(client, spike())
    demo = client.get("/api/v1/statistics?source=demo").get_json()
    assert demo["signals"] == 0 and all(b["state"] == "insufficient_baseline" for b in demo["baselines"])
    assert client.get("/api/v1/statistics?source=imported").get_json()["signals"] == 1


def test_statistics_failure_is_isolated_from_ingestion_and_rules(client, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("statistics bug")
    monkeypatch.setattr(statistics, "compute", broken)
    upload(client, spike(extra=[raw(5, eventid="cowrie.command.input", input="hostname", session="h0-5")]))
    assert len(client.get("/api/overview?source=imported").get_json()["incidents"]) == 1  # rules still ran
    status = client.get("/api/v1/statistics?source=imported").get_json()
    assert status["dirty"] == 1 and "RuntimeError" in status["last_error"]
    monkeypatch.undo()
    assert client.get("/api/v1/statistics?source=imported").get_json()["signals"] == 1


def test_rule_and_statistics_recomputes_never_supersede_each_other(client):
    upload(client, spike(extra=[raw(30, eventid="cowrie.command.input", input="uname", session="h0-30")]))
    app = client.application
    store, analyzer = app.extensions["store"], app.extensions["analyzer"]
    active = lambda: {f["rule_id"] for f in store.findings("imported", {"status": "active"}, 50, 0)[1]}
    analyzer.analyze("imported", {"192.0.2.50"})
    analyzer.analyze("imported")  # full recomputes run at startup and after settings changes
    assert active() == {"DISC-001", "STAT-001"}  # rule recomputes left the statistical finding alone
    analyzer.statistics("imported")
    assert active() == {"DISC-001", "STAT-001"}  # and a statistics recompute left the rule finding alone
    assert store.findings("imported", {"status": "superseded"}, 50, 0)[0] == 0


def test_statistics_can_be_disabled(tmp_path):
    client = make_client(tmp_path / "db.sqlite3", {"statistical_enabled": False})
    upload(client, spike())
    status = client.get("/api/v1/statistics?source=imported").get_json()
    assert status["enabled"] is False and status["signals"] == 0
    assert not any(r["engine"] == "statistical" for r in client.get("/api/overview").get_json()["rules"])


@pytest.mark.parametrize("overrides,message", [
    ({"stats_min_baseline": 30}, "cannot exceed"),
    ({"stats_z_threshold": 1}, "stats_z_threshold"),
    ({"stats_peer_window_seconds": 60, "stats_bucket_seconds": 3600}, "stats_peer_window_seconds"),
    ({"statistical_enabled": "yes"}, "statistical_enabled"),
])
def test_invalid_statistics_settings(overrides, message):
    with pytest.raises(ValueError, match=message):
        validate_config(overrides)


def test_live_statistics_are_throttled_but_reads_catch_up(client, tmp_path, monkeypatch):
    import aegis.analysis as analysis
    monkeypatch.setattr(analysis, "STATS_INTERVAL", 10_000)
    app = client.application
    log = tmp_path / "cowrie.json"
    log.write_bytes(jsonl([raw(n) for n in range(5)]))
    collector = Collector(app.extensions["store"], log, on_commit=app.extensions["analyzer"].after_live_commit)
    collector.poll()
    with log.open("ab") as f:
        f.write(jsonl([raw(100 + n) for n in range(5)]))
    collector.poll()
    store = app.extensions["store"]
    assert store.stats_state("live")["event_count"] < 10  # live batches inside the interval do not recompute
    client.get("/api/v1/statistics?source=live")
    assert store.stats_state("live")["event_count"] == 10


def test_first_live_batch_computes_statistics_without_waiting(tmp_path, monkeypatch):
    import aegis.analysis as analysis
    from aegis.store import Store
    monkeypatch.setattr(analysis, "STATS_INTERVAL", 10_000)
    store = Store(tmp_path / "db.sqlite3")
    analyzer = analysis.Analyzer(store)  # no startup refresh: statistics have never run
    log = tmp_path / "cowrie.json"
    log.write_bytes(jsonl([raw(n) for n in range(5)]))
    Collector(store, log, on_commit=analyzer.after_live_commit).poll()
    assert store.stats_state("live")["event_count"] == 5


def test_series_endpoint(client):
    upload(client, spike(final=30, extra=[raw(4000, eventid="cowrie.session.closed", session="h1-0", duration_ms=120000)]))
    series = client.get("/api/v1/statistics/series?source=imported&bucket=3600").get_json()
    assert [b["events"] for b in series["series"]][:3] == [10, 13, 9]
    assert series["series"][1]["change_from_previous"] == 3
    assert series["sessions"]["duration_ms"]["count"] == 1
    windowed = client.get("/api/v1/statistics/series?source=imported&bucket=3600&since=2026-01-01T20:00:00Z").get_json()
    assert [b["events"] for b in windowed["series"]] == [30]
    assert client.get("/api/v1/statistics/series?bucket=10").status_code == 400
    assert client.get("/api/v1/statistics/series?source=imported&bucket=60").status_code == 400  # over 1,000 buckets


# --- Labeled evaluation harness ------------------------------------------------------------------

def write_dataset(path, labels, events, synthetic=True):
    path.mkdir()
    (path / "manifest.json").write_text(json.dumps({"name": "fixture", "version": "1", "description": "Synthetic test fixture.",
                                                    "source": "tests", "license": "CC0", "synthetic": synthetic}))
    (path / "events.jsonl").write_bytes(jsonl(events))
    (path / "labels.jsonl").write_text("\n".join(json.dumps(l) for l in labels))
    return path


def labeled_events():
    brute = [raw(n * 5, eventid="cowrie.login.failed", session=f"bf{n}", src_ip="203.0.113.5", username="root") for n in range(5)]
    login = [raw(40, eventid="cowrie.login.success", session="in", src_ip="203.0.113.5", username="root"),
             raw(45, eventid="cowrie.command.input", input="uname -a", session="in", src_ip="203.0.113.5")]
    quiet = [raw(9000 + n, session=f"ok{n}", src_ip="192.0.2.77") for n in range(3)]
    noisy = [raw(9500, eventid="cowrie.command.input", input="hostname", session="admin", src_ip="192.0.2.78")]
    return brute + login + quiet + noisy


def test_labeled_evaluation_reports_metrics_and_limitations(tmp_path):
    labels = [{"session": f"bf{n}", "label": "malicious", "types": ["credential_access"]} for n in range(5)]
    labels += [{"session": "in", "label": "malicious", "types": ["credential_access", "discovery", "intrusion_sequence"]}]
    labels += [{"session": f"ok{n}", "label": "benign"} for n in range(3)] + [{"session": "admin", "label": "benign"}]
    result = labeled_eval.evaluate_dataset(write_dataset(tmp_path / "ds", labels, labeled_events()), validate_config({}))
    anything = result["detectors"]["any"]
    assert anything["confusion"] == {"tp": 6, "fp": 1, "fn": 0, "tn": 3}  # the admin's hostname is a labeled false positive
    assert anything["precision"] == round(6 / 7, 4) and anything["recall"] == 1.0 and anything["false_positive_rate"] == 0.25
    assert result["detectors"]["SEQ-002"]["confusion"]["tp"] == 6  # its evidence includes the five address-linked failure sessions
    assert result["by_type"]["discovery"]["confusion"] == {"tp": 1, "fp": 1, "fn": 0, "tn": 8}
    assert result["detectors"]["XFER-001"]["precision"] is None  # never fired: undefined, not zero
    assert any("Synthetic dataset" in item for item in result["limitations"])
    assert any("Small evaluation set" in item for item in result["limitations"])
    assert len(result["files_sha256"]["events.jsonl"]) == 64
    split = labeled_eval.evaluate_dataset(tmp_path / "ds", validate_config({}), "2026-01-01T02:00:00Z")
    assert split["sessions"]["evaluated"] == 4 and split["split"]["method"] == "time-separated"


def test_sensor_level_spikes_are_not_scored_per_session(tmp_path):
    records = spike()  # STAT-001 fires on the final bucket's 100 connection sessions
    labels = [{"session": r["session"], "label": "benign"} for r in records]
    result = labeled_eval.evaluate_dataset(write_dataset(tmp_path / "ds", labels, records), validate_config({}))
    assert result["sensor_level_findings"]["rules"] == ["STAT-001"]
    assert result["detectors"]["STAT-001"]["confusion"]["fp"] == 0 and result["detectors"]["any"]["confusion"]["fp"] == 0


def test_labeled_evaluation_cli_and_input_errors(tmp_path, capsys):
    good = write_dataset(tmp_path / "good", [{"session": "in", "label": "malicious"}], labeled_events())
    assert labeled_eval.main([str(good)]) == 0
    out = capsys.readouterr().out
    assert "| any |" in out and "## Limitations" in out and "1 session(s)" not in out
    bad = write_dataset(tmp_path / "bad", [{"session": "in", "label": "maybe"}], labeled_events())
    assert labeled_eval.main([str(bad)]) == 2 and "malicious or benign" in capsys.readouterr().err
    twice = labeled_events() + [raw(50, session="in", sensor="other")]
    ambiguous = write_dataset(tmp_path / "ambiguous", [{"session": "in", "label": "malicious"}], twice)
    assert labeled_eval.main([str(ambiguous)]) == 2 and "add a sensor field" in capsys.readouterr().err
