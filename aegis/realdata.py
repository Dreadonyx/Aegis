"""Reproducible detection and ML evaluation on real Cowrie telemetry. No network activity.

    python -m aegis.realdata data/honeypot-logs/2026-10-11 --out reports/realdata-2026-10-11

Steps: ingest the logs into a fresh evaluation database (with raw provenance); label sessions with the
documented behavioral criteria below; split sessions by start time into train, calibration, and test
windows; run rules, sequences, and statistics; train Isolation Forest variants on the training window only,
calibrate each on the calibration window only, select by calibration score, and measure everything on the
untouched test window. Writes report.md and report.json.

Labels here are produced by written criteria, not by independent human review. The criteria look at
session behavior, which overlaps what the rules detect, so rule scores against these labels are optimistic.
Analyst labels (session view, python -m aegis.labels export) should replace them."""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from aegis import labeled_eval, labels, ml
from aegis.analysis import Analyzer, load_config
from aegis.features import session_features
from aegis.ingestion import make_record
from aegis.rules import order, session_key
from aegis.store import Store

CRITERIA_VERSION = "1"
CRITERIA = {
    "malicious": [
        "an accepted login followed by at least one command or file transfer",
        "any completed file download or upload",
        "five or more failed logins within the session",
        "a direct-tcpip (port forwarding) request",
    ],
    "benign": ["no login attempt, command, transfer, or tunnel request (scanning or banner grabbing)"],
    "excluded": ["anything else, for example an accepted login with no further activity or one to four failed logins"],
}
RECON = ("uname", "whoami", "id", "hostname", "nproc", "lscpu", "free", "uptime", "ifconfig", "ps", "/proc/cpuinfo", "w")
FETCH = ("wget", "curl", "tftp", "ftpget", "scp")


def criteria_label(items):
    """(label, types, reason) for one session's events, or (None, [], reason) when the criteria do not decide."""
    ids = [e["eventid"] for e in items]
    login, fails = "cowrie.login.success" in ids, ids.count("cowrie.login.failed")
    commands = [e.get("input", "") for e in items if e["eventid"].startswith("cowrie.command.")]
    transfers = sum(i in ("cowrie.session.file_download", "cowrie.session.file_upload") for i in ids)
    tunnel = "cowrie.direct-tcpip.request" in ids
    types = set()
    if fails >= 5 or (login and fails):
        types.add("credential_access")
    if any(word in c.split() or word in c for c in commands for word in RECON):
        types.add("discovery")
    if transfers or any(tool in c for c in commands for tool in FETCH):
        types.add("transfer")
    if login and commands and "transfer" in types:
        types.add("intrusion_sequence")
    if (login and (commands or transfers)) or transfers or fails >= 5 or tunnel:
        return "malicious", sorted(types), "meets a malicious criterion"
    if not login and not fails and not commands and not transfers and not tunnel:
        return "benign", [], "no interaction"
    return None, [], f"undecided (login={login}, failed logins={fails}, commands={len(commands)})"


def by_session_events(store, finding):
    """Events cited by a finding (used to map rule findings to labeled sessions)."""
    total, found = 0, []
    for event_id in finding["evidence_event_ids"]:
        total, events = store.query_events(finding["dataset"], filters={"id": event_id}, limit=1)
        found += events
    return found


def read_logs(paths):
    files = []
    for path in map(Path, paths):
        # aws s3 sync keeps the per-host folder, so search recursively for Cowrie JSON logs.
        files += sorted(p for p in path.rglob("cowrie.json*") if p.is_file()) if path.is_dir() else [path]
    return files


def ingest(store, files):
    records, rejected = [], 0
    for f in files:
        for n, line in enumerate(f.read_bytes().splitlines(), 1):
            if not line.strip():
                continue
            try:
                records.append(make_record(line, "imported", f"{f.name}:line:{n}"))
            except (ValueError, RecursionError):
                rejected += 1
    result = {"inserted": 0, "duplicates": 0}
    for start in range(0, len(records), 2000):
        part = store.commit(records[start:start + 2000], dict(mode="import", source_id="realdata", source_type="cowrie", file_id="realdata"))
        result = {k: result[k] + part[k] for k in result}
    return {**result, "rejected": rejected, "lines": len(records) + rejected}


def boundaries(starts, train_frac, cal_frac):
    """Split points by session count in start-time order, snapped to session start times."""
    ordered = sorted(starts)
    cal_start = ordered[int(len(ordered) * train_frac)]
    test_start = ordered[int(len(ordered) * (train_frac + cal_frac))]
    return cal_start, test_start


def backtest(rows, label_of, overall_predicted, config, out, initial=60, fold=25):
    """Forward-chaining evaluation: for each block of sessions after the first `initial`, train on every earlier
    session and score the block with the model's default threshold (training 99th percentile). Nothing is tuned
    on test sessions. Rules need no training, so they are scored on the same sessions for comparison."""
    ordered = sorted(rows, key=lambda r: r["first_seen"])
    labeled = lambda chosen: {r["session_key"] for r in chosen if label_of(r)}
    folds, flagged, past_calibrated, population = [], set(), set(), set()
    for start in range(initial, len(ordered), fold):
        train, block = ordered[:start], ordered[start:start + fold]
        model_dir = out / "models" / "backtest" / f"fold-{len(folds) + 1}"
        ml.train(train, {"source": "realdata-backtest", "dataset": "imported", "since": None, "until": block[0]["first_seen"],
                         "synthetic": False, "variant": "all-sessions"}, model_dir)
        model = ml.load(model_dir, config["ml_max_model_age_days"])
        block_scores = model.score(block)
        hits = {r["session_key"] for r, result in zip(block, block_scores) if result["flagged"]}
        # Threshold tuned only on earlier labeled sessions: what an analyst would have known at the time.
        past = [r for r in train if label_of(r)]
        past_scores = {r["session_key"]: res["score"] for r, res in zip(past, model.score(past))}
        past_positive = {r["session_key"] for r in past if label_of(r) == "malicious"}
        threshold = model.threshold
        if past_positive and len(past_positive) < len(past):
            values = sorted(set(past_scores.values()))
            candidates = [values[0] - 1e-6] + [(a + b) / 2 for a, b in zip(values, values[1:])] + [values[-1]]
            threshold = max(candidates, key=lambda t: (ml._point(t, past_scores, past_positive)["f1"], t))
        tuned = {r["session_key"] for r, res in zip(block, block_scores) if res["score"] > threshold}
        scored = labeled(block)
        flagged |= hits & scored
        past_calibrated |= tuned & scored
        population |= scored
        folds.append({"fold": len(folds) + 1, "train_sessions": len(train), "test_sessions": len(block), "test_from": block[0]["first_seen"],
                      "malicious": sum(label_of(r) == "malicious" for r in block), "flagged": len(hits & scored),
                      "past_threshold": round(threshold, 6), "past_positives": len(past_positive), "flagged_past_calibrated": len(tuned & scored)})
    positives = {k for k in population if label_of(next(r for r in rows if r["session_key"] == k)) == "malicious"}
    rules = overall_predicted & population
    return {"method": f"forward chaining: initial {initial} sessions, blocks of {fold}; default threshold (training 99th percentile)",
            "folds": folds, "ml": labeled_eval.metrics(flagged, positives, population),
            "ml_past_calibrated": labeled_eval.metrics(past_calibrated, positives, population),
            "rules_or_ml_past_calibrated": labeled_eval.metrics(rules | past_calibrated, positives, population),
            "rules": labeled_eval.metrics(rules, positives, population),
            "rules_or_ml": labeled_eval.metrics(rules | flagged, positives, population),
            "ml_only_catches": len((flagged - rules) & positives), "ml_only_false_alarms": len((flagged - rules) - positives),
            "ml_past_only_catches": len((past_calibrated - rules) & positives), "ml_past_only_false_alarms": len((past_calibrated - rules) - positives)}


def window_counts(rows, label_of, low, high):
    chosen = [r for r in rows if (low is None or r["first_seen"] >= low) and (high is None or r["first_seen"] < high)]
    tally = {"sessions": len(chosen), "malicious": 0, "benign": 0, "excluded": 0}
    for r in chosen:
        tally[label_of(r) or "excluded"] += 1
    return tally


def run(paths, out_dir, config=None, train_frac=0.5, cal_frac=0.25, objective="f1", notes=()):
    config = config or load_config()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=False)
    files = read_logs(paths)
    if not files:
        raise ValueError("No log files found")
    store = Store(out / "work" / "evaluation.sqlite3")
    ingestion = ingest(store, files)
    analyzer = Analyzer(store, config, model_dir="")
    analyzer.refresh()

    events = sorted(store.events("imported"), key=order)
    by_session = {}
    for e in events:
        by_session.setdefault(session_key(e), []).append(e)
    decisions = {key: criteria_label(items) for key, items in by_session.items()}
    for key, (label, types, _) in decisions.items():
        if label:
            first = by_session[key][0]
            store.set_label("imported", key, first["session"], first["sensor"], label, types, f"criteria v{CRITERIA_VERSION}",
                            f"criteria-v{CRITERIA_VERSION} (automated)")
    rows = session_features(events, config)
    label_of = lambda r: decisions[r["session_key"]][0]
    if sum(label_of(r) == "malicious" for r in rows) < 2:
        raise ValueError("Fewer than two sessions meet the malicious criteria; there is nothing meaningful to measure yet")
    cal_start, test_start = boundaries([r["first_seen"] for r in rows], train_frac, cal_frac)
    dataset = out / "dataset"
    labels.export(store.path, "imported", dataset)

    overall = labeled_eval.evaluate_dataset(dataset, config)
    test_rules = labeled_eval.evaluate_dataset(dataset, config, test_start)

    train_rows = [r for r in rows if r["first_seen"] < cal_start]
    variants = {"all-sessions": train_rows, "benign-only": [r for r in train_rows if label_of(r) == "benign"]}
    models = {}
    for name, chosen in variants.items():
        entry = {"training_sessions": len(chosen)}
        try:
            ml.train(chosen, {"source": "realdata", "dataset": "imported", "since": None, "until": cal_start, "synthetic": False,
                              "variant": name, "criteria_version": CRITERIA_VERSION}, out / "models" / name)
            entry["base_model"] = str(out / "models" / name)
            try:
                calibrated = ml.calibrate(out / "models" / name, dataset, out / "models" / f"{name}-calibrated", config,
                                          cal_start, objective, before=test_start)
                entry.update(model=str(out / "models" / f"{name}-calibrated"), calibration=calibrated["calibration"]["chosen"],
                             calibration_warnings=calibrated["calibration"]["warnings"])
            except ValueError as error:  # for example no malicious session in the calibration window
                entry.update(model=entry["base_model"], calibration=None, calibration_error=str(error))
        except ValueError as error:
            entry["error"] = str(error)
        models[name] = entry
    usable = {n: m for n, m in models.items() if "model" in m}
    selected = max(usable, key=lambda n: ((usable[n]["calibration"] or {}).get("f1", -1), n == "all-sessions")) if usable else None
    tests = {n: labeled_eval.evaluate_dataset(dataset, config, test_start, m["model"]) for n, m in usable.items()}

    keys = {(r["sensor"], r["session"]): r["session_key"] for r in rows}
    rule_hits = {keys[(e["sensor"], e["session"])] for i in store.incidents("imported")[1] for f in i["findings"]
                 if f["engine"] in ("rule", "sequence") for e in [*by_session_events(store, f)]}
    chained = backtest(rows, label_of, rule_hits, config, out)
    test_population = window_counts(rows, label_of, test_start, None)
    malicious_test = {r["session_key"] for r in rows if r["first_seen"] >= test_start and label_of(r) == "malicious"}
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "data": {"files": [f.name for f in files], "ingestion": ingestion, "events": len(events), "sessions": len(rows),
                 "span": [events[0]["timestamp"], events[-1]["timestamp"]], "sensors": sorted({e["sensor"] for e in events}),
                 "dataset_sha256": overall["files_sha256"]},
        "labels": {"method": f"behavioral criteria v{CRITERIA_VERSION}, automated (not independent human review)", "criteria": CRITERIA,
                   "counts": window_counts(rows, label_of, None, None)},
        "split": {"method": "session start time; train, calibration, test by session count", "calibration_start": cal_start, "test_start": test_start,
                  "train": window_counts(rows, label_of, None, cal_start), "calibration": window_counts(rows, label_of, cal_start, test_start),
                  "test": test_population},
        "rules_all_labeled": overall["detectors"], "rules_test_window": test_rules["detectors"],
        "ml": {"variants": models, "selected": selected, "selection": "highest calibration F1 (calibration window only); the test window was not used",
               "test_window": {n: {k: t["detectors"][k] for k in ("engine:ml", "ML-001", "any")} for n, t in tests.items()}},
        "malicious_in_test_window": len(malicious_test),
        "backtest": chained,
        "limitations": [],
    }
    lim = report["limitations"]
    lim.extend(notes)
    lim.append("Labels come from automated behavioral criteria, not independent analysts. The criteria overlap what the rules detect, so rule "
               "metrics are optimistic; treat them as agreement with the criteria, not field accuracy.")
    n_mal = report["labels"]["counts"]["malicious"]
    lim.append(f"Only {n_mal} malicious sessions in total and {len(malicious_test)} in the test window: confidence intervals are wide and a "
               "single session changes the metrics substantially.")
    lim.append(f"One sensor and {report['data']['span'][0][:16]} to {report['data']['span'][1][:16]} of traffic; results may not transfer to other "
               "sensors, periods, or Cowrie configurations.")
    if report["labels"]["counts"]["excluded"]:
        lim.append(f"{report['labels']['counts']['excluded']} sessions met no criterion and were excluded from scoring.")
    if not any(e["eventid"] == "cowrie.login.failed" for e in events):
        lim.append("The sensor logged no failed logins (permissive user database), so credential-guessing detection is untested.")
    for name, m in models.items():
        if m.get("calibration_error"):
            lim.append(f"ML variant {name}: calibration was not possible ({m['calibration_error']}); its threshold is the training 99th percentile.")
    (out / "report.json").write_text(json.dumps(report, indent=2))
    (out / "report.md").write_text(markdown(report))
    return report


def _row(name, m):
    f = lambda v: "n/a" if v is None else f"{v:.2f}"
    ci = lambda k: "" if not m["ci95"][k] else f" [{m['ci95'][k][0]:.2f}–{m['ci95'][k][1]:.2f}]"
    c = m["confusion"]
    return f"| {name} | {f(m['precision'])}{ci('precision')} | {f(m['recall'])}{ci('recall')} | {f(m['f1'])} | {f(m['false_positive_rate'])} | {c['tp']} | {c['fp']} | {c['fn']} | {c['tn']} |"


def markdown(r):
    header = ["| Detector | Precision [95% CI] | Recall [95% CI] | F1 | FPR | TP | FP | FN | TN |", "|---|---|---|---|---|---|---|---|---|"]
    keys = ["any", "engine:rule", "engine:sequence", "engine:statistical", "AUTH-001", "AUTH-002", "DISC-001", "XFER-001", "XFER-002", "SEQ-001", "SEQ-002"]
    s = r["split"]
    lines = ["# Aegis real-data evaluation", "", f"Generated {r['generated_at']}. Reproduce with `python -m aegis.realdata`.", "",
             "## Data", f"- {r['data']['events']} events, {r['data']['sessions']} sessions, sensors: {', '.join(r['data']['sensors'])}",
             f"- Span: {r['data']['span'][0]} to {r['data']['span'][1]}",
             f"- Ingestion: {r['data']['ingestion']['inserted']} stored, {r['data']['ingestion']['duplicates']} duplicates, {r['data']['ingestion']['rejected']} rejected",
             "", "## Labels", f"Method: {r['labels']['method']}.", ""]
    lines += [f"- **{k}**: " + "; ".join(v) for k, v in r["labels"]["criteria"].items()]
    lc = r["labels"]["counts"]
    lines += ["", f"Counts: {lc['malicious']} malicious, {lc['benign']} benign, {lc['excluded']} excluded.", "",
              "## Time split", "| Window | Starts | Sessions | Malicious | Benign | Excluded |", "|---|---|---|---|---|---|"]
    for name, start in (("Train", r["data"]["span"][0]), ("Calibration", s["calibration_start"]), ("Test", s["test_start"])):
        w = s[name.lower()]
        lines.append(f"| {name} | {start[:19]} | {w['sessions']} | {w['malicious']} | {w['benign']} | {w['excluded']} |")
    lines += ["", "## Rules, sequences, and statistics: all labeled sessions", *header]
    lines += [_row(k, r["rules_all_labeled"][k]) for k in keys if k in r["rules_all_labeled"]]
    lines += ["", "## Rules, sequences, and statistics: test window", *header]
    lines += [_row(k, r["rules_test_window"][k]) for k in keys if k in r["rules_test_window"]]
    lines += ["", "## Machine learning (real data only)", f"Selection: {r['ml']['selection']}. Selected: **{r['ml']['selected']}**.", ""]
    for name, m in r["ml"]["variants"].items():
        cal = m.get("calibration")
        detail = (f"calibrated F1 {cal['f1']:.2f} at threshold {cal['threshold']}" if cal else
                  f"not calibrated ({m.get('calibration_error') or m.get('error')})")
        lines.append(f"- {name}: {m['training_sessions']} training sessions; {detail}")
    lines += ["", "Test window:", *header]
    for name, t in r["ml"]["test_window"].items():
        lines += [_row(f"{name}: ML-001", t["ML-001"]), _row(f"{name}: any engine incl. ML", t["any"])]
    b = r["backtest"]
    lines += ["", "## Forward-chaining backtest (primary result)", f"Method: {b['method']}.", "",
              "| Fold | Trained on | Tested sessions | Tested from | Malicious | ML flagged (default) | Past positives | ML flagged (past-calibrated) |",
              "|---|---|---|---|---|---|---|---|"]
    lines += [f"| {f['fold']} | {f['train_sessions']} | {f['test_sessions']} | {f['test_from'][:19]} | {f['malicious']} | {f['flagged']} | "
              f"{f['past_positives']} | {f['flagged_past_calibrated']} |" for f in b["folds"]]
    lines += ["", *header, _row("ML-001, default threshold", b["ml"]), _row("ML-001, threshold from earlier labels", b["ml_past_calibrated"]),
              _row("rules and sequences (same sessions)", b["rules"]), _row("rules OR ML (default)", b["rules_or_ml"]),
              _row("rules OR ML (earlier labels)", b["rules_or_ml_past_calibrated"]), "",
              f"Default threshold: ML caught {b['ml_only_catches']} malicious session(s) the rules missed, with {b['ml_only_false_alarms']} extra false alarm(s). "
              f"Threshold from earlier labels: {b['ml_past_only_catches']} and {b['ml_past_only_false_alarms']}."]
    lines += ["", "## Limitations"] + [f"- {item}" for item in r["limitations"]]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Evaluate Aegis on real Cowrie logs with time-separated windows.")
    parser.add_argument("logs", nargs="+", help="Cowrie JSON log files or directories")
    parser.add_argument("--out", required=True, help="New directory for the report and working files")
    parser.add_argument("--config")
    parser.add_argument("--objective", default="f1")
    parser.add_argument("--note", action="append", default=[], help="Add a limitation to the report (repeatable)")
    args = parser.parse_args(argv)
    try:
        report = run(args.logs, args.out, load_config(args.config), objective=args.objective, notes=args.note)
    except (ValueError, OSError, ml.ModelUnavailable) as error:
        print(f"Evaluation failed: {error}", file=sys.stderr)
        return 2
    print(markdown(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
