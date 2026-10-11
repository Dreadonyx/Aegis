"""Evaluate detection against a labeled Cowrie dataset. No network activity.

    python -m aegis.labeled_eval DATASET_DIR [--test-after ISO_TIME] [--config settings.json] [--format markdown|json]

DATASET_DIR contains:
  manifest.json  {"name", "version", "description", "source", "license", "synthetic": bool}
  events.jsonl   Cowrie JSON lines
  labels.jsonl   {"session": "...", "sensor": "..." (optional), "label": "malicious" | "benign",
                  "types": ["credential_access", "discovery", "transfer", "intrusion_sequence", "anomaly"] (optional)}

Labels are per session. A session is predicted positive when any finding's evidence includes one of its
events. Metrics describe this dataset only; the report states its size, balance, and limitations."""
import argparse
import hashlib
import json
import sys
from pathlib import Path

from aegis import statistics
from aegis.analysis import load_config
from aegis.canonical import normalize
from aegis.engine import detect
from aegis.rules import RULE_IDS, SEQUENCE_IDS, STAT_IDS, order, ts

TYPE_RULES = {"credential_access": {"AUTH-001", "AUTH-002"}, "discovery": {"DISC-001"}, "transfer": {"XFER-001", "XFER-002"},
              "intrusion_sequence": set(SEQUENCE_IDS), "anomaly": set(STAT_IDS)}
LABELS = ("malicious", "benign")


def metrics(predicted, positives, population):
    tp = len(predicted & positives)
    fp = len(predicted - positives)
    fn = len(positives - predicted)
    tn = len(population - predicted - positives)
    ratio = lambda a, b: round(a / b, 4) if b else None
    precision, recall = ratio(tp, tp + fp), ratio(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 4) if precision and recall else (0.0 if precision == 0 or recall == 0 else None)
    return {"confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn}, "precision": precision, "recall": recall, "f1": f1,
            "false_positive_rate": ratio(fp, fp + tn), "support": {"positive": len(positives), "negative": len(population - positives)}}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(directory):
    directory = Path(directory)
    manifest = json.loads((directory / "manifest.json").read_text())
    events, rejected = [], 0
    for line in (directory / "events.jsonl").read_bytes().splitlines():
        if not line.strip():
            continue
        try:
            events.append(normalize(json.loads(line), "labeled"))
        except (ValueError, RecursionError):
            rejected += 1
    labels = []
    for n, line in enumerate((directory / "labels.jsonl").read_text().splitlines(), 1):
        if not line.strip():
            continue
        label = json.loads(line)
        if not isinstance(label, dict) or label.get("label") not in LABELS or not isinstance(label.get("session"), str):
            raise ValueError(f"labels.jsonl line {n}: needs a session and a label of malicious or benign")
        unknown = set(label.get("types", [])) - set(TYPE_RULES)
        if unknown:
            raise ValueError(f"labels.jsonl line {n}: unknown types {sorted(unknown)}")
        labels.append(label)
    files = {name: digest(directory / name) for name in ("manifest.json", "events.jsonl", "labels.jsonl")}
    return manifest, events, rejected, labels, files


def evaluate_dataset(directory, config=None, test_after=None):
    config = config or load_config()
    manifest, events, rejected, labels, files = load(directory)
    sessions = {}
    for e in sorted(events, key=order):
        sessions.setdefault((e["sensor"], e["session"]), []).append(e)
    by_id = {}
    for label in labels:
        matches = [k for k in sessions if k[1] == label["session"] and label.get("sensor") in (None, k[0])]
        if len(matches) > 1:
            raise ValueError(f"Label for session {label['session']} matches several sensors; add a sensor field")
        if matches:
            by_id[matches[0]] = label
    cutoff = ts({"timestamp": test_after}) if test_after else None
    population = {k for k in by_id if cutoff is None or ts(sessions[k][0]) >= cutoff}
    positives = {k for k in population if by_id[k]["label"] == "malicious"}

    findings = [f for i in detect(events, config) for f in i["findings"]] + statistics.compute(events, config)["findings"]
    event_session = {e["id"]: (e["sensor"], e["session"]) for e in events}
    touched = {f["finding_id"]: {event_session[i] for i in f["evidence_event_ids"]} for f in findings}
    predicted = lambda keep: set().union(*([touched[f["finding_id"]] for f in findings if keep(f)] or [set()])) & population

    results = {"any": metrics(predicted(lambda f: True), positives, population)}
    for engine in ("rule", "sequence", "statistical"):
        results[f"engine:{engine}"] = metrics(predicted(lambda f, engine=engine: f["engine"] == engine), positives, population)
    for rule_id in RULE_IDS + SEQUENCE_IDS + STAT_IDS:
        results[rule_id] = metrics(predicted(lambda f, rule_id=rule_id: f["rule_id"] == rule_id), positives, population)
    by_type = {}
    for kind, rules in TYPE_RULES.items():
        typed = {k for k in population if kind in by_id[k].get("types", [])}
        if typed:
            by_type[kind] = metrics(predicted(lambda f, rules=rules: f["rule_id"] in rules), typed, population)
    by_sensor = {}
    for sensor in sorted({k[0] for k in population}):
        group = {k for k in population if k[0] == sensor}
        by_sensor[sensor] = metrics(predicted(lambda f: True) & group, positives & group, group)

    n, malicious = len(population), len(positives)
    limitations = ["Metrics describe this dataset only and do not establish field performance.",
                   "Rules are not trained on this data. Statistical baselines use only earlier events from the same dataset."]
    if manifest.get("synthetic"):
        limitations.insert(0, "Synthetic dataset: validates detection logic, not real-world accuracy.")
    if n < 100:
        limitations.append(f"Small evaluation set ({n} sessions); metrics are unstable.")
    if n and min(malicious, n - malicious) / n < 0.1:
        limitations.append(f"Class imbalance: {malicious} malicious and {n - malicious} benign sessions.")
    unlabeled = len(sessions) - len(by_id)
    if unlabeled:
        limitations.append(f"{unlabeled} session(s) without labels were excluded.")
    if rejected:
        limitations.append(f"{rejected} event line(s) failed validation and were excluded.")
    if not by_type:
        limitations.append("No session carries detection types, so per-type coverage is unavailable.")
    return {"dataset": {k: manifest.get(k) for k in ("name", "version", "description", "source", "license", "synthetic")}, "files_sha256": files,
            "split": {"test_after": test_after, "method": "time-separated" if test_after else "whole dataset"},
            "sessions": {"evaluated": n, "malicious": malicious, "benign": n - malicious, "unlabeled_excluded": unlabeled},
            "events": {"accepted": len(events), "rejected": rejected}, "detectors": results, "by_type": by_type, "by_sensor": by_sensor,
            "limitations": limitations}


def markdown(result):
    d = result["dataset"]
    lines = [f"# Detection evaluation: {d['name']} v{d['version']}", "", d.get("description") or "",
             f"Sessions evaluated: {result['sessions']['evaluated']} ({result['sessions']['malicious']} malicious, {result['sessions']['benign']} benign). "
             f"Split: {result['split']['method']}{' after ' + result['split']['test_after'] if result['split']['test_after'] else ''}.", "",
             "| Detector | Precision | Recall | F1 | FPR | TP | FP | FN | TN |", "|---|---|---|---|---|---|---|---|---|"]
    fmt = lambda v: "n/a" if v is None else f"{v:.3f}"
    for name, m in list(result["detectors"].items()) + [(f"type:{k}", v) for k, v in result["by_type"].items()]:
        c = m["confusion"]
        lines.append(f"| {name} | {fmt(m['precision'])} | {fmt(m['recall'])} | {fmt(m['f1'])} | {fmt(m['false_positive_rate'])} | {c['tp']} | {c['fp']} | {c['fn']} | {c['tn']} |")
    lines += ["", "## Limitations"] + [f"- {item}" for item in result["limitations"]]
    lines += ["", "Dataset files (SHA-256): " + ", ".join(f"{k} {v[:16]}" for k, v in result["files_sha256"].items())]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Evaluate Aegis detection against a labeled Cowrie dataset.")
    parser.add_argument("dataset")
    parser.add_argument("--test-after", help="Only score sessions starting at or after this ISO 8601 time")
    parser.add_argument("--config", help="Detection settings JSON (defaults to AEGIS_DETECTION_CONFIG)")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    args = parser.parse_args(argv)
    try:
        result = evaluate_dataset(args.dataset, load_config(args.config), args.test_after)
    except (OSError, ValueError) as error:
        print(f"Evaluation failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2) if args.format == "json" else markdown(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
