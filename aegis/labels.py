"""Analyst labels for real sessions, and export of a labeled dataset for evaluation and ML calibration.

A label is an analyst's judgment of whether a session is alert-worthy:
  malicious  - activity the analyst wants an alert for (for example an accepted login followed by commands
               or transfers, or a credential-guessing burst)
  benign     - activity that should stay quiet (for example banner grabbing or scanning without interaction)
Everything reaching a honeypot is unsolicited, so "benign" means "not alert-worthy", not "authorized".

Suggestions come from rule findings and simple session shape. Accepting them without review makes any
evaluation circular, so they are never applied automatically.

    python -m aegis.labels export --db data/aegis.sqlite3 --dataset live --out datasets/live-2026-10-28
"""
import argparse
import hashlib
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

LABEL_TYPES = ("credential_access", "discovery", "transfer", "intrusion_sequence", "anomaly")
RULE_TYPES = {"AUTH-001": "credential_access", "AUTH-002": "credential_access", "DISC-001": "discovery", "XFER-001": "transfer",
              "XFER-002": "transfer", "SEQ-001": "intrusion_sequence", "SEQ-002": "intrusion_sequence"}
DEFINITIONS = {"malicious": "Alert-worthy activity in the analyst's judgment.",
               "benign": "Activity that should not raise an alert (unsolicited but not alert-worthy, such as scanning)."}


def redact(raw):
    """Original record for display or export, with attempted passwords and login messages masked.
    Returns None when the bytes are not a JSON object."""
    try:
        record = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(record, dict):
        return None
    if isinstance(record.get("password"), str):
        record["password"] = f"[redacted: {len(record['password'])} characters]"
    if str(record.get("eventid", "")).startswith("cowrie.login.") and "message" in record:
        record["message"] = "[redacted: Cowrie login messages repeat the attempted password]"
    return record


def suggest(events, findings):
    """A reviewable suggestion, or None when the session needs a human decision."""
    rule_ids = {f["rule_id"] for f in findings if f["engine"] in ("rule", "sequence")}
    if rule_ids:
        return {"label": "malicious", "types": sorted({RULE_TYPES[r] for r in rule_ids if r in RULE_TYPES}),
                "basis": f"Rule findings: {', '.join(sorted(rule_ids))}. Review the session before accepting; accepting rule-based "
                         "suggestions unreviewed makes evaluation of those rules circular."}
    interactive = any(e["eventid"] in ("cowrie.login.success", "cowrie.command.input", "cowrie.session.file_download",
                                       "cowrie.session.file_upload") for e in events)
    if not interactive and not any(e["eventid"] == "cowrie.login.failed" for e in events):
        return {"label": "benign", "types": [], "basis": "No login attempt, command, or transfer: looks like scanning or banner grabbing."}
    return None


def _canonical_to_record(event):
    """Fallback for events stored before raw evidence existed: rebuild the Cowrie field names."""
    record = {k: v for k, v in event.items() if k not in ("id", "source", "event_type", "client_version", "filename")}
    if event.get("client_version"):
        record["version"] = event["client_version"]
    if event.get("filename"):
        record["filename" if event["eventid"] == "cowrie.session.file_upload" else "destfile"] = event["filename"]
    return record


def export(db_path, dataset, out_dir, since=None, until=None):
    """Write manifest.json, events.jsonl (all events in range, passwords redacted) and labels.jsonl."""
    out = Path(out_dir)
    db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        where, args = ["source=?"], [dataset]
        if since:
            where.append("event_time >= ?")
            args.append(since)
        if until:
            where.append("event_time < ?")
            args.append(until)
        events = [json.loads(r[0]) for r in db.execute(f"SELECT body FROM events WHERE {' AND '.join(where)} ORDER BY event_time, id", args)]
        raws, ids = {}, [e["id"] for e in events]
        for start in range(0, len(ids), 500):
            part = ids[start:start + 500]
            for event_id, raw in db.execute(f"SELECT event_id, raw FROM raw_events WHERE event_id IN ({','.join('?' * len(part))}) ORDER BY seq", part):
                raws.setdefault(event_id, raw)
        present = {(e["sensor"], e["session"]) for e in events}
        labels = [{"session": session, "sensor": sensor, "label": label, "types": json.loads(types)}
                  for session, sensor, label, types in db.execute("SELECT session, sensor, label, types FROM session_labels WHERE dataset=? ORDER BY session", (dataset,))
                  if (sensor, session) in present]
    finally:
        db.close()
    if not labels:
        raise ValueError("No labeled sessions in this range; label sessions in the session view first")
    out.mkdir(parents=True, exist_ok=False)
    lines, legacy = [], 0
    for event in events:
        record = redact(raws[event["id"]]) if raws.get(event["id"]) is not None else None
        if record is None:
            record, legacy = _canonical_to_record(event), legacy + 1
        lines.append(json.dumps(record, ensure_ascii=False))
    (out / "events.jsonl").write_text("\n".join(lines) + "\n")
    (out / "labels.jsonl").write_text("\n".join(json.dumps(l) for l in labels) + "\n")
    counts = {k: sum(1 for l in labels if l["label"] == k) for k in ("malicious", "benign")}
    exported_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    manifest = {"name": f"aegis-{dataset}", "version": exported_at, "description": f"Aegis {dataset} telemetry with analyst session labels.",
                "source": "aegis export", "license": "Private: contains attacker addresses. Do not publish.", "synthetic": dataset == "demo",
                "dataset": dataset, "window": {"since": since, "until": until}, "label_definitions": DEFINITIONS,
                "counts": {"events": len(events), "labeled_sessions": len(labels), **counts, "events_without_raw_record": legacy},
                "exported_at": exported_at, "redaction": "Attempted passwords and login messages are masked."}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    manifest["files_sha256"] = {n: hashlib.sha256((out / n).read_bytes()).hexdigest() for n in ("manifest.json", "events.jsonl", "labels.jsonl")}
    return manifest


def main(argv=None):
    from aegis.ml import _utc
    parser = argparse.ArgumentParser(description="Export Aegis telemetry with analyst labels as an evaluation dataset.")
    commands = parser.add_subparsers(dest="command", required=True)
    e = commands.add_parser("export")
    e.add_argument("--db", required=True)
    e.add_argument("--dataset", required=True, choices=("live", "imported", "demo"))
    e.add_argument("--since")
    e.add_argument("--until")
    e.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        result = export(args.db, args.dataset, args.out, _utc(args.since, "--since") if args.since else None,
                        _utc(args.until, "--until") if args.until else None)
    except (ValueError, OSError, sqlite3.Error) as error:
        print(f"Export failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
