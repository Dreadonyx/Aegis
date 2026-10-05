"""Normalize untrusted Cowrie records and detect observable activity. Never execute input."""
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone

RULES = [
    {"id": "AUTH-001", "name": "Repeated authentication failures", "severity": "medium", "technique": "T1110.001", "description": "Five failed logins from one source on one sensor within 60 seconds, across sessions."},
    {"id": "AUTH-002", "name": "Login following repeated failures", "severity": "high", "technique": None, "description": "A honeypot login succeeds within five minutes after at least five failures from the same source and sensor. This does not establish a real account compromise."},
    {"id": "DISC-001", "name": "System discovery command observed", "severity": "low", "technique": "T1082", "description": "Shell input contains uname or hostname as a command. Input is observed; execution success is not established."},
    {"id": "XFER-001", "name": "File download recorded", "severity": "high", "technique": "T1105", "description": "Cowrie reports a completed file download. This does not establish payload execution or maliciousness."},
]
BY_ID = {r["id"]: r for r in RULES}


def normalize(raw, source):
    if not isinstance(raw, dict):
        raise ValueError("Each record must be a JSON object")
    for key in ("timestamp", "eventid", "session", "sensor", "src_ip"):
        if not isinstance(raw.get(key), str) or not raw[key].strip() or len(raw[key]) > 200:
            raise ValueError(f"{key} must be a nonempty string of at most 200 characters")
    try:
        when = datetime.fromisoformat(raw["timestamp"].replace("Z", "+00:00"))
        if when.tzinfo is None:
            raise ValueError()
        when = when.astimezone(timezone.utc)
        ip = str(ipaddress.ip_address(raw["src_ip"]))
    except ValueError:
        raise ValueError("timestamp must include a timezone and src_ip must be a valid IP") from None
    if not raw["eventid"].startswith("cowrie."):
        raise ValueError("Only Cowrie event IDs are supported")
    # Allowlist: do not retain passwords, raw login messages, keys, or unknown fields.
    data = {k: raw[k] for k in ("eventid", "session", "sensor")}
    data.update(timestamp=when.isoformat(timespec="microseconds"), src_ip=ip, source=source)
    for key in ("username", "input", "url", "shasum"):
        if key in raw:
            if not isinstance(raw[key], str) or len(raw[key]) > 4096:
                raise ValueError(f"{key} must be a string of at most 4096 characters")
            if key == "username" or (key == "input" and raw["eventid"].startswith("cowrie.command.")) or (key in ("url", "shasum") and raw["eventid"] == "cowrie.session.file_download"):
                data[key] = raw[key]
    data["id"] = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:20]
    return data


def session_key(event):
    return hashlib.sha256(json.dumps([event[k] for k in ("source", "sensor", "src_ip", "session")]).encode()).hexdigest()[:16]


def detect(events):
    failures, incidents = {}, {}
    for event in sorted(events, key=lambda e: (e["timestamp"], e["id"])):
        t = datetime.fromisoformat(event["timestamp"]).timestamp()
        key = (event["source"], event["sensor"], event["src_ip"])
        history = failures.setdefault(key, [])
        history[:] = [(ts, e) for ts, e in history if t - ts <= 300]
        matches = []
        if event["eventid"] == "cowrie.login.failed":
            history.append((t, event))
            recent = [e for ts, e in history if t - ts <= 60]
            if len(recent) >= 5:
                matches.append(("AUTH-001", [e["id"] for e in recent]))
        elif event["eventid"] == "cowrie.login.success" and len(history) >= 5:
            matches.append(("AUTH-002", [e["id"] for _, e in history] + [event["id"]]))
        elif event["eventid"] == "cowrie.command.input" and re.search(r"(?:^|[;|&]\s*)\s*(?:/[^\s;|&]+/)?(?:uname|hostname)(?=\s|$|[;|&])", event.get("input", "")):
            matches.append(("DISC-001", [event["id"]]))
        elif event["eventid"] == "cowrie.session.file_download":
            matches.append(("XFER-001", [event["id"]]))
        if not matches:
            continue
        sid = session_key(event)
        incident = incidents.setdefault(sid, {"id": sid, "session": event["session"], "sensor": event["sensor"], "src_ip": event["src_ip"], "source": event["source"], "findings": {}, "last_seen": event["timestamp"]})
        incident["last_seen"] = event["timestamp"]
        for rule, ids in matches:
            finding = incident["findings"].setdefault(rule, {**BY_ID[rule], "evidence_ids": []})
            finding["evidence_ids"] = list(dict.fromkeys(finding["evidence_ids"] + ids))
    rank = {"low": 1, "medium": 2, "high": 3}
    for incident in incidents.values():
        incident["findings"] = list(incident["findings"].values())
        incident["severity"] = max((f["severity"] for f in incident["findings"]), key=rank.get)
        incident["title"] = max(incident["findings"], key=lambda f: rank[f["severity"]])["name"]
        related = {i for f in incident["findings"] for i in f["evidence_ids"]}
        incident["events"] = sorted([e for e in events if session_key(e) == incident["id"] or e["id"] in related], key=lambda e: (e["timestamp"], e["id"]))
    return sorted(incidents.values(), key=lambda i: (rank[i["severity"]], i["last_seen"]), reverse=True)


def report(incident):
    lines = [f"# Aegis incident {incident['id']}", "", "Report source: deterministic detection rules (not AI)", f"Telemetry: {incident['source']}", f"Severity: {incident['severity']} | Workflow: {incident['status']}", f"Source: {incident['src_ip']} | Sensor: {incident['sensor']}", "", "## Findings"]
    for finding in incident["findings"]:
        lines += [f"- {finding['id']}: {finding['name']}", f"  {finding['description']}", f"  Evidence: {', '.join(finding['evidence_ids'])}"]
        if finding["technique"]:
            lines.append(f"  Candidate ATT&CK mapping: {finding['technique']}")
    lines += ["", "## Evidence timeline"]
    for event in incident["events"]:
        detail = event.get("input", event.get("url", event.get("username", "")))
        lines.append(f"- [{event['id']}] {event['timestamp']} {event['eventid']} {json.dumps(detail)}")
    lines += ["", "## Investigation", "Review the cited events and session context. Compare with authorized lab activity before escalating.", "", "## Limits", "Honeypot observations do not prove production compromise. Command input does not prove successful execution. A file download does not prove malware or C2. Technique mappings are candidates for analyst review. Severity is rule priority, not a calibrated probability."]
    return "\n".join(lines)
