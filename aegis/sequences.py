"""Layer D: ordered multi-event sequences. Steps inside one Cowrie session are strongly linked; steps
joined only by source address are labeled weak and never treated as proof of a single actor.

Events are evaluated in event-time order, so late or out-of-order arrivals change the result exactly as
if they had arrived in order. No session-close record is required."""
from aegis.rules import FailureIndex, discovery_commands, is_shell_command, make_finding, order, session_key, ts

TRANSFERS = ("cowrie.session.file_download", "cowrie.session.file_upload")


def catalog(config):
    window = config["sequence_window_seconds"]
    sequence = lambda **fields: {"engine": "sequence", "version": "1", "technique": None, "category": "intrusion-sequence", **fields}
    return [
        sequence(id="SEQ-001", name="Login, discovery, then file transfer", severity="high",
                 severity_rationale="An accepted login followed by reconnaissance and tooling transfer is a common intrusion pattern.",
                 description=f"In one session and within {window} seconds of the login: an accepted login, then a discovery command, then a completed download or upload, in that order."),
        sequence(id="SEQ-002", name="Repeated failures, login, then shell input", severity="high",
                 severity_rationale="Guessing that ends in an accepted login and immediate shell use suggests automated intrusion tooling.",
                 description=f"At least {config['login_failure_threshold']} failures from the same source address within {config['login_lookback_seconds']} seconds before an accepted login, then shell input in the login's session within {window} seconds. The failure step is a weak, address-based link."),
    ]


def _first(events, start, predicate, deadline):
    for event in events[start:]:
        if ts(event) > deadline:
            return None
        if predicate(event):
            return event
    return None


def _step(name, event, link="session"):
    return {"step": name, "event_id": event["id"], "at": event["timestamp"], "link": link}


def sequence_findings(events, config):
    meta = {m["id"]: m for m in catalog(config)}
    enabled = lambda rule_id: rule_id not in config["disabled_rules"]
    window = config["sequence_window_seconds"]
    names = set(config["discovery_commands"])
    index = FailureIndex(events, config)
    sessions = {}
    for event in sorted(events, key=order):
        sessions.setdefault(session_key(event), []).append(event)
    findings = []
    for session in sessions.values():
        logins = [(i, e) for i, e in enumerate(session) if e["eventid"] == "cowrie.login.success"]
        if enabled("SEQ-001"):
            for i, login in logins:
                deadline = ts(login) + window
                found = _first(session, i + 1, lambda e: is_shell_command(e) and discovery_commands(e["input"], names), deadline)
                transfer = found and _first(session, session.index(found) + 1, lambda e: e["eventid"] in TRANSFERS, deadline)
                if transfer:
                    steps = [_step("login", login), _step("discovery", found), _step("transfer", transfer)]
                    facts = {"steps": steps, "window_seconds": window, "elapsed_seconds": round(ts(transfer) - ts(login), 3)}
                    explanation = f"Session {login['session']}: login at {login['timestamp']}, discovery at {found['timestamp']}, transfer at {transfer['timestamp']}."
                    findings.append(make_finding(meta["SEQ-001"], transfer, [login, found, transfer], facts, explanation, f"{session_key(login)}:SEQ-001"))
                    break
        if enabled("SEQ-002"):
            threshold, lookback = config["login_failure_threshold"], config["login_lookback_seconds"]
            for i, login in logins:
                failures = index.before(login, lookback)
                if len(failures) < threshold:
                    continue
                shell = _first(session, i + 1, lambda e: is_shell_command(e) or e["eventid"] == "cowrie.command.failed", ts(login) + window)
                if shell:
                    steps = [{"step": "repeated_failures", "event_ids": [f["id"] for f in failures], "count": len(failures),
                              "first_at": failures[0]["timestamp"], "last_at": failures[-1]["timestamp"], "link": "source_address"},
                             _step("login", login), _step("shell_input", shell)]
                    facts = {"steps": steps, "window_seconds": window, "lookback_seconds": lookback, "threshold": threshold,
                             "elapsed_seconds": round(ts(shell) - ts(failures[0]), 3)}
                    explanation = (f"{len(failures)} failures from {login['src_ip']} (address-linked), then login at {login['timestamp']} "
                                   f"and shell input at {shell['timestamp']} in session {login['session']}.")
                    findings.append(make_finding(meta["SEQ-002"], shell, failures + [login, shell], facts, explanation, f"{session_key(login)}:SEQ-002"))
                    break
    return findings
