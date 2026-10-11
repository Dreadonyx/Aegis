"""Layer A: deterministic, explainable rules. Every finding cites its exact evidence events and the
facts that caused the match."""
import bisect
import hashlib
import json
import re
import shlex
from datetime import datetime

RULESET_VERSION = "2026.10.2"

DEFAULT_CONFIG = {
    "auth_failure_threshold": 5,
    "auth_failure_window_seconds": 60,
    "login_failure_threshold": 5,
    "login_lookback_seconds": 300,
    "auth_group_by": "sensor_and_source",
    "discovery_commands": ["uname", "hostname"],
    "sequence_window_seconds": 1800,
    "statistical_enabled": True,
    "stats_bucket_seconds": 3600,
    "stats_baseline_buckets": 24,
    "stats_min_baseline": 12,
    "stats_peer_window_seconds": 604800,
    "stats_peer_min": 20,
    "stats_z_threshold": 3.5,
    "ml_enabled": False,
    "ml_max_model_age_days": 90,
    "disabled_rules": [],
}
RULE_IDS = ("AUTH-001", "AUTH-002", "INT-001", "DISC-001", "XFER-001", "XFER-002")
SEQUENCE_IDS = ("SEQ-001", "SEQ-002")
STAT_IDS = ("STAT-001", "STAT-002", "STAT-003", "STAT-004")
ML_IDS = ("ML-001",)
COMMAND_NAME = re.compile(r"^[A-Za-z0-9_.+-]{1,64}$")


def validate_config(overrides=None):
    """Return a complete, validated configuration. Unknown keys and out-of-range values are errors."""
    overrides = overrides or {}
    if not isinstance(overrides, dict):
        raise ValueError("Detection configuration must be a JSON object")
    unknown = set(overrides) - set(DEFAULT_CONFIG)
    if unknown:
        raise ValueError(f"Unknown detection settings: {', '.join(sorted(unknown))}")
    config = {**DEFAULT_CONFIG, **overrides}
    ranges = {"auth_failure_threshold": (2, 1000), "login_failure_threshold": (1, 1000),
              "auth_failure_window_seconds": (1, 86400), "login_lookback_seconds": (1, 86400),
              "sequence_window_seconds": (1, 604800), "stats_bucket_seconds": (60, 86400), "stats_baseline_buckets": (3, 2000),
              "stats_min_baseline": (3, 2000), "stats_peer_window_seconds": (3600, 31536000), "stats_peer_min": (5, 100000),
              "ml_max_model_age_days": (1, 3650)}
    for key, (low, high) in ranges.items():
        value = config[key]
        if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
            raise ValueError(f"{key} must be an integer from {low} to {high}")
    if config["stats_min_baseline"] > config["stats_baseline_buckets"]:
        raise ValueError("stats_min_baseline cannot exceed stats_baseline_buckets")
    if config["stats_peer_window_seconds"] < config["stats_bucket_seconds"]:
        raise ValueError("stats_peer_window_seconds must be at least stats_bucket_seconds")
    z = config["stats_z_threshold"]
    if not isinstance(z, (int, float)) or isinstance(z, bool) or not 2 <= z <= 50:
        raise ValueError("stats_z_threshold must be a number from 2 to 50")
    for flag in ("statistical_enabled", "ml_enabled"):
        if not isinstance(config[flag], bool):
            raise ValueError(f"{flag} must be true or false")
    if config["auth_group_by"] not in ("sensor_and_source", "source"):
        raise ValueError("auth_group_by must be sensor_and_source or source")
    commands = config["discovery_commands"]
    if not isinstance(commands, list) or not 1 <= len(commands) <= 100 or not all(isinstance(c, str) and COMMAND_NAME.match(c) for c in commands):
        raise ValueError("discovery_commands must list 1-100 command names (letters, digits, . _ + -)")
    disabled = config["disabled_rules"]
    known = RULE_IDS + SEQUENCE_IDS + STAT_IDS + ML_IDS
    if not isinstance(disabled, list) or not set(disabled) <= set(known):
        raise ValueError(f"disabled_rules may contain only: {', '.join(known)}")
    config["discovery_commands"] = sorted(set(commands))
    config["disabled_rules"] = sorted(set(disabled))
    return config


def fingerprint(config):
    """Changes whenever rule logic or configuration changes; stored detection results are then recomputed."""
    return hashlib.sha256(json.dumps([RULESET_VERSION, config], sort_keys=True).encode()).hexdigest()[:16]


def catalog(config):
    scope = "on one sensor" if config["auth_group_by"] == "sensor_and_source" else "across all sensors"
    rule = lambda **fields: {"engine": "rule", "version": "2", **fields}
    return [
        rule(id="AUTH-001", name="Repeated authentication failures", severity="medium", technique="T1110.001", category="credential-access",
             severity_rationale="Automated password guessing against the sensor; failures alone grant no access.",
             description=f"At least {config['auth_failure_threshold']} failed logins within {config['auth_failure_window_seconds']} seconds from one source address {scope}, across sessions. Overlapping windows form one finding per burst."),
        rule(id="AUTH-002", name="Login following repeated failures", severity="high", technique=None, category="initial-access",
             severity_rationale="The honeypot accepted credentials after guessing, so follow-on activity is likely. This does not establish a real account compromise.",
             description=f"A honeypot login succeeds within {config['login_lookback_seconds']} seconds after at least {config['login_failure_threshold']} failures from the same source address {scope}. Failures may come from other sessions."),
        rule(id="INT-001", name="Shell input after an accepted login", severity="medium", technique="T1059.004", category="execution",
             severity_rationale="Hands-on or scripted shell use after the honeypot accepted credentials; never legitimate on a honeypot, but scripted one-command probes are common and low impact.",
             description="A honeypot login is accepted and shell input (or a command Cowrie reports as failed) follows in the same session. Input is observed; execution success is not established."),
        rule(id="DISC-001", name="System discovery command observed", severity="low", technique="T1082", category="discovery",
             severity_rationale="Common reconnaissance that is frequently benign on its own.",
             description=f"Shell input runs one of these as a command: {', '.join(config['discovery_commands'])}. Input is observed; execution success is not established."),
        rule(id="XFER-001", name="File download recorded", severity="high", technique="T1105", category="ingress-tool-transfer",
             severity_rationale="Captured downloads are often follow-on tooling; the file has not been executed or classified.",
             description="Cowrie reports a completed download with a captured file digest. The URL is absent for stdin or redirect captures. This does not establish payload execution or maliciousness."),
        rule(id="XFER-002", name="File upload recorded", severity="high", technique="T1105", category="ingress-tool-transfer",
             severity_rationale="Files pushed over SCP or SFTP are often tooling; the file has not been executed or classified.",
             description="Cowrie reports a file uploaded into the honeypot over SCP or SFTP. This does not establish payload execution or maliciousness."),
    ]


def ts(event):
    return datetime.fromisoformat(event["timestamp"]).timestamp()


def order(event):
    return (event["timestamp"], event["id"])


def session_key(event):
    return hashlib.sha256(json.dumps([event[k] for k in ("source", "sensor", "src_ip", "session")]).encode()).hexdigest()[:16]


def auth_key(event, config):
    if config["auth_group_by"] == "source":
        return (event["source"], event["src_ip"])
    return (event["source"], event["sensor"], event["src_ip"])


def discovery_commands(text, names):
    """Command names from `names` found in simple shell command positions. Input is never interpreted
    or executed; quoted text and arguments are not commands."""
    lexer = shlex.shlex(text, posix=False, punctuation_chars=";&|()\n")
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
    except ValueError:
        return []
    found, command_position = [], True
    for token in tokens:
        if token and all(c in ";&|()\n" for c in token):
            command_position = True
        elif command_position:
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token):
                continue
            command_position = False
            name = token.strip("\"'").rsplit("/", 1)[-1]
            if name in names and name not in found:
                found.append(name)
    return found


def is_discovery(text, names=("uname", "hostname")):
    return bool(discovery_commands(text, names))


def is_shell_command(event):
    return event["eventid"] == "cowrie.command.input" and not event.get("realm")


class FailureIndex:
    """Failed logins grouped by the configured authentication key, in event order."""

    def __init__(self, events, config):
        self.config, self.groups = config, {}
        for event in events:
            if event["eventid"] == "cowrie.login.failed":
                self.groups.setdefault(auth_key(event, config), []).append(event)
        self.keys = {k: [order(e) for e in v] for k, v in self.groups.items()}

    def before(self, event, seconds):
        """Failures ordered before `event` and at most `seconds` older."""
        key = auth_key(event, self.config)
        failures = self.groups.get(key, [])
        end = bisect.bisect_left(self.keys.get(key, []), order(event))
        limit = ts(event) - seconds
        return [f for f in failures[:end] if ts(f) >= limit]


def make_finding(meta, anchor, evidence, facts, explanation, dedup_key):
    evidence = sorted({e["id"]: e for e in evidence}.values(), key=order)
    ids = [e["id"] for e in evidence]
    dataset = anchor["source"]
    return {
        "finding_id": hashlib.sha256(json.dumps([dataset, meta["engine"], meta["id"], meta["version"], dedup_key]).encode()).hexdigest()[:20],
        "engine": meta["engine"], "rule_id": meta["id"], "id": meta["id"], "rule_version": meta["version"],
        "title": meta["name"], "name": meta["name"], "description": meta["description"], "category": meta["category"],
        "severity": meta["severity"], "severity_rationale": meta["severity_rationale"], "technique": meta["technique"],
        "dataset": dataset, "observed_at": anchor["timestamp"], "first_seen": evidence[0]["timestamp"], "last_seen": evidence[-1]["timestamp"],
        "anchor_event_id": anchor["id"], "session": anchor["session"], "session_key": session_key(anchor),
        "sensor": anchor["sensor"], "src_ip": anchor["src_ip"],
        "evidence_event_ids": ids, "evidence_ids": ids,
        "rationale": {"explanation": explanation, "facts": facts},
        "score": None, "score_type": None, "dedup_key": dedup_key, "status": "active",
    }


def per_session(matches):
    """Group (event, detail) matches by session, keeping event order."""
    grouped = {}
    for event, detail in matches:
        grouped.setdefault(session_key(event), []).append((event, detail))
    return grouped.values()


def auth_bursts(meta, index, config):
    threshold, window = config["auth_failure_threshold"], config["auth_failure_window_seconds"]
    for failures in index.groups.values():
        times = [ts(f) for f in failures]
        bursts, left = [], 0
        for right in range(len(failures)):
            while times[right] - times[left] > window:
                left += 1
            if right - left + 1 < threshold:
                continue
            if bursts and left <= bursts[-1]["end"]:  # shares events with the current burst
                bursts[-1]["end"] = right
            else:
                bursts.append({"start": left, "end": right, "anchor": failures[right]})
        for burst in bursts:
            evidence = failures[burst["start"]:burst["end"] + 1]
            anchor = burst["anchor"]
            facts = {"failures": len(evidence), "threshold": threshold, "window_seconds": window, "group_by": config["auth_group_by"],
                     "first_failure_at": evidence[0]["timestamp"], "last_failure_at": evidence[-1]["timestamp"],
                     "sessions": len({session_key(e) for e in evidence}), "distinct_usernames": len({e.get("username") for e in evidence if e.get("username")})}
            explanation = (f"{len(evidence)} failed logins from {anchor['src_ip']} between {facts['first_failure_at']} and {facts['last_failure_at']} "
                           f"across {facts['sessions']} session(s); at least {threshold} fell within {window} seconds.")
            yield make_finding(meta, anchor, evidence, facts, explanation, anchor["id"])


def rule_findings(events, config):
    events = sorted(events, key=order)
    meta = {m["id"]: m for m in catalog(config)}
    enabled = lambda rule_id: rule_id not in config["disabled_rules"]
    index = FailureIndex(events, config)
    findings = []
    if enabled("AUTH-001"):
        findings.extend(auth_bursts(meta["AUTH-001"], index, config))
    if enabled("AUTH-002"):
        threshold, lookback = config["login_failure_threshold"], config["login_lookback_seconds"]
        matches = [(e, index.before(e, lookback)) for e in events if e["eventid"] == "cowrie.login.success"]
        for items in per_session([(e, f) for e, f in matches if len(f) >= threshold]):
            anchor, first = items[0]
            evidence = [e for e, _ in items] + [f for _, failures in items for f in failures]
            facts = {"logins": len(items), "failures_before_first_login": len(first), "threshold": threshold, "lookback_seconds": lookback,
                     "first_login_at": anchor["timestamp"], "failure_sessions": len({session_key(f) for f in first}),
                     "link": "Failures are linked to the login by source address" + (" and sensor" if config["auth_group_by"] == "sensor_and_source" else "")
                             + ", not by session. Clients behind shared addresses can appear as one source."}
            explanation = f"Login accepted at {anchor['timestamp']} after {len(first)} failures from {anchor['src_ip']} in the previous {lookback} seconds."
            findings.append(make_finding(meta["AUTH-002"], anchor, evidence, facts, explanation, anchor_key(anchor, "AUTH-002")))
    if enabled("INT-001"):
        logged_in, matches = {}, []
        for e in events:
            key = session_key(e)
            if e["eventid"] == "cowrie.login.success":
                logged_in.setdefault(key, e)
            elif key in logged_in and (is_shell_command(e) or e["eventid"] == "cowrie.command.failed"):
                matches.append((e, logged_in[key]))
        for items in per_session(matches):
            login, commands = items[0][1], [e for e, _ in items]
            facts = {"commands": len(commands), "login_at": login["timestamp"], "first_command_at": commands[0]["timestamp"],
                     "seconds_to_first_command": round(ts(commands[0]) - ts(login), 3)}
            explanation = f"Login accepted at {login['timestamp']}, then {len(commands)} shell input(s) in session {login['session']}."
            findings.append(make_finding(meta["INT-001"], commands[0], [login] + commands, facts, explanation, anchor_key(login, "INT-001")))
    if enabled("DISC-001"):
        names = set(config["discovery_commands"])
        matches = [(e, discovery_commands(e["input"], names)) for e in events if is_shell_command(e)]
        for items in per_session([(e, found) for e, found in matches if found]):
            anchor = items[0][0]
            commands = sorted({name for _, found in items for name in found})
            facts = {"inputs": len(items), "commands_matched": commands, "first_at": anchor["timestamp"]}
            explanation = f"{len(items)} shell input(s) in session {anchor['session']} ran discovery commands: {', '.join(commands)}."
            findings.append(make_finding(meta["DISC-001"], anchor, [e for e, _ in items], facts, explanation, anchor_key(anchor, "DISC-001")))
    for rule_id, eventid, noun in (("XFER-001", "cowrie.session.file_download", "download"), ("XFER-002", "cowrie.session.file_upload", "upload")):
        if not enabled(rule_id):
            continue
        for items in per_session([(e, None) for e in events if e["eventid"] == eventid]):
            anchor, transfers = items[0][0], [e for e, _ in items]
            digests = sorted({e["shasum"] for e in transfers if e.get("shasum")})
            facts = {f"{noun}s": len(transfers), "sha256": digests[:20]}
            if noun == "download":
                facts["with_url"] = sum(1 for e in transfers if e.get("url"))
            explanation = f"Cowrie recorded {len(transfers)} completed file {noun}(s) in session {anchor['session']} with {len(digests)} distinct digest(s)."
            findings.append(make_finding(meta[rule_id], anchor, transfers, facts, explanation, anchor_key(anchor, rule_id)))
    return findings


def anchor_key(event, rule_id):
    return f"{session_key(event)}:{rule_id}"
