"""Versioned session features for the optional ML layer. Pure Python, so they can be inspected and tested
without scikit-learn. Changing a feature, its order, or its transform requires a new FEATURE_VERSION; a
model trained on another version is refused."""
import math

from aegis.rules import discovery_commands, is_shell_command, order, session_key, ts

FEATURE_VERSION = "1"
# (name, description). All values are non-negative and passed through log1p before modeling.
FEATURES = (
    ("events", "events in the session"),
    ("duration_s", "session length in seconds (Cowrie duration_ms when present, otherwise first to last event)"),
    ("auth_failures", "failed logins"),
    ("auth_successes", "accepted logins"),
    ("distinct_usernames", "distinct usernames tried"),
    ("commands", "shell command lines"),
    ("distinct_commands", "distinct shell command lines"),
    ("failed_commands", "commands Cowrie reported as failed"),
    ("mean_command_length", "mean characters per shell command line"),
    ("discovery_commands", "shell lines running a configured discovery command"),
    ("downloads", "completed downloads"),
    ("uploads", "completed uploads"),
    ("tunnel_requests", "direct-tcpip (port forwarding) requests"),
    ("client_version_reported", "1 when the client sent a version string"),
    ("events_per_minute", "events divided by session minutes (at least one second)"),
)
NAMES = tuple(name for name, _ in FEATURES)


def session_features(events, config):
    """One feature row per session, with the identifiers needed to cite its evidence."""
    sessions = {}
    for e in sorted(events, key=order):
        sessions.setdefault(session_key(e), []).append(e)
    names = set(config["discovery_commands"])
    rows = []
    for key, items in sessions.items():
        commands = [e["input"] for e in items if is_shell_command(e)]
        closed = [e["duration_ms"] for e in items if e["eventid"] == "cowrie.session.closed" and isinstance(e.get("duration_ms"), (int, float))]
        duration = closed[-1] / 1000 if closed else ts(items[-1]) - ts(items[0])
        count = lambda eventid: sum(1 for e in items if e["eventid"] == eventid)
        values = {
            "events": len(items), "duration_s": max(0.0, duration),
            "auth_failures": count("cowrie.login.failed"), "auth_successes": count("cowrie.login.success"),
            "distinct_usernames": len({e["username"] for e in items if e["eventid"].startswith("cowrie.login.") and e.get("username")}),
            "commands": len(commands), "distinct_commands": len(set(commands)), "failed_commands": count("cowrie.command.failed"),
            "mean_command_length": sum(map(len, commands)) / len(commands) if commands else 0.0,
            "discovery_commands": sum(1 for c in commands if discovery_commands(c, names)),
            "downloads": count("cowrie.session.file_download"), "uploads": count("cowrie.session.file_upload"),
            "tunnel_requests": count("cowrie.direct-tcpip.request"),
            "client_version_reported": int(any(e.get("client_version") for e in items)),
        }
        values["events_per_minute"] = len(items) / (max(duration, 1.0) / 60)
        rows.append({"session_key": key, "session": items[0]["session"], "sensor": items[0]["sensor"], "src_ip": items[0]["src_ip"],
                     "dataset": items[0]["source"], "first_seen": items[0]["timestamp"], "last_seen": items[-1]["timestamp"],
                     "events": items, "values": values})
    return rows


def vector(values):
    return [math.log1p(float(values[name])) for name in NAMES]
