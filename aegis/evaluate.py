"""Repeatable synthetic checks; run with python -m aegis.evaluate. No network activity.

Every rule and sequence has positive and negative fixtures here. These validate logic, not field accuracy."""
import json
from datetime import datetime, timedelta, timezone

from aegis.demo import demo_records, EXPECTED_NEGATIVE, EXPECTED_POSITIVE
from aegis import statistics
from aegis.suricata import normalize_eve
from aegis.engine import DEFAULT, RULESET_VERSION, detect, normalize

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def record(second=0, **fields):
    return normalize(dict(timestamp=(BASE + timedelta(seconds=second)).isoformat(), sensor="evaluation", session="evaluation",
                          src_ip="192.0.2.90", eventid="cowrie.login.failed") | fields, "demo")


def login(second, session="evaluation"):
    return record(second, session=session, eventid="cowrie.login.success", username="root")


def shell(second, text, session="evaluation", **fields):
    return record(second, session=session, eventid="cowrie.command.input", input=text, **fields)


def download(second, session="evaluation", **fields):
    return record(second, session=session, eventid="cowrie.session.file_download", shasum="b" * 64, **fields)


def ids_alert(second, src_port, flow=1):
    return normalize_eve({"timestamp": (BASE + timedelta(seconds=second)).strftime("%Y-%m-%dT%H:%M:%S.%f+0000"), "flow_id": flow,
                          "event_type": "alert", "src_ip": "192.0.2.90", "src_port": src_port, "dest_ip": "198.51.100.1", "dest_port": 22,
                          "proto": "TCP", "alert": {"action": "allowed", "signature_id": 1000001, "signature": "Fixture signature", "severity": 1}}, "demo")


def failures(count, spacing=5, start=0, **fields):
    return [record(start + n * spacing, session=f"guess-{n}", **fields) for n in range(count)]


CASES = [
    ("Below authentication threshold", [record(n) for n in range(4)], set(), None),
    ("Five failures in 60 seconds", [record(n * 15) for n in range(5)], {"AUTH-001"}, None),
    ("Failures outside time window", [record(n * 16) for n in range(5)], set(), None),
    ("Distinct sources stay separate", [record(n, src_ip=f"192.0.2.{n + 1}") for n in range(5)], set(), None),
    ("Distinct sensors stay separate", [record(n, sensor=f"sensor-{n}") for n in range(5)], set(), None),
    ("One burst across sessions is one finding", failures(8, spacing=3), {"AUTH-001"}, 1),
    ("Discovery command", [shell(0, "uname -a")], {"DISC-001"}, None),
    ("Quoted text is not a command", [shell(0, 'echo "example; hostname"')], set(), None),
    ("Interactive stdin is not shell input", [record(eventid="cowrie.command.input", input="hostname", realm="cat")], set(), None),
    ("Multiline shell input", [shell(0, "echo example\nhostname")], {"DISC-001"}, None),
    ("Recorded download", [download(0, url="https://artifact.example/test.txt")], {"XFER-001"}, None),
    ("Download captured from stdin has no URL", [download(0)], {"XFER-001"}, None),
    ("Failed download stays quiet", [record(eventid="cowrie.session.file_download.failed", url="https://artifact.example/x")], set(), None),
    ("Recorded upload", [record(eventid="cowrie.session.file_upload", filename="tool.bin", shasum="c" * 64)], {"XFER-002"}, None),
    ("Login, discovery, then download", [login(0), shell(10, "uname -a"), download(20)], {"INT-001", "DISC-001", "XFER-001", "SEQ-001"}, 1),
    ("Download before discovery is not the sequence", [login(0), download(10), shell(20, "uname -a")], {"INT-001", "DISC-001", "XFER-001"}, 1),
    ("Sequence outside its window", [login(0), shell(10, "uname -a"), download(4000)], {"INT-001", "DISC-001", "XFER-001"}, 1),
    ("Failures, login, then shell input", failures(5) + [login(30, "entry"), shell(35, "echo hi", "entry")], {"AUTH-001", "AUTH-002", "INT-001", "SEQ-002"}, 1),
    ("Late events are evaluated in event order", list(reversed([login(0), shell(10, "hostname"), download(20)])), {"INT-001", "DISC-001", "XFER-001", "SEQ-001"}, 1),
    ("Login then one shell command", [login(0), shell(1, "echo ok")], {"INT-001"}, 1),
    ("Accepted login alone is not shell activity", [login(0)], set(), 0),
    ("Shell input before the login does not count", [shell(0, "echo ok"), login(5)], set(), 0),
    ("IDS alert matching a session's flow joins its incident",
     [record(0, eventid="cowrie.session.connect", src_port=40001), shell(5, "uname"), ids_alert(3, 40001)], {"DISC-001", "EXT-001"}, 1),
    ("IDS alert sharing only the address stays separate",
     [record(0, eventid="cowrie.session.connect", src_port=40001), shell(5, "uname"), ids_alert(3, 50000, 2)], {"DISC-001", "EXT-001"}, 2),
    ("Shared address alone does not chain sessions", [login(0, "a"), shell(10, "uname", "b"), download(20, "c")], {"DISC-001", "XFER-001"}, 2),
]


HOUR = 3600
RATES = [10, 12, 9, 11, 8, 10, 13, 9, 10, 11, 12, 10, 9, 11, 10, 12, 8, 10, 11, 9]


def connects(hour, count, sensor="stats"):
    return [record(hour * HOUR + n, eventid="cowrie.session.connect", session=f"h{hour}-{n}", sensor=sensor, src_ip="192.0.2.50") for n in range(count)]


def rate_series(final):
    return [e for hour, count in enumerate(RATES + [final]) for e in connects(hour, count)]


def peers(make, count=25):
    return [e for n in range(count) for e in make(n, n * HOUR)]


def guesses(n, start, names=None, sensor="stats"):
    names = names or [f"user{k}" for k in range(1 + n % 3)]
    return [record(start + k, session=f"src{n}-{k}", src_ip=f"198.51.100.{n + 1}", sensor=sensor, username=name) for k, name in enumerate(names)]


def commands(n, start, count=None, sensor="stats"):
    return [shell(start + k, f"echo {k}", f"cmd{n}", sensor=sensor) for k in range(count or 1 + n % 3)]


def closed(n, start, duration=None, sensor="stats", login=True):
    session = [record(start, eventid="cowrie.session.closed", session=f"len{n}", sensor=sensor, duration_ms=duration or 10000 + n * 2000)]
    if login:
        session.insert(0, record(start - 1, eventid="cowrie.login.success", session=f"len{n}", sensor=sensor, username="root"))
    return session


def scanners(count):
    return [record(n, eventid="cowrie.session.closed", session=f"scan{n}", duration_ms=0) for n in range(count)]


STAT_CASES = [
    ("Statistics stay quiet during cold start", [e for h, c in enumerate([10, 11, 9, 10, 200]) for e in connects(h, c)], set()),
    ("Event rate spike after an established baseline", rate_series(100), {"STAT-001"}),
    ("Small absolute increase stays below the excess guard", rate_series(16), set()),
    ("Constant baseline uses the documented fallback", [e for h in range(21) for e in connects(h, 10 if h < 20 else 60)], {"STAT-001"}),
    ("Username breadth outlier against established peers", peers(guesses) + guesses(99, 30 * HOUR, [f"name{k}" for k in range(30)], "other"), {"STAT-002"}),
    ("Command-heavy session against established peers", peers(commands) + commands(99, 30 * HOUR, 40, "other"), {"STAT-003"}),
    ("Long session against established peers", peers(closed) + closed(99, 30 * HOUR, 7200000, "other"), {"STAT-004"}),
    ("Too few peers stays quiet", peers(commands, 5) + commands(99, 30 * HOUR, 40, "other"), set()),
    ("Scanner sessions do not form the duration baseline", scanners(60) + peers(closed, 5) + closed(99, 30 * HOUR, 7200000, "other"), set()),
    ("A long session without a login is not judged", peers(closed) + closed(99, 30 * HOUR, 7200000, "other", login=False), set()),
    ("Baseline excludes the judged bucket", [e for h, c in enumerate(RATES[:11] + [100]) for e in connects(h, c)], set()),
    ("Peers exclude the judged session", peers(commands, 19) + commands(99, 30 * HOUR, 40, "other"), set()),
    ("Spread baseline with MAD of zero uses mean absolute deviation",
     # The 40s fall inside the cold-start period, so the final baseline is twelve 10s and eight 40s:
     # median 10 and MAD 0, but a mean absolute deviation of 12 keeps 45 below the threshold.
     [e for h, c in enumerate([40, 10, 40, 10, 40, 10, 40, 10, 40, 40, 40, 40] + [10] * 8 + [45]) for e in connects(h, c)], set()),
]


def evaluate():
    demo = [normalize(e, "demo") for e in demo_records()]
    sessions = {e["id"]: e["session"] for e in demo}
    predicted = {sessions[i] for incident in detect(demo) for f in incident["findings"] for i in f["evidence_ids"]}
    results = []
    for name, events, expected, incidents in CASES:
        found = detect(events)
        actual = {f["id"] for i in found for f in i["findings"]}
        count = sum(len(i["findings"]) for i in found)
        passed = actual == expected and (incidents is None or len(found) == incidents)
        if name.startswith("One burst"):
            passed = passed and count == 1
        results.append(dict(name=name, passed=passed, expected=sorted(expected), actual=sorted(actual),
                            incidents=len(found), expected_incidents=incidents))
    for name, events, expected in STAT_CASES:
        actual = {f["id"] for f in statistics.compute(events, DEFAULT)["findings"]}
        results.append(dict(name=name, passed=actual == expected, expected=sorted(expected), actual=sorted(actual), engine="statistical"))
    return dict(ruleset_version=RULESET_VERSION,
        scope="Synthetic regression checks only. These are not independent real-world detection benchmarks.",
        sessions=dict(true_positives=len(predicted & EXPECTED_POSITIVE), false_positives=len(predicted & EXPECTED_NEGATIVE),
            false_negatives=len(EXPECTED_POSITIVE - predicted), true_negatives=len(EXPECTED_NEGATIVE - predicted)),
        checks=results, passed=sum(c["passed"] for c in results), total=len(results))


if __name__ == "__main__":
    result = evaluate()
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] == result["total"] and not result["sessions"]["false_negatives"] and not result["sessions"]["false_positives"] else 1)
