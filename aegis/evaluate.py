"""Repeatable synthetic checks; run with python -m aegis.evaluate. No network activity.

Every rule and sequence has positive and negative fixtures here. These validate logic, not field accuracy."""
import json
from datetime import datetime, timedelta, timezone

from aegis.demo import demo_records, EXPECTED_NEGATIVE, EXPECTED_POSITIVE
from aegis.engine import RULESET_VERSION, detect, normalize

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def record(second=0, **fields):
    return normalize(dict(timestamp=(BASE + timedelta(seconds=second)).isoformat(), sensor="evaluation", session="evaluation",
                          src_ip="192.0.2.90", eventid="cowrie.login.failed") | fields, "demo")


def login(second, session="evaluation"):
    return record(second, session=session, eventid="cowrie.login.success", username="root")


def shell(second, text, session="evaluation"):
    return record(second, session=session, eventid="cowrie.command.input", input=text)


def download(second, session="evaluation", **fields):
    return record(second, session=session, eventid="cowrie.session.file_download", shasum="b" * 64, **fields)


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
    ("Login, discovery, then download", [login(0), shell(10, "uname -a"), download(20)], {"DISC-001", "XFER-001", "SEQ-001"}, 1),
    ("Download before discovery is not the sequence", [login(0), download(10), shell(20, "uname -a")], {"DISC-001", "XFER-001"}, 1),
    ("Sequence outside its window", [login(0), shell(10, "uname -a"), download(4000)], {"DISC-001", "XFER-001"}, 1),
    ("Failures, login, then shell input", failures(5) + [login(30, "entry"), shell(35, "echo hi", "entry")], {"AUTH-001", "AUTH-002", "SEQ-002"}, 1),
    ("Late events are evaluated in event order", list(reversed([login(0), shell(10, "hostname"), download(20)])), {"DISC-001", "XFER-001", "SEQ-001"}, 1),
    ("Shared address alone does not chain sessions", [login(0, "a"), shell(10, "uname", "b"), download(20, "c")], {"DISC-001", "XFER-001"}, 2),
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
    return dict(ruleset_version=RULESET_VERSION,
        scope="Synthetic regression checks only. These are not independent real-world detection benchmarks.",
        sessions=dict(true_positives=len(predicted & EXPECTED_POSITIVE), false_positives=len(predicted & EXPECTED_NEGATIVE),
            false_negatives=len(EXPECTED_POSITIVE - predicted), true_negatives=len(EXPECTED_NEGATIVE - predicted)),
        checks=results, passed=sum(c["passed"] for c in results), total=len(results))


if __name__ == "__main__":
    result = evaluate()
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] == result["total"] and not result["sessions"]["false_negatives"] and not result["sessions"]["false_positives"] else 1)
