"""Synthetic observations only; no connections, shell execution, or payloads."""
from datetime import datetime, timedelta, timezone


def demo_records():
    base = datetime(2026, 10, 5, 14, 30, tzinfo=timezone.utc)
    records = []

    def add(session, host, second, eventid, **fields):
        records.append(dict(timestamp=(base + timedelta(seconds=second)).isoformat(), eventid="cowrie." + eventid, sensor="ssh-lab-01", session=session, src_ip=host, **fields))

    add("demo-auth", "192.0.2.42", 0, "session.connect")
    for n in range(5):
        add("demo-auth", "192.0.2.42", 5 + n * 6, "login.failed", username="admin")
    add("demo-auth", "192.0.2.42", 40, "login.success", username="admin")
    add("demo-auth", "192.0.2.42", 45, "command.input", input="uname -a")
    add("demo-download", "198.51.100.23", 70, "session.connect")
    add("demo-download", "198.51.100.23", 74, "login.success", username="guest")
    add("demo-download", "198.51.100.23", 80, "session.file_download", url="https://artifact.example/diagnostic.txt", shasum="a" * 64)
    add("demo-discovery", "203.0.113.18", 95, "command.input", input="hostname")
    add("demo-benign-1", "192.0.2.10", 100, "session.connect")
    add("demo-benign-1", "192.0.2.10", 101, "login.failed", username="test")
    add("demo-benign-1", "192.0.2.10", 110, "session.closed")
    add("demo-benign-2", "192.0.2.11", 120, "session.connect")
    add("demo-benign-2", "192.0.2.11", 125, "command.input", input="echo lab-check")
    add("demo-benign-2", "192.0.2.11", 130, "session.closed")
    return records


EXPECTED_POSITIVE = {"demo-auth", "demo-download", "demo-discovery"}
EXPECTED_NEGATIVE = {"demo-benign-1", "demo-benign-2"}
