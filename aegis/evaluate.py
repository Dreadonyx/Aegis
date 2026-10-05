"""Repeatable synthetic checks; run with python -m aegis.evaluate. No network activity."""
import json
from datetime import datetime, timedelta, timezone

from aegis.demo import demo_records, EXPECTED_NEGATIVE, EXPECTED_POSITIVE
from aegis.engine import RULESET_VERSION, detect, normalize


def evaluate():
    demo = detect([normalize(e, "demo") for e in demo_records()])
    predicted = {i["session"] for i in demo}
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def record(second=0, **fields):
        return normalize(dict(timestamp=(base+timedelta(seconds=second)).isoformat(),
            sensor="evaluation", session="evaluation", src_ip="192.0.2.90",
            eventid="cowrie.login.failed") | fields, "demo")

    cases = [
        ("Below authentication threshold", [record(n) for n in range(4)], set()),
        ("Five failures in 60 seconds", [record(n*15) for n in range(5)], {"AUTH-001"}),
        ("Failures outside time window", [record(n*16) for n in range(5)], set()),
        ("Distinct sources stay separate", [record(n, src_ip=f"192.0.2.{n+1}") for n in range(5)], set()),
        ("Discovery command", [record(eventid="cowrie.command.input", input="uname -a")], {"DISC-001"}),
        ("Quoted text is not a command", [record(eventid="cowrie.command.input", input='echo "example; hostname"')], set()),
        ("Interactive stdin is not shell input", [record(eventid="cowrie.command.input", input="hostname", realm="cat")], set()),
        ("Multiline shell input", [record(eventid="cowrie.command.input", input="echo example\nhostname")], {"DISC-001"}),
        ("Recorded download", [record(eventid="cowrie.session.file_download", url="https://artifact.example/test.txt")], {"XFER-001"}),
        ("Failed download stays quiet", [record(eventid="cowrie.session.file_download.failed")], set()),
    ]
    results = []
    for name, events, expected in cases:
        actual = {f["id"] for i in detect(events) for f in i["findings"]}
        results.append(dict(name=name, passed=actual == expected, expected=sorted(expected), actual=sorted(actual)))
    return dict(ruleset_version=RULESET_VERSION,
        scope="Synthetic regression checks only. These are not independent real-world detection benchmarks.",
        sessions=dict(true_positives=len(predicted & EXPECTED_POSITIVE), false_positives=len(predicted & EXPECTED_NEGATIVE),
            false_negatives=len(EXPECTED_POSITIVE-predicted), true_negatives=len(EXPECTED_NEGATIVE-predicted)),
        checks=results, passed=sum(c["passed"] for c in results), total=len(results))


if __name__ == "__main__":
    result = evaluate()
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] == result["total"] and not result["sessions"]["false_negatives"] and not result["sessions"]["false_positives"] else 1)
