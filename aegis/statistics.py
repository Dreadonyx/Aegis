"""Layer B: inspectable statistics over one dataset's own history.

Baselines are robust (median and median absolute deviation) and look only backward from the value
being judged. Nothing is alerted until a baseline meets its minimum sample size. A honeypot sample is
small and biased, so a statistical finding means "unusual for this dataset", never "malicious": these
findings are low severity and never create incidents on their own."""
import bisect
import hashlib
import json
import statistics as stats
from datetime import datetime, timezone

from aegis.rules import STAT_IDS, is_shell_command, order, session_key, ts

STATS_VERSION = "1"
MAD_SCALE = 1.4826       # makes MAD comparable to a standard deviation for normal data
MEAN_AD_SCALE = 1.2533   # fallback when more than half the baseline is identical (MAD = 0)
EVIDENCE_LIMIT = 1000

METRICS = {
    "STAT-001": dict(name="Event rate spike on a sensor", kind="temporal", unit="events per bucket", min_excess=20, scope="sensor"),
    "STAT-002": dict(name="Unusual username breadth from one source", kind="peer", unit="distinct usernames per bucket", min_excess=5, scope="source"),
    "STAT-003": dict(name="Unusual command volume in a session", kind="peer", unit="shell commands per session", min_excess=10, scope="session"),
    "STAT-004": dict(name="Unusually long interactive session", kind="peer", unit="session duration (ms)", min_excess=300000, scope="session"),
}
assert tuple(METRICS) == STAT_IDS


def catalog(config):
    bucket, window = config["stats_bucket_seconds"], config["stats_baseline_buckets"]
    peers = f"other entities in the preceding {config['stats_peer_window_seconds']} seconds (at least {config['stats_peer_min']})"
    descriptions = {
        "STAT-001": f"Events on one sensor in a {bucket}-second bucket compared with its previous {window} buckets (at least {config['stats_min_baseline']}).",
        "STAT-002": f"Distinct usernames one source address tried in a {bucket}-second bucket compared with {peers}.",
        "STAT-003": f"Shell commands in one session compared with {peers} that ran commands.",
        "STAT-004": f"Duration of a session with an accepted login, compared with {peers} that also logged in. Scanner sessions are excluded because they dominate honeypot traffic and close almost instantly.",
    }
    return [{"id": rule_id, "name": m["name"], "engine": "statistical", "version": STATS_VERSION, "severity": "low", "technique": None,
             "category": "anomaly", "description": descriptions[rule_id] + f" Alerts need a robust z-score of at least {config['stats_z_threshold']} "
             f"and an excess of at least {m['min_excess']} {m['unit'].split(' per ')[0].split(' (')[0]} over the baseline median.",
             "severity_rationale": "Unusual relative to this dataset's own history. Not evidence of malicious intent."}
            for rule_id, m in METRICS.items()]


def fingerprint(config):
    return hashlib.sha256(json.dumps(["stats", STATS_VERSION, config], sort_keys=True).encode()).hexdigest()[:16]


def baseline(values):
    """Robust location and scale. The scale source is recorded so a reader can see when a fallback applied."""
    median = stats.median(values)
    deviations = [abs(v - median) for v in values]
    mad = stats.median(deviations)
    if mad > 0:
        scale, source = MAD_SCALE * mad, "mad"
    elif any(deviations):
        scale, source = MEAN_AD_SCALE * stats.fmean(deviations), "mean_absolute_deviation"
    else:
        scale, source = 1.0, "constant_baseline_floor"
    return {"sample_size": len(values), "median": median, "mad": mad, "scale": round(scale, 6), "scale_source": source}


def iso(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat(timespec="seconds")


def _finding(rule_id, config, dataset, scope, evidence, observed, base, window, explanation, dedup_key, extra=None):
    meta = METRICS[rule_id]
    z = (observed - base["median"]) / base["scale"]
    evidence = sorted(evidence, key=order)
    ids = [e["id"] for e in evidence[:EVIDENCE_LIMIT]]
    facts = {"metric": meta["unit"], "observed": observed, "robust_z": round(z, 2), "threshold": config["stats_z_threshold"],
             "min_excess": meta["min_excess"], "method": "median/MAD robust z-score; baseline uses only earlier data",
             "baseline": {**base, "window_start": window[0], "window_end": window[1]},
             "evidence_total": len(evidence), "evidence_truncated": len(evidence) > EVIDENCE_LIMIT, **(extra or {})}
    anchor = evidence[-1]
    return {
        "finding_id": hashlib.sha256(json.dumps([dataset, "statistical", rule_id, STATS_VERSION, dedup_key]).encode()).hexdigest()[:20],
        "engine": "statistical", "rule_id": rule_id, "id": rule_id, "rule_version": STATS_VERSION, "title": meta["name"], "name": meta["name"],
        "description": next(c["description"] for c in catalog(config) if c["id"] == rule_id), "category": "anomaly", "severity": "low",
        "severity_rationale": "Unusual relative to this dataset's own history. Not evidence of malicious intent.", "technique": None,
        "dataset": dataset, "observed_at": anchor["timestamp"], "first_seen": evidence[0]["timestamp"], "last_seen": anchor["timestamp"],
        "anchor_event_id": anchor["id"], "scope": scope, "session": scope.get("session"), "session_key": scope.get("session_key", ""),
        "sensor": scope.get("sensor", ""), "src_ip": scope.get("src_ip", ""), "evidence_event_ids": ids, "evidence_ids": ids,
        "rationale": {"explanation": explanation, "facts": facts}, "score": round(z, 2), "score_type": "robust_z",
        "dedup_key": dedup_key, "status": "active",
    }


def _alerting(rule_id, config, observed, base):
    z = (observed - base["median"]) / base["scale"]
    return z >= config["stats_z_threshold"] and observed - base["median"] >= METRICS[rule_id]["min_excess"]


def _peer_entities(entities, config):
    """Judge each entity against entities that started in the preceding peer window. Entities are
    (time, value, payload); returns (entity, baseline, window) for every entity with enough peers."""
    entities = sorted(entities, key=lambda e: e[0])
    times = [e[0] for e in entities]
    bucket, span = config["stats_bucket_seconds"], config["stats_peer_window_seconds"]
    results, cache = [], {}
    for entity in entities:
        start = entity[0] // bucket * bucket  # peers are fixed per bucket, so entities in one bucket share a baseline
        if start not in cache:
            low, high = bisect.bisect_left(times, start - span), bisect.bisect_left(times, start)
            values = [entities[i][1] for i in range(low, high)]
            cache[start] = (baseline(values) if len(values) >= config["stats_peer_min"] else None, (iso(start - span), iso(start)), len(values))
        results.append((entity, *cache[start]))
    return results


def compute(events, config):
    """Statistical findings plus the current baseline status of every metric (as of the newest event)."""
    findings, status = [], []
    if not events or not config["statistical_enabled"]:
        return {"findings": findings, "baselines": status, "enabled": config["statistical_enabled"]}
    enabled = lambda rule_id: rule_id not in config["disabled_rules"]
    dataset = events[0]["source"]
    bucket = config["stats_bucket_seconds"]
    events = sorted(events, key=order)
    times = {e["id"]: ts(e) for e in events}
    latest = int(max(times.values()) // bucket)

    # STAT-001: per-sensor event counts per bucket against the trailing buckets (zero-filled between
    # the sensor's first and last bucket; sensor downtime is indistinguishable from silence).
    per_sensor = {}
    for e in events:
        per_sensor.setdefault(e["sensor"], {}).setdefault(int(times[e["id"]] // bucket), []).append(e)
    n, minimum = config["stats_baseline_buckets"], config["stats_min_baseline"]
    for sensor, buckets in sorted(per_sensor.items()):
        first, last = min(buckets), max(buckets)
        counts = lambda lo, hi: [len(buckets.get(k, ())) for k in range(max(first, lo), hi)]
        if enabled("STAT-001"):
            for b in range(first, last + 1):
                window = counts(b - n, b)
                observed = len(buckets.get(b, ()))
                if len(window) < minimum or not observed:
                    continue
                base = baseline(window)
                if _alerting("STAT-001", config, observed, base):
                    previous = window[-1]
                    findings.append(_finding("STAT-001", config, dataset, {"type": "sensor", "sensor": sensor}, buckets[b], observed, base,
                        (iso(max(first, b - n) * bucket), iso(b * bucket)),
                        f"{observed} events on {sensor} in the bucket starting {iso(b * bucket)}; the previous {len(window)} buckets had a median of {base['median']}.",
                        f"{sensor}:{b}", {"bucket_start": iso(b * bucket), "bucket_seconds": bucket, "previous_bucket": previous,
                                          "change_from_previous": observed - previous,
                                          "evidence_selector": {"sensor": sensor, "since": iso(b * bucket), "until": iso((b + 1) * bucket)}}))
        current = counts(latest + 1 - n, latest + 1)
        prior = counts(latest + 1 - 2 * n, latest + 1 - n)
        drift = None
        if len(current) >= minimum and len(prior) >= minimum:
            before, now = stats.median(prior), stats.median(current)
            drift = {"previous_median": before, "current_median": now, "change_ratio": round(now / before, 3) if before else None}
        status.append({"metric": "STAT-001", "entity": {"sensor": sensor}, "sample_size": len(current), "required": minimum,
                       "state": "established" if len(current) >= minimum else "insufficient_baseline",
                       **({"median": baseline(current)["median"]} if current else {}), "drift": drift})

    # Peer metrics: one value per entity, judged against entities of the preceding peer window.
    auth, commands, durations = {}, {}, []
    by_session = {}
    interactive = {session_key(e) for e in events if e["eventid"] == "cowrie.login.success"}
    for e in events:
        by_session.setdefault(session_key(e), []).append(e)
        if e["eventid"] in ("cowrie.login.failed", "cowrie.login.success") and e.get("username"):
            entry = auth.setdefault((e["src_ip"], int(times[e["id"]] // bucket)), {"names": set(), "events": []})
            entry["names"].add(e["username"])
            entry["events"].append(e)
        if is_shell_command(e):
            commands.setdefault(session_key(e), []).append(e)
        if e["eventid"] == "cowrie.session.closed" and isinstance(e.get("duration_ms"), (int, float)) and session_key(e) in interactive:
            durations.append(e)
    peer_sets = {
        "STAT-002": [(b * bucket, len(v["names"]), (src, b, v["events"])) for (src, b), v in auth.items()],
        "STAT-003": [(times[cmds[0]["id"]], len(cmds), (key, cmds)) for key, cmds in commands.items()],
        "STAT-004": [(times[e["id"]], e["duration_ms"], (session_key(e), [e])) for e in durations],
    }
    for rule_id, entities in peer_sets.items():
        judged = _peer_entities(entities, config)
        for (when, observed, payload), base, window, _ in judged:
            if base is None or not enabled(rule_id) or not _alerting(rule_id, config, observed, base):
                continue
            if rule_id == "STAT-002":
                src, b, evidence = payload
                scope, key = {"type": "source", "src_ip": src}, f"{src}:{b}"
                text = f"{observed} distinct usernames from {src} in the bucket starting {iso(b * bucket)}; peers (n={base['sample_size']}) had a median of {base['median']}."
                extra = {"bucket_start": iso(b * bucket), "bucket_seconds": bucket}
            else:
                key, evidence = payload
                first = evidence[0]
                scope = {"type": "session", "session": first["session"], "session_key": key, "sensor": first["sensor"], "src_ip": first["src_ip"]}
                noun = "shell commands" if rule_id == "STAT-003" else "ms session duration"
                text = f"Session {first['session']}: {observed} {noun}; peer sessions (n={base['sample_size']}) had a median of {base['median']}."
                extra = {}
                if rule_id == "STAT-004":
                    evidence = by_session[key]  # the whole session is the evidence for its duration
            findings.append(_finding(rule_id, config, dataset, scope, evidence, observed, base, window, text, key, extra))
        peers_now = sum(1 for e in entities if (latest + 1) * bucket - config["stats_peer_window_seconds"] <= e[0] < (latest + 1) * bucket)
        status.append({"metric": rule_id, "entity": {"peer_group": METRICS[rule_id]["scope"]}, "sample_size": peers_now,
                       "required": config["stats_peer_min"], "state": "established" if peers_now >= config["stats_peer_min"] else "insufficient_baseline"})
    return {"findings": findings, "baselines": status, "enabled": True, "as_of": iso((latest + 1) * bucket)}


MAX_BUCKETS = 1000


def describe(events, bucket_seconds, since=None, until=None):
    """Descriptive analytics for charts: per-bucket counts and distinct counts over an explicit, zero-filled
    range (since/until, or the span of the events), plus session summaries."""
    buckets, sessions = {}, {}
    for e in events:
        b = int(ts(e) // bucket_seconds)
        row = buckets.setdefault(b, {"events": 0, "by_event_type": {}, "sources": set(), "usernames": set(), "commands": set(), "sessions": set()})
        row["events"] += 1
        row["by_event_type"][e.get("event_type", "other")] = row["by_event_type"].get(e.get("event_type", "other"), 0) + 1
        row["sources"].add(e["src_ip"])
        row["sessions"].add(session_key(e))
        if e.get("username") and e["eventid"].startswith("cowrie.login."):
            row["usernames"].add(e["username"])
        if is_shell_command(e):
            row["commands"].add(e["input"])
        session = sessions.setdefault(session_key(e), {"events": 0, "duration_ms": None})
        session["events"] += 1
        if e["eventid"] == "cowrie.session.closed" and isinstance(e.get("duration_ms"), (int, float)):
            session["duration_ms"] = e["duration_ms"]
    seconds = lambda value: datetime.fromisoformat(value).timestamp()
    first = int(seconds(since) // bucket_seconds) if since else min(buckets, default=None)
    last = int((seconds(until) - 1) // bucket_seconds) if until else max(buckets, default=None)
    if first is None or last is None or last < first:
        indexes = []
    elif last - first + 1 > MAX_BUCKETS:
        raise ValueError(f"The range produces more than {MAX_BUCKETS:,} buckets; narrow it or use a larger bucket")
    else:
        indexes = range(first, last + 1)
    empty = {"events": 0, "by_event_type": {}, "sources": (), "usernames": (), "commands": (), "sessions": ()}
    series = [{"bucket_start": iso(b * bucket_seconds), "events": r["events"], "by_event_type": r["by_event_type"],
               "distinct_sources": len(r["sources"]), "distinct_usernames": len(r["usernames"]),
               "distinct_commands": len(r["commands"]), "sessions": len(r["sessions"])} for b in indexes for r in [buckets.get(b, empty)]]
    for previous, row in zip(series, series[1:]):
        row["change_from_previous"] = row["events"] - previous["events"]

    def summary(values):
        if not values:
            return None
        values = sorted(values)
        return {"count": len(values), "median": stats.median(values), "p90": values[min(len(values) - 1, int(0.9 * len(values)))]}
    timed = [s for s in sessions.values() if s["duration_ms"]]
    return {"bucket_seconds": bucket_seconds, "series": series,
            "sessions": {"total": len(sessions), "events_per_session": summary([s["events"] for s in sessions.values()]),
                         "duration_ms": summary([s["duration_ms"] for s in timed]),
                         "events_per_minute": summary([round(s["events"] / (s["duration_ms"] / 60000), 3) for s in timed]),
                         "note": "Duration and density use only sessions with a Cowrie session-close record."}}
