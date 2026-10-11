import atexit
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import signal
import sqlite3
import sys
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, Response, jsonify, render_template, request, session
from werkzeug.exceptions import HTTPException

from aegis.demo import demo_records, EXPECTED_NEGATIVE, EXPECTED_POSITIVE
from aegis.engine import RULES, RULESET_VERSION, detect, report
from aegis.evaluate import evaluate
from aegis.ingestion import Collector, make_record, read_log_batch, validate_source  # noqa: F401  (read_log_batch: public helper)
from aegis.store import Store

ROOT = Path(__file__).resolve().parent


def create_app(database=None):
    app = Flask(__name__)
    app.config.update(SECRET_KEY=secrets.token_hex(32), MAX_CONTENT_LENGTH=2 * 1024 * 1024,
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
                      TRUSTED_HOSTS=["localhost", "127.0.0.1", "[::1]"])
    store = Store(database or os.environ.get("AEGIS_DB", ROOT / "data/aegis.sqlite3"))
    app.extensions["store"] = store
    ai_lock = threading.Lock()

    @app.before_request
    def protect():
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            expected = session.get("csrf", "")
            supplied = request.headers.get("X-Aegis-CSRF", "")
            if not expected or not hmac.compare_digest(expected, supplied):
                return jsonify(error="Refresh the dashboard before making changes."), 403
            if request.headers.get("Origin") and request.headers["Origin"] != request.host_url.rstrip("/"):
                return jsonify(error="Cross-origin requests are not allowed."), 403
            if request.headers.get("Sec-Fetch-Site") == "cross-site":
                return jsonify(error="Cross-site requests are not allowed."), 403

    @app.after_request
    def headers(response):
        response.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})
        return response

    @app.errorhandler(HTTPException)
    def http_error(error):
        return jsonify(error=error.description), error.code

    @app.errorhandler(ValueError)
    def invalid(error):
        return jsonify(error=str(error)), 400

    @app.errorhandler(sqlite3.Error)
    def storage_error(error):
        app.logger.error("Storage operation failed: %s", type(error).__name__)
        return jsonify(error="Storage is unavailable. Check database access and free disk space, then retry."), 503

    def source_arg():
        source = request.args.get("source", "demo")
        if source not in ("demo", "imported", "live"):
            raise ValueError("source must be demo, imported, or live")
        return source

    def collector_status():
        collector = app.extensions.get("collector")
        if not collector:
            return "Not configured"
        return f"{collector.status['state'].replace('_', ' ').capitalize()}: {collector.status['detail']}"

    def incidents(source, events=None):
        states = store.statuses()
        return [{**i, "status": states.get(i["id"], "open")} for i in detect(events if events is not None else store.events(source))]

    def incident_by_id(incident_id):
        incident = next((i for i in incidents(source_arg()) if i["id"] == incident_id), None)
        if incident:
            incident["activity"] = store.activity(incident_id)
        return incident

    @app.get("/")
    def index():
        session.setdefault("csrf", secrets.token_hex(32))
        return render_template("index.html", csrf=session["csrf"])

    @app.get("/api/health")
    def health():
        return jsonify(status="ok", mode="local lab", storage=store.usage())

    @app.get("/api/overview")
    def overview():
        source = source_arg()
        events = store.events(source)
        found = incidents(source, events)
        timeline = {}
        for e in sorted(events, key=lambda e: e["timestamp"]):
            minute = e["timestamp"][:16]
            timeline[minute] = timeline.get(minute, 0) + 1
        return jsonify(events=len(events), incidents=[{k: v for k, v in i.items() if k != "events"} for i in found],
            sources=len({e["src_ip"] for e in events}), sensors=len({e["sensor"] for e in events}),
            open_incidents=sum(i["status"] != "resolved" for i in found),
            timeline=[{"time": k, "count": v} for k, v in timeline.items()][-40:],
            rules=RULES, ai_enabled=bool(os.environ.get("AEGIS_OLLAMA_MODEL")),
            ruleset_version=RULESET_VERSION, storage=store.usage(),
            collector=collector_status())

    @app.get("/api/events")
    def event_list():
        events = sorted(store.events(source_arg()), key=lambda e: (e["timestamp"], e["id"]), reverse=True)
        query = request.args.get("q", "").casefold()
        if len(query) > 200:
            raise ValueError("Search text must be at most 200 characters")
        try:
            page = int(request.args.get("page", "1"))
            limit = int(request.args.get("limit", "50"))
            if page < 1 or not 1 <= limit <= 500:
                raise ValueError()
        except ValueError:
            raise ValueError("page must be positive and limit must be between 1 and 500") from None
        events = [e for e in events if query in json.dumps(e).casefold()]
        start = (page - 1) * limit
        return jsonify(total=len(events), events=events[start:start+limit], limit=limit, page=page,
                       pages=max(1, (len(events)+limit-1)//limit))

    @app.get("/api/evaluation")
    def evaluation():
        return jsonify(evaluate())

    @app.get("/api/v1/health/live")
    def live():
        return jsonify(status="alive")

    @app.get("/api/v1/health/ready")
    def ready():
        checks = {"database": "ok", "schema_version": store.schema_version()}
        store.usage()
        collector = app.extensions.get("collector")
        if collector:
            checks["collector"] = collector.status["state"]
            if not collector.healthy():
                return jsonify(status="not_ready", checks=checks), 503
        return jsonify(status="ready", checks=checks)

    def source_health(source):
        collector = app.extensions.get("collector")
        runtime = None
        if collector and collector.source_id == source["source_id"]:
            runtime = {k: collector.status[k] for k in ("state", "detail", "last_read_at", "last_error_at", "consecutive_failures", "worker_restarts")}
            runtime["bytes_behind"] = collector.bytes_behind()
        lag = None
        if source["last_event_time"]:
            lag = round((datetime.now(timezone.utc) - datetime.fromisoformat(source["last_event_time"])).total_seconds(), 3)
        return {**source, "seconds_since_last_event": lag, "collector": runtime}

    @app.get("/api/v1/sources")
    def source_list():
        return jsonify(sources=[source_health(s) for s in store.sources()])

    @app.get("/api/v1/sources/<source_id>/health")
    def source_detail(source_id):
        source = store.source(source_id)
        return jsonify(source_health(source)) if source else (jsonify(error="Source not found"), 404)

    @app.get("/api/v1/sources/<source_id>/errors")
    def source_errors(source_id):
        try:
            limit = int(request.args.get("limit", "50"))
            if not 1 <= limit <= 200:
                raise ValueError()
        except ValueError:
            raise ValueError("limit must be between 1 and 200") from None
        return jsonify(errors=store.errors(source_id, limit))

    @app.get("/api/v1/evidence/verify")
    def verify_evidence():
        return jsonify(store.verify_chain())

    @app.get("/api/v1/metrics")
    def metrics():
        """Prometheus text exposition, built from durable source totals and live collector state."""
        def label(value):
            return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

        def epoch(value):
            return datetime.fromisoformat(value).timestamp() if value else None

        lines = []

        def metric(name, kind, help_text, samples):
            lines.extend([f"# HELP {name} {help_text}", f"# TYPE {name} {kind}"])
            for labels, value in samples:
                if value is None:
                    continue
                rendered = ",".join(f'{k}="{label(v)}"' for k, v in labels.items())
                lines.append(f"{name}{{{rendered}}} {value}" if rendered else f"{name} {value}")

        sources = store.sources()
        per = lambda key, f=lambda v: v: [({"source_id": s["source_id"], "mode": s["ingestion_mode"]}, f(s[key])) for s in sources]
        metric("aegis_source_events_total", "counter", "New canonical events committed per source.", per("events_total"))
        metric("aegis_source_duplicates_total", "counter", "Records skipped as already stored.", per("duplicates_total"))
        metric("aegis_source_malformed_total", "counter", "Lines quarantined as malformed.", per("malformed_total"))
        metric("aegis_source_rotations_total", "counter", "Log rotations followed.", per("rotations_total"))
        metric("aegis_source_truncations_total", "counter", "Log truncations detected.", per("truncations_total"))
        metric("aegis_source_last_event_timestamp_seconds", "gauge", "Newest Cowrie event time per source.", per("last_event_time", epoch))
        metric("aegis_source_last_commit_timestamp_seconds", "gauge", "Last successful commit per source.", per("last_commit_at", epoch))
        usage = store.usage()
        metric("aegis_events_stored", "gauge", "Canonical events stored across datasets.", [({}, usage["events"])])
        metric("aegis_events_limit", "gauge", "Configured canonical event cap.", [({}, usage["limit"])])
        metric("aegis_raw_evidence_records", "gauge", "Hash-chained raw evidence records.", [({}, store.raw_count())])
        collector = app.extensions.get("collector")
        if collector:
            c, who = collector.counters, {"source_id": collector.source_id}
            metric("aegis_collector_up", "gauge", "1 when the collector is healthy.", [(who, int(collector.healthy()))])
            metric("aegis_collector_lines_read_total", "counter", "Lines read since process start.", [(who, c["lines_read"])])
            metric("aegis_collector_records_committed_total", "counter", "Records committed since process start.", [(who, c["records_committed"])])
            metric("aegis_collector_lines_quarantined_total", "counter", "Lines quarantined since process start.", [(who, c["lines_quarantined"])])
            metric("aegis_collector_batches_total", "counter", "Batches committed since process start.", [(who, c["batches_committed"])])
            metric("aegis_collector_last_batch_seconds", "gauge", "Read-to-commit time of the last batch.", [(who, c["last_batch_seconds"])])
            metric("aegis_collector_bytes_behind", "gauge", "Unread bytes in the current log file.", [(who, collector.bytes_behind())])
            metric("aegis_collector_consecutive_failures", "gauge", "Consecutive failed polls.", [(who, collector.status["consecutive_failures"])])
            metric("aegis_collector_worker_restarts_total", "counter", "Collector recoveries from unexpected errors.", [(who, collector.status["worker_restarts"])])
        return Response("\n".join(lines) + "\n", mimetype="text/plain; version=0.0.4")

    @app.post("/api/replay")
    def replay():
        records = [make_record(json.dumps(r).encode(), "demo", f"demo:{n}") for n, r in enumerate(demo_records(), 1)]
        events = [r["event"] for r in records]
        added = store.commit(records, dict(mode="synthetic", source_id="demo-replay", source_type="cowrie"))["inserted"]
        predicted = {i["session"] for i in detect(events)}
        tp = len(predicted & EXPECTED_POSITIVE)
        fp = len(predicted & EXPECTED_NEGATIVE)
        fn = len(EXPECTED_POSITIVE - predicted)
        tn = len(EXPECTED_NEGATIVE - predicted)
        return jsonify(inserted=added, duplicates=len(events)-added,
            evaluation=dict(true_positives=tp, false_positives=fp, false_negatives=fn, true_negatives=tn,
                scope="Five synthetic sessions only; not an estimate of real-world performance."))

    @app.post("/api/import")
    def import_events():
        uploaded = request.files.get("file")
        if not uploaded:
            raise ValueError("Choose a Cowrie JSONL file")
        content = uploaded.read()
        try:
            lines = content.decode("utf-8-sig").splitlines()
        except UnicodeDecodeError:
            raise ValueError("The file must be UTF-8 JSONL") from None
        if len(lines) > 5000:
            raise ValueError("Import up to 5,000 lines at a time")
        # Atomic by design: any invalid line rejects the whole upload so the analyst can fix the file.
        # The live collector instead quarantines bad lines and continues.
        records = []
        for n, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                records.append(make_record(line.encode(), "imported", f"line:{n}"))
            except (ValueError, RecursionError) as error:
                raise ValueError(f"Line {n}: invalid Cowrie record. {str(error)[:200]}") from None
        if not records:
            raise ValueError("The file contains no events")
        result = store.commit(records, dict(mode="import", source_id="upload", source_type="cowrie",
                                            file_id="upload:" + hashlib.sha256(content).hexdigest()[:16]))
        return jsonify(inserted=result["inserted"], duplicates=result["duplicates"])

    @app.get("/api/incidents/<incident_id>")
    def detail(incident_id):
        incident = incident_by_id(incident_id)
        return jsonify(incident) if incident else (jsonify(error="Incident not found"), 404)

    @app.patch("/api/incidents/<incident_id>")
    def update(incident_id):
        if not incident_by_id(incident_id):
            return jsonify(error="Incident not found"), 404
        body = request.get_json()
        if not isinstance(body, dict) or body.get("status") not in ("open", "investigating", "resolved"):
            raise ValueError("Choose open, investigating, or resolved")
        store.set_status(incident_id, body["status"])
        return jsonify(status=body["status"])

    @app.post("/api/incidents/<incident_id>/notes")
    def add_note(incident_id):
        if not incident_by_id(incident_id):
            return jsonify(error="Incident not found"), 404
        body = request.get_json()
        text = body.get("text") if isinstance(body, dict) else None
        if not isinstance(text, str) or not text.strip() or len(text) > 2000:
            raise ValueError("Write a note between 1 and 2,000 characters")
        store.add_note(incident_id, text.strip())
        return jsonify(activity=store.activity(incident_id)), 201

    @app.get("/api/incidents/<incident_id>/evidence")
    def evidence_export(incident_id):
        incident = incident_by_id(incident_id)
        if not incident:
            return jsonify(error="Incident not found"), 404
        return Response(json.dumps({"schema_version": 1, "incident": incident}, indent=2), mimetype="application/json",
                        headers={"Content-Disposition": f'attachment; filename="aegis-{incident_id}-evidence.json"'})

    @app.get("/api/incidents/<incident_id>/report")
    def download_report(incident_id):
        incident = incident_by_id(incident_id)
        if not incident:
            return jsonify(error="Incident not found"), 404
        return Response(report(incident), mimetype="text/plain", headers={"Content-Disposition": f'attachment; filename="aegis-{incident_id}.md"'})

    @app.post("/api/incidents/<incident_id>/ai")
    def ai_report(incident_id):
        incident = incident_by_id(incident_id)
        if not incident:
            return jsonify(error="Incident not found"), 404
        model = os.environ.get("AEGIS_OLLAMA_MODEL")
        if not model:
            return jsonify(error="Local AI is not configured. Rule-based reports remain available."), 503
        endpoint = os.environ.get("AEGIS_OLLAMA_URL", "http://127.0.0.1:11434")
        parsed = urlsplit(endpoint)
        try:
            local = parsed.hostname == "localhost" or ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            local = False
        if parsed.scheme != "http" or not local or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
            return jsonify(error="Ollama must use an HTTP loopback address."), 503
        if not ai_lock.acquire(blocking=False):
            return jsonify(error="An AI report is already generating. Try again shortly."), 429
        try:
            # Only deterministic findings and evidence IDs go to the model. No attacker-controlled commands.
            evidence = [{"rule": f["id"], "finding": f["name"], "meaning": f["description"], "evidence_ids": f["evidence_ids"][:20]} for f in incident["findings"]]
            payload = {"model": model, "stream": False, "options": {"temperature": 0, "num_predict": 700},
                "system": "You are a defensive SOC analyst. Summarize the supplied rule findings, cite their evidence IDs, state uncertainty, and suggest manual investigation. Do not invent facts or probabilities. Honeypot observations are not proof of real compromise. No offensive instructions.",
                "prompt": json.dumps({"synthetic_demo": incident["source"] == "demo", "findings": evidence})}
            req = urllib.request.Request(endpoint.rstrip("/") + "/api/generate", json.dumps(payload).encode(), {"Content-Type": "application/json"})
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
            with opener.open(req, timeout=float(os.environ.get("AEGIS_OLLAMA_TIMEOUT", "45"))) as response:
                result = json.loads(response.read(100000))
            if not isinstance(result, dict) or not isinstance(result.get("response"), str) or not result["response"].strip():
                raise ValueError("Empty model response")
            return jsonify(text=result["response"], model=model, label="AI draft — verify all claims against the evidence")
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            return jsonify(error="Local model request failed. Check Ollama and the configured model, then retry."), 502
        finally:
            ai_lock.release()

    # Versioned aliases keep existing /api routes working while clients move to /api/v1.
    for rule in list(app.url_map.iter_rules()):
        if rule.rule.startswith("/api/") and not rule.rule.startswith("/api/v1/"):
            app.add_url_rule("/api/v1/" + rule.rule[5:], endpoint=rule.endpoint,
                             view_func=app.view_functions[rule.endpoint], methods=rule.methods - {"HEAD", "OPTIONS"})
    return app


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def follow_log(app, path, source_id=None):
    """Start the live collector; its state is reported by /api/v1/health/ready and /api/v1/sources."""
    source_id = source_id or os.environ.get("AEGIS_SOURCE_ID", "cowrie-live")
    collector = Collector(app.extensions["store"], validate_source(path, source_id), source_id)
    app.extensions["collector"] = collector.start()
    atexit.register(collector.stop)
    return collector


if __name__ == "__main__":
    # docker stop sends SIGTERM; exiting through SystemExit runs atexit, so the collector
    # finishes its current batch instead of being killed mid-poll.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    app = create_app()
    if os.environ.get("AEGIS_COWRIE_LOG"):
        try:
            follow_log(app, os.environ["AEGIS_COWRIE_LOG"])
        except ValueError as error:
            sys.exit(f"Aegis configuration error: {error}")
    app.run(host=os.environ.get("AEGIS_BIND", "127.0.0.1"), port=int(os.environ.get("AEGIS_PORT", "8000")), debug=False)
