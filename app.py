import hmac
import ipaddress
import json
import os
import secrets
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, Response, jsonify, render_template, request, session
from werkzeug.exceptions import HTTPException

from aegis.demo import demo_records, EXPECTED_NEGATIVE, EXPECTED_POSITIVE
from aegis.engine import RULES, RULESET_VERSION, detect, normalize, report
from aegis.evaluate import evaluate
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
        if source not in ("demo", "imported"):
            raise ValueError("source must be demo or imported")
        return source

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
            collector=app.config.get("COLLECTOR_STATUS", "Not configured"))

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

    @app.post("/api/replay")
    def replay():
        events = [normalize(r, "demo") for r in demo_records()]
        added = store.ingest(events)
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
        try:
            lines = uploaded.read().decode("utf-8-sig").splitlines()
        except UnicodeDecodeError:
            raise ValueError("The file must be UTF-8 JSONL") from None
        if len(lines) > 5000:
            raise ValueError("Import up to 5,000 lines at a time")
        events = []
        for n, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                events.append(normalize(json.loads(line), "imported"))
            except (ValueError, RecursionError) as error:
                raise ValueError(f"Line {n}: invalid Cowrie record. {str(error)[:200]}") from None
        if not events:
            raise ValueError("The file contains no events")
        count = store.ingest(events)
        return jsonify(inserted=count, duplicates=len(events)-count)

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

    return app


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def read_log_batch(path, offset=0, discarding=False):
    batch, rejected = [], 0
    with open(path, "rb") as stream:
        stream.seek(offset)
        for _ in range(500):
            line = stream.readline(65537)
            if not line:
                break
            if discarding:
                offset = stream.tell()
                discarding = not line.endswith(b"\n")
                continue
            if len(line) > 65536:
                offset = stream.tell()
                discarding = not line.endswith(b"\n")
                rejected += 1
                continue
            if not line.endswith(b"\n"):
                break
            offset = stream.tell()
            try:
                batch.append(normalize(json.loads(line), "imported"))
            except (ValueError, RecursionError):
                rejected += 1
    return batch, offset, discarding, rejected


def follow_log(app, path):
    """Poll JSONL; event hashes make rereads safe across restarts and rotation."""
    def worker():
        identity, offset, discarding = None, 0, False
        while True:
            try:
                info = os.stat(path)
                current = (info.st_dev, info.st_ino)
                if current != identity or info.st_size < offset:
                    identity, offset, discarding = current, 0, False
                batch, next_offset, next_discarding, rejected = read_log_batch(path, offset, discarding)
                if batch:
                    app.extensions["store"].ingest(batch)
                offset, discarding = next_offset, next_discarding
                app.config["COLLECTOR_STATUS"] = f"Watching Cowrie log; last poll skipped {rejected} unsupported records"
            except (OSError, ValueError, sqlite3.Error):
                app.config["COLLECTOR_STATUS"] = "Waiting for a readable Cowrie log or available storage"
            time.sleep(2)
    threading.Thread(target=worker, daemon=True).start()


if __name__ == "__main__":
    app = create_app()
    if os.environ.get("AEGIS_COWRIE_LOG"):
        follow_log(app, os.environ["AEGIS_COWRIE_LOG"])
    app.run(host=os.environ.get("AEGIS_BIND", "127.0.0.1"), port=int(os.environ.get("AEGIS_PORT", "8000")), debug=False)
