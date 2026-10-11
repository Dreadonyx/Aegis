import atexit
import csv
import hashlib
import io
import hmac
import ipaddress
import json
import os
import re
import secrets
import signal
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, Response, g, jsonify, redirect, render_template, request, session
from werkzeug.exceptions import HTTPException

from aegis.demo import demo_records, EXPECTED_NEGATIVE, EXPECTED_POSITIVE
from aegis import assistant, logs
from aegis.auth import RateLimiter, allowed, verify
from aegis.engine import validate_config
from aegis.analysis import Analyzer, load_config
from aegis.engine import RULESET_VERSION, detect, report
from aegis.statistics import describe
from aegis.evaluate import evaluate
from aegis.labels import LABEL_TYPES, redact, suggest
from aegis.suricata import normalize_eve
from aegis.rules import session_key
from aegis.ingestion import Collector, make_record, read_log_batch, validate_source  # noqa: F401  (read_log_batch: public helper)
from aegis.store import TRANSITIONS, Store, TransitionError

ROOT = Path(__file__).resolve().parent


CSV_LIMIT = 10000
# Control, bidirectional, and zero-width characters, plus tab and newlines, so a cell stays on one line.
UNSAFE_TEXT = re.compile("[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")
CSV_COLUMNS = ("event_time", "dataset", "dataset_label", "sensor", "session", "src_ip", "src_port", "event_type", "eventid",
               "username", "input", "url", "filename", "shasum", "client_version", "id")


def csv_cell(value):
    """Spreadsheet-safe text: visible escapes for unsafe characters and a leading quote before anything a
    spreadsheet could read as a formula (OWASP CSV injection guidance)."""
    text = UNSAFE_TEXT.sub(lambda m: f"\\u{ord(m.group()):04x}", "" if value is None else str(value))
    return "'" + text if text.startswith(("=", "+", "-", "@")) else text


DATASET_LABELS = {"demo": "synthetic replay; not observed attacks", "imported": "uploaded historical telemetry",
                  "live": "collected from the configured Cowrie sensor"}


def runtime_settings(environ=None):
    """Deployment settings from the environment. Production refuses to start without its secrets."""
    env = os.environ if environ is None else environ
    mode = env.get("AEGIS_ENV", "development")
    if mode not in ("development", "production"):
        raise ValueError("AEGIS_ENV must be development or production")
    production = mode == "production"
    auth = env.get("AEGIS_AUTH", "required" if production else "off")
    if auth not in ("required", "off"):
        raise ValueError("AEGIS_AUTH must be required or off")
    secret = env.get("AEGIS_SECRET_KEY", "")
    if production:
        if auth != "required":
            raise ValueError("Production requires AEGIS_AUTH=required")
        if len(secret) < 32:
            raise ValueError("Production requires AEGIS_SECRET_KEY with at least 32 characters (for example: python -c 'import secrets; print(secrets.token_hex(32))')")
    hosts = [h.strip() for h in env.get("AEGIS_TRUSTED_HOSTS", "").split(",") if h.strip()]
    return {"production": production, "auth_required": auth == "required", "secret_key": secret or secrets.token_hex(32),
            "trusted_hosts": ["localhost", "127.0.0.1", "[::1]"] + hosts, "cookie_secure": env.get("AEGIS_COOKIE_SECURE", "true" if production else "false") == "true",
            "metrics_token": env.get("AEGIS_METRICS_TOKEN") or None, "session_hours": float(env.get("AEGIS_SESSION_HOURS", "8"))}


PUBLIC_PATHS = {"/login", "/api/v1/health/live", "/api/v1/health/ready", "/api/v1/auth/login", "/api/v1/auth/me"}
ADMIN_ENDPOINTS = {"update_detection_settings"}
# (requests, seconds) per client for expensive endpoints.
LIMITS = {"download_report": (30, 60), "evidence_export": (30, 60), "export_events": (10, 60), "import_events": (10, 60),
          "import_eve_or_cowrie": (10, 60), "replay": (10, 60), "statistics_series": (60, 60), "ai_report": (6, 60)}


def create_app(database=None, detection_config=None, model_dir=None, settings=None):
    settings = settings or runtime_settings()
    app = Flask(__name__)
    app.config.update(SECRET_KEY=settings["secret_key"], MAX_CONTENT_LENGTH=2 * 1024 * 1024,
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict", SESSION_COOKIE_NAME="aegis_session",
                      SESSION_COOKIE_SECURE=settings["cookie_secure"], PERMANENT_SESSION_LIFETIME=int(settings["session_hours"] * 3600),
                      TRUSTED_HOSTS=settings["trusted_hosts"], AUTH_REQUIRED=settings["auth_required"], PRODUCTION=settings["production"])
    store = Store(database or os.environ.get("AEGIS_DB", ROOT / "data/aegis.sqlite3"))
    app.extensions["store"] = store
    saved = store.setting("detection")
    config = validate_config(saved) if saved else (detection_config if detection_config is not None else load_config())
    analyzer = Analyzer(store, config, model_dir)
    app.extensions["analyzer"] = analyzer
    analyzer.refresh()  # recompute stored detections when rules or settings changed
    ai_lock = threading.Lock()
    limiter = RateLimiter()
    app.extensions["limiter"] = limiter
    logs.install(app)  # request IDs first, so every later log line carries one

    def client_key():
        return session.get("user") or request.remote_addr or "unknown"

    @app.before_request
    def authenticate():
        """Who is calling, and may they? Runs before CSRF checks; health probes and the login page are public."""
        g.user, g.role = ("local-analyst", "admin") if not settings["auth_required"] else (None, None)
        if not settings["auth_required"]:
            return None
        if request.path.startswith("/static/") or request.path in PUBLIC_PATHS:
            username = session.get("user")
            if username:
                g.user, g.role = username, session.get("role")
            return None
        username = session.get("user")
        account = store.user(username) if username else None
        if account and not account["disabled"]:
            g.user, g.role = account["username"], account["role"]  # role changes apply on the next request
            session["role"] = account["role"]
        elif username:
            session.clear()
        token = settings["metrics_token"]
        if not g.user and token and request.path == "/api/v1/metrics" and hmac.compare_digest(request.headers.get("Authorization", ""), f"Bearer {token}"):
            g.user, g.role = "metrics-scraper", "viewer"
        if not g.user:
            if request.path.startswith("/api/"):
                return jsonify(error="Sign in to use Aegis."), 401
            return redirect("/login")
        needed = "admin" if request.endpoint in ADMIN_ENDPOINTS else ("viewer" if request.method in ("GET", "HEAD", "OPTIONS") else "analyst")
        if not allowed(g.role, needed):
            return jsonify(error=f"This action needs the {needed} role."), 403
        return None

    @app.before_request
    def limit():
        rule = LIMITS.get(request.endpoint)
        if rule:
            wait = limiter.hit(f"{request.endpoint}:{client_key()}", *rule)
            if wait:
                response = jsonify(error="Too many requests. Wait a moment and try again.")
                response.headers["Retry-After"] = str(wait)
                return response, 429
        return None

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

    @app.errorhandler(TransitionError)
    def conflict(error):
        return jsonify(error=str(error)), 409

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

    def collectors():
        found = list(app.extensions.get("collectors", []))
        legacy = app.extensions.get("collector")
        return found + ([legacy] if legacy and legacy not in found else [])

    def collector_status():
        running = collectors()
        if not running:
            return "Not configured"
        return " · ".join(f"{c.source_id}: {c.status['state'].replace('_', ' ')} ({c.status['detail']})" if len(running) > 1
                          else f"{c.status['state'].replace('_', ' ').capitalize()}: {c.status['detail']}" for c in running)

    def incident_by_id(incident_id):
        dataset = source_arg()
        analyzer.ensure_current(dataset)
        incident = store.incident(dataset, incident_id)
        if incident:
            incident["signals"] = store.signals_for(incident)
        return incident

    def paging(default=50, maximum=500):
        try:
            page = int(request.args.get("page", "1"))
            limit = int(request.args.get("limit", str(default)))
            if page < 1 or not 1 <= limit <= maximum:
                raise ValueError()
        except ValueError:
            raise ValueError(f"page must be positive and limit must be between 1 and {maximum}") from None
        return page, limit, (page - 1) * limit

    def text_args(*names, limit=200):
        values = {}
        for name in names:
            value = request.args.get(name, "")
            if len(value) > limit:
                raise ValueError(f"{name} must be at most {limit} characters")
            if value:
                values[name] = value
        return values

    def time_arg(name):
        value = request.args.get(name)
        if not value:
            return None
        try:
            when = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if when.tzinfo is None:
                raise ValueError()
        except ValueError:
            raise ValueError(f"{name} must be an ISO 8601 time with a timezone") from None
        return when.astimezone(timezone.utc).isoformat(timespec="microseconds")

    def page_result(key, total, items, page, limit):
        return jsonify({key: items, "total": total, "page": page, "limit": limit, "pages": max(1, (total + limit - 1) // limit)})

    def summary(incident):
        return {k: v for k, v in incident.items() if k not in ("event_refs", "session_keys", "events")}

    @app.get("/")
    def index():
        session.setdefault("csrf", secrets.token_hex(32))
        return render_template("index.html", csrf=session["csrf"])

    @app.get("/login")
    def login_page():
        if not settings["auth_required"] or session.get("user"):
            return redirect("/")
        session.setdefault("csrf", secrets.token_hex(32))
        return render_template("login.html", csrf=session["csrf"])

    @app.post("/api/v1/auth/login")
    def login():
        body = request.get_json(silent=True)
        if not settings["auth_required"]:
            return jsonify(error="Authentication is turned off (AEGIS_AUTH=off)."), 400
        if not isinstance(body, dict) or not isinstance(body.get("username"), str) or not isinstance(body.get("password"), str):
            raise ValueError("username and password are required")
        username = body["username"].strip().lower()[:64]
        for key, rule in ((f"login-ip:{request.remote_addr}", (20, 300)), (f"login-user:{username}", (5, 300))):
            wait = limiter.hit(key, *rule)
            if wait:
                response = jsonify(error="Too many sign-in attempts. Wait and try again.")
                response.headers["Retry-After"] = str(wait)
                return response, 429
        account = store.user(username)
        if not verify(account["password_hash"] if account else None, body["password"]) or account["disabled"]:
            app.logger.warning(json.dumps({"event": "login_failed", "username": username, "remote": request.remote_addr}))
            return jsonify(error="Invalid username or password."), 401
        limiter.reset(f"login-user:{username}")
        session.clear()  # new session on sign-in: no fixation
        session.permanent = True
        session.update(user=account["username"], role=account["role"], csrf=secrets.token_hex(32))
        store.update_user(account["username"], last_login_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        app.logger.info(json.dumps({"event": "login", "username": account["username"], "role": account["role"]}))
        return jsonify(user=account["username"], role=account["role"], csrf=session["csrf"])

    @app.post("/api/v1/auth/logout")
    def logout():
        session.clear()
        return jsonify(status="signed out")

    @app.get("/api/v1/auth/me")
    def whoami():
        return jsonify(user=g.user, role=g.role, auth="required" if settings["auth_required"] else "off")

    @app.get("/api/health")
    def health():
        return jsonify(status="ok", mode="local lab", storage=store.usage())

    @app.get("/api/overview")
    def overview():
        source = source_arg()
        analyzer.ensure_current(source)
        stats = store.overview(source)
        _, found = store.incidents(source)
        return jsonify(events=stats["events"], incidents=[summary(i) for i in found], sources=stats["sources"], sensors=stats["sensors"],
            open_incidents=sum(i["status"] in ("open", "investigating") for i in found), timeline=stats["timeline"],
            rules=analyzer.catalog, ai_enabled=bool(os.environ.get("AEGIS_OLLAMA_MODEL")), ruleset_version=RULESET_VERSION,
            dataset_label=DATASET_LABELS[source], detection=store.detection_state(source), storage=store.usage(),
            statistics=statistics_summary(source), ml=ml_summary(source),
            finding_counts=store.finding_counts(source),
            collector=collector_status())

    @app.get("/api/events")
    def event_list():
        source = source_arg()
        query = request.args.get("q", "")
        if len(query) > 200:
            raise ValueError("Search text must be at most 200 characters")
        filters = text_args("event_type", "eventid", "session", "sensor", "src_ip")
        filters.update(since=time_arg("since"), until=time_arg("until"))
        page, limit, offset = paging()
        total, events = store.query_events(source, query, filters, limit, offset)
        return page_result("events", total, events, page, limit)

    def statistics_summary(dataset):
        state = store.stats_state(dataset) or {}
        baselines = state.get("baselines", [])
        return dict(enabled=analyzer.config["statistical_enabled"], as_of=state.get("as_of"), computed_at=state.get("computed_at"),
                    dirty=state.get("dirty"), last_error=state.get("last_error"), baselines=baselines,
                    cold_start=any(b["state"] == "insufficient_baseline" for b in baselines) or not baselines,
                    signals=store.findings(dataset, {"engine": "statistical", "status": "active"}, 1, 0)[0])

    def ml_summary(dataset):
        state = store.signal_state(dataset, "ml") or {}
        return dict(enabled=analyzer.config["ml_enabled"], status=state.get("status", "not_run"), detail=state.get("detail"),
                    model=state.get("model"), scored_sessions=state.get("scored_sessions", 0), computed_at=state.get("computed_at"),
                    dirty=state.get("dirty"), last_error=state.get("last_error"),
                    signals=store.findings(dataset, {"engine": "ml", "status": "active"}, 1, 0)[0])

    @app.get("/api/v1/ml")
    def ml_status():
        source = source_arg()
        analyzer.ensure_current(source)
        return jsonify(dataset=source, **ml_summary(source),
                       note="Isolation Forest scores show unusualness relative to the training sessions. They are not probabilities.")

    @app.get("/api/v1/statistics")
    def statistics_status():
        source = source_arg()
        analyzer.ensure_current(source)
        return jsonify(dataset=source, **statistics_summary(source), finding_counts=store.finding_counts(source),
                       note="Baselines use only this dataset's earlier data. Unusual is not malicious.")

    @app.get("/api/v1/statistics/series")
    def statistics_series():
        source = source_arg()
        try:
            bucket = int(request.args.get("bucket", "3600"))
            if not 60 <= bucket <= 86400:
                raise ValueError()
        except ValueError:
            raise ValueError("bucket must be from 60 to 86400 seconds") from None
        since, until = time_arg("since"), time_arg("until")
        result = describe(store.events_between(source, since, until), bucket, since, until)
        return jsonify(dataset=source, since=since, until=until, **result)

    @app.get("/api/v1/incidents")
    def incident_list():
        source = source_arg()
        filters = text_args("status", "severity")
        if filters.get("status") and filters["status"] not in TRANSITIONS:
            raise ValueError(f"status must be one of: {', '.join(TRANSITIONS)}")
        page, limit, offset = paging(25, 200)
        analyzer.ensure_current(source)
        total, found = store.incidents(source, filters.get("status"), filters.get("severity"), limit, offset)
        return page_result("incidents", total, [summary(i) for i in found], page, limit)

    @app.get("/api/v1/findings")
    def finding_list():
        source = source_arg()
        filters = text_args("engine", "rule_id", "severity", "status", "incident_id")
        filters.setdefault("status", "active")
        page, limit, offset = paging(50, 200)
        analyzer.ensure_current(source)
        total, found = store.findings(source, filters, limit, offset)
        return page_result("findings", total, found, page, limit)

    @app.get("/api/v1/sessions/<session_id>/timeline")
    def session_timeline(session_id):
        if len(session_id) > 200:
            raise ValueError("session must be at most 200 characters")
        source = source_arg()
        analyzer.ensure_current(source)
        result = store.session_timeline(source, session_id, text_args("sensor").get("sensor"))
        if not result["events"]:
            return jsonify(error="Session not found"), 404
        keys = {session_key(e) for e in result["events"]}
        label = history = hint = None
        if len(keys) == 1:
            label, history = store.label(source, keys.pop())
            hint = suggest(result["events"], result["findings"])
        return jsonify(session=session_id, dataset=source, **result, ambiguous=len({e["sensor"] for e in result["events"]}) > 1,
                       label=label, label_history=history or [], suggestion=hint)

    @app.put("/api/v1/sessions/<session_id>/label")
    def set_session_label(session_id):
        source = source_arg()
        if len(session_id) > 200:
            raise ValueError("session must be at most 200 characters")
        events = store.session_timeline(source, session_id, text_args("sensor").get("sensor"))["events"]
        if not events:
            return jsonify(error="Session not found"), 404
        if len({e["sensor"] for e in events}) > 1:
            raise ValueError("This session ID appears on several sensors; add ?sensor=")
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or body.get("label") not in ("malicious", "benign", None):
            raise ValueError("label must be malicious, benign, or null to clear it")
        types = body.get("types", [])
        if not isinstance(types, list) or not set(types) <= set(LABEL_TYPES):
            raise ValueError(f"types may contain only: {', '.join(LABEL_TYPES)}")
        note = body.get("note")
        if note is not None and (not isinstance(note, str) or len(note) > 500):
            raise ValueError("note must be text of at most 500 characters")
        first = events[0]
        store.set_label(source, session_key(first), first["session"], first["sensor"], body["label"], types if body["label"] else [],
                        note.strip() if note else None, g.user)
        label, history = store.label(source, session_key(first))
        return jsonify(label=label, label_history=history)

    @app.get("/api/v1/labels")
    def label_list():
        source = source_arg()
        page, limit, offset = paging(50, 200)
        counts, rows = store.labels(source, limit, offset)
        return jsonify(dataset=source, counts=counts, labels=rows, page=page, limit=limit,
                       note="Labels are analyst judgments of alert-worthiness. Export them with python -m aegis.labels export.")

    @app.get("/api/v1/events/<event_id>/provenance")
    def event_provenance(event_id):
        source = source_arg()
        if not re.fullmatch(r"[0-9a-f]{20}", event_id):
            raise ValueError("Event IDs are 20 hexadecimal characters")
        total, events = store.query_events(source, filters={"id": event_id}, limit=1)
        if not total:
            return jsonify(error="Event not found"), 404
        raw = store.raw_records([event_id]).get(event_id)
        return jsonify(event=events[0], dataset_label=DATASET_LABELS[source], provenance=store.provenance([event_id]).get(event_id, []),
                       original=redact(raw) if raw is not None else None,
                       note="Original record as received, with attempted passwords and login messages masked. "
                            "Events stored before schema 2 have no original record.")

    @app.get("/api/v1/events/export.csv")
    def export_events():
        source = source_arg()
        query = request.args.get("q", "")
        if len(query) > 200:
            raise ValueError("Search text must be at most 200 characters")
        filters = text_args("event_type", "eventid", "session", "sensor", "src_ip")
        filters.update(since=time_arg("since"), until=time_arg("until"))
        total, events = store.query_events(source, query, filters, CSV_LIMIT + 1, 0)
        if total > CSV_LIMIT:
            raise ValueError(f"{total:,} events match; narrow the filters to at most {CSV_LIMIT:,} per export")
        out = io.StringIO()
        writer = csv.writer(out, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
        writer.writerow(CSV_COLUMNS)
        for e in reversed(events):
            row = {**e, "event_time": e["timestamp"], "dataset": source, "dataset_label": DATASET_LABELS[source]}
            writer.writerow([csv_cell(row.get(c)) for c in CSV_COLUMNS])
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return Response(out.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="aegis-{source}-events-{stamp}.csv"'})

    @app.get("/api/v1/detection")
    def detection_settings():
        return jsonify(config=analyzer.config, fingerprint=analyzer.fingerprint, ruleset_version=RULESET_VERSION,
                       catalog=analyzer.catalog, state={d: store.detection_state(d) for d in ("demo", "imported", "live")},
                       history=store.settings_history("detection"), source="database" if store.setting("detection") else "file or defaults")

    @app.put("/api/v1/detection")
    def update_detection_settings():
        """Admin only. Validated, persisted with history, and applied by recomputing stored detections."""
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            raise ValueError("Send the detection settings as a JSON object")
        config = validate_config(body)
        store.set_setting("detection", config, g.user)
        analyzer.reconfigure(config)
        app.logger.info(json.dumps({"event": "detection_settings_changed", "actor": g.user, "fingerprint": analyzer.fingerprint}))
        return jsonify(config=analyzer.config, fingerprint=analyzer.fingerprint, history=store.settings_history("detection"))

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
        running = collectors()
        if running:
            checks["collector"] = running[0].status["state"]
            checks["collectors"] = {c.source_id: c.status["state"] for c in running}
            if not all(c.healthy() for c in running):
                return jsonify(status="not_ready", checks=checks), 503
        return jsonify(status="ready", checks=checks)

    def source_health(source):
        collector = next((c for c in collectors() if c.source_id == source["source_id"]), None)
        runtime = None
        if collector:
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
        for collector in collectors():
            c, who = collector.counters, {"source_id": collector.source_id}
            metric("aegis_collector_up", "gauge", "1 when the collector is healthy.", [(who, int(collector.healthy()))])
            metric("aegis_collector_lines_read_total", "counter", "Lines read since process start.", [(who, c["lines_read"])])
            metric("aegis_collector_records_committed_total", "counter", "Records committed since process start.", [(who, c["records_committed"])])
            metric("aegis_collector_lines_quarantined_total", "counter", "Lines quarantined since process start.", [(who, c["lines_quarantined"])])
            metric("aegis_collector_lines_skipped_total", "counter", "Lines the parser does not apply to (for example non-alert EVE records).", [(who, c["lines_skipped"])])
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
        analyzer.after_commit(records)
        sessions = {e["id"]: e["session"] for e in events}
        predicted = {sessions[i] for incident in detect(events) for f in incident["findings"] for i in f["evidence_ids"]}
        tp = len(predicted & EXPECTED_POSITIVE)
        fp = len(predicted & EXPECTED_NEGATIVE)
        fn = len(EXPECTED_POSITIVE - predicted)
        tn = len(EXPECTED_NEGATIVE - predicted)
        return jsonify(inserted=added, duplicates=len(events)-added,
            evaluation=dict(true_positives=tp, false_positives=fp, false_negatives=fn, true_negatives=tn,
                scope="Five synthetic sessions only; not an estimate of real-world performance."))

    @app.post("/api/v1/imports")
    def import_eve_or_cowrie():
        """Atomic upload of Cowrie JSONL (format=cowrie) or Suricata EVE JSON (format=suricata-eve). EVE lines that
        are not alerts are skipped and counted."""
        fmt = request.args.get("format", "cowrie")
        if fmt == "cowrie":
            return import_events()
        if fmt != "suricata-eve":
            raise ValueError("format must be cowrie or suricata-eve")
        uploaded = request.files.get("file")
        if not uploaded:
            raise ValueError("Choose a Suricata EVE JSON file")
        content = uploaded.read()
        try:
            lines = content.decode("utf-8-sig").splitlines()
        except UnicodeDecodeError:
            raise ValueError("The file must be UTF-8 JSON lines") from None
        if len(lines) > 5000:
            raise ValueError("Import up to 5,000 lines at a time")
        sensor = (request.args.get("sensor") or "suricata")[:200]
        records, skipped = [], 0
        for n, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                record = make_record(line.encode(), "imported", f"line:{n}", lambda raw, src: normalize_eve(raw, src, sensor))
            except (ValueError, RecursionError) as error:
                raise ValueError(f"Line {n}: invalid EVE record. {str(error)[:200]}") from None
            if record is None:
                skipped += 1
            else:
                records.append(record)
        if not records:
            raise ValueError(f"The file contains no Suricata alerts ({skipped} other EVE records skipped)")
        result = store.commit(records, dict(mode="import", source_id="upload-suricata", source_type="suricata",
                                            file_id="upload:" + hashlib.sha256(content).hexdigest()[:16]))
        analyzer.after_commit(records)
        return jsonify(inserted=result["inserted"], duplicates=result["duplicates"], skipped_non_alert=skipped)

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
        analyzer.after_commit(records)
        return jsonify(inserted=result["inserted"], duplicates=result["duplicates"])

    @app.get("/api/incidents/<incident_id>")
    def detail(incident_id):
        incident = incident_by_id(incident_id)
        return jsonify(incident) if incident else (jsonify(error="Incident not found"), 404)

    @app.patch("/api/incidents/<incident_id>")
    def update(incident_id):
        incident = incident_by_id(incident_id)
        if not incident:
            return jsonify(error="Incident not found"), 404
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or body.get("status") not in TRANSITIONS:
            raise ValueError("Choose open, investigating, resolved, or false_positive")
        store.set_status(incident["id"], body["status"], g.user)
        return jsonify(status=body["status"], incident_id=incident["id"])

    @app.post("/api/incidents/<incident_id>/notes")
    def add_note(incident_id):
        incident = incident_by_id(incident_id)
        if not incident:
            return jsonify(error="Incident not found"), 404
        body = request.get_json(silent=True)
        text = body.get("text") if isinstance(body, dict) else None
        if not isinstance(text, str) or not text.strip() or len(text) > 2000:
            raise ValueError("Write a note between 1 and 2,000 characters")
        store.add_note(incident["id"], text.strip(), g.user)
        return jsonify(activity=store.activity(incident["id"])), 201

    @app.get("/api/incidents/<incident_id>/evidence")
    def evidence_export(incident_id):
        incident = incident_by_id(incident_id)
        if not incident:
            return jsonify(error="Incident not found"), 404
        bundle = {"schema_version": 2, "generated_at": datetime.now(timezone.utc).isoformat(), "dataset": incident["source"],
                  "dataset_label": DATASET_LABELS[incident["source"]], "synthetic": incident["source"] == "demo",
                  "detection": {"ruleset_version": RULESET_VERSION, "fingerprint": analyzer.fingerprint, "config": analyzer.config},
                  "incident": incident, "provenance": store.provenance(e["id"] for e in incident["events"]),
                  "evidence_chain": {**store.chain_head(), "note": "Head at export time, not verified here. Verify with /api/v1/evidence/verify and keep a copy elsewhere."}}
        return Response(json.dumps(bundle, indent=2), mimetype="application/json",
                        headers={"Content-Disposition": f'attachment; filename="aegis-{incident_id}-evidence.json"'})

    @app.get("/api/incidents/<incident_id>/report")
    def download_report(incident_id):
        incident = incident_by_id(incident_id)
        if not incident:
            return jsonify(error="Incident not found"), 404
        return Response(report(incident, store.provenance(e["id"] for e in incident["events"]), incident.get("signals")), mimetype="text/plain", headers={"Content-Disposition": f'attachment; filename="aegis-{incident_id}.md"'})

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
        started = time.monotonic()
        prompt = assistant.build_prompt(incident)
        try:
            # Only findings (templates, rationale, evidence IDs) go to the model. No attacker-entered command text.
            payload = {"model": model, "stream": False, "options": {"temperature": 0, "num_predict": 700},
                       "system": assistant.SYSTEM, "prompt": json.dumps(prompt)}
            req = urllib.request.Request(endpoint.rstrip("/") + "/api/generate", json.dumps(payload).encode(), {"Content-Type": "application/json"})
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
            with opener.open(req, timeout=float(os.environ.get("AEGIS_OLLAMA_TIMEOUT", "45"))) as response:
                result = json.loads(response.read(100000))
            if not isinstance(result, dict) or not isinstance(result.get("response"), str) or not result["response"].strip():
                raise ValueError("Empty model response")
            check = assistant.validate(result["response"], prompt)
            app.logger.info(assistant.log_entry(model, incident["id"], prompt, "ok", time.monotonic() - started, check["verdict"]))
            return jsonify(text=result["response"], model=model, validation=check,
                           label="AI draft: an assistant's summary, not a detection. Verify every claim against the cited evidence.")
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as error:
            app.logger.warning(assistant.log_entry(model, incident["id"], prompt, type(error).__name__, time.monotonic() - started))
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


def follow_log(app, path, source_id=None, parser=None, source_type="cowrie"):
    """Start a live collector; its state is reported by /api/v1/health/ready and /api/v1/sources."""
    source_id = source_id or os.environ.get("AEGIS_SOURCE_ID", "cowrie-live")
    collector = Collector(app.extensions["store"], validate_source(path, source_id), source_id,
                          on_commit=app.extensions["analyzer"].after_live_commit, parser=parser, source_type=source_type)
    app.extensions.setdefault("collectors", []).append(collector.start())
    app.extensions.setdefault("collector", collector)
    atexit.register(collector.stop)
    return collector


def follow_eve(app, path):
    """Optional read-only Suricata EVE collector (AEGIS_SURICATA_EVE) into the live dataset."""
    sensor = os.environ.get("AEGIS_SURICATA_SENSOR", "suricata")
    return follow_log(app, path, "suricata-eve", lambda raw, source: normalize_eve(raw, source, sensor), "suricata")


def loopback(address):
    try:
        return address == "localhost" or ipaddress.ip_address(address.strip("[]")).is_loopback
    except ValueError:
        return False


def serve(app):
    """Production WSGI server (waitress). Set AEGIS_TRUSTED_PROXY to the reverse proxy's address so client
    addresses (rate limits, logs) and HTTPS come from X-Forwarded-* headers."""
    from waitress import serve as waitress_serve
    bind, port = os.environ.get("AEGIS_BIND", "127.0.0.1"), int(os.environ.get("AEGIS_PORT", "8000"))
    if not app.config["AUTH_REQUIRED"] and not loopback(bind) and os.environ.get("AEGIS_ALLOW_UNAUTHENTICATED_BIND") != "true":
        sys.exit(f"Refusing to listen on {bind} without sign-in. Set AEGIS_AUTH=required, bind to 127.0.0.1, or (only when the port "
                 "is published on host loopback, as in compose.yaml) set AEGIS_ALLOW_UNAUTHENTICATED_BIND=true.")
    options = {"host": bind, "port": port, "threads": int(os.environ.get("AEGIS_THREADS", "8")), "ident": "aegis"}
    proxy = os.environ.get("AEGIS_TRUSTED_PROXY")
    if proxy:
        options.update(trusted_proxy=proxy, trusted_proxy_count=1, trusted_proxy_headers={"x-forwarded-for", "x-forwarded-proto"},
                       clear_untrusted_proxy_headers=True)
    app.logger.info(json.dumps({"event": "start", "bind": bind, "port": port, "auth": "required" if app.config["AUTH_REQUIRED"] else "off",
                                "production": app.config["PRODUCTION"], "schema_version": app.extensions["store"].schema_version()}))
    waitress_serve(app, **options)


if __name__ == "__main__":
    # docker stop sends SIGTERM; exiting through SystemExit runs atexit, so the collector
    # finishes its current batch instead of being killed mid-poll.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    logs.configure(os.environ.get("AEGIS_LOG_LEVEL", "INFO"))
    try:
        app = create_app()
    except ValueError as error:
        sys.exit(f"Aegis configuration error: {error}")
    try:
        if os.environ.get("AEGIS_COWRIE_LOG"):
            follow_log(app, os.environ["AEGIS_COWRIE_LOG"])
        if os.environ.get("AEGIS_SURICATA_EVE"):
            follow_eve(app, os.environ["AEGIS_SURICATA_EVE"])
    except ValueError as error:
        sys.exit(f"Aegis configuration error: {error}")
    serve(app)
