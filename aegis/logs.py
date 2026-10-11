"""Structured JSON logging with request IDs. Log lines never include request bodies, query strings,
passwords, raw telemetry, or generated AI text; json.dumps escapes control characters, so attacker-supplied
values cannot forge extra log lines."""
import json
import logging
import re
import sys
import time
import uuid

REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
QUIET_PATHS = ("/api/v1/health/live", "/api/v1/health/ready", "/api/health")


class JsonFormatter(logging.Formatter):
    def format(self, record):
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
                 "level": record.levelname.lower(), "logger": record.name}
        request_id = getattr(record, "request_id", None)
        if request_id:
            entry["request_id"] = request_id
        message = record.getMessage()
        try:
            data = json.loads(message) if message.startswith("{") else None
        except ValueError:
            data = None
        if isinstance(data, dict):
            entry.update({k: v for k, v in data.items() if k not in entry})
        else:
            entry["message"] = message
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info).splitlines()[-1]  # type and message only, no frames
        return json.dumps(entry, ensure_ascii=True)


class RequestIdFilter(logging.Filter):
    def filter(self, record):
        try:
            from flask import g, has_request_context
            if has_request_context():
                record.request_id = getattr(g, "request_id", None)
        except ImportError:
            pass
        return True


def configure(level="INFO"):
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RequestIdFilter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    logging.getLogger("waitress.queue").setLevel("WARNING")


def request_id(header):
    return header if header and REQUEST_ID.match(header) else uuid.uuid4().hex


def install(app):
    """Assign a request ID, return it in X-Request-ID, and log one access line per request."""
    from flask import g, request

    @app.before_request
    def start():
        g.request_id = request_id(request.headers.get("X-Request-ID"))
        g.started = time.monotonic()

    @app.after_request
    def finish(response):
        response.headers["X-Request-ID"] = getattr(g, "request_id", "")
        if not request.path.startswith("/static/"):
            level = logging.DEBUG if request.path in QUIET_PATHS else logging.INFO
            app.logger.log(level, json.dumps({"event": "request", "method": request.method, "path": request.path, "status": response.status_code,
                                              "ms": round((time.monotonic() - getattr(g, "started", time.monotonic())) * 1000, 1),
                                              "user": getattr(g, "user", None)}))
        return response
