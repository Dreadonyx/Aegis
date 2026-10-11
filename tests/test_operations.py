import json
import logging
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from app import create_app
from aegis import logs

ROOT = Path(__file__).resolve().parent.parent


def client(tmp_path):
    app = create_app(tmp_path / "aegis.sqlite3")
    app.config["TESTING"] = True
    return app, app.test_client()


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_request_ids_are_echoed_or_replaced(tmp_path):
    _, c = client(tmp_path)
    assert c.get("/api/v1/health/live", headers={"X-Request-ID": "trace-12345678"}).headers["X-Request-ID"] == "trace-12345678"
    forged = c.get("/api/v1/health/live", headers={"X-Request-ID": 'x"} {"level": "critical'}).headers["X-Request-ID"]
    assert len(forged) == 32 and forged.isalnum()  # unsafe IDs are replaced, never echoed into logs


def test_access_log_lines_are_json_without_query_strings(tmp_path, caplog):
    app, c = client(tmp_path)
    with caplog.at_level(logging.DEBUG):
        c.get("/api/events?q=secret-search-text", headers={"X-Request-ID": "req-abcdefgh"})
        c.get("/api/v1/health/live")
    formatter = logs.JsonFormatter()
    lines = []
    for record in caplog.records:
        if '"event": "request"' in record.getMessage():
            record.request_id = "req-abcdefgh"
            lines.append(json.loads(formatter.format(record)))
    events = next(line for line in lines if line["path"] == "/api/events")
    assert events["status"] == 200 and events["request_id"] == "req-abcdefgh" and events["user"] == "local-analyst"
    assert "secret-search-text" not in json.dumps(lines)
    health = next(r for r in caplog.records if '"/api/v1/health/live"' in r.getMessage())
    assert health.levelno == logging.DEBUG  # probes do not flood INFO logs


def test_formatter_escapes_and_trims():
    formatter = logs.JsonFormatter()
    record = logging.LogRecord("aegis", logging.WARNING, __file__, 1, "attacker said \n{\"level\": \"critical\"}\x1b[31m", None, None)
    line = formatter.format(record)
    assert "\n" not in line and "\x1b" not in line and json.loads(line)["level"] == "warning"
    try:
        raise RuntimeError("boom")
    except RuntimeError:
        failure = logging.LogRecord("aegis", logging.ERROR, __file__, 1, "failed", None, sys.exc_info())
    assert json.loads(formatter.format(failure))["exception"] == "RuntimeError: boom"  # no stack frames or locals


def run_app(tmp_path, **env):
    full = dict(os.environ, AEGIS_DB=str(tmp_path / "db.sqlite3"), **env)
    full.pop("AEGIS_COWRIE_LOG", None)
    return subprocess.Popen([sys.executable, "app.py"], cwd=ROOT, env=full, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def test_startup_guards(tmp_path):
    exposed = run_app(tmp_path, AEGIS_BIND="0.0.0.0", AEGIS_PORT=str(free_port()))
    _, err = exposed.communicate(timeout=20)
    assert exposed.returncode == 1 and b"without sign-in" in err
    production = run_app(tmp_path, AEGIS_ENV="production")
    _, err = production.communicate(timeout=20)
    assert production.returncode == 1 and b"AEGIS_SECRET_KEY" in err


def test_production_server_emits_json_logs(tmp_path):
    port = free_port()
    server = run_app(tmp_path, AEGIS_PORT=str(port))
    try:
        deadline = time.monotonic() + 15
        while True:
            try:
                response = urllib.request.urlopen(f"http://127.0.0.1:{port}/api/overview", timeout=1)
                break
            except OSError:
                assert time.monotonic() < deadline, "server did not start"
                time.sleep(0.2)
        assert response.headers["Server"] == "aegis" and len(response.headers["X-Request-ID"]) == 32
    finally:
        server.send_signal(15)
        out, _ = server.communicate(timeout=10)
    entries = [json.loads(line) for line in out.decode().splitlines() if line.startswith("{")]
    assert any(e.get("event") == "start" and e["auth"] == "off" for e in entries)
    assert any(e.get("event") == "request" and e["path"] == "/api/overview" and e.get("request_id") for e in entries)
    assert server.returncode == 0
