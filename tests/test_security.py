import io

import pytest

from app import create_app, runtime_settings
from aegis import users
from aegis.auth import hash_password

PASSWORD = "correct horse battery"


def secure_app(tmp_path, **extra):
    settings = runtime_settings({"AEGIS_AUTH": "required", **extra})
    app = create_app(tmp_path / "aegis.sqlite3", settings=settings)
    app.config["TESTING"] = True
    store = app.extensions["store"]
    for name, role in (("vera", "viewer"), ("ana", "analyst"), ("adam", "admin")):
        store.add_user(name, hash_password(PASSWORD), role)
    return app


def signed_in(app, username, password=PASSWORD):
    client = app.test_client()
    client.get("/login")
    with client.session_transaction() as session:
        csrf = session["csrf"]
    response = client.post("/api/v1/auth/login", json={"username": username, "password": password}, headers={"X-Aegis-CSRF": csrf})
    if response.status_code == 200:
        client.environ_base["HTTP_X_AEGIS_CSRF"] = response.get_json()["csrf"]
    return client, response


# --- Configuration ----------------------------------------------------------------------------------

@pytest.mark.parametrize("env,message", [
    ({"AEGIS_ENV": "production"}, "AEGIS_SECRET_KEY"),
    ({"AEGIS_ENV": "production", "AEGIS_SECRET_KEY": "x" * 40, "AEGIS_AUTH": "off"}, "AEGIS_AUTH=required"),
    ({"AEGIS_ENV": "staging"}, "AEGIS_ENV"), ({"AEGIS_AUTH": "maybe"}, "AEGIS_AUTH"),
])
def test_production_configuration_fails_fast(env, message):
    with pytest.raises(ValueError, match=message):
        runtime_settings(env)


def test_production_defaults_are_secure():
    settings = runtime_settings({"AEGIS_ENV": "production", "AEGIS_SECRET_KEY": "s" * 64, "AEGIS_TRUSTED_HOSTS": "aegis.example.internal"})
    assert settings["auth_required"] and settings["cookie_secure"] and "aegis.example.internal" in settings["trusted_hosts"]
    assert not runtime_settings({})["auth_required"]  # local development keeps the single-user lab


# --- Authentication ---------------------------------------------------------------------------------

def test_everything_but_probes_and_login_requires_a_session(tmp_path):
    client = secure_app(tmp_path).test_client()
    assert client.get("/api/overview").status_code == 401
    assert client.get("/api/v1/events/export.csv").status_code == 401
    assert client.get("/").headers["Location"].endswith("/login")
    assert client.get("/api/v1/health/live").status_code == 200 and client.get("/api/v1/health/ready").status_code == 200
    assert client.get("/login").status_code == 200 and client.get("/static/login.js").status_code == 200
    assert client.get("/api/v1/auth/me").get_json() == {"user": None, "role": None, "auth": "required"}


def test_sign_in_is_generic_rate_limited_and_rotates_the_session(tmp_path):
    app = secure_app(tmp_path)
    _, wrong = signed_in(app, "ana", "wrong password!!")
    _, nobody = signed_in(app, "ghost", "whatever password")
    assert wrong.status_code == nobody.status_code == 401 and wrong.get_json() == nobody.get_json()
    client = app.test_client()
    client.get("/login")
    with client.session_transaction() as session:
        before = session["csrf"]
    attempt = lambda: client.post("/api/v1/auth/login", json={"username": "vera", "password": "nope nope nope"}, headers={"X-Aegis-CSRF": before})
    codes = [attempt().status_code for _ in range(6)]
    assert codes[:5] == [401] * 5 and codes[5] == 429  # five tries per account per five minutes
    ok, response = signed_in(app, "ana")
    assert response.status_code == 200 and response.get_json()["csrf"] != before
    assert ok.get("/api/overview").status_code == 200
    assert ok.post("/api/v1/auth/logout").status_code == 200 and ok.get("/api/overview").status_code == 401


def test_sign_in_lockout_survives_a_restart(tmp_path):
    app = secure_app(tmp_path)
    for _ in range(5):
        assert signed_in(app, "vera", "wrong password!!")[1].status_code == 401
    restarted = create_app(tmp_path / "aegis.sqlite3", settings=runtime_settings({"AEGIS_AUTH": "required"}))
    restarted.config["TESTING"] = True
    _, response = signed_in(restarted, "vera")  # even the right password waits out the lockout
    assert response.status_code == 429 and int(response.headers["Retry-After"]) > 0
    store = restarted.extensions["store"]
    assert store.limit_hit("probe", 1, 300, now=1000.0) == 0 and store.limit_hit("probe", 1, 300, now=1001.0) == 300
    assert store.limit_hit("probe", 1, 300, now=1400.0) == 0  # a new window starts after expiry


def test_sign_in_discards_the_pre_login_session(tmp_path):
    app = secure_app(tmp_path)
    client = app.test_client()
    client.get("/login")
    with client.session_transaction() as session:
        session["planted"] = "attacker-chosen"  # anything carried over would enable session fixation
        csrf = session["csrf"]
    assert client.post("/api/v1/auth/login", json={"username": "ana", "password": PASSWORD}, headers={"X-Aegis-CSRF": csrf}).status_code == 200
    with client.session_transaction() as session:
        assert "planted" not in session and session["user"] == "ana"


def test_disabled_or_changed_accounts_take_effect_immediately(tmp_path):
    app = secure_app(tmp_path)
    store = app.extensions["store"]
    client, _ = signed_in(app, "ana")
    store.update_user("ana", role="viewer")
    assert client.post("/api/replay").status_code == 403
    store.update_user("ana", disabled=1)
    assert client.get("/api/overview").status_code == 401
    assert signed_in(app, "ana")[1].status_code == 401


# --- Authorization and attribution ------------------------------------------------------------------

def test_roles_are_enforced_and_actions_attributed(tmp_path):
    app = secure_app(tmp_path)
    viewer, _ = signed_in(app, "vera")
    analyst, _ = signed_in(app, "ana")
    admin, _ = signed_in(app, "adam")
    assert analyst.post("/api/replay").status_code == 200
    incident = viewer.get("/api/overview").get_json()["incidents"][0]["id"]
    assert viewer.patch(f"/api/incidents/{incident}", json={"status": "investigating"}).status_code == 403
    assert viewer.put("/api/v1/sessions/demo-auth/label", json={"label": "malicious"}).status_code == 403
    assert analyst.patch(f"/api/incidents/{incident}", json={"status": "investigating"}).status_code == 200
    analyst.post(f"/api/incidents/{incident}/notes", json={"text": "Checked the session."})
    assert {a["actor"] for a in viewer.get(f"/api/incidents/{incident}").get_json()["activity"]} == {"ana"}
    analyst.put("/api/v1/sessions/demo-auth/label", json={"label": "malicious"})
    assert viewer.get("/api/v1/sessions/demo-auth/timeline").get_json()["label"]["actor"] == "ana"
    assert analyst.put("/api/v1/detection", json={"auth_failure_threshold": 6}).status_code == 403
    assert admin.put("/api/v1/detection", json={"auth_failure_threshold": 6}).status_code == 200


def test_detection_settings_are_validated_audited_and_persisted(tmp_path):
    app = secure_app(tmp_path)
    admin, _ = signed_in(app, "adam")
    before = admin.get("/api/v1/detection").get_json()
    assert admin.put("/api/v1/detection", json={"auth_failure_threshold": 1}).status_code == 400
    changed = admin.put("/api/v1/detection", json={"disabled_rules": ["DISC-001"]}).get_json()
    assert changed["fingerprint"] != before["fingerprint"] and changed["history"][0]["actor"] == "adam"
    assert not any(r["id"] == "DISC-001" for r in admin.get("/api/overview").get_json()["incidents"])
    restarted = create_app(tmp_path / "aegis.sqlite3", settings=runtime_settings({"AEGIS_AUTH": "required"}))
    assert restarted.extensions["analyzer"].config["disabled_rules"] == ["DISC-001"]  # survives restart


def test_metrics_token_and_rate_limits(tmp_path, monkeypatch):
    import app as module
    app = secure_app(tmp_path, AEGIS_METRICS_TOKEN="scrape-token-123")
    scraper = app.test_client()
    assert scraper.get("/api/v1/metrics").status_code == 401
    assert scraper.get("/api/v1/metrics", headers={"Authorization": "Bearer scrape-token-123"}).status_code == 200
    assert scraper.get("/api/overview", headers={"Authorization": "Bearer scrape-token-123"}).status_code == 401  # metrics only
    monkeypatch.setitem(module.LIMITS, "export_events", (2, 60))
    analyst, _ = signed_in(app, "ana")
    codes = [analyst.get("/api/v1/events/export.csv").status_code for _ in range(3)]
    assert codes == [200, 200, 429]


# --- Accounts CLI -----------------------------------------------------------------------------------

def test_users_cli(tmp_path, monkeypatch, capsys):
    db = str(tmp_path / "cli.sqlite3")
    monkeypatch.setattr("sys.stdin", io.StringIO(PASSWORD + "\n"))
    assert users.main(["--db", db, "add", "carol", "--role", "analyst", "--password-stdin"]) == 0
    monkeypatch.setattr("sys.stdin", io.StringIO("short\n"))
    assert users.main(["--db", db, "add", "dave", "--password-stdin"]) == 2 and "12 characters" in capsys.readouterr().err
    monkeypatch.setattr("sys.stdin", io.StringIO(PASSWORD + "\n"))
    assert users.main(["--db", db, "add", "carol", "--password-stdin"]) == 2
    assert users.main(["--db", db, "add", "Bad Name", "--password-stdin"]) == 2
    assert users.main(["--db", db, "set-role", "carol", "admin"]) == 0 and users.main(["--db", db, "disable", "carol"]) == 0
    capsys.readouterr()
    assert users.main(["--db", db, "list"]) == 0
    listing = capsys.readouterr().out
    assert "carol" in listing and "admin" in listing and "disabled" in listing and PASSWORD not in listing
    assert users.main(["--db", db, "set-role", "nobody", "admin"]) == 2
