"""Canonical event layer: validate untrusted Cowrie records into a versioned schema. Never execute input.

Field names follow the Cowrie output reference for the pinned sensor (3.1.1):
https://github.com/cowrie/cowrie/blob/v3.1.1/docs/OUTPUT.rst
"""
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone

SCHEMA_VERSION = 2

EVENT_TYPES = {
    "cowrie.session.connect": "session_start",
    "cowrie.session.closed": "session_end",
    "cowrie.session.params": "session_params",
    "cowrie.client.version": "client_version",
    "cowrie.client.kex": "client_kex",
    "cowrie.client.fingerprint": "client_key",
    "cowrie.client.size": "client_info",
    "cowrie.client.var": "client_info",
    "cowrie.login.success": "auth_success",
    "cowrie.login.failed": "auth_failure",
    "cowrie.command.input": "command",
    "cowrie.command.success": "command_success",
    "cowrie.command.failed": "command_failed",
    "cowrie.session.input": "session_input",
    "cowrie.session.file_download": "file_download",
    "cowrie.session.file_download.failed": "file_download_failed",
    "cowrie.session.file_upload": "file_upload",
    "cowrie.direct-tcpip.request": "tunnel_request",
    "cowrie.direct-tcpip.data": "tunnel_data",
    "cowrie.log.open": "tty_log",
    "cowrie.log.closed": "tty_log",
}
COMMAND_EVENTS = ("cowrie.command.input", "cowrie.command.success", "cowrie.command.failed")
HEX = re.compile(r"^[0-9a-f]+$")


def event_type(eventid):
    return EVENT_TYPES.get(eventid, "other")


def _port(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 65535 else None


def _text(value, limit):
    return value if isinstance(value, str) and 0 < len(value) <= limit else None


def _duration_ms(raw):
    value = raw.get("duration_ms")
    scale = 1
    if value is None and "duration" in raw:  # pre-3.x sensors report seconds
        value, scale = raw["duration"], 1000
    try:
        number = float(value) * scale if isinstance(value, (int, float, str)) and not isinstance(value, bool) else None
    except ValueError:
        return None
    return round(number, 3) if number is not None and 0 <= number < 1e12 else None


def context_fields(raw, eventid):
    """Optional fields kept only when present and well formed. Invalid values are dropped from the
    canonical event; the original stays in raw evidence."""
    fields = {"protocol": _text(raw.get("protocol"), 16), "src_port": _port(raw.get("src_port")),
              "dst_port": _port(raw.get("dst_port")), "late": True if raw.get("late") is True else None}
    try:
        fields["dst_ip"] = str(ipaddress.ip_address(raw["dst_ip"])) if isinstance(raw.get("dst_ip"), str) else None
    except ValueError:
        fields["dst_ip"] = None
    if eventid in ("cowrie.session.closed", "cowrie.log.closed"):
        fields["duration_ms"] = _duration_ms(raw)
    if eventid == "cowrie.client.version":
        fields["client_version"] = _text(raw.get("version"), 256)
    if eventid == "cowrie.client.kex":
        hassh = _text(raw.get("hassh"), 32)
        fields["hassh"] = hassh if hassh and HEX.match(hassh) else None
    if eventid == "cowrie.session.file_upload":
        fields["filename"] = _text(raw.get("filename"), 1024)
        digest = _text(raw.get("shasum"), 64)
        fields["shasum"] = digest if digest and HEX.match(digest) else None
    if eventid == "cowrie.session.file_download":
        fields["filename"] = _text(raw.get("destfile"), 1024)
    if eventid == "cowrie.session.file_download.failed":
        fields["url"] = _text(raw.get("url"), 4096)
    return {k: v for k, v in fields.items() if v is not None}


def normalize(raw, source):
    if not isinstance(raw, dict):
        raise ValueError("Each record must be a JSON object")
    for key in ("timestamp", "eventid", "session", "sensor", "src_ip"):
        if not isinstance(raw.get(key), str) or not raw[key].strip() or len(raw[key]) > 200:
            raise ValueError(f"{key} must be a nonempty string of at most 200 characters")
    try:
        when = datetime.fromisoformat(raw["timestamp"].replace("Z", "+00:00"))
        if when.tzinfo is None:
            raise ValueError()
        when = when.astimezone(timezone.utc)
        ip = str(ipaddress.ip_address(raw["src_ip"]))
    except (ValueError, OverflowError):
        raise ValueError("timestamp must include a timezone and src_ip must be a valid IP") from None
    eventid = raw["eventid"]
    if not eventid.startswith("cowrie."):
        raise ValueError("Only Cowrie event IDs are supported")
    # Allowlist: do not retain passwords, raw login messages, keys, or unknown fields.
    data = {k: raw[k] for k in ("eventid", "session", "sensor")}
    data.update(timestamp=when.isoformat(timespec="microseconds"), src_ip=ip, source=source)
    for key in ("username", "input", "url", "shasum", "realm"):
        if key in raw:
            if not isinstance(raw[key], str) or len(raw[key]) > 4096:
                raise ValueError(f"{key} must be a string of at most 4096 characters")
            if key == "username" or (key in ("input", "realm") and eventid.startswith("cowrie.command.")) or (key in ("url", "shasum") and eventid == "cowrie.session.file_download"):
                data[key] = raw[key]
    if eventid in COMMAND_EVENTS and "input" not in data:
        raise ValueError("input is required for Cowrie command events")
    # Identity covers exactly the schema 1 fields above, so stored events keep their IDs across
    # schema versions. Fields added below never change an event's ID.
    data["id"] = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:20]
    data["event_type"] = event_type(eventid)
    data.update(context_fields(raw, eventid))
    return data
