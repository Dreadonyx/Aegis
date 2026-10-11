"""Read-only Suricata EVE JSON adapter. Its schema mapping is kept separate from Cowrie parsing.

Only `event_type: alert` records become events; other EVE types (flow, dns, stats, ...) are skipped and
counted. Field names follow the EVE format reference: https://docs.suricata.io/en/latest/output/eve/eve-json-format.html

Aegis never blocks traffic. `alert.action` (and `verdict.action` when present) are recorded exactly as the
sensor reported them; the EVE reference notes that alert.action is not necessarily the final packet verdict."""
import hashlib
import ipaddress
import json
from datetime import datetime, timezone

from aegis.canonical import _port, _text

# EVE severity carries the rule priority, where 1 is the highest (Suricata rule docs). The EVE page itself does
# not define the field, so this mapping is documented as an assumption to check against the ruleset in use.
SEVERITY = {1: "high", 2: "medium"}


def eve_time(value):
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("timestamp must be an EVE timestamp string")
    try:
        when = datetime.fromisoformat(value)  # Python 3.11+ accepts EVE's colon-less offsets (+0100)
    except ValueError:
        raise ValueError("timestamp must be an ISO 8601 time with an offset") from None
    if when.tzinfo is None:
        raise ValueError("timestamp must include an offset")
    return when.astimezone(timezone.utc).isoformat(timespec="microseconds")


def normalize_eve(raw, source, default_sensor="suricata"):
    """A canonical event for an EVE alert, or None for other EVE event types. Raises ValueError when an alert
    record is malformed."""
    if not isinstance(raw, dict):
        raise ValueError("Each record must be a JSON object")
    if raw.get("event_type") != "alert":
        return None
    alert = raw.get("alert")
    if not isinstance(alert, dict):
        raise ValueError("alert records need an alert object")
    try:
        src = str(ipaddress.ip_address(raw["src_ip"]))
        dst = str(ipaddress.ip_address(raw["dest_ip"]))
    except (KeyError, TypeError, ValueError):
        raise ValueError("alert records need valid src_ip and dest_ip") from None
    sid = alert.get("signature_id")
    if not isinstance(sid, int) or isinstance(sid, bool) or sid < 0:
        raise ValueError("alert.signature_id must be a non-negative integer")
    sensor = _text(raw.get("host"), 200) or default_sensor
    flow = raw.get("flow_id")
    data = {"eventid": "suricata.alert", "timestamp": eve_time(raw.get("timestamp")), "src_ip": src, "source": source, "sensor": sensor,
            "session": f"flow-{flow}" if isinstance(flow, int) and not isinstance(flow, bool) else "flow-unknown",
            "dst_ip": dst, "signature_id": sid}
    for key, value in (("src_port", _port(raw.get("src_port"))), ("dst_port", _port(raw.get("dest_port"))),
                       ("protocol", _text(raw.get("proto"), 16)), ("signature", _text(alert.get("signature"), 512)),
                       ("category", _text(alert.get("category"), 200)), ("alert_action", _text(alert.get("action"), 32)),
                       ("verdict_action", _text((raw.get("verdict") or {}).get("action") if isinstance(raw.get("verdict"), dict) else None, 32)),
                       ("rev", alert.get("rev") if isinstance(alert.get("rev"), int) and not isinstance(alert.get("rev"), bool) else None),
                       ("sensor_severity", alert.get("severity") if isinstance(alert.get("severity"), int) and not isinstance(alert.get("severity"), bool) else None)):
        if value is not None:
            data[key] = value
    identity = {k: data[k] for k in ("eventid", "timestamp", "src_ip", "source", "sensor", "session", "dst_ip", "signature_id")}
    identity.update({k: data[k] for k in ("src_port", "dst_port") if k in data})
    data["id"] = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:20]
    data["event_type"] = "ids_alert"
    return data


def severity(event):
    return SEVERITY.get(event.get("sensor_severity"), "low")
