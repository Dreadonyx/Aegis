"""Detection facade: canonical events -> rule and sequence findings -> fused incidents. Never execute input."""
import json

from aegis.canonical import normalize  # noqa: F401  (public API)
from aegis.fusion import fuse
from aegis.rules import (DEFAULT_CONFIG, RULESET_VERSION, catalog as rule_catalog, fingerprint, is_discovery,  # noqa: F401
                         rule_findings, session_key, validate_config)
from aegis.sequences import catalog as sequence_catalog, sequence_findings

DEFAULT = validate_config(DEFAULT_CONFIG)


def catalog(config=DEFAULT):
    return rule_catalog(config) + sequence_catalog(config)


RULES = catalog()


def detect(events, config=DEFAULT):
    events = list(events)
    return fuse(rule_findings(events, config) + sequence_findings(events, config), events, config)


DATASET_LABELS = {"demo": "demo (synthetic replay; these are not observed attacks)",
                  "imported": "imported (uploaded historical Cowrie telemetry)",
                  "live": "live (collected from the configured Cowrie sensor)"}
LINKS = {"anchor_session": "", "finding_session": " [other finding session]", "source_address": " [other session, address-linked]"}


def report(incident, provenance=None):
    lines = [f"# Aegis incident {incident['id']}", "", "Report source: deterministic detection rules (not AI)",
             f"Telemetry: {DATASET_LABELS.get(incident['source'], incident['source'])}",
             f"Severity: {incident['severity']} | Workflow: {incident['status']}",
             f"Source: {incident['src_ip']} | Sensor: {', '.join(incident.get('sensors') or [incident['sensor']])} | Sessions: {len(incident.get('sessions') or [incident['session']])}",
             "", "## Findings"]
    for finding in incident["findings"]:
        lines += [f"- {finding['id']} v{finding.get('rule_version', '1')} ({finding.get('engine', 'rule')}): {finding['name']}",
                  f"  {finding['description']}"]
        if finding.get("rationale"):
            lines.append(f"  Why: {finding['rationale']['explanation']}")
        lines.append(f"  Evidence: {', '.join(finding['evidence_ids'])}")
        if finding["technique"]:
            lines.append(f"  Candidate ATT&CK mapping: {finding['technique']}")
    if incident.get("correlation"):
        lines += ["", "## Correlation"]
        lines += [f"- {c['strength']}: {c['explanation']}" for c in incident["correlation"]]
    lines += ["", "## Evidence timeline"]
    for event in incident["events"]:
        detail = event.get("input", event.get("url", event.get("username", "")))
        lines.append(f"- [{event['id']}] {event['timestamp']} {event['eventid']} {json.dumps(detail)}{LINKS.get(event.get('link'), '')}")
    if provenance is not None:
        modes = sorted({f"{p['ingestion_mode']}:{p['source_id']} (parser {p['parser_version']})" for rows in provenance.values() for p in rows})
        missing = sum(1 for e in incident["events"] if not provenance.get(e["id"]))
        lines += ["", "## Provenance", f"Ingested from: {', '.join(modes) or 'no raw evidence records'}"]
        if missing:
            lines.append(f"{missing} event(s) predate raw evidence retention (schema 1) and have no raw record.")
    lines += ["", f"Ruleset: {incident.get('ruleset_version', RULESET_VERSION)}", "", "## Analyst activity"]
    for item in reversed(incident.get("activity", [])):
        lines.append(f"- {item['timestamp']} ({item['kind']}, {item.get('actor', 'local-analyst')}): {json.dumps(item['body'])}")
    lines += ["", "## Investigation", "Review the cited events and session context. Compare with authorized lab activity before escalating.", "", "## Limits",
              "Honeypot observations do not prove production compromise. Command input does not prove successful execution. A file download does not prove malware or C2. "
              "Address-linked sessions may belong to different clients behind shared addresses. Technique mappings are candidates for analyst review. "
              "Severity is rule priority, not a calibrated probability."]
    if incident["source"] == "demo":
        lines += ["", "This report describes synthetic replay data generated for demonstration. It contains no observed attacker activity."]
    return "\n".join(lines)
