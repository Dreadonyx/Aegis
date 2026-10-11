"""Evidence fusion: group findings into incidents without erasing or double-counting evidence.

Findings join one incident when they touch a common Cowrie session (through their anchor or evidence).
Every finding is kept with its own rationale. The incident ID is the session key of its earliest
finding's anchor event, which stays stable as later activity arrives and matches v0.2 incident IDs."""
from aegis.rules import RULESET_VERSION, SEQUENCE_IDS, RULE_IDS, order, session_key

RANK = {"low": 1, "medium": 2, "high": 3}
CATALOG_ORDER = {rule_id: n for n, rule_id in enumerate(RULE_IDS + SEQUENCE_IDS)}


def fuse(findings, events, config):
    by_id = {e["id"]: e for e in events}
    keys = {e["id"]: session_key(e) for e in events}
    parent = {}

    def find(key):
        parent.setdefault(key, key)
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    touched = {}
    for f in findings:
        sessions = {f["session_key"]} | {keys[i] for i in f["evidence_event_ids"]}
        touched[f["finding_id"]] = sessions
        first = find(f["session_key"])
        for key in sessions:
            parent[find(key)] = first
    components = {}
    for f in findings:
        components.setdefault(find(f["session_key"]), []).append(f)

    by_session = {}
    for e in events:
        by_session.setdefault(keys[e["id"]], []).append(e)
    weak_scope = "source address and sensor" if config["auth_group_by"] == "sensor_and_source" else "source address"
    incidents = []
    for group in components.values():
        group.sort(key=lambda f: (f["observed_at"], CATALOG_ORDER[f["rule_id"]], f["finding_id"]))
        anchor = group[0]
        anchor_sessions = {f["session_key"] for f in group}
        evidence = {i for f in group for i in f["evidence_event_ids"]}
        related = {by_id[i]["id"]: by_id[i] for i in evidence}
        for key in anchor_sessions:
            related.update((e["id"], e) for e in by_session.get(key, []))
        ordered = sorted(related.values(), key=order)
        refs = [{"id": e["id"], "relationship": "evidence" if e["id"] in evidence else "context",
                 "link": "anchor_session" if keys[e["id"]] == anchor["session_key"] else ("finding_session" if keys[e["id"]] in anchor_sessions else "source_address")}
                for e in ordered]
        session_keys = sorted({keys[e["id"]] for e in ordered})
        severity = max((f["severity"] for f in group), key=RANK.get)
        correlation = [{"type": "same_session", "strength": "strong",
                        "explanation": "Findings and context events share a Cowrie session."}]
        if len(session_keys) > 1:
            correlation.append({"type": "same_" + weak_scope.replace(" ", "_"), "strength": "weak", "sessions": len(session_keys),
                                "explanation": f"Sessions are joined because rule evidence shares a {weak_scope} within a rule window. "
                                               "A shared address does not establish a single actor (NAT, proxies, shared infrastructure)."})
        incidents.append({
            "id": anchor["session_key"], "source": anchor["dataset"], "session": anchor["session"], "sensor": anchor["sensor"], "src_ip": anchor["src_ip"],
            "sessions": sorted({e["session"] for e in ordered}), "sensors": sorted({e["sensor"] for e in ordered}), "session_keys": session_keys,
            "findings": group, "severity": severity, "title": next(f["title"] for f in group if f["severity"] == severity),
            "events": [{**related[r["id"]], "relationship": r["relationship"], "link": r["link"]} for r in refs], "event_refs": refs,
            "first_seen": ordered[0]["timestamp"], "last_seen": ordered[-1]["timestamp"], "correlation": correlation, "ruleset_version": RULESET_VERSION,
        })
    return sorted(incidents, key=lambda i: (RANK[i["severity"]], i["last_seen"], i["id"]), reverse=True)
