# Detection reference (ruleset 2026.10.2)

Detection is layered: canonical events → deterministic rules (Layer A), sequences (Layer D), and statistics (Layer B) → evidence fusion into incidents. Optional ML (Layer C) is not implemented yet. Everything here is deterministic and covered by fixtures in `aegis/evaluate.py` (31 checks, also shown under **Lab & validation**). To measure detection against labeled data, see [EVALUATION.md](EVALUATION.md).

## Canonical events (schema 2)

`aegis/canonical.py` validates each Cowrie record against the [Cowrie 3.1.1 output reference](https://github.com/cowrie/cowrie/blob/v3.1.1/docs/OUTPUT.rst).

- **Required on every record:** `timestamp` (with timezone), `eventid` (`cowrie.*`), `session`, `sensor`, `src_ip`. Command events also require `input`.
- **Identity:** the event `id` is a SHA-256 over the schema 1 fields only (the required fields plus `username`, command `input`/`realm`, and download `url`/`shasum`). Fields added in schema 2 never change an ID, so upgraded databases do not duplicate events.
- **Optional fields** are kept only when present and well formed: `protocol`, `src_port`, `dst_ip`, `dst_port`, `late`, `duration_ms` (also accepts the pre-3.x `duration` in seconds), `client_version`, `hassh`, `filename` (upload `filename` or download `destfile`), upload `shasum`, and failed-download `url`. Malformed optional values are dropped from the canonical event; the original stays in raw evidence.
- **`event_type`** maps `eventid` to a vendor-neutral name (`auth_failure`, `auth_success`, `command`, `file_download`, `file_upload`, `session_start`, `session_end`, ...). Unknown event IDs become `other`.
- **Never kept:** passwords, public keys, raw messages, unknown fields. Missing data is never filled in.

## Rules (Layer A)

| ID | Version | Severity | Trigger | Grouping |
|---|---|---|---|---|
| AUTH-001 | 2 | medium | ≥ `auth_failure_threshold` failed logins within `auth_failure_window_seconds` | source address (+ sensor by default); overlapping windows merge into one finding per burst |
| AUTH-002 | 2 | high | accepted login with ≥ `login_failure_threshold` earlier failures within `login_lookback_seconds` | same as AUTH-001; one finding per login session |
| DISC-001 | 2 | low | shell input runs a command in `discovery_commands` (command position only; quoted text and stdin ignored) | one finding per session |
| XFER-001 | 2 | high | `cowrie.session.file_download` (completed; failed downloads never match) | one finding per session |
| XFER-002 | 2 | high | `cowrie.session.file_upload` (SCP/SFTP) | one finding per session |

Severity is rule priority with a stated rationale (shown on the rules page). It is not a probability.

## Sequences (Layer D)

| ID | Steps, in event-time order | Links |
|---|---|---|
| SEQ-001 | login → discovery command → completed download or upload, within `sequence_window_seconds` of the login | all steps in one session (strong) |
| SEQ-002 | ≥ `login_failure_threshold` failures within `login_lookback_seconds` → login → shell input within `sequence_window_seconds` | failures are address-linked (weak); login and input share a session (strong) |

Sequences are evaluated over stored events sorted by event time, so late or out-of-order arrivals produce the same result as in-order delivery. Duplicates are removed at ingestion. No session-close record is required.

## Statistics (Layer B)

A honeypot sees a small, biased slice of attacker behavior, so statistics here answer one question: is this unusual *for this dataset's own history*? Unusual is not malicious. Statistical findings are always severity `low`, carry `score` = robust z-score with `score_type` = `robust_z` (never a probability, never mixed into severity), and **never create incidents**. They appear as related signals on incidents that share their session, source address, or sensor and overlap in time, and in `/api/v1/findings?engine=statistical`.

| ID | Metric | Baseline |
|---|---|---|
| STAT-001 | events per sensor per bucket (`stats_bucket_seconds`) | that sensor's previous `stats_baseline_buckets` buckets, zero-filled between its first and last bucket; needs `stats_min_baseline` |
| STAT-002 | distinct usernames one source tried per bucket | peer (source, bucket) values from the preceding `stats_peer_window_seconds`; needs `stats_peer_min` peers |
| STAT-003 | shell commands per session | peer sessions with commands from the preceding peer window |
| STAT-004 | session duration (`duration_ms` from Cowrie's session close) | peer sessions with a duration from the preceding peer window |

**Method.** Robust z = (observed − median) / scale, where scale = 1.4826 × MAD. When more than half the baseline is identical (MAD = 0), the scale falls back to 1.2533 × mean absolute deviation; if every baseline value is identical, a floor of 1.0 applies. The facts record which (`scale_source`). An alert needs z ≥ `stats_z_threshold` (default 3.5) **and** an absolute excess over the median of at least 20 events, 5 usernames, 10 commands, or 300,000 ms. The excess guard stops tiny absolute changes in quiet datasets from alerting.

**No lookahead.** Every baseline ends where the judged bucket begins. Peers come from strictly earlier buckets, so the judged entity and its contemporaries are never part of their own baseline. Fixtures verify both.

**Cold start.** Below the minimum sample, a metric raises nothing and reports `insufficient_baseline` with its sample size and requirement (`/api/v1/statistics`, **Lab & validation**). STAT-001 also reports drift: the median of the current baseline window against the window before it.

**Facts on every statistical finding:** metric, observed value, robust z, threshold, excess guard, method, baseline (window start and end, sample size, median, MAD, scale, scale source), and evidence totals. STAT-001 adds the bucket, the previous bucket's count, the change from it, and an `evidence_selector` (sensor + time range) that reproduces the full evidence set through `/api/events` when it exceeds the 1,000 stored IDs.

**Known limits.** Sensor downtime is indistinguishable from silence in STAT-001. Peer metrics describe only entities that did the measured thing (for example, sources that tried usernames). Baselines never span datasets, so demo and uploaded data never shape live baselines.

**Execution.** Statistics recompute for a whole dataset after uploads and replays, at most every 60 seconds during live collection, and whenever a read finds them behind the data. A statistics failure is recorded and retried without affecting ingestion or rules. Set `statistical_enabled` to `false` to turn the layer off.

## Finding contract

Every finding, from any engine, has: `finding_id` (stable hash of dataset, engine, rule, rule version, and dedup key), `engine`, `rule_id`, `rule_version`, `title`, `description`, `category`, `severity`, `severity_rationale`, `technique` (a candidate ATT&CK mapping), `observed_at` (when the condition first held), `first_seen`, `last_seen`, `session`, `session_key`, `sensor`, `src_ip`, `evidence_event_ids`, `rationale` (`explanation` text plus machine-readable `facts`), `score` and `score_type` (both null for rules and sequences), `dedup_key`, `status` (`active` or `superseded`), and, when stored, `created_at` and `updated_at`. `id`, `name`, and `evidence_ids` are kept as aliases for 1.x clients.

When rules or settings change, the next startup recomputes all stored detections. Findings that no longer hold are marked `superseded`, never deleted.

## Fusion and incidents

Findings that touch a common Cowrie session, through their anchor event or their evidence, form one incident. Each finding keeps its own rationale and evidence. Overlapping evidence is listed once.

- **Incident ID:** the session key of the earliest finding's anchor event. It stays stable as later activity arrives and matches v0.2 IDs.
- **Correlation:** every incident lists why its parts are joined. `same_session` is a strong link. When evidence from other sessions is included through an address-based rule, the incident also carries a weak `same_source_address...` link that states this does not establish a single actor.
- **Event links:** timeline events are marked `anchor_session`, `finding_session`, or `source_address` (weak).
- **Merges:** if new or late evidence joins a case into another incident, the old ID resolves to the new incident. Its workflow status carries over when the target has none, and a `merge` entry (actor `aegis`) records the change in the activity trail.
- **Workflow:** `open → investigating | resolved | false_positive`, `investigating → open | resolved | false_positive`, `resolved | false_positive → open | investigating`. Other transitions return 409. Every change records actor, time, and before/after values. The actor is `local-analyst` until authentication is added.

## Configuration

Set `AEGIS_DETECTION_CONFIG` to a JSON file. Unknown keys or out-of-range values stop startup with a clear error. Defaults:

```json
{
  "auth_failure_threshold": 5,
  "auth_failure_window_seconds": 60,
  "login_failure_threshold": 5,
  "login_lookback_seconds": 300,
  "auth_group_by": "sensor_and_source",
  "discovery_commands": ["hostname", "uname"],
  "sequence_window_seconds": 1800,
  "statistical_enabled": true,
  "stats_bucket_seconds": 3600,
  "stats_baseline_buckets": 24,
  "stats_min_baseline": 12,
  "stats_peer_window_seconds": 604800,
  "stats_peer_min": 20,
  "stats_z_threshold": 3.5,
  "disabled_rules": []
}
```

`auth_group_by` may be `source` to correlate failures across sensors. `disabled_rules` accepts any rule, sequence, or statistic ID. The active settings, fingerprint, and catalog are available at `GET /api/v1/detection`. Changing settings through the API requires authentication (Phase 7) and is not offered yet.

## Execution model

Detection runs after every committed batch (upload, replay, or live collector), recomputing only the source addresses that batch touched. Events are read, findings computed, and results written in one database transaction. A detection failure never rolls back or blocks ingestion: the dataset is marked dirty and fully recomputed on the next read or startup.
