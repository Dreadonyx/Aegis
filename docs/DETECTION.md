# Detection reference (ruleset 2026.10.2)

Detection is layered: canonical events → deterministic rules (Layer A), sequences (Layer D), and statistics (Layer B) → evidence fusion into incidents. Optional ML (Layer C) is implemented but off by default (see below). Everything here is deterministic and covered by fixtures in `aegis/evaluate.py` (31 checks, also shown under **Lab & validation**). To measure detection against labeled data, see [EVALUATION.md](EVALUATION.md).

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
| STAT-004 | duration (`duration_ms`) of a session with an accepted login | peer logged-in sessions from the preceding peer window; scanner sessions are excluded (on real data, 137 of 146 sessions were scanners and half lasted 0 ms, which made every interactive session look extreme) |

**Method.** Robust z = (observed − median) / scale, where scale = 1.4826 × MAD. When more than half the baseline is identical (MAD = 0), the scale falls back to 1.2533 × mean absolute deviation; if every baseline value is identical, a floor of 1.0 applies. The facts record which (`scale_source`). An alert needs z ≥ `stats_z_threshold` (default 3.5) **and** an absolute excess over the median of at least 20 events, 5 usernames, 10 commands, or 300,000 ms. The excess guard stops tiny absolute changes in quiet datasets from alerting.

**No lookahead.** Every baseline ends where the judged bucket begins. Peers come from strictly earlier buckets, so the judged entity and its contemporaries are never part of their own baseline. Fixtures verify both.

**Cold start.** Below the minimum sample, a metric raises nothing and reports `insufficient_baseline` with its sample size and requirement (`/api/v1/statistics`, **Lab & validation**). STAT-001 also reports drift: the median of the current baseline window against the window before it.

**Facts on every statistical finding:** metric, observed value, robust z, threshold, excess guard, method, baseline (window start and end, sample size, median, MAD, scale, scale source), and evidence totals. STAT-001 adds the bucket, the previous bucket's count, the change from it, and an `evidence_selector` (sensor + time range) that reproduces the full evidence set through `/api/events` when it exceeds the 1,000 stored IDs.

**Known limits.** Sensor downtime is indistinguishable from silence in STAT-001. Peer metrics describe only entities that did the measured thing (for example, sources that tried usernames). Baselines never span datasets, so demo and uploaded data never shape live baselines.

**Execution.** Statistics recompute for a whole dataset after uploads and replays, at most every 60 seconds during live collection, and whenever a read finds them behind the data. A statistics failure is recorded and retried without affecting ingestion or rules. Set `statistical_enabled` to `false` to turn the layer off.

## Optional ML (Layer C)

An Isolation Forest scores session features. It is **off by default** and stays off until a labeled evaluation shows it adds value. Enabling it takes both `"ml_enabled": true` in the detection settings and a verified model in `AEGIS_ML_MODEL_DIR`.

**Features** (`aegis/features.py`, version 1, each passed through `log1p`): events, duration, failed and accepted logins, distinct usernames, commands, distinct commands, failed commands, mean command length, discovery commands, downloads, uploads, tunnel requests, whether a client version was sent, and events per minute.

**Training is manual and explicit.** It never happens automatically, because attacker-controlled traffic can poison a baseline:

```bash
python3 -m aegis.ml train --db data/aegis.sqlite3 --dataset live --until 2026-10-20T00:00:00Z --out models/live-2026-10-20
python3 -m aegis.ml train --labeled path/to/dataset --benign-only --out models/labeled-v1
python3 -m aegis.ml inspect models/live-2026-10-20     # verify and print the manifest
```

- `--until` is required: the end of the window you reviewed. Later events are never used.
- Synthetic data (the demo dataset, or a labeled set marked synthetic) is refused unless you pass `--allow-synthetic`, and the model is then marked synthetic. A synthetic model is refused when scoring observed telemetry.
- At least 50 sessions are required. An existing output directory is never overwritten.
- Parameters are fixed and recorded (`n_estimators=200`, `contamination="auto"`, `random_state=42`).

**Manifest (`model.json`):** model version, algorithm and parameters, feature version and list, training window, source, session count and synthetic flag, calibrated threshold (by default, the 99th percentile of training scores), library versions, training time, and the SHA-256 of `model.joblib`.

**Fails closed.** A model is used only after these checks pass, in this order: the manifest is readable; the format is supported; `model.joblib` matches the recorded digest (nothing is unpickled before this); the feature version matches; the scikit-learn version matches; the model is younger than `ml_max_model_age_days` (default 90); the threshold, feature version, training time, and synthetic flag in the manifest match the copies inside the verified file; and the model is not synthetic when scoring observed data. Otherwise the status is `missing`, `integrity`, `stale`, `incompatible`, `rejected`, or `dependency` (scikit-learn not installed), no ML findings are produced, earlier ML findings are superseded, and rules and statistics continue. Unexpected scoring errors mark the layer for recomputation without affecting the other layers.

Model files use pickle (through joblib). The digest check stops accidental or casual tampering, but keep the model directory operator-controlled and never load models from untrusted sources.

**Findings (`ML-001`)** are low-severity signals that never create incidents. They carry `score` (the raw `-score_samples` value; higher is more unusual) with `score_type` = `isolation_forest_anomaly`, plus the training percentile, threshold, model and feature versions, training summary, the session's feature values, and the three features furthest from the training medians. Those three are context only: Isolation Forest does not attribute its score to features. The score is never presented as a probability.

**First real-data run (2026-10-11).** Trained on the 87 honeypot sessions before 2026-10-10 12:00 UTC and scored all 146. It flagged one session, the login, discovery, and download session that `SEQ-001` already caught (mean command length 1,132 characters), and none of the 59 later sessions. On two days of mostly scanner traffic, ML added nothing beyond the rules, which is why it stays off by default.

**Installing.** scikit-learn is optional: `pip install -r requirements-ml.txt`, or build the image with `--build-arg INSTALL_ML=true` (about 78 MB larger). Mount the model directory read-only.

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
  "ml_enabled": false,
  "ml_max_model_age_days": 90,
  "disabled_rules": []
}
```

`auth_group_by` may be `source` to correlate failures across sensors. `disabled_rules` accepts any rule, sequence, statistic, or ML ID. `ml_enabled` (default `false`) and `ml_max_model_age_days` (default 90) control the optional ML layer. The active settings, fingerprint, and catalog are available at `GET /api/v1/detection`. Changing settings through the API requires authentication (Phase 7) and is not offered yet.

## Execution model

Detection runs after every committed batch (upload, replay, or live collector), recomputing only the source addresses that batch touched. Events are read, findings computed, and results written in one database transaction. A detection failure never rolls back or blocks ingestion: the dataset is marked dirty and fully recomputed on the next read or startup.
