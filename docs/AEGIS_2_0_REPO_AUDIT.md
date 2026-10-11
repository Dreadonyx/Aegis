# Aegis 2.0 — Repository Audit (Phase 0)

Status: **baseline captured, no code changed.** This is the mandatory Phase 0
deliverable from the Aegis 2.0 specification (§2). It maps what exists today,
what is proven by tests, what is missing or risky versus the spec, and the
smallest safe migration path. Nothing here claims production readiness.

- Date: 2026-10-11
- Audited commit: `beea747` (main, clean tree)
- Auditor note: every statement below was verified against the source at this
  commit, not inferred from memory or the README.

---

## 1. Actual stack (verified)

| Layer | What is actually there |
|---|---|
| Backend | Flask 3.1.3, single app factory `create_app()` in `app.py` (304 lines) |
| Detection | `aegis/engine.py` (134 lines): `normalize`, `detect`, `report`, `is_discovery`, `session_key` |
| Storage | `aegis/store.py` (80 lines): SQLite + WAL, tables `events`, `workflow`, `activity` |
| Demo/eval | `aegis/demo.py` (synthetic records), `aegis/evaluate.py` (10 regression checks) |
| Frontend | Server-rendered Jinja `templates/index.html` + vanilla `static/app.js` (298 lines) + `static/style.css`. No JS framework, no build step. |
| Ingestion (live) | `follow_log()` / `read_log_batch()` in `app.py`: a daemon thread polling `cowrie.json` every 2s |
| Tests | `tests/test_aegis.py` (19 test functions), `tests/browser_smoke.py` (Playwright) |
| Local deploy | `Dockerfile`, `compose.yaml` (dashboard + cowrie + ssh-relay, hardened: cap_drop ALL, read_only, no-new-privileges) |
| AWS deploy | `deploy/compose.aws.yaml`, `deploy/ssh_relay.py`, CDK stack `infra/aegis_stack.py` (EC2 honeypot, S3, Budgets, DOCKER-USER firewall, SSM-only admin) |
| Auth | **None.** Single-user local lab. CSRF token + Origin + Sec-Fetch-Site checks guard mutating requests. |

Dependencies are pinned (`Flask==3.1.3`; Cowrie image pinned by digest to 3.1.1).

## 2. Entry points, routes, env vars

**Routes** (all registered in `create_app`):

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Dashboard (sets CSRF token) |
| GET | `/api/health` | Single health blob (no live/ready split) |
| GET | `/api/overview` | Counts, timeline, incidents, rules, collector status |
| GET | `/api/events` | Paginated event search (`q`, `page`, `limit≤500`) |
| GET | `/api/evaluation` | Runs the 10 synthetic regression checks |
| POST | `/api/replay` | Ingest 18 synthetic demo records |
| POST | `/api/import` | Upload Cowrie JSONL (≤2 MB, ≤5000 lines) |
| GET | `/api/incidents/<id>` | Incident detail + activity |
| PATCH | `/api/incidents/<id>` | Status: open/investigating/resolved |
| POST | `/api/incidents/<id>/notes` | Append analyst note (≤2000 chars, ≤100/incident) |
| GET | `/api/incidents/<id>/evidence` | JSON evidence export |
| GET | `/api/incidents/<id>/report` | Markdown report export |
| POST | `/api/incidents/<id>/ai` | Optional local Ollama draft (loopback-only, flagged) |

**Env vars:** `AEGIS_DB`, `AEGIS_COWRIE_LOG`, `AEGIS_OLLAMA_MODEL`,
`AEGIS_OLLAMA_URL`, `AEGIS_OLLAMA_TIMEOUT`, `AEGIS_BIND`, `AEGIS_PORT`.
No developer paths are hardcoded; sources are env-driven (meets spec §4.1 on that point).

## 3. Data model (current)

```
events(id TEXT PRIMARY KEY, source TEXT, body TEXT)   -- body = full normalized JSON
workflow(id TEXT PRIMARY KEY, status TEXT)
activity(id INTEGER PK, incident_id TEXT, timestamp TEXT, kind TEXT, body TEXT)
```

Key structural facts:
- **Incidents are not persisted.** `detect()` recomputes them from events on every
  request. Only workflow *status* and *activity* (notes/status history) are stored.
- Event `id` = `sha256(normalized_json)[:20]` → gives idempotent dedup via
  `INSERT OR IGNORE`.
- Normalized events live as a single JSON blob; there are **no columns/indexes** on
  `event_time`, `session`, `src_ip`, or `event_type`.

## 4. What works today, and the tests that prove it

- Cowrie JSONL import with strict validation, dedup, size/line caps — covered by `test_aegis.py`.
- Four deterministic rules (AUTH-001, AUTH-002, DISC-001, XFER-001) with exact
  evidence IDs — covered by the 10 regression checks in `aegis/evaluate.py`.
- Cross-session auth correlation + incident grouping by (source, sensor, src_ip, session).
- Incident workflow: status transitions, append-only notes, timestamped history.
- Evidence (JSON) and report (Markdown) exports with evidence IDs and explicit limits.
- Optional Ollama draft: loopback-enforced, no attacker-controlled command text sent,
  tested with mocks.
- Live collector: inode/size rotation handling, partial/oversized-line handling,
  restart-safe via hash dedup.

**Baseline captured 2026-10-11:** `pytest tests/test_aegis.py` → **31 passed**;
`python -m aegis.evaluate` → **10/10 checks pass**, 0 synthetic FP/FN.

## 5. Gaps, stubs, and risks versus the Aegis 2.0 spec

Ordered by how much each blocks the spec's release gates (§17).

1. **Raw evidence not preserved (spec §4.3, §5).** `normalize()` keeps only an
   allowlist and discards the raw record and unknown fields. There is no
   `raw_payload`, no `raw_sha256`, no `schema_version`/`parser_version`. This is the
   biggest provenance gap.
2. **No durable ingestion checkpoint (spec §4.2).** `follow_log` holds the byte
   offset in memory only; on restart it re-reads from offset 0 and leans on hash
   dedup. Correct in effect, but there is no persisted `(file identity, offset)`
   checkpoint and no committed-offset discipline.
3. **Live vs imported collision (spec §4.1, §15).** The live collector tags events
   `source="imported"`, identical to manually uploaded history. Live telemetry and
   historical import are therefore **not distinguishable** — a provenance gate issue.
   (Demo vs non-demo *is* cleanly separated.)
4. **Finding contract incomplete (spec §6).** Findings lack `finding_id`, `engine`,
   `rule_version`, `score`/`score_type`, `created_at`, `status`, and an explicit
   dedup/correlation key. They are recomputed, never stored.
5. **Only detection Layer A exists.** No statistical layer (B), no ML/IsolationForest
   (C), no ordered-sequence engine (D — only auth correlation + grouping), AI
   assistant is a single draft endpoint (E, partial).
6. **No versioned migrations (spec §9).** Schema is `CREATE TABLE IF NOT EXISTS` at
   startup. Additive changes are safe today but there is no migration runner/history.
7. **Import is all-or-nothing (spec §4.2).** `/api/import` raises on the first bad
   line instead of quarantining it and continuing. The collector path counts
   rejected lines but does not persist bounded error records.
8. **Observability is minimal (spec §13).** One `/api/health` blob; no live/ready
   split, no metrics (events read/committed, lag, parse errors, duplicates), no
   structured logs with correlation IDs.
9. **No auth/authz (spec §10).** Acceptable for the current single-user local lab;
   a hard gate the moment multi-user or non-loopback exposure is in scope.
10. **No Suricata EVE adapter (spec §8).** Not started (correctly deferred).

Good news — these already meet the spec and should be **preserved**:
- Passwords are never retained (`normalize` allowlist) — meets §5 redaction by design.
- Idempotent, hash-keyed writes — meets §4.2 idempotency.
- Loopback-only, evidence-only AI with explicit "not proof" framing — meets §6.5.
- Hardened containers, pinned images, DOCKER-USER firewall, SSM-only admin — meets much of §10/§13.
- Honest, non-overclaiming language throughout UI, reports, and `PENDING.md`.

## 6. Smallest safe migration path

Guiding rule (spec §3, §18): **modular monolith, no rewrite.** Keep Flask, SQLite,
and the server-rendered frontend. Add capability additively behind the existing
app factory.

1. **Introduce `/api/v1` as aliases first.** Register existing handlers under
   `/api/v1/...` while keeping current paths working, so the frontend and any
   consumers migrate without a breaking change.
2. **Additive schema + a tiny migration runner.** New tables alongside the existing
   three: `raw_events` (raw payload + sha256 + provenance), `findings`, `incidents`,
   `checkpoints`, `ingest_errors`. A `schema_migrations` table + ordered SQL files;
   never destructive recreation.
3. **Split modules by boundary** (`aegis/ingestion`, `aegis/detection`,
   `aegis/api`, `aegis/persistence`) incrementally — move code, keep behavior,
   keep tests green at every step.
4. **Preserve raw at ingest, derive canonical from it.** Store raw first, then
   normalize; this unblocks provenance (gap 1), checkpoints (gap 2), and
   live/imported labeling (gap 3) together.
5. **Every change ships with tests + docs in the same commit** (spec §18.5). The
   current green baseline is the regression guard.

## 7. Release-gate status snapshot (spec §17)

| Gate | Status today |
|---|---|
| Existing behavior mapped + regression-covered | ◐ mapped here; baseline green |
| Live Cowrie ingestion survives restart | ◐ works via dedup; no durable checkpoint |
| Rotation / partial / malformed / dup / DB-outage tested | ◐ partial (rotation, partial, dup yes; malformed-continue + DB-outage no) |
| Provenance + synthetic/live separation preserved in exports | ✗ raw not preserved; live==imported collision |
| Findings carry reproducible rationale + exact evidence IDs | ✓ (rationale), ◐ (no finding_id/version/status) |
| Rule/stat/ML layers fail independently | ✗ only rules exist |
| ML disabled by default until evaluated | n/a — not built |
| Authn/authz, validation, rate limits, secret handling reviewed | ◐ validation/CSRF yes; no authn, no rate limits |
| Migrations, backup, restore tested | ✗ no migration framework |
| Health, readiness, lag, error metrics | ✗ single health blob |
| Labeled detection evaluation with real metrics | ✗ synthetic only (see PENDING.md) |
| Pinned images/deps, least privilege, documented exposure | ✓ largely met |
| No automated block/remediation by default | ✓ none exists |
| Runbook, env template, rollback, release notes | ◐ README + PENDING; no env template/rollback doc |

Legend: ✓ met · ◐ partial · ✗ not started.

---

**Phase 0 conclusion:** the repo is a small but genuinely well-engineered,
security-conscious, honest local lab. It is a strong foundation, not a prototype to
throw away. The 2.0 effort is additive hardening and new detection layers, taken in
small reviewable phases per the spec — not a rewrite.

---

## Phase 1 progress (2026-10-11)

Implemented, with tests:

- `aegis/ingestion.py`: `make_record`, `read_batch`, and a `Collector` whose checkpoint commits in the same transaction as its batch. Covers restart resume, partial lines, oversized and malformed lines (quarantined as digest + length + reason), rename rotation (drains the old file, and finds it by inode after a restart), truncation, and storage outages (exponential backoff with jitter; the position is not advanced).
- `aegis/store.py`: versioned migration runner (`schema_migrations`; migration 1 = v0.2 schema, migration 2 = `raw_events`, `sources`, `ingest_errors`), hash-chained raw evidence with `verify_chain()`, and retention via `purge_raw()` that keeps the chain intact.
- Decisions: raw evidence keeps attempted passwords in the restricted table only (user decision); uploads stay atomic while the collector quarantines; the collector now writes into a separate `live` dataset. See `docs/EVIDENCE_POLICY.md`.
- API: `/api/v1` aliases for every route, plus `health/live`, `health/ready`, `sources`, `sources/<id>/health`, `sources/<id>/errors`, `evidence/verify`. UI: Live sensor dataset, evidence-chain status, honest live empty state.

Verification: `pytest` → 51 passed (31 original, 20 new). Five deliberate mutations (ignore the checkpoint, skip the rotation drain, skip the rotated-file search, chain without metadata, silently drop bad lines) each made at least one test fail. A real server end-to-end run (live tailing, append while running, restart) and the Playwright smoke test (`AEGIS_TEST_URL` mode) passed.

Completed after the first pass: startup configuration validation (rejects `cowrie.log`, directories, missing directories, invalid source IDs), graceful SIGTERM shutdown (tested in a subprocess), and `/api/v1/metrics` in Prometheus text format. The suite now has 57 tests.

Phase 1 is complete against the spec's Phase 1 list. Carried into later phases, by the spec's own phase plan:

- Structured JSON logs with request IDs, and a production WSGI server (Phase 7).
- Control-character escaping in rendered strings (Phase 2 canonical model / Phase 5 UI).
- Automated hash-chain head anchoring outside the host (documented; optional, Phase 7).
- Lines written immediately before a copy-truncate rotation can be lost; this is inherent to copy-truncate, and Cowrie uses rename rotation.

Gate changes: "Live Cowrie ingestion survives restart" → ✓. "Rotation / partial / malformed / dup / DB-outage tested" → ✓. "Provenance + synthetic/live separation" → ◐ (stored and separated; provenance is not yet in exports). "Health, readiness, lag, error metrics" → ✓ (structured logs remain for Phase 7). "Migrations" → ◐ (runner yes; backup/restore not yet tested).
