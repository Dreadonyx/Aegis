# Operating Aegis 2.0

## Components

One process (the dashboard) contains the web API, the live collectors (Cowrie and optional Suricata EVE), detection, statistics, optional ML scoring, and optional raw-evidence retention. State is a single SQLite database. Cowrie runs in its own container on an internal network; it never talks to the dashboard directly. The dashboard reads Cowrie's JSON log from a shared read-only volume.

SQLite suits a single node with one writer process. For several analysts at once or sustained high ingest, plan a move to PostgreSQL: the store module is the only place that would change.

## Network layout and exposure

| Port | Service | Bound to | Who should reach it |
|---|---|---|---|
| 8000 | Dashboard and API | host loopback (`127.0.0.1:8000`) | Analysts through SSH or SSM tunnels, or a TLS reverse proxy on the same host |
| 2222 | Local SSH relay to Cowrie | host loopback | Local lab testing only |
| 22 | Cowrie (AWS overlay only) | public | Attackers (this is the honeypot) |
| 11434 | Ollama (optional) | dashboard network namespace | The dashboard only |

- Never expose port 8000 to the internet. For remote access, run a TLS reverse proxy on the host, set `AEGIS_ENV=production`, `AEGIS_TRUSTED_PROXY` to the proxy address, and `AEGIS_TRUSTED_HOSTS` to its hostname.
- The server refuses to listen beyond loopback without sign-in unless `AEGIS_ALLOW_UNAUTHENTICATED_BIND=true`. That setting is only for compose, where the container port is published on host loopback.
- On AWS, the host firewall (DOCKER-USER chain, `infra/aegis_stack.py`) drops new outbound connections from the honeypot network and all container access to instance metadata. Admin access is through SSM only.

## Volumes and resources

| Volume | Contents | Sensitivity |
|---|---|---|
| `aegis-data` (`/app/data`) | SQLite database: events, raw evidence (including attempted passwords), findings, labels, accounts | High: restrict access, keep encrypted at rest |
| `cowrie-log` | Cowrie's original JSON logs | High: attacker addresses and attempted credentials |
| models directory (optional) | ML model files (pickles) | Operator-controlled only |

The canonical event cap is 50,000. See [PERFORMANCE.md](PERFORMANCE.md) for measured ingest rates, recompute times, and API latency at that size. Compose limits Cowrie to 512 MB and the SSH relay to 128 MB; the dashboard needs about 300 MB at the cap (more with ML).

## Configuration

Every setting is an environment variable; `.env.example` lists them with placeholders. The important ones:

| Variable | Purpose |
|---|---|
| `AEGIS_ENV` | `development` (default) or `production`. Production requires sign-in and a secret key, and defaults to secure cookies |
| `AEGIS_SECRET_KEY` | Session signing key, 32+ characters (`python -c 'import secrets; print(secrets.token_hex(32))'`). Changing it signs everyone out |
| `AEGIS_AUTH` | `required` or `off` (default `off` in development) |
| `AEGIS_TRUSTED_HOSTS`, `AEGIS_TRUSTED_PROXY` | Reverse-proxy deployments |
| `AEGIS_METRICS_TOKEN` | Bearer token that lets a scraper read `/api/v1/metrics` without an account |
| `AEGIS_COWRIE_LOG`, `AEGIS_SOURCE_ID` | Live Cowrie collector |
| `AEGIS_SURICATA_EVE`, `AEGIS_SURICATA_SENSOR` | Optional read-only EVE collector |
| `AEGIS_DETECTION_CONFIG` | Detection settings file (an admin can also change settings in the API; database settings take precedence) |
| `AEGIS_ML_MODEL_DIR` | Verified ML model, used only with `"ml_enabled": true` |
| `AEGIS_RAW_RETENTION_DAYS` | Daily purge of raw bytes older than this many days |
| `AEGIS_LOG_LEVEL`, `AEGIS_THREADS` | Logging level; waitress worker threads (default 8) |

## Production checklist

1. Build from a tagged commit: `docker build -t aegis:2.0.0-rc1 .` (add `--build-arg INSTALL_ML=true` only if ML will run).
2. Create the secret key and store it in your secret manager, not in the repository or compose files.
3. Set `AEGIS_ENV=production`, `AEGIS_TRUSTED_HOSTS`, and `AEGIS_TRUSTED_PROXY`; terminate TLS at the proxy.
4. Create accounts: `docker compose run --rm dashboard python -m aegis.users add <name> --role admin`. Give analysts `analyst` and read-only users `viewer`.
5. Start, then confirm `GET /api/v1/health/ready` returns 200, the schema version is the latest, and `/api/v1/evidence/verify` is valid.
6. Schedule backups (below) and confirm the first one verifies.
7. Point monitoring at the readiness endpoint and metrics (below).
8. Record the evidence-chain head (`/api/v1/evidence/verify`) somewhere the Aegis host cannot write.

## Upgrades and database migrations

Migrations are versioned, additive, and transactional; they run automatically at startup. There is no automatic downgrade, so a rollback means restoring a backup.

1. `python -m aegis.backup create --db <db> --out backups/pre-upgrade-<date>.sqlite3`, then `verify` it.
2. Stop the dashboard (SIGTERM; the collector finishes its batch).
3. Deploy the new image or commit and start it.
4. Check readiness (200), `schema_version` in `/api/v1/health/ready`, `/api/v1/evidence/verify`, and the Sources view (collector running, lag falling).

## Rollback

1. Stop the dashboard.
2. Move the current database aside (restore never overwrites): `mv data/aegis.sqlite3 data/aegis.sqlite3.failed`.
3. `python -m aegis.backup restore backups/pre-upgrade-<date>.sqlite3 --to data/aegis.sqlite3` (it verifies before copying).
4. Start the previous release (for example, the `aegis-1.0` branch or the previous image tag) and check readiness.

The live collector re-reads anything written after the backup from its checkpoint. Analyst work done after the backup (notes, labels, status changes) is lost.

## Backup and restore

```bash
python -m aegis.backup create --db /app/data/aegis.sqlite3 --out /backups/aegis-$(date -u +%F).sqlite3
python -m aegis.backup verify /backups/aegis-2026-10-11.sqlite3
python -m aegis.backup restore /backups/aegis-2026-10-11.sqlite3 --to /app/data/aegis.sqlite3
```

Backups are consistent while the collector writes, owner-readable only, and self-contained. Verification checks the digest, SQLite integrity, every hash-chain link, and row counts. Run `verify` on a schedule as well as at backup time, keep copies off the host, and treat backups as sensitive (they contain raw evidence).

## Monitoring

- **Liveness:** `GET /api/v1/health/live`. **Readiness:** `GET /api/v1/health/ready` returns 503 when the database is unavailable or a collector has failed.
- **Metrics** (`/api/v1/metrics`, Prometheus text): alert on `aegis_collector_up == 0`, a growing `aegis_collector_bytes_behind`, a rising `aegis_source_malformed_total` rate, `aegis_collector_consecutive_failures > 3`, and `aegis_events_stored` approaching `aegis_events_limit`.
- **Logs** are JSON lines on stdout with `request_id`; useful events are `request`, `login`, `login_failed`, `detection_settings_changed`, `ai_draft`, `raw_retention`, and `start`. Logs never contain passwords, query strings, raw telemetry, or AI text.

## Dependency and image updates

```bash
uv pip compile requirements.txt --generate-hashes --exclude-newer <two weeks ago> --python-version 3.12 --refresh --upgrade -o requirements.lock
# repeat for requirements-ml.txt, requirements-dev.txt, requirements-ci.txt
uvx --from pip-audit==2.10.1 pip-audit --require-hashes --disable-pip --strict -r requirements.lock -r requirements-ml.lock -r requirements-dev.lock
```

Update the base image digest in the Dockerfile on purpose, to pick up Debian security fixes, and check the CI image scan. Security fixes may take a newer release when the advisory warrants it; record why in the lockfile commit.

## If the Aegis host may be compromised

1. Isolate the host (security group or firewall) but keep it running if you need memory or disk evidence.
2. Rotate `AEGIS_SECRET_KEY` (signs everyone out) and reset every account password.
3. Check the evidence chain against the head hashes you recorded elsewhere; anything after the last matching head is suspect.
4. Restore from a verified backup onto a clean host, review the `login`, `login_failed`, and `detection_settings_changed` log events, and keep the original disk for analysis.
