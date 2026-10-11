# Performance at the event cap

Measured 2026-10-11 with `python -m aegis.loadtest --events 50000` on a 16-core x86_64 workstation, Python 3.14, SQLite in WAL mode. The traffic was synthetic and shaped like the real sensor (80% scanner sessions, 15% guessing bursts, 5% interactive sessions), using documentation-range addresses. Results depend on hardware; rerun the command on yours.

| Measure | Result |
|---|---|
| Events / sessions | 50,000 / 12,178 |
| Incidents / active findings | 500 / 2,309 |
| Live-style ingestion (500-event batches, detection after each commit) | 3,659 events/s; batch p50 132.7 ms, p95 216.9 ms |
| Full detection and statistics recompute | 1.41 s |
| Database size | 81.9 MB |
| Evidence chain after load | valid |

API latency (application time through the WSGI test client, 15 requests each, measured right after ingestion):

| Endpoint | p50 ms | p95 ms |
|---|---|---|
| overview | 59.8 | 232.1 |
| events page | 2.0 | 3.2 |
| filtered events | 1.3 | 1.7 |
| incidents | 5.6 | 6.5 |
| findings | 3.9 | 5.8 |
| session timeline | 15.7 | 17.3 |
| statistics | 6.6 | 8.1 |
| series (hourly) | 186.4 | 233.2 |
| metrics | 1.6 | 2.6 |

## Reading the numbers

- The overview's p95 is the first read after a bulk ingest, when deferred statistics catch up. During live collection statistics recompute at most every 60 seconds, so ingestion stays fast; in steady use consecutive overview requests took 67–102 ms.
- The overview returns the 500 most severe and recent incidents plus true totals; `/api/v1/incidents` pages through the rest. Hourly series are aggregated in SQLite (equivalent to the in-memory reference, which a test checks).
- Before these optimizations (same data): overview p50 132 ms / p95 324 ms; hourly series p50 471 ms / p95 531 ms.
- The real AWS sensor produced about 441 events in 41 hours. Ingestion capacity is several orders of magnitude above that; the 50,000-event cap is reached long before throughput matters.
