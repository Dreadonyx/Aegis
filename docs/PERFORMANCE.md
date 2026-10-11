# Performance at the event cap

Measured 2026-10-11 with `python -m aegis.loadtest --events 50000` on a 16-core x86_64 workstation, Python 3.14, SQLite in WAL mode. The traffic was synthetic and shaped like the real sensor (80% scanner sessions, 15% guessing bursts, 5% interactive sessions), using documentation-range addresses. Results depend on hardware; rerun the command on yours.

| Measure | Result |
|---|---|
| Events / sessions | 50,000 / 12,178 |
| Incidents / active findings | 1,968 / 2,309 |
| Live-style ingestion (500-event batches, detection after each commit) | 3,574 events/s; batch p50 140.5 ms, p95 233.4 ms |
| Full detection and statistics recompute | 1.55 s |
| Database size | 81.9 MB |
| Evidence chain after load | valid |

API latency (application time through the WSGI test client, 15 requests each):

| Endpoint | p50 ms | p95 ms |
|---|---|---|
| overview | 132.3 | 324.2 |
| events page | 2.1 | 2.8 |
| filtered events | 1.4 | 1.6 |
| incidents | 5.5 | 9.0 |
| findings | 4.0 | 4.2 |
| session timeline | 15.8 | 18.2 |
| statistics | 6.7 | 7.6 |
| series (hourly) | 471.4 | 531.0 |
| metrics | 1.7 | 3.4 |

## Reading the numbers

- The real AWS sensor produced about 441 events in 41 hours. Ingestion capacity is several orders of magnitude above that; the 50,000-event cap is reached long before throughput matters.
- The overview and the hourly series are the slowest reads, because they summarize the whole dataset in Python. They are acceptable at the cap; if the cap is raised, precompute their aggregates in SQL first.
- Statistics recompute at most every 60 seconds during live collection, and reads catch up, so ingestion cost stays flat.
