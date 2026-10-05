# Verification status

Verified locally on 2026-10-05.

| Check | Result |
| --- | --- |
| Python unit/API suite | 31 tests passed |
| JavaScript syntax | Passed `node --check static/app.js` |
| Browser, 1440px desktop and 390px mobile | Replay, search, workflow/note persistence, draft preservation, event inspection, Markdown/JSON exports, workflow filtering, regression display, import escaping, and no horizontal overflow passed |
| Browser JavaScript errors | None observed |
| Docker Compose | Dashboard, Cowrie 3.1.1, and fixed-destination SSH relay started |
| Local SSH connectivity | Banner read successfully through `127.0.0.1:2222`; no authentication or commands attempted |
| Collector | Fresh Cowrie connection telemetry appeared in the imported dataset |
| Cowrie network | Internal network only; route table had no default route |
| Published ports | Dashboard `127.0.0.1:8000`, relay `127.0.0.1:2222` |
| Optional AI | Disabled by default; adapter and endpoint restrictions tested with mocks |

## Synthetic evaluation

The fixture contains 18 events in five sessions. Three sessions are expected positives; two are expected negatives. Results: **TP 3, FP 0, FN 0, TN 2**. This tests known pipeline behavior, not general detection accuracy. No representative external dataset, independent labeling study, or real-world false-positive estimate is available yet.

Ten standalone regression checks also pass via `python3 -m aegis.evaluate`. They cover thresholds, time windows, source separation, quoted text, multiline input, interactive stdin, and successful/failed downloads.

## Additional tested boundaries

Authentication threshold boundaries, expiration, cross-session evidence linkage, out-of-order inputs, sensor/source/dataset isolation, password-field removal, timestamp canonicalization, atomic imports, deduplication, invalid workflow values, CSRF and host restrictions, missing incidents, AI-disabled behavior, oversized collector lines, partial collector writes, duplicate imports at storage capacity, transactional rollback on storage overflow, append-only notes, idempotent status history, evidence bundle contents, pagination completeness, and database-readiness errors.

## Not claimed

Internet deployment readiness, production authentication, resistance to sustained hostile traffic, full SSH emulation correctness, real-model quality, malware classification, C2 detection, or universal ATT&CK coverage. Network isolation was checked through configuration and routing inspection; this was not a penetration test.
