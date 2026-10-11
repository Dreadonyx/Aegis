# Aegis 2.0.0-rc1 (2026-10-11)

A release candidate. Every specification release gate passes except independent labeled detection evaluation (see "Open gate" below), so this release is not labeled production-ready.

## Highlights

- **Reliable live ingestion:** checkpointed collectors (Cowrie and optional Suricata EVE) that survive restarts, rotation, truncation, partial lines, malformed records, and storage outages without losing or duplicating data.
- **Evidence you can verify:** original records kept in a SHA-256 hash chain with provenance; passwords never displayed; verified backups that detect tampering.
- **Explainable layered detection:** six versioned rules, two sequences, four statistical signals with explicit cold start, optional Isolation Forest scoring (off by default), and an IDS correlation rule. Every finding cites its evidence and facts. Findings are fused into incidents; address-only links are labeled weak.
- **Investigation workspace:** filters, CSV export, provenance, session timelines, analyst labels, Findings and Sources views, and evidence-grounded AI drafts with citation checks.
- **Operations:** sign-in with viewer, analyst, and admin roles; JSON logs with request IDs; waitress; rate limits; metrics; backup, restore, and retention; hash-locked dependencies; a pinned base image; CI with dependency and image scanning.
- **Real-data evaluation:** a reproducible pipeline over real honeypot logs with time-separated backtesting and confidence intervals.

## Upgrading from 1.0

Database migrations run automatically at startup (schema 1 → 7), are additive, and were rehearsed on a real 1.0 database, including a rollback to the 1.0 code. Back up first (`python -m aegis.backup create`).

Behavior changes:

- The live collector now writes the `live` dataset; collector data from before 2.0 stays in `imported`.
- The evidence export is `schema_version` 2 (fields added).
- A brute-force burst and the login it precedes now form one incident.
- Uploads remain atomic. Detection settings can be changed by admins in the API (with history).
- `python app.py` serves with waitress and refuses to listen beyond loopback without sign-in.

## Verification

- 163 automated tests, 38 detection fixtures, and browser smoke tests pass.
- Mutation checks were run on every phase's safety properties: each deliberately broken behavior made a test fail. Surviving mutants led to stronger tests or to removing dead code.
- pip-audit reports no known vulnerabilities in any lockfile. Werkzeug 3.1.9 fixes CVE-2026-102598, which affects Windows hosts only.
- Trivy: 0 critical; 44 high in Debian base packages, none with an available fix.
- The 50,000-event load test passed.

## Open gate

**Labeled detection evaluation (partly closed).** 177 real sessions now carry independent labels: 175 from a separate AI model with no access to the rules, and 1 from the analyst. On 117 unseen sessions, rules OR calibrated real-data ML caught 8 of 10 attacks with 1 false alarm (recall 0.80, 95% CI 0.49–0.94); see `docs/REALDATA_EVALUATION.md`. Fully closing this gate needs human verification of the labels and a larger sample.

## Known limitations

- SQLite, single node, 50,000-event cap.
- Lines written just before a copy-truncate rotation can be lost (Cowrie uses rename rotation).
- The evidence chain cannot detect deletion of its newest records unless you keep the head hash elsewhere.
- The optional Ollama image in the AWS overlay is pinned by tag, not digest.
- Real local-model quality testing of AI drafts has not been done.
