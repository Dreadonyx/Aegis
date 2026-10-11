# Verification status

Aegis 2.0.0-rc1, verified 2026-10-11. Each check below was run, not assumed.

| Check | Result |
| --- | --- |
| Automated tests | 169 passed (Python 3.14 locally; Python 3.12 in CI and in the production image) |
| Detection fixtures | 38/38 (`python -m aegis.evaluate`; logic checks, not field accuracy) |
| Browser smoke (1440 px desktop, 390 px mobile) | Passes standalone and against the full compose stack; repeatable against a persistent database |
| GitHub CI | Tests, dependency audit, and image scan green; a browser job was added and runs on the next push |
| Full compose stack | A real SSH connection reached Cowrie, the collector, and the live dataset with sensor name `ssh-lab-01`; dashboard healthy, non-root (uid 1000), read-only filesystem, JSON logs; clean exit (code 0) on SIGTERM |
| Mutation checks | Every phase's safety properties: each deliberately broken behavior failed a test; survivors led to stronger tests or removed dead code |
| Dependencies | Hash-locked; pip-audit reports no known vulnerabilities (Werkzeug 3.1.9 for CVE-2026-102598) |
| Container image | Base pinned by digest; Trivy reports 0 critical and 44 high in Debian packages, none with a fix |
| Backup and restore | Online backup, read-only verification (including evidence edited inside a backup with a forged digest), safe restore |
| Upgrade and rollback | Real 1.0 database upgraded to schema 8 and rolled back; the `aegis-1.0` code served the restored data |
| Load | 50,000 events: about 3,650 events/s ingestion, 1.4 s full recompute (docs/PERFORMANCE.md) |
| Real data | 177 honeypot sessions with independent labels; on 117 unseen sessions, rules OR calibrated ML caught 8 of 10 attacks with 1 false alarm (docs/REALDATA_EVALUATION.md) |

## Not claimed

- Production-ready certification: one specification gate (labeled evaluation) is only partly closed.
- Human-verified labels: 175 of 176 labels come from a separate AI model.
- Quality of AI drafts with a real local model (only simulated model replies were tested).
- An independent security review or penetration test.
- Multi-node operation or more than 50,000 events.
