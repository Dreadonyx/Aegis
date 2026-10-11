# Open items (2.0.0-rc1)

Everything else in the 2.0 specification is implemented and verified (docs/VERIFICATION.md). These remain:

1. **Labeled evaluation (partly closed).** Human-check the 11 malicious sessions in the session view; label the sessions from the final collection; measure INT-001 and a candidate "accepted honeypot login" rule on data collected after 2026-10-11 (docs/REALDATA_EVALUATION.md).
2. **Failed-login telemetry.** The AWS Cowrie user database accepts almost every password, so the credential-guessing rules are untested on real traffic. A stricter user database is a deployment decision.
3. **AI drafts with a real model.** Run the optional Ollama drafts against a real local model and record citation validity, accuracy, and latency.
4. **Independent security review** of authentication, sessions, and exports.
5. **Optional hardening:** PostgreSQL for multi-user or long-running deployments, a password-change page and MFA, and automated export of the evidence-chain head.
6. **AWS honeypot teardown** on 2026-10-27 (runbook in infra/README.md), after a final log download.

## Restart the local lab

```bash
docker compose up -d --build     # dashboard at http://127.0.0.1:8000
docker compose down              # keeps the database and Cowrie log volumes
```
