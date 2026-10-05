# Remaining validation

The local Aegis lab is implemented and tested. These two items remain before making broader accuracy or AI-quality claims.

## 1. Independent detection evaluation

- Obtain a suitably licensed, independently labeled Cowrie-compatible telemetry dataset containing benign and suspicious activity.
- Keep evaluation data separate from development fixtures and document its provenance, labels, and limitations.
- Measure per-rule true positives, false positives, false negatives, precision, and recall where the labels support those measurements.
- Review missed detections and benign alerts, documenting rule limitations and any resulting changes.

Current evidence: 31 unit/API tests, 10 synthetic detection regression checks, and desktop/mobile browser checks passed. The five-session synthetic demo is a pipeline check, not a real-world accuracy benchmark.

## 2. Live local AI validation

- Configure an installed local Ollama model using the native Python deployment described in README.md.
- Verify successful generation, unavailable-model handling, timeouts, and the analyst review workflow.
- Evaluate whether drafts cite valid evidence IDs, accurately describe findings, preserve uncertainty, and avoid unsupported claims.
- Record the tested model/version, hardware, latency, and observed quality limitations.

Current evidence: the adapter is tested with mocks. No live model quality or latency evaluation has been completed. Rule-based reports work without AI.

## Scope

Production hosting, multi-user access, additional sensors, adaptive deception, and malware analysis are optional future expansions, not requirements for the current local lab.

## Restart the lab

From this project directory:

```bash
docker compose up -d --build
```

Open http://127.0.0.1:8000. Stopping with `docker compose down` preserves the database and Cowrie log volumes.
