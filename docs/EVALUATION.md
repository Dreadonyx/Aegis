# Measuring detection quality

The fixtures under **Lab & validation** prove the logic works on hand-built cases. They say nothing about accuracy on real traffic. For that, evaluate against a labeled dataset:

```bash
python3 -m aegis.labeled_eval path/to/dataset                                   # Markdown report
python3 -m aegis.labeled_eval path/to/dataset --format json                     # machine-readable
python3 -m aegis.labeled_eval path/to/dataset --test-after 2026-10-20T00:00:00Z # time-separated
python3 -m aegis.labeled_eval path/to/dataset --config settings.json            # alternative thresholds
python3 -m aegis.labeled_eval path/to/dataset --model models/live-2026-10-20     # include an ML model
```

With `--model`, the report adds `engine:ml` and `ML-001`, records the model version and training window, and warns about leakage when the model was trained on the same dataset or its training window ends after evaluated sessions start. Score ML only on sessions after its training window (`--test-after` at or after the training end). Enable ML in production only if that evaluation shows it adds value over rules and statistics.

## Dataset format

A directory with three files:

- `manifest.json`: `{"name", "version", "description", "source", "license", "synthetic": true|false}`
- `events.jsonl`: Cowrie JSON lines, exactly as Cowrie writes them
- `labels.jsonl`: one line per session:
  `{"session": "a1b2c3", "sensor": "hp-1", "label": "malicious", "types": ["credential_access", "transfer"]}`
  - `label` is `malicious` or `benign`.
  - `sensor` is needed only when a session ID appears on more than one sensor.
  - `types` is optional: `credential_access`, `discovery`, `transfer`, `intrusion_sequence`, `anomaly`. With it, the report adds per-type coverage.

## What is measured

A session counts as detected when any finding's evidence includes one of its events. Sequence and address-linked findings therefore also count every session whose events they cite, which matches how an analyst would see them.

For the whole detector, each engine (`rule`, `sequence`, `statistical`), and each rule, sequence, and statistic, the report gives the confusion matrix, precision, recall, F1, and false-positive rate. It also breaks results down per detection type (when labels carry types) and per sensor. A metric whose denominator is zero is reported as `n/a`, not 0.

Time separation (`--test-after`) runs detection over the whole dataset, so statistical baselines can use earlier data, but scores only sessions that start at or after the cutoff. Rules are not trained, so this mainly matters for statistics now and for ML later.

## What the report always states

The dataset name, version, and SHA-256 of each file (so results are tied to an exact dataset); session counts and class balance; how many sessions were unlabeled or how many lines failed validation; and limitations, including small-sample and class-imbalance warnings and a synthetic-data warning. Do not quote a precision or recall figure without that context.

## Getting labeled data

Options, roughly from best to quickest:

1. Real Aegis telemetry, labeled by an analyst session by session. The live honeypot produces the events; labels come from review in the incident workbench.
2. A published, suitably licensed Cowrie dataset with independent labels. Record its license and provenance in the manifest.
3. Controlled lab traffic you generate yourself (benign administration plus scripted attacks against your own sensor). This is useful, but label it `synthetic: true`, because it reflects your scripts rather than real attackers.
