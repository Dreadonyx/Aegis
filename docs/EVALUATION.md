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

## Labeling your own telemetry

1. Open a session (from any event, finding, or incident timeline) and set **Malicious (alert-worthy)** or **Benign (should stay quiet)**, with optional types and a note. Every change records who made it and when.
2. A suggestion appears when rule findings or the session's shape make one obvious. It is never applied automatically. Accepting rule-based suggestions without review makes the rules' scores circular.
3. Export: `python3 -m aegis.labels export --db data/aegis.sqlite3 --dataset live --out datasets/live-2026-10-28`. The export holds every event in range (cross-session rules need the context), labels for the labeled sessions, masked passwords, and a manifest. It contains attacker addresses, so keep it private.

## Training, calibrating, and measuring ML without leakage

Use three time-ordered windows over real data:

```bash
python3 -m aegis.ml train --db data/aegis.sqlite3 --dataset live --until 2026-10-18T00:00:00Z --out models/train-1018
python3 -m aegis.ml calibrate --model models/train-1018 --labeled datasets/live-2026-10-28 \
    --test-after 2026-10-18T00:00:00Z --objective f1 --out models/cal-1023   # objective: f1, precision:0.9, recall:0.8
python3 -m aegis.labeled_eval datasets/live-2026-10-28 --test-after 2026-10-23T00:00:00Z --model models/cal-1023
```

To keep the measurement window untouched, give `calibrate` a labeled export that ends where the test window begins (`labels export --until 2026-10-23T00:00:00Z`). Calibration refuses sessions from the training window unless you pass `--allow-overlap`, writes a new model version (the original is never edited), records the full precision/recall curve, and warns when fewer than 20 malicious sessions make the threshold unstable.

## One-command real-data evaluation

`python3 -m aegis.realdata path/to/cowrie-logs --out data/reports/<name>` ingests real logs into a fresh database, labels sessions with documented behavioral criteria (recorded as an automated actor), and runs a forward-chaining ML backtest plus a single time split. It reports Wilson 95% intervals and writes `report.md` and `report.json`. Use `--note` to record caveats, such as a rule designed after seeing the same data. Keep the output under `data/`: it contains attacker addresses. See [REALDATA_EVALUATION.md](REALDATA_EVALUATION.md) for the first results.

## Getting labeled data

Options, roughly from best to quickest:

1. Real Aegis telemetry, labeled by an analyst session by session. The live honeypot produces the events; labels come from review in the incident workbench.
2. A published, suitably licensed Cowrie dataset with independent labels. Record its license and provenance in the manifest.
3. Controlled lab traffic you generate yourself (benign administration plus scripted attacks against your own sensor). This is useful, but label it `synthetic: true`, because it reflects your scripts rather than real attackers.
