# Real-data evaluation, 2026-10-11

The first measurement of Aegis 2.0 detection and ML on real honeypot traffic. It contains aggregate figures only: no attacker addresses, session IDs, or sensor identifiers. Reproduce it with:

```bash
python3 -m aegis.realdata path/to/cowrie-logs --out data/reports/realdata-YYYY-MM-DD
```

## Bottom line

- **Rules frozen before seeing this data** caught **2 of 5** out-of-sample intrusions with **no false alarms** (recall 0.40, 95% CI 0.12–0.77). They missed three bots that logged in, ran one command, and left within two seconds.
- **ML trained only on real data** caught **1 of 5** with its default threshold, and **2 of 5** when each block's threshold was tuned on earlier labels only. **Rules OR that ML** caught **3 of 5**, still with no false alarms (recall 0.60, CI 0.23–0.88). On this data, ML added one detection the rules missed.
- **INT-001** ("shell input after an accepted login") was added to close the gap. It reaches 6 of 6, but that figure is in-sample and close to circular, because the rule nearly restates the first labeling criterion. It must be measured on newer traffic.
- With only 6 alert-worthy sessions, every interval is wide. These results show behavior and direction, not field accuracy. ML stays off by default, as the specification requires.

## Data

- One AWS Cowrie 3.1.1 sensor, 2026-10-09 14:25 UTC to 2026-10-11 07:56 UTC (about 41 hours).
- 441 events, all parsed (0 rejected), 170 sessions.
- 160 sessions were scanning or banner grabbing. The sensor logged no failed logins, because its user database accepts most credentials, so credential-guessing detection is untested.

## Labels

Automated behavioral criteria (v1), applied to raw session events. These are not independent human labels.

- **Malicious (alert-worthy):** an accepted login followed by a command or transfer; any completed download or upload; five or more failed logins in a session; a port-forwarding request.
- **Benign:** no login attempt, command, transfer, or tunnel.
- **Excluded:** anything else (here, accepted logins with no further activity).

Counts: 6 malicious, 160 benign, 4 excluded.

## Method

- **Forward-chaining backtest (primary result).** After an initial 60 sessions, each block of 25 later sessions is scored by an Isolation Forest trained only on the sessions before it. The default threshold is the training 99th percentile; the "earlier labels" variant tunes the threshold for F1 on earlier labeled sessions only. No choice uses the scored block. The rules need no training and are scored on the same sessions.
- **Single 50/25/25 time split (secondary).** The count-based split put all three one-command bots in the calibration window, leaving the test window with no positives. That illustrates why a single split is unreliable at this size.
- **Intervals** are 95% Wilson score intervals.
- **Sensor-level findings** (STAT-001 traffic spikes) are reported but not attributed to individual sessions. An earlier draft attributed them and counted 21 false positives that were a methodology error, not detector behavior.

## Results

Forward-chaining backtest, 106 labeled out-of-sample sessions (5 malicious).

| Detector | Precision [95% CI] | Recall [95% CI] | F1 | False positives |
|---|---|---|---|---|
| Rules and sequences (frozen) | 1.00 [0.34–1.00] | 0.40 [0.12–0.77] | 0.57 | 0 |
| ML, default threshold | 1.00 [0.21–1.00] | 0.20 [0.04–0.62] | 0.33 | 0 |
| ML, threshold from earlier labels | 1.00 [0.34–1.00] | 0.40 [0.12–0.77] | 0.57 | 0 |
| Rules OR ML (earlier labels) | 1.00 [0.44–1.00] | 0.60 [0.23–0.88] | 0.75 | 0 |
| Rules including INT-001 (in-sample) | 1.00 [0.57–1.00] | 1.00 [0.57–1.00] | 1.00 | 0 |

All 166 labeled sessions, frozen rules: precision 1.00 [0.44–1.00], recall 0.50 [0.19–0.81]. With INT-001 (in-sample): 6/6 [0.61–1.00].

The statistical layer raised two sensor-wide spike signals and no session-level findings: STAT-002, STAT-003, and STAT-004 lacked enough peers for a baseline.

## Model trained on real data

`if-2026-10-11-34b31442`: an Isolation Forest trained on all 170 real sessions (no synthetic data), feature version 1, default threshold at the training 99th percentile. It is kept locally under `models/` and is not committed (it is a pickle derived from attacker telemetry). It is suitable for scoring traffic after 2026-10-11 08:00 UTC, which it has not seen.

## What would change these conclusions

1. **More data.** The sensor keeps collecting until teardown on 2026-10-28. Downloading all of it gives a clean holdout for INT-001 and the ML.
2. **Human labels.** Labeling sessions in the session view and exporting them (`python -m aegis.labels export`) removes the circularity between criteria and rules.
3. **A stricter Cowrie user database** would produce failed-login telemetry and let the credential-guessing rules be measured.
