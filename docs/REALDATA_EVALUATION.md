# Real-data evaluation

## Final evaluation with independent labels (2026-10-11)

This supersedes the criteria-labeled results further down. It contains aggregate figures only: no attacker addresses or sensor identifiers.

**Labels:** 177 real sessions (460 events, 2026-10-09 to 2026-10-11 09:36 UTC).
- 175 were labeled by **Codex**, a separate AI model. It worked from a self-contained task folder with session behavior only, no addresses or passwords, and no access to Aegis's rules or suggestions.
- 1 was labeled by the human analyst.
- 1 was marked "unsure" (a scanner that sent a malformed SSH packet) and excluded.

Result: **11 malicious** (every session with an accepted login) and **165 benign** (scanners). A consistency check found every login session labeled malicious with types matching its behavior, every scanner labeled benign, and Codex agreeing with the analyst's label on the overlapping pattern.

**Method:** a forward-chaining backtest. After the first 60 sessions, each block of 25 is scored by an Isolation Forest trained only on earlier sessions; its threshold comes from the model default or from earlier sessions' labels only. Rules are scored on the same 117 out-of-sample sessions (10 malicious). The headline uses the rules as they stood before any real data was seen (INT-001 off). Brackets are 95% Wilson intervals.

| Detector (117 unseen sessions, 10 attacks) | Recall | Precision | False alarms | Accuracy |
|---|---|---|---|---|
| Rules and sequences (frozen) | 0.20 [0.06–0.51] | 1.00 [0.34–1.00] | 0 / 107 | 93.2% |
| ML, default threshold | 0.10 [0.02–0.40] | 1.00 [0.21–1.00] | 0 / 107 | 92.3% |
| **ML, threshold from earlier labels** | **0.70 [0.40–0.89]** | **0.88 [0.53–0.98]** | 1 / 107 | 96.6% |
| **Rules OR ML (earlier labels)** | **0.80 [0.49–0.94]** | **0.89 [0.56–0.98]** | **1 / 107** | **97.4%** |
| Rules including INT-001 (in-sample) | 0.50 [0.24–0.76] | 1.00 [0.57–1.00] | 0 / 107 | 95.7% |
| *Never alert (baseline)* | *0* | *n/a* | *0* | *91.5%* |

All 176 labeled sessions, frozen rules: recall 3/11 (0.27), precision 1.00, 0 false alarms out of 165. With INT-001 (in-sample): 6/11.

### What this shows

1. **Rules are precise but narrow.** No false alarm in any configuration, but the frozen rules caught only 2 of 10 attacks. Every attack here is a login; the rules alert on logins only after failed attempts (which this permissive sensor never records), on specific discovery commands, or on transfers.
2. **Real-data ML adds the most, once its threshold is calibrated.** Trained on real sessions only, with each threshold set from earlier labels, it caught 7 of 10, including 6 the frozen rules missed, at the cost of one false alarm. With its default threshold (the training 99th percentile) it caught only 1 of 10: calibration, not the model, makes the difference.
3. **Rules and ML complement each other.** Together they caught 8 of 10. The SCP upload that ML scored just under its threshold was caught by XFER-002.
4. **Still missed:** two bots that logged in and disconnected immediately, which no rule covers and ML scored just below threshold. Alerting on any accepted honeypot login is the obvious candidate rule, but it was not added here, because tuning to this data would make its score in-sample. Test it on the next collection.
5. **The one false alarm** was a connection that sent nothing (not even an SSH version) and stayed silent for 32 seconds before closing: unusual among the scanners, and arguably worth a look.

### Limits

- The labels are a separate AI's judgments plus one human label, not full human review. Spot-checking the 11 malicious sessions in the session view would strengthen them.
- There are only 10 or 11 attacks, so every interval is wide; one session moves recall by 10 points.
- One sensor and two days of traffic from a permissive Cowrie configuration.
- INT-001 was designed after seeing this data.

### Deployable real-data model

`if-2026-10-11-8478a3fe` was trained on the 87 real sessions before 2026-10-10 12:00 UTC (no synthetic data), and its threshold (0.646) was calibrated for F1 on the 90 labeled sessions after that time (7 malicious). On that calibration set it scored 7/7 with no false alarms, but the threshold was chosen on those same sessions, so that is not an accuracy estimate; the backtest above is. It is kept locally in `models/real-calibrated-2026-10-11/` (not committed). Enable it with `"ml_enabled": true` and `AEGIS_ML_MODEL_DIR` pointing at that folder.

### Recommendation

- For this sensor, rules plus real-data ML with a label-calibrated threshold is the best measured combination. Enable it per deployment only after `python -m aegis.ml calibrate` on labeled data from after the training window. The default stays off, as the specification requires, until a larger labeled sample confirms these numbers.
- Keep labeling as data arrives, and measure INT-001 and an accepted-login rule on sessions collected after 2026-10-11.

---

# Earlier result: automated criteria labels (2026-10-11)


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
