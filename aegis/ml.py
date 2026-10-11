"""Layer C: optional Isolation Forest anomaly scoring over session features. Off by default.

Models are trained only on purpose, by an operator, over an explicit time window, never automatically:
attacker-controlled traffic can poison a baseline. Each model ships with a manifest (features, parameters,
training window and data, library versions, calibrated threshold, file digest). Scoring fails closed: a
missing, tampered, stale, or incompatible model yields no ML output and a recorded reason.

    python -m aegis.ml train --db data/aegis.sqlite3 --dataset live --until 2026-10-20T00:00:00Z --out models/live-2026-10-20
    python -m aegis.ml train --labeled path/to/dataset --benign-only --out models/labeled-v1
    python -m aegis.ml inspect models/live-2026-10-20

The score is -IsolationForest.score_samples (higher is more unusual). It is not a probability; the facts
state how a session ranks against the training sessions instead."""
import argparse
import bisect
import hashlib
import json
import sqlite3
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path

from aegis.features import FEATURE_VERSION, FEATURES, NAMES, session_features, vector

MODEL_FORMAT = 1
ML_VERSION = "1"
PARAMS = {"n_estimators": 200, "max_samples": "auto", "contamination": "auto", "random_state": 42}
MIN_TRAINING_SESSIONS = 50
INTERPRETATION = ("Isolation Forest score (higher is more unusual than the training sessions). Not a probability of "
                  "maliciousness; the training percentile is the honest reading.")


class ModelUnavailable(Exception):
    """Raised with a status (missing, integrity, stale, incompatible, rejected, dependency) and a reason."""

    def __init__(self, status, reason):
        super().__init__(reason)
        self.status, self.reason = status, reason


def _libraries():
    try:
        import joblib
        import numpy
        import sklearn
        from sklearn.ensemble import IsolationForest
    except ImportError:
        raise ModelUnavailable("dependency", "scikit-learn is not installed; install requirements-ml.txt to use the ML layer") from None
    return joblib, numpy, sklearn, IsolationForest


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def train(rows, training, out_dir, threshold_quantile=0.99):
    """Fit a model on feature rows and write model.joblib plus model.json. `training` describes the data
    (source, dataset or labeled set, window, synthetic flag) and is recorded verbatim in the manifest."""
    joblib, numpy, sklearn, IsolationForest = _libraries()
    if len(rows) < MIN_TRAINING_SESSIONS:
        raise ValueError(f"Training needs at least {MIN_TRAINING_SESSIONS} sessions; got {len(rows)}")
    if not 0.5 <= threshold_quantile < 1:
        raise ValueError("threshold_quantile must be at least 0.5 and below 1")
    matrix = numpy.array([vector(r["values"]) for r in rows])
    model = IsolationForest(**PARAMS).fit(matrix)
    scores = sorted(float(s) for s in -model.score_samples(matrix))
    threshold = float(numpy.quantile(scores, threshold_quantile))
    columns = list(zip(*[[r["values"][n] for n in NAMES] for r in rows]))
    medians = [statistics.median(c) for c in columns]
    scales = [statistics.median([abs(v - m) for v in c]) * 1.4826 or 1.0 for c, m in zip(columns, medians)]
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=False)
    trained_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    # Fields that change how scores are read live inside the digest-protected bundle too, so an edited
    # model.json is detected rather than trusted.
    core = core_fields(FEATURE_VERSION, threshold_quantile, round(threshold, 6), trained_at, bool(training.get("synthetic")))
    joblib.dump({"model": model, "training_scores": scores, "medians": medians, "scales": scales, "core": core}, out / "model.joblib")
    digest = sha256_file(out / "model.joblib")
    manifest = {
        "format": MODEL_FORMAT, "model_version": f"if-{trained_at[:10]}-{digest[:8]}", "ml_version": ML_VERSION,
        "algorithm": "sklearn.ensemble.IsolationForest", "params": PARAMS, "feature_version": FEATURE_VERSION,
        "features": [{"name": n, "description": d, "transform": "log1p"} for n, d in FEATURES],
        "trained_at": trained_at, "training": {**training, "sessions": len(rows)},
        "threshold": {"quantile": threshold_quantile, "score": round(threshold, 6),
                      "meaning": f"Flags sessions scoring above {threshold_quantile:.0%} of training sessions."},
        "libraries": {"scikit-learn": sklearn.__version__, "numpy": numpy.__version__, "joblib": joblib.__version__},
        "model_sha256": digest, "interpretation": INTERPRETATION,
    }
    (out / "model.json").write_text(json.dumps(manifest, indent=2))
    return manifest


def core_fields(feature_version, quantile, threshold, trained_at, synthetic):
    return {"feature_version": feature_version, "threshold_quantile": quantile, "threshold": threshold, "trained_at": trained_at, "synthetic": synthetic}


class Model:
    def __init__(self, manifest, bundle):
        self.manifest, self.model = manifest, bundle["model"]
        self.training_scores, self.medians, self.scales = bundle["training_scores"], bundle["medians"], bundle["scales"]
        self.threshold = manifest["threshold"]["score"]

    def score(self, rows):
        _, numpy, _, _ = _libraries()
        if not rows:
            return []
        scores = -self.model.score_samples(numpy.array([vector(r["values"]) for r in rows]))
        results = []
        for row, score in zip(rows, scores):
            score = float(score)
            rank = bisect.bisect_right(self.training_scores, score) / len(self.training_scores)
            deviations = sorted(((abs(row["values"][n] - m) / s, n, row["values"][n], m) for n, m, s in zip(NAMES, self.medians, self.scales)), reverse=True)
            results.append({"score": round(score, 6), "training_percentile": round(rank * 100, 2), "flagged": score > self.threshold,
                            "context": [{"feature": n, "observed": round(v, 3), "training_median": round(m, 3)} for d, n, v, m in deviations[:3] if d > 0]})
        return results


def load(model_dir, max_age_days, dataset=None):
    """Verify, then load. Nothing is unpickled until the manifest and file digest check out."""
    if not model_dir:
        raise ModelUnavailable("missing", "No model directory configured (AEGIS_ML_MODEL_DIR)")
    directory = Path(model_dir)
    try:
        manifest = json.loads((directory / "model.json").read_text())
    except (OSError, ValueError):
        raise ModelUnavailable("missing", "model.json is missing or unreadable") from None
    if manifest.get("format") != MODEL_FORMAT:
        raise ModelUnavailable("incompatible", f"Unsupported model format {manifest.get('format')}")
    path = directory / "model.joblib"
    if not path.is_file():
        raise ModelUnavailable("missing", "model.joblib is missing")
    if sha256_file(path) != manifest.get("model_sha256"):
        raise ModelUnavailable("integrity", "model.joblib does not match the digest in model.json; refusing to load it")
    if manifest.get("feature_version") != FEATURE_VERSION:
        raise ModelUnavailable("stale", f"Model uses feature version {manifest.get('feature_version')}; this release computes version {FEATURE_VERSION}")
    joblib, numpy, sklearn, _ = _libraries()
    if manifest.get("libraries", {}).get("scikit-learn") != sklearn.__version__:
        raise ModelUnavailable("incompatible", f"Model was saved with scikit-learn {manifest.get('libraries', {}).get('scikit-learn')}; "
                                               f"installed is {sklearn.__version__}. Retrain the model.")
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(manifest["trained_at"])).days
    if age > max_age_days:
        raise ModelUnavailable("stale", f"Model is {age} days old; the limit is {max_age_days}. Retrain on a reviewed window.")
    bundle = joblib.load(path)  # safe to unpickle: the file matches the recorded digest
    expected = core_fields(manifest.get("feature_version"), manifest.get("threshold", {}).get("quantile"),
                           manifest.get("threshold", {}).get("score"), manifest.get("trained_at"), bool(manifest.get("training", {}).get("synthetic")))
    if bundle.get("core") != expected or not manifest.get("model_version", "").endswith(manifest["model_sha256"][:8]):
        raise ModelUnavailable("integrity", "model.json disagrees with the verified model file (edited manifest); refusing to use it")
    if dataset not in (None, "demo") and bundle["core"]["synthetic"]:
        raise ModelUnavailable("rejected", "A model trained on synthetic data cannot score observed telemetry")
    return Model(manifest, bundle)


def finding(row, result, manifest, config):
    from aegis.statistics import EVIDENCE_LIMIT
    evidence = row["events"]
    ids = [e["id"] for e in evidence[:EVIDENCE_LIMIT]]
    dataset, key = row["dataset"], row["session_key"]
    facts = {"model_version": manifest["model_version"], "feature_version": manifest["feature_version"], "score": result["score"],
             "threshold": manifest["threshold"], "training_percentile": result["training_percentile"],
             "training": {k: manifest["training"].get(k) for k in ("dataset", "since", "until", "sessions", "synthetic", "source")},
             "features": row["values"], "largest_deviations": result["context"],
             "deviation_note": "Features furthest from the training medians, for context. Isolation Forest does not attribute its score to features.",
             "interpretation": INTERPRETATION}
    explanation = (f"Session {row['session']} scored {result['score']:.3f}, above the model threshold and more unusual than "
                   f"{result['training_percentile']:.1f}% of {manifest['training']['sessions']} training sessions.")
    return {
        "finding_id": hashlib.sha256(json.dumps([dataset, "ml", "ML-001", manifest["model_version"], key]).encode()).hexdigest()[:20],
        "engine": "ml", "rule_id": "ML-001", "id": "ML-001", "rule_version": manifest["model_version"], "title": "Session unusual for the trained model",
        "name": "Session unusual for the trained model", "description": catalog(config)[0]["description"], "category": "anomaly", "severity": "low",
        "severity_rationale": catalog(config)[0]["severity_rationale"], "technique": None, "dataset": dataset,
        "observed_at": row["last_seen"], "first_seen": row["first_seen"], "last_seen": row["last_seen"], "anchor_event_id": evidence[-1]["id"],
        "scope": {"type": "session", "session": row["session"], "session_key": key, "sensor": row["sensor"], "src_ip": row["src_ip"]},
        "session": row["session"], "session_key": key, "sensor": row["sensor"], "src_ip": row["src_ip"],
        "evidence_event_ids": ids, "evidence_ids": ids, "rationale": {"explanation": explanation, "facts": facts},
        "score": result["score"], "score_type": "isolation_forest_anomaly", "dedup_key": key, "status": "active",
    }


def catalog(config):
    return [{"id": "ML-001", "name": "Session unusual for the trained model", "engine": "ml", "version": ML_VERSION, "severity": "low",
             "technique": None, "category": "anomaly",
             "description": "An operator-trained Isolation Forest scores each session's features; sessions above the model's calibrated "
                            "threshold are reported. Off unless ml_enabled is true and a verified model is configured.",
             "severity_rationale": "Unusual relative to the training sessions. Not evidence of malicious intent, and not a probability."}]


def compute(events, config, model_dir, cache=None):
    """ML findings for a dataset, or an empty result with the reason the model could not be used."""
    if not config["ml_enabled"]:
        return {"findings": [], "status": "disabled", "detail": "ML scoring is off (ml_enabled is false)."}
    dataset = events[0]["source"] if events else None
    try:
        model = cache(model_dir, config["ml_max_model_age_days"], dataset) if cache else load(model_dir, config["ml_max_model_age_days"], dataset)
    except ModelUnavailable as error:
        return {"findings": [], "status": error.status, "detail": error.reason}
    rows = session_features(events, config)
    results = model.score(rows)
    findings = [finding(row, result, model.manifest, config) for row, result in zip(rows, results) if result["flagged"]]
    return {"findings": findings, "status": "ok", "detail": f"Scored {len(rows)} sessions with {model.manifest['model_version']}.",
            "scored_sessions": len(rows), "model": {k: model.manifest[k] for k in ("model_version", "trained_at", "feature_version", "threshold", "training")}}


def _rows_from_db(path, dataset, since, until, config):
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        where, args = ["source=?"], [dataset]
        if since:
            where.append("event_time >= ?")
            args.append(since)
        where.append("event_time < ?")
        args.append(until)
        events = [json.loads(r[0]) for r in db.execute(f"SELECT body FROM events WHERE {' AND '.join(where)}", args)]
    finally:
        db.close()
    return session_features(events, config)


def _utc(value, name):
    try:
        when = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if when.tzinfo is None:
            raise ValueError()
    except ValueError:
        raise ValueError(f"{name} must be an ISO 8601 time with a timezone") from None
    return when.astimezone(timezone.utc).isoformat(timespec="microseconds")


def main(argv=None):
    from aegis.analysis import load_config
    parser = argparse.ArgumentParser(description="Train or inspect Aegis Isolation Forest models.")
    commands = parser.add_subparsers(dest="command", required=True)
    t = commands.add_parser("train", help="Train a model over an explicit, reviewed window")
    source = t.add_mutually_exclusive_group(required=True)
    source.add_argument("--db", help="Aegis SQLite database (opened read-only)")
    source.add_argument("--labeled", help="Labeled dataset directory (see docs/EVALUATION.md)")
    t.add_argument("--dataset", choices=("live", "imported", "demo"), help="Dataset to train on (with --db)")
    t.add_argument("--since", help="Start of the training window (ISO 8601, optional)")
    t.add_argument("--until", help="End of the training window (ISO 8601, required with --db)")
    t.add_argument("--benign-only", action="store_true", help="With --labeled, train only on sessions labeled benign")
    t.add_argument("--allow-synthetic", action="store_true", help="Permit synthetic training data; the model is marked synthetic")
    t.add_argument("--threshold-quantile", type=float, default=0.99)
    t.add_argument("--config", help="Detection settings JSON")
    t.add_argument("--out", required=True, help="New directory for model.joblib and model.json")
    i = commands.add_parser("inspect", help="Verify a model and print its manifest")
    i.add_argument("model_dir")
    i.add_argument("--config")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        if args.command == "inspect":
            model = load(args.model_dir, config["ml_max_model_age_days"])
            print(json.dumps({**model.manifest, "verified": True}, indent=2))
            return 0
        if args.db:
            if not args.dataset or not args.until:
                raise ValueError("--db training needs --dataset and an explicit --until (the end of the window you reviewed)")
            synthetic = args.dataset == "demo"
            if synthetic and not args.allow_synthetic:
                raise ValueError("The demo dataset is synthetic; pass --allow-synthetic to train a model marked synthetic")
            since = _utc(args.since, "--since") if args.since else None
            until = _utc(args.until, "--until")
            rows = _rows_from_db(args.db, args.dataset, since, until, config)
            training = {"source": "database", "dataset": args.dataset, "since": since, "until": until, "synthetic": synthetic}
        else:
            from aegis import labeled_eval
            manifest, events, rejected, labels, files = labeled_eval.load(args.labeled)
            synthetic = bool(manifest.get("synthetic"))
            if synthetic and not args.allow_synthetic:
                raise ValueError("The labeled dataset is marked synthetic; pass --allow-synthetic to train a model marked synthetic")
            rows = session_features(events, config)
            if args.benign_only:
                benign = {(l.get("sensor"), l["session"]) for l in labels if l["label"] == "benign"}
                rows = [r for r in rows if (r["sensor"], r["session"]) in benign or (None, r["session"]) in benign]
            times = sorted(e["timestamp"] for e in events)
            training = {"source": "labeled", "dataset": f"{manifest.get('name')} v{manifest.get('version')}", "files_sha256": files,
                        "benign_only": args.benign_only, "since": times[0] if times else None, "until": times[-1] if times else None,
                        "synthetic": synthetic}
        result = train(rows, training, args.out, args.threshold_quantile)
    except (ModelUnavailable, ValueError, OSError, sqlite3.Error) as error:
        print(f"ML command failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps({k: result[k] for k in ("model_version", "trained_at", "training", "threshold", "model_sha256")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
