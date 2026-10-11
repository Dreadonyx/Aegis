"""Run detection after ingestion and persist findings and incidents.

Detection is a separate layer from ingestion: a detection failure is logged and marks the dataset for
recomputation, but never rolls back or blocks committed events."""
import json
import logging
import os
import threading
import time
from pathlib import Path

from aegis import statistics
from aegis.engine import catalog, detect, fingerprint, validate_config

DATASETS = ("demo", "imported", "live")
STATS_INTERVAL = 60  # live batches refresh statistics at most this often; reads catch up immediately
log = logging.getLogger("aegis.analysis")


def load_config(path=None):
    """Detection settings from a JSON file (AEGIS_DETECTION_CONFIG); defaults when unset."""
    path = path or os.environ.get("AEGIS_DETECTION_CONFIG")
    if not path:
        return validate_config({})
    try:
        overrides = json.loads(Path(path).read_text())
    except (OSError, ValueError) as error:
        raise ValueError(f"AEGIS_DETECTION_CONFIG could not be read as JSON: {type(error).__name__}") from None
    return validate_config(overrides)


class Analyzer:
    def __init__(self, store, config=None):
        self.store = store
        self.config = validate_config(config or {})
        self.fingerprint = fingerprint(self.config)
        self.stats_fingerprint = statistics.fingerprint(self.config)
        self.catalog = catalog(self.config)
        self.lock = threading.Lock()
        self.stats_run = {}

    def analyze(self, dataset, src_ips=None):
        """Recompute detection for some source addresses of a dataset, or all of it. Returns a summary,
        or None when detection failed (the dataset is then marked for recomputation)."""
        try:
            with self.lock:
                return self.store.replace_detection(dataset, src_ips, lambda events: detect(events, self.config), self.fingerprint)
        except Exception as error:
            log.exception("Detection failed for dataset %s", dataset)
            try:
                self.store.mark_dirty(dataset, f"{type(error).__name__} during detection")
            except Exception:
                log.exception("Could not mark dataset %s for recomputation", dataset)
            return None

    def statistics(self, dataset):
        """Recompute statistical findings and baselines for a dataset. Failures are isolated like detection's."""
        try:
            with self.lock:
                self.stats_run[dataset] = time.monotonic()
                return self.store.replace_signals(dataset, lambda events: statistics.compute(events, self.config), self.stats_fingerprint)
        except Exception as error:
            log.exception("Statistics failed for dataset %s", dataset)
            try:
                self.store.mark_stats_dirty(dataset, f"{type(error).__name__} during statistics")
            except Exception:
                log.exception("Could not mark statistics for dataset %s for recomputation", dataset)
            return None

    def after_commit(self, records, force_statistics=True):
        """Detection for the source addresses touched by newly committed records, then statistics
        (immediately for uploads and replays, at most every STATS_INTERVAL seconds for live batches)."""
        touched = {}
        for record in records:
            event = record["event"] if "event" in record else record
            touched.setdefault(event["source"], set()).add(event["src_ip"])
        results = {dataset: self.analyze(dataset, src_ips) for dataset, src_ips in touched.items()}
        for dataset in touched:
            last = self.stats_run.get(dataset)
            if force_statistics or last is None or time.monotonic() - last >= STATS_INTERVAL:
                self.statistics(dataset)
        return results

    def after_live_commit(self, records):
        return self.after_commit(records, force_statistics=False)

    def ensure_current(self, dataset):
        """Full recomputation when rules or settings changed, a previous run failed, or statistics lag the data."""
        state = self.store.detection_state(dataset)
        result = None
        if not state or state["dirty"] or state["fingerprint"] != self.fingerprint:
            result = self.analyze(dataset)
        stats_state = self.store.stats_state(dataset)
        if not stats_state or stats_state["dirty"] or stats_state["fingerprint"] != self.stats_fingerprint \
                or stats_state["event_count"] != self.store.event_count(dataset):
            self.statistics(dataset)
        return result

    def refresh(self):
        return {dataset: self.ensure_current(dataset) for dataset in DATASETS}
