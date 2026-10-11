"""Run detection after ingestion and persist findings and incidents.

Detection is a separate layer from ingestion: a detection failure is logged and marks the dataset for
recomputation, but never rolls back or blocks committed events."""
import json
import logging
import os
import threading
from pathlib import Path

from aegis.engine import catalog, detect, fingerprint, validate_config

DATASETS = ("demo", "imported", "live")
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
        self.catalog = catalog(self.config)
        self.lock = threading.Lock()

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

    def after_commit(self, records):
        """Detection for the source addresses touched by newly committed records."""
        touched = {}
        for record in records:
            event = record["event"] if "event" in record else record
            touched.setdefault(event["source"], set()).add(event["src_ip"])
        return {dataset: self.analyze(dataset, src_ips) for dataset, src_ips in touched.items()}

    def ensure_current(self, dataset):
        """Full recomputation when rules or settings changed, or a previous run failed."""
        state = self.store.detection_state(dataset)
        if not state or state["dirty"] or state["fingerprint"] != self.fingerprint:
            return self.analyze(dataset)
        return None

    def refresh(self):
        return {dataset: self.ensure_current(dataset) for dataset in DATASETS}
