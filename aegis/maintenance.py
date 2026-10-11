"""Scheduled raw-evidence retention. Off unless AEGIS_RAW_RETENTION_DAYS is set.

Purging clears raw bytes older than the retention period. Digests, provenance, and hash-chain links stay,
so the chain still verifies; canonical events, findings, and incidents are not affected."""
import json
import logging
import threading
from datetime import datetime, timedelta, timezone

log = logging.getLogger("aegis.maintenance")


class Retention:
    def __init__(self, store, days, interval=86400):
        if not isinstance(days, int) or days < 1:
            raise ValueError("AEGIS_RAW_RETENTION_DAYS must be a whole number of days, at least 1")
        self.store, self.days, self.interval = store, days, interval
        self.stop_event = threading.Event()
        self.thread = None
        self.status = {"last_run_at": None, "last_purged": 0, "purged_total": 0, "last_error": None}

    def run_once(self, now=None):
        cutoff = ((now or datetime.now(timezone.utc)) - timedelta(days=self.days)).isoformat(timespec="microseconds")
        purged = self.store.purge_raw(cutoff)
        self.status.update(last_run_at=datetime.now(timezone.utc).isoformat(timespec="seconds"), last_purged=purged,
                           purged_total=self.status["purged_total"] + purged, last_error=None)
        log.info(json.dumps({"event": "raw_retention", "cutoff": cutoff, "purged": purged}))
        return purged

    def _run(self):
        while not self.stop_event.is_set():
            try:
                self.run_once()
            except Exception as error:  # retention must never take the service down
                self.status["last_error"] = type(error).__name__
                log.exception("Raw evidence retention failed")
            self.stop_event.wait(self.interval)

    def start(self):
        self.thread = threading.Thread(target=self._run, name="aegis-retention", daemon=True)
        self.thread.start()
        return self

    def stop(self, timeout=5):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout)
