"""Turn Cowrie JSONL bytes into committed evidence. Records are parsed, never executed."""
import hashlib
import json
import logging
import os
import random
import re
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from aegis.engine import normalize

PARSER_VERSION = "2.0.0"
SCHEMA_VERSION = 1
MAX_LINE = 65536
BATCH_LINES = 500
POLL_SECONDS = 2
MAX_BACKOFF = 60

log = logging.getLogger("aegis.ingestion")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def make_record(raw, source, locator=None):
    """Parse one JSONL record (bytes, no line terminator). Raises ValueError or RecursionError."""
    parsed = json.loads(raw)
    event = normalize(parsed, source)
    # Idempotency key: the same record in the same dataset is stored once, however it is formatted.
    canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return dict(event=event, raw=bytes(raw), raw_sha256=sha256(raw), key=sha256(f"{source}\0{canonical}".encode()),
                locator=locator, parser_version=PARSER_VERSION, schema_version=SCHEMA_VERSION)


def quarantine(line, locator, reason):
    # Keep a digest and length, not content: malformed lines may still hold credentials.
    return dict(locator=locator, reason=reason[:200], line_sha256=sha256(line), line_bytes=len(line))


def read_batch(stream, offset=0, discarding=False, source="live", limit=BATCH_LINES):
    """Read up to `limit` complete lines from an open binary stream. An incomplete final line is left
    unread so the writer can finish it. Returns (records, next_offset, discarding, errors)."""
    records, errors = [], []
    stream.seek(offset)
    for _ in range(limit):
        start = offset
        line = stream.readline(MAX_LINE + 1)
        if not line:
            break
        if discarding:  # remainder of an oversized line that was already quarantined
            offset = stream.tell()
            discarding = not line.endswith(b"\n")
            continue
        if len(line) > MAX_LINE:
            offset = stream.tell()
            discarding = not line.endswith(b"\n")
            errors.append(quarantine(line, f"offset:{start}", "Line exceeds 64 KiB"))
            continue
        if not line.endswith(b"\n"):
            break
        offset = stream.tell()
        body = line[:-1]
        if not body.strip():
            continue
        try:
            records.append(make_record(body, source, f"offset:{start}"))
        except (ValueError, RecursionError) as error:
            errors.append(quarantine(body, f"offset:{start}", str(error) or type(error).__name__))
    return records, offset, discarding, errors


def read_log_batch(path, offset=0, discarding=False):
    """Compatibility helper: canonical events only, plus a count of rejected lines."""
    with open(path, "rb") as stream:
        records, offset, discarding, errors = read_batch(stream, offset, discarding)
    return [r["event"] for r in records], offset, discarding, len(errors)


SOURCE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


def validate_source(path, source_id):
    """Fail startup on configuration that would silently collect nothing or the wrong file."""
    if not SOURCE_ID.match(source_id or ""):
        raise ValueError("AEGIS_SOURCE_ID must be 1-64 lowercase letters, digits, '.', '_' or '-'")
    path = Path(path)
    if path.suffix == ".log":
        raise ValueError(f"{path.name} is Cowrie's diagnostic text log; set AEGIS_COWRIE_LOG to the JSON log (cowrie.json)")
    if path.exists() and not path.is_file():
        raise ValueError("AEGIS_COWRIE_LOG must be a regular file")
    if not path.parent.is_dir():
        raise ValueError("AEGIS_COWRIE_LOG's directory does not exist")
    return path


def file_identity(info):
    return f"{info.st_dev}:{info.st_ino}"


class Collector:
    """Tail one Cowrie JSONL file. The checkpoint (file identity + byte offset) is committed in the
    same transaction as the events it covers, so a crash or storage failure rereads, never skips."""

    def __init__(self, store, path, source_id="cowrie-live"):
        self.store, self.path, self.source_id = store, Path(path), source_id
        self.stream = self.identity = None
        self.offset, self.discarding = 0, False
        self.pending = {"rotations": 0, "truncations": 0}
        self.pending_errors = []
        self.failures = 0
        self.thread = None
        self.stop_event = threading.Event()
        self.status = dict(state="starting", detail="Not polled yet", last_read_at=None, last_commit_at=None,
                           last_error_at=None, consecutive_failures=0, worker_restarts=0)
        # Process-lifetime counters for metrics; durable totals live in the sources table.
        self.counters = dict(lines_read=0, records_committed=0, lines_quarantined=0, batches_committed=0, last_batch_seconds=0.0)

    def origin(self):
        return dict(mode="live", source_id=self.source_id, source_type="cowrie", file_id=self.identity)

    def _open(self, path):
        stream = open(path, "rb")
        return stream, file_identity(os.fstat(stream.fileno()))

    def _find_rotated(self, identity):
        """After a restart, locate a previous file renamed by rotation (cowrie.json.YYYY-MM-DD)."""
        for candidate in self.path.parent.glob(self.path.name + ".*"):
            try:
                if candidate.is_file() and file_identity(candidate.stat()) == identity:
                    return candidate
            except OSError:
                continue
        return None

    def _attach(self):
        try:
            stream, identity = self._open(self.path)
        except OSError:
            self.status.update(state="waiting", detail="Waiting for a readable Cowrie log")
            return False
        try:
            saved = self.store.source(self.source_id)
        except Exception:
            stream.close()
            raise
        self.offset, self.discarding = 0, False
        if saved and saved["file_id"] == identity:
            if os.fstat(stream.fileno()).st_size >= saved["file_offset"]:
                self.offset, self.discarding = saved["file_offset"], bool(saved["discarding"])
            else:
                self.pending["truncations"] += 1
        elif saved and saved["file_id"]:
            previous = self._find_rotated(saved["file_id"])
            if previous:
                stream.close()
                stream, identity = self._open(previous)
                self.offset, self.discarding = saved["file_offset"], bool(saved["discarding"])
            else:
                self.pending["rotations"] += 1
                self.pending_errors.append(dict(file_id=saved["file_id"], locator=f"offset:{saved['file_offset']}",
                    reason="Previous log file was not found after restart; lines written after this offset may be missing"))
        self.stream, self.identity = stream, identity
        return True

    def poll(self):
        """Read and commit at most one batch. Returns bytes consumed. Storage errors propagate
        with the in-memory position unchanged, so the same lines are retried."""
        if self.stream is None and not self._attach():
            return 0
        started = time.monotonic()
        try:
            current = file_identity(os.stat(self.path))
        except OSError:
            current = None  # removed or mid-rotation; keep reading the open file
        rotated = current is not None and current != self.identity
        size = os.fstat(self.stream.fileno()).st_size
        if not rotated and size < self.offset:
            self.offset, self.discarding = 0, False
            self.pending["truncations"] += 1
        records, offset, discarding, errors = read_batch(self.stream, self.offset, self.discarding)
        finished = rotated and offset == self.offset and not records and not errors
        if finished and size > offset:
            # A rotated file will never receive the rest of its final line.
            self.stream.seek(offset)
            errors.append(quarantine(self.stream.read(MAX_LINE), f"offset:{offset}", "Incomplete final line in rotated log"))
            offset, discarding = size, False
        errors = self.pending_errors + errors
        if records or errors or offset != self.offset or any(self.pending.values()):
            self.store.commit(records, self.origin(), errors,
                              dict(file_id=self.identity, offset=offset, discarding=discarding, **self.pending))
            self.status["last_commit_at"] = datetime.now(timezone.utc).isoformat()
            self.counters["lines_read"] += len(records) + len(errors) - len(self.pending_errors)
            self.counters["records_committed"] += len(records)
            self.counters["lines_quarantined"] += len(errors) - len(self.pending_errors)
            self.counters["batches_committed"] += 1
            self.counters["last_batch_seconds"] = round(time.monotonic() - started, 6)
        consumed = offset - self.offset
        self.offset, self.discarding = offset, discarding
        self.pending, self.pending_errors = {"rotations": 0, "truncations": 0}, []
        self.status.update(state="running", detail="Watching Cowrie log", last_read_at=datetime.now(timezone.utc).isoformat())
        if finished:
            # Switch directly; going through _attach would find the drained file again by inode.
            try:
                stream, identity = self._open(self.path)
            except OSError:
                return 0
            self.stream.close()
            self.stream, self.identity, self.offset, self.discarding = stream, identity, 0, False
            self.pending["rotations"] += 1
            return 1  # read the new file without waiting
        return consumed

    def bytes_behind(self):
        try:
            return max(0, os.fstat(self.stream.fileno()).st_size - self.offset) if self.stream else None
        except (OSError, ValueError):
            return None

    def run(self):
        while not self.stop_event.is_set():
            delay = POLL_SECONDS
            try:
                if self.poll():
                    delay = 0
                self.failures = 0
            except sqlite3.Error:
                delay = self._failed("storage_unavailable", "Storage unavailable; retrying without advancing the checkpoint")
            except ValueError as error:  # storage limit reached; retrying will not help until an operator acts
                delay = self._failed("blocked", str(error)[:200], MAX_BACKOFF)
            except Exception:
                log.exception("Collector failed unexpectedly")
                self.status["worker_restarts"] += 1
                self._reset()
                delay = self._failed("failed", "Collector error; restarting from the last committed checkpoint")
            self.status["consecutive_failures"] = self.failures
            self.stop_event.wait(delay)
        self._reset()

    def _failed(self, state, detail, delay=None):
        self.failures += 1
        self.status.update(state=state, detail=detail, last_error_at=datetime.now(timezone.utc).isoformat())
        return delay or min(MAX_BACKOFF, 2 ** self.failures) * random.uniform(0.5, 1.0)

    def _reset(self):
        if self.stream:
            self.stream.close()
        self.stream = self.identity = None

    def start(self):
        self.thread = threading.Thread(target=self.run, name="aegis-collector", daemon=True)
        self.thread.start()
        return self

    def stop(self, timeout=5):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout)

    def healthy(self):
        alive = self.thread is None or self.thread.is_alive()
        return alive and self.status["state"] in ("starting", "waiting", "running")
