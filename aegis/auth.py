"""Local accounts, roles, and request limits.

Passwords are hashed with Werkzeug's reviewed implementation (scrypt by default); Aegis contains no custom
password cryptography. Roles are cumulative: viewer (read), analyst (investigate, label, import), admin
(change detection settings). Accounts are managed from the command line only:

    python -m aegis.users add alice --role analyst
"""
import threading
import time

from werkzeug.security import check_password_hash, generate_password_hash

ROLES = ("viewer", "analyst", "admin")
RANK = {role: n for n, role in enumerate(ROLES)}
# Checked when a username does not exist, so response time does not reveal which usernames are valid.
DUMMY_HASH = generate_password_hash("aegis-timing-equaliser")
MIN_PASSWORD = 12


def hash_password(password):
    if not isinstance(password, str) or len(password) < MIN_PASSWORD:
        raise ValueError(f"Passwords need at least {MIN_PASSWORD} characters")
    return generate_password_hash(password)


def verify(stored_hash, password):
    return check_password_hash(stored_hash or DUMMY_HASH, password or "") and stored_hash is not None


def allowed(role, required):
    return role in RANK and RANK[role] >= RANK[required]


class RateLimiter:
    """Fixed-window counters per key, in memory (one process). Returns seconds to wait when over the limit."""

    def __init__(self):
        self.lock, self.windows = threading.Lock(), {}

    def hit(self, key, limit, window):
        now = time.monotonic()
        with self.lock:
            start, count = self.windows.get(key, (now, 0))
            if now - start >= window:
                start, count = now, 0
            count += 1
            self.windows[key] = (start, count)
            if len(self.windows) > 10000:  # bound memory under key churn
                cutoff = now - window
                self.windows = {k: v for k, v in self.windows.items() if v[0] >= cutoff}
            return 0 if count <= limit else int(window - (now - start)) + 1

    def reset(self, key):
        with self.lock:
            self.windows.pop(key, None)
