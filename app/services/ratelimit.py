"""Tiny dependency-free in-memory rate limiter + lockout.

Used to throttle credential-guessing on /login and abuse of /enroll. State is
per-process (good enough for a single-instance deployment); it is intentionally
simple — a sliding window of recent hit timestamps per key (usually a client IP).
"""
from __future__ import annotations

import threading
import time


class RateLimiter:
    def __init__(self, max_hits: int, window_seconds: float, lockout_seconds: float = 0.0):
        self.max_hits = max_hits
        self.window = window_seconds
        self.lockout = lockout_seconds
        self._hits: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> bool:
        """Return True if the action is allowed, False if it must be blocked.

        A blocked caller is recorded; once over the limit, callers stay locked
        out for ``lockout_seconds`` (if set) or until the window drains.
        """
        now = time.monotonic()
        with self._lock:
            locked = self._locked_until.get(key)
            if locked is not None:
                if now < locked:
                    return False
                del self._locked_until[key]

            hits = [t for t in self._hits.get(key, []) if now - t < self.window]
            hits.append(now)
            self._hits[key] = hits

            if len(hits) > self.max_hits:
                if self.lockout:
                    self._locked_until[key] = now + self.lockout
                return False
            return True

    def reset(self, key: str) -> None:
        """Clear a key's history (e.g. after a successful login)."""
        with self._lock:
            self._hits.pop(key, None)
            self._locked_until.pop(key, None)


# 10 attempts / 5 min per IP, then a 5-minute lockout.
login_limiter = RateLimiter(max_hits=10, window_seconds=300, lockout_seconds=300)
# 20 enrollments / minute per IP.
enroll_limiter = RateLimiter(max_hits=20, window_seconds=60)
