import threading
import time
from collections import defaultdict


class RateLimitExceeded(Exception):
    pass


class RateLimiter:
    """In-memory sliding window. One uvicorn worker is enough for this project.

    The counts reset when the process restarts, and they are not shared if more
    than one worker is ever added.
    """

    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._hits: dict[int, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def check(self, key: int) -> None:
        now = time.monotonic()
        with self._lock:
            recent = [hit for hit in self._hits[key] if now - hit < self.window_seconds]
            if len(recent) >= self.limit:
                self._hits[key] = recent
                raise RateLimitExceeded
            recent.append(now)
            self._hits[key] = recent
