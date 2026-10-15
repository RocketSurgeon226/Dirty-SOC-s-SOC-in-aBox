"""Owner: Brady — Remove repeated alerts (same device + category within a time window).

Usage:

    from analysis.dedup import Deduplicator

    dedup = Deduplicator(settings.dedup.window_minutes)
    alert, is_new = dedup.add(alert)
    #is_new=True  -> first time in the window: build a new card
    #is_new=False -> `alert` is the earlier alert, with count and last_seen
    #                updated: refresh that card instead of adding another

Two alerts are repeats when they share Alert.dedup_key (device + category) and
the new one arrives within window_minutes of the last time that alert was
seen. The window slides: a port scan that keeps going stays one card with a
growing count instead of a fresh card every 15 minutes.

Times are the alerts' own timestamps (from eve.json), not the wall clock, so
replaying an old log dedups the same way it did live.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from threading import Lock
from typing import Optional

from analysis.models import Alert, Category


class Deduplicator:
    """Remembers recent alerts and folds repeats into them."""

    def __init__(self, window_minutes: float) -> None:
        if window_minutes <= 0:
            raise ValueError("window_minutes must be greater than 0")
        self.window = timedelta(minutes=window_minutes)
        self._recent: dict[tuple[Optional[str], Category], Alert] = {}
        self._latest: Optional[datetime] = None
        self._lock = Lock()  # detectors may add alerts from other threads

    def add(self, alert: Alert) -> tuple[Alert, bool]:
        """Record `alert`. Returns (alert to show, True if it's new)."""
        with self._lock:
            when = alert.last_seen or alert.timestamp
            self._prune(when)

            existing = self._recent.get(alert.dedup_key)
            if existing is not None and abs(when - existing.last_seen) <= self.window:
                existing.merge(alert)
                return existing, False

            self._recent[alert.dedup_key] = alert
            return alert, True

    def __len__(self) -> int:
        return len(self._recent)

    def _prune(self, when: datetime) -> None:
        """Forget alerts whose window closed before the newest time seen."""
        if self._latest is None or when > self._latest:
            self._latest = when
        cutoff = self._latest - self.window
        stale = [k for k, a in self._recent.items() if a.last_seen < cutoff]
        for key in stale:
            del self._recent[key]
