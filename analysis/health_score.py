"""Owner: Brady — Compute the network health score and its trend over time.

Usage:

    from analysis.issues import list_issues
    issues = list_issues(db)
    health_score(issues)          # -> HealthScore(score=80, label="Good", color="green")
    points_for(issue, issues)     # -> 10: what fixing this one issue would win back
    health_trend(issues, days=7)  # -> [(date, score), ...] oldest first

Starts at 100. Each open issue (one device + one problem, however many times
it happened) active in the last 7 days takes PENALTY percent of the points
that are left (a lone "Act now" issue: 100 -> 75), and each category counts
at most CATEGORY_CAP issues, so one noisy detector can't sink the grade
alone. Taking a share of what's left means the score never bottoms out at 0,
so fixing any one problem visibly helps. Handled issues don't count. Cards (AlertCard) work too: each counts as its own issue
unless it carries a `key`.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Iterable, Optional

from analysis.models import Severity, utcnow

MAX_SCORE = 100
WINDOW = timedelta(days=7)
PENALTY = {Severity.HIGH: 25, Severity.MEDIUM: 10, Severity.LOW: 3}
CATEGORY_CAP = 2  #a category takes at most this many of its worst issues' points

#(lowest score for the label, label, color), best first
LABELS = ((80, "Good", "green"), (50, "Fair", "yellow"), (0, "At risk", "red"))


@dataclass
class HealthScore:
    score: int
    label: str
    color: str
    high: int = 0  #how many issues of each severity were counted
    medium: int = 0
    low: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def health_score(items: Iterable[Any], now: Optional[datetime] = None) -> HealthScore:
    """Score from the open issues active in the WINDOW up to `now`."""
    now = now or utcnow()
    active = _active(items, now)
    counted = {s: 0 for s in Severity}
    for item in active:
        counted[Severity(item.severity)] += 1
    score = round(MAX_SCORE * _remaining(active))
    label, color = label_for(score)
    return HealthScore(
        score=score, label=label, color=color,
        high=counted[Severity.HIGH], medium=counted[Severity.MEDIUM], low=counted[Severity.LOW],
    )


def points_for(item: Any, items: Iterable[Any], now: Optional[datetime] = None) -> int:
    """Points the score would gain if `item` were handled."""
    now = now or utcnow()
    items = list(items)
    rest = [i for i in items if i is not item]
    return health_score(rest, now).score - health_score(items, now).score


def health_trend(
    items: Iterable[Any], days: int = 7, now: Optional[datetime] = None
) -> list[tuple[date, int]]:
    """Score at the end of each of the last `days` days (UTC), oldest first.

    Today's entry is the current score. Handled issues are skipped for past
    days too, since we don't record when they were handled.
    """
    now = now or utcnow()
    items = list(items)
    today = now.astimezone(timezone.utc).date()
    trend = []
    for offset in range(days - 1, -1, -1):
        day = today - timedelta(days=offset)
        end = now if offset == 0 else datetime.combine(day, time.max, tzinfo=timezone.utc)
        trend.append((day, health_score(items, now=end).score))
    return trend


def label_for(score: int) -> tuple[str, str]:
    for floor, label, color in LABELS:
        if score >= floor:
            return label, color
    return LABELS[-1][1], LABELS[-1][2]


def _active(items: Iterable[Any], now: datetime) -> list[Any]:
    out = []
    for item in items:
        if getattr(item, "acknowledged", False):
            continue
        first = getattr(item, "first_seen", None) or item.timestamp
        last = getattr(item, "last_seen", None) or item.timestamp
        if first <= now and last > now - WINDOW:
            out.append(item)
    return out


def _remaining(active: list[Any]) -> float:
    """Share of the points left after each counted issue takes its PENALTY percent."""
    by_category: dict[Any, list[int]] = {}
    for item in active:
        category = getattr(item.category, "value", item.category)
        by_category.setdefault(category, []).append(PENALTY[Severity(item.severity)])
    left = 1.0
    for penalties in by_category.values():
        for p in sorted(penalties, reverse=True)[:CATEGORY_CAP]:
            left *= 1 - p / 100
    return left
