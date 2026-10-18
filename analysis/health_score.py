"""Owner: Brady — Compute the network health score and its trend over time.

Usage:

    from analysis.health_score import health_score, health_trend

    cards = db.list_cards(limit=10_000, since=now - timedelta(days=7))
    health_score(cards)        # -> HealthScore(score=75, label="Fair", color="yellow")
    health_trend(cards, days=7)  # -> [(date, score), ...] oldest first

Starts at 100 and loses PENALTY points per unacknowledged card from the last
24 hours (floor 0). A card counts once however many repeats dedup folded into
it, so one noisy device can't sink the score alone; acknowledging a card
raises the score back.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Iterable, Optional

from analysis.models import AlertCard, Severity, utcnow

MAX_SCORE = 100
WINDOW = timedelta(hours=24)
PENALTY = {Severity.HIGH: 25, Severity.MEDIUM: 10, Severity.LOW: 3}
#(lowest score for the label, label, color), best first
LABELS = ((80, "Good", "green"), (50, "Fair", "yellow"), (0, "At risk", "red"))


@dataclass
class HealthScore:
    score: int
    label: str
    color: str
    high: int = 0  #how many cards of each severity were counted
    medium: int = 0
    low: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def health_score(cards: Iterable[AlertCard], now: Optional[datetime] = None) -> HealthScore:
    """Score from cards in the 24 hours up to `now`."""
    now = now or utcnow()
    counted = {s: 0 for s in Severity}
    for card in cards:
        if not card.acknowledged and now - WINDOW < card.timestamp <= now:
            counted[card.severity] += 1

    score = MAX_SCORE - sum(PENALTY[s] * n for s, n in counted.items())
    score = max(0, score)
    label, color = label_for(score)
    return HealthScore(
        score=score,
        label=label,
        color=color,
        high=counted[Severity.HIGH],
        medium=counted[Severity.MEDIUM],
        low=counted[Severity.LOW],
    )


def health_trend(
    cards: Iterable[AlertCard], days: int = 7, now: Optional[datetime] = None
) -> list[tuple[date, int]]:
    """Score at the end of each of the last `days` days (UTC), oldest first.

    Today's entry is the current score. Acknowledged cards are skipped for past
    days too, since we don't record when they were acknowledged.
    """
    now = now or utcnow()
    cards = list(cards)
    today = now.astimezone(timezone.utc).date()
    trend = []
    for offset in range(days - 1, -1, -1):
        day = today - timedelta(days=offset)
        end = now if offset == 0 else datetime.combine(day, time.max, tzinfo=timezone.utc)
        trend.append((day, health_score(cards, now=end).score))
    return trend


def label_for(score: int) -> tuple[str, str]:
    for floor, label, color in LABELS:
        if score >= floor:
            return label, color
    return LABELS[-1][1], LABELS[-1][2]