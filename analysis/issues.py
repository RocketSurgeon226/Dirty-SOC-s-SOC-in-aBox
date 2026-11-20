"""Owner: Brady — Group cards into issues: one per device + problem, however many cards.

Usage:

    from analysis.issues import list_issues, set_issue_acknowledged
    issues = list_issues(db)                      # open issues, worst + newest first
    issues = list_issues(db, acknowledged=True)   # handled ones, for History
    set_issue_acknowledged(db, issue.id, True)    # "Got it" on every card in the issue

The pipeline already folds repeats into the open card, but older databases (and
an issue that came back after "Got it") can hold several cards for one problem.
The dashboard shows issues, so "Adam's PC is sending a lot of data" is one card
with a start date and a running count, not forty.

Text comes from the current templates unless the LLM reworded the card, so
wording fixes reach cards that were stored before the fix. Severity is
recomputed the same way (see analysis/severity.py).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Optional

from analysis.models import Alert, AlertSource, Category, Severity, _parse_dt, utcnow
from analysis.severity import assign_severity
from analysis.storage.db import Database, _row_device_key
from analysis.translate.templates import scan_direction, template_for_alert

OPEN_WINDOW = timedelta(days=7)  #open issues with no activity for longer than this drop off the home page
HANDLED_WINDOW = timedelta(days=30)
SEVERITY_RANK = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}


@dataclass
class Issue:
    key: tuple[str, str]  #(device key, category)
    alert_ids: list[str]  #newest activity first; alert_ids[0] is the issue's id
    category: Category
    severity: Severity
    device_name: str
    description: str
    action: str
    meaning: str
    count: int
    first_seen: datetime
    last_seen: datetime
    acknowledged: bool
    device_mac: Optional[str] = None
    device_ip: Optional[str] = None
    direction: Optional[str] = None
    site: Optional[str] = None  #where a password was sent, if known
    llm_enhanced: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return self.alert_ids[0]

    @property
    def timestamp(self) -> datetime:  #so code written for cards keeps working
        return self.last_seen

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "alert_ids": list(self.alert_ids),
            "category": self.category.value,
            "severity": self.severity.value,
            "device_name": self.device_name,
            "device_mac": self.device_mac,
            "device_ip": self.device_ip,
            "description": self.description,
            "action": self.action,
            "meaning": self.meaning,
            "count": self.count,
            "cards": len(self.alert_ids),
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "timestamp": self.last_seen.isoformat(),
            "acknowledged": self.acknowledged,
            "direction": self.direction,
            "site": self.site,
            "llm_enhanced": self.llm_enhanced,
        }


def list_issues(
    db: Database, acknowledged: bool = False, now: Optional[datetime] = None
) -> list[Issue]:
    """Open (or, with acknowledged=True, handled) issues, worst first, then newest."""
    now = now or utcnow()
    since = now - (HANDLED_WINDOW if acknowledged else OPEN_WINDOW)
    issues = group_rows(db.issue_rows(acknowledged=acknowledged, since=since))
    issues.sort(key=lambda i: (SEVERITY_RANK[i.severity], -i.last_seen.timestamp()))
    return issues


def group_rows(rows: list[dict[str, Any]]) -> list[Issue]:
    """Rows from Database.issue_rows (newest activity first) -> issues."""
    by_key: dict[tuple[str, str], Issue] = {}
    for row in rows:
        device_key = _row_device_key(row) or "card:" + row["alert_id"]
        key = (device_key, row["category"])
        first, last = _parse_dt(row["timestamp"]), _parse_dt(row["last_seen"])
        issue = by_key.get(key)
        if issue is None:
            by_key[key] = _issue_from_row(key, row, first, last)
            continue
        issue.alert_ids.append(row["alert_id"])
        issue.count += int(row["count"] or 1)
        issue.first_seen = min(issue.first_seen, first)
        issue.last_seen = max(issue.last_seen, last)
        if issue.device_name.lower().startswith("unrecognized"):
            issue.device_name = row["device_name"]
        if not issue.site:
            issue.site = _site(row)
    return list(by_key.values())


def set_issue_acknowledged(db: Database, alert_id: str, acknowledged: bool = True) -> bool:
    """Apply "Got it" / "Not fixed yet" to every card in the issue `alert_id` belongs to.
    Returns False if there's no such card."""
    rows = db.issue_rows(acknowledged=None)
    target = next((r for r in rows if r["alert_id"] == alert_id), None)
    if target is None:
        return False
    key = (_row_device_key(target), target["category"])
    if key[0] is None:
        ids = [alert_id]
    else:
        ids = [r["alert_id"] for r in rows
               if (_row_device_key(r), r["category"]) == key and bool(r["acknowledged"]) != acknowledged]
    db.set_acknowledged_many(ids or [alert_id], acknowledged)
    return True


def issue_device_key(db: Database, alert_id: str) -> Optional[tuple[str, str]]:
    """(device key, category) for the card `alert_id`, for muting."""
    row = next((r for r in db.issue_rows(acknowledged=None) if r["alert_id"] == alert_id), None)
    if row is None:
        return None
    device_key = _row_device_key(row)
    return (device_key, row["category"]) if device_key else None


def _issue_from_row(key: tuple[str, str], row: dict[str, Any], first: datetime, last: datetime) -> Issue:
    alert = Alert(category=row["category"], source=AlertSource.PYTHON, details=row["details"] or {})
    assign_severity(alert)
    template = template_for_alert(alert)
    llm = bool(row["llm_enhanced"])
    category = Category(row["category"])
    return Issue(
        key=key,
        alert_ids=[row["alert_id"]],
        category=category,
        severity=alert.severity,
        device_name=row["device_name"],
        description=row["description"] if llm else template.description,
        action=row["action"] if llm else template.action,
        meaning=template.meaning,
        count=int(row["count"] or 1),
        first_seen=first,
        last_seen=last,
        acknowledged=bool(row["acknowledged"]),
        device_mac=row.get("device_mac"),
        device_ip=(row["details"] or {}).get("home_ip") or row.get("src_ip"),
        direction=scan_direction(alert) if category == Category.PORT_SCAN else None,
        site=_site(row),
        llm_enhanced=llm,
    )


def _site(row: dict[str, Any]) -> Optional[str]:
    if row["category"] != Category.PLAINTEXT_CREDENTIALS.value:
        return None
    details = row.get("details") or {}
    return details.get("hostname") or details.get("remote_ip") or row.get("dest_ip")
