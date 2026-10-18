"""Owner: Brady — Assign low / medium / high severity per the severity mapping table.

Usage:

    from analysis.severity import assign_severity
    assign_severity(alert)
    alert.severity  # -> Severity.HIGH

Severity comes only from the category (SEVERITY_BY_CATEGORY, kept in sync
with README.md), so the same kind of problem always gets the same color.
"""

from __future__ import annotations

from analysis.models import Alert, Category, Severity

SEVERITY_BY_CATEGORY: dict[Category, Severity] = {
    Category.MALICIOUS_CONTACT: Severity.HIGH,
    Category.PLAINTEXT_CREDENTIALS: Severity.HIGH,
    Category.PORT_SCAN: Severity.MEDIUM,
    Category.NEW_DEVICE: Severity.MEDIUM,
    Category.OUTBOUND_VOLUME: Severity.MEDIUM,
    Category.TRACKER_DNS: Severity.LOW,
}


def severity_for(category: Category) -> Severity:
    return SEVERITY_BY_CATEGORY[Category(category)]


def assign_severity(alert: Alert) -> Alert:
    alert.severity = severity_for(alert.category)
    return alert
