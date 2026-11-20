"""Owner: Brady — Assign low / medium / high severity per the severity mapping table.

Usage:

    from analysis.severity import assign_severity
    assign_severity(alert)
    alert.severity  # -> Severity.HIGH

Severity comes from the category (SEVERITY_BY_CATEGORY, kept in sync with
README.md), so the same kind of problem always gets the same color. One
exception: a port scan from the internet is LOW ("Just so you know"), since
it happens to every connection; a scan started by a home device stays MEDIUM.
"""

from __future__ import annotations

from analysis.models import Alert, Category, Severity
from analysis.translate.templates import scan_direction

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
    if alert.category == Category.PORT_SCAN and scan_direction(alert) == "inbound":
        alert.severity = Severity.LOW
    return alert
