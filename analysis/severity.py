"""Owner: Brady — Assign low / medium / high severity per the severity mapping table.

Usage:

    from analysis.severity import assign_severity
    assign_severity(alert)
    alert.severity  # -> Severity.HIGH

Severity comes only from the category, matching the table in README.md, so
every homeowner sees the same color for the same kind of problem:

    malicious_contact      high
    plaintext_credentials  high
    port_scan              medium
    new_device             medium
    outbound_volume        medium
    tracker_dns            low
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
    """Look up the severity for a category."""
    return SEVERITY_BY_CATEGORY[Category(category)]


def assign_severity(alert: Alert) -> Alert:
    """Set alert.severity from its category and return the same alert."""
    alert.severity = severity_for(alert.category)
    return alert
