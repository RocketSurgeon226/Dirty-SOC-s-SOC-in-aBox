"""Owner: Brady — Map raw Suricata events to one of the six alert categories.

Usage:

    from analysis.categorize import categorize
    alert = categorize(event, settings.network)  # -> Alert, or None

Only Suricata `alert` events produce malicious_contact, plaintext_credentials,
and port_scan; the other three categories come from the Python detectors.
Alerts that fit no category (ET INFO, ET POLICY, ...) are dropped as noise.

Only metadata is copied. Payloads, URLs, and HTTP bodies are never read, since
the plaintext credential rules fire on exactly those.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from analysis.config import NetworkSettings
from analysis.models import Alert, AlertSource, Category, _parse_dt, normalize_mac

log = logging.getLogger(__name__)

#Our custom rules in sensor/suricata/rules/. Keep in sync with Adam's sids.
PLAINTEXT_CRED_SIDS = {9000001, 9000002}

PLAINTEXT_PREFIX = "SOCBOX Plaintext"
PORT_SCAN_PREFIXES = ("SOCBOX Port Scan", "SOCBOX Portscan", "ET SCAN")

#Signature prefixes for ET Open and URLhaus rules that mean "talked to
#something known bad". Checked with str.startswith, so order doesn't matter.
MALICIOUS_PREFIXES = (
    "ET CINS",
    "ET CNC",
    "ET COMPROMISED",
    "ET DROP",
    "ET DSHIELD",
    "ET EXPLOIT_KIT",
    "ET MALWARE",
    "ET MOBILE_MALWARE",
    "ET PHISHING",
    "ET THREATFOX",
    "ET TROJAN",
    "ET WORM",
)

#Suricata classtype descriptions (alert.category) that mean the same thing,
#for rules whose message doesn't follow the prefixes above.
MALICIOUS_CLASSTYPES = {
    "A Network Trojan was detected",
    "Malware Command and Control Activity Detected",
    "Domain Observed Used for C2 Detected",
    "Known malware command and control traffic",
}
PORT_SCAN_CLASSTYPES = {"Detection of a Network Scan"}

#Fields from the event worth keeping for the card and dashboard. Nothing here
#can hold a payload or credential.
_HOSTNAME_FIELDS = (("http", "hostname"), ("tls", "sni"), ("dns", "rrname"))


def categorize(event: dict[str, Any], network: Optional[NetworkSettings] = None) -> Optional[Alert]:
    """Turn one eve.json event into an Alert, or None if it isn't one of ours.

    `network` picks which side is the home device; without it, the source is.
    """
    if event.get("event_type") != "alert":
        return None
    rule = event.get("alert")
    if not isinstance(rule, dict):
        return None

    signature = str(rule.get("signature") or "")
    category = category_for(signature, _int(rule.get("signature_id")), rule.get("category"))
    if category is None:
        log.debug("Ignoring uncategorized alert: %s", signature)
        return None

    try:
        return _build_alert(event, rule, signature, category, network)
    except (ValueError, TypeError) as e:
        log.warning("Skipping malformed alert event (%s): %.200s", e, signature)
        return None


def category_for(
    signature: str, signature_id: Optional[int], classtype: Optional[str] = None
) -> Optional[Category]:
    """Pick the category for a Suricata rule, or None if it isn't one of the six."""
    if signature_id in PLAINTEXT_CRED_SIDS or signature.startswith(PLAINTEXT_PREFIX):
        return Category.PLAINTEXT_CREDENTIALS
    if signature.startswith(PORT_SCAN_PREFIXES) or classtype in PORT_SCAN_CLASSTYPES:
        return Category.PORT_SCAN
    if signature.startswith(MALICIOUS_PREFIXES) or classtype in MALICIOUS_CLASSTYPES:
        return Category.MALICIOUS_CONTACT
    return None


def _build_alert(
    event: dict[str, Any],
    rule: dict[str, Any],
    signature: str,
    category: Category,
    network: Optional[NetworkSettings],
) -> Alert:
    src_ip, dest_ip = event.get("src_ip"), event.get("dest_ip")
    direction = _direction(src_ip, dest_ip, network)
    home_is_dest = direction == "inbound"

    details: dict[str, Any] = {
        "direction": direction,
        "home_ip": dest_ip if home_is_dest else src_ip,
        "remote_ip": src_ip if home_is_dest else dest_ip,
        "rule_category": rule.get("category"),
        "rule_severity": rule.get("severity"),
        "action": rule.get("action"),
        "app_proto": event.get("app_proto"),
        "flow_id": event.get("flow_id"),
        "hostname": _hostname(event),
    }

    ether = event.get("ether") or {}
    mac = ether.get("dest_mac" if home_is_dest else "src_mac")

    return Alert(
        category=category,
        source=AlertSource.SURICATA,
        timestamp=_parse_dt(event.get("timestamp")),
        src_ip=src_ip,
        dest_ip=dest_ip,
        src_port=_int(event.get("src_port")),
        dest_port=_int(event.get("dest_port")),
        proto=event.get("proto"),
        device_mac=_mac(mac),
        signature=signature or None,
        signature_id=_int(rule.get("signature_id")),
        details={k: v for k, v in details.items() if v is not None},
    )


def _direction(src_ip: Any, dest_ip: Any, network: Optional[NetworkSettings]) -> str:
    """"outbound" (home -> internet), "inbound" (internet -> home), or "internal"."""
    if network is None:
        return "outbound"
    src_home = bool(src_ip) and network.is_home_ip(src_ip)
    dest_home = bool(dest_ip) and network.is_home_ip(dest_ip)
    if src_home and dest_home:
        return "internal"
    if dest_home:
        return "inbound"
    return "outbound"


def _hostname(event: dict[str, Any]) -> Optional[str]:
    for section, key in _HOSTNAME_FIELDS:
        value = (event.get(section) or {}).get(key)
        if value:
            return str(value)
    return None


def _mac(value: Any) -> Optional[str]:
    try:
        return normalize_mac(value)
    except ValueError:
        return None


def _int(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
