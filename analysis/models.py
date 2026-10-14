"""Owner: Brady — Shared data classes: Alert, AlertCard, Device, Severity.

Data flows through the analysis service in this order:

    Suricata eve.json / Python detector
        -> Alert       (normalized detection, one of the six categories)
        -> AlertCard   (four-part plain-language card for the dashboard)

Device is the inventory entry that turns a MAC/IP into a friendly name.

Everything here is plain stdlib so the dashboard, storage, and tests can import
it without pulling in Suricata, scapy, or the LLM client.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

UNRECOGNIZED_DEVICE = "Unrecognized device"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def normalize_mac(mac: Optional[str]) -> Optional[str]:
    """Return a MAC as lowercase colon-separated hex, or None if empty."""
    if not mac:
        return None
    hex_digits = "".join(c for c in mac.lower() if c in "0123456789abcdef")
    if len(hex_digits) != 12:
        raise ValueError(f"Invalid MAC address: {mac!r}")
    return ":".join(hex_digits[i:i + 2] for i in range(0, 12, 2))


class Severity(str, Enum):
    """Household-facing severity (traffic-light colors on the dashboard)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @property
    def color(self) -> str:
        return _SEVERITY_COLOR[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank


_SEVERITY_RANK = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3}
_SEVERITY_COLOR = {Severity.LOW: "green", Severity.MEDIUM: "yellow", Severity.HIGH: "red"}


class Category(str, Enum):
    """The six alert categories. Each maps to exactly one template and one action."""

    MALICIOUS_CONTACT = "malicious_contact"
    PORT_SCAN = "port_scan"
    NEW_DEVICE = "new_device"
    TRACKER_DNS = "tracker_dns"
    PLAINTEXT_CREDENTIALS = "plaintext_credentials"
    OUTBOUND_VOLUME = "outbound_volume"


class AlertSource(str, Enum):
    """Where a detection came from."""

    SURICATA = "suricata"
    PYTHON = "python"


@dataclass
class Device:
    """One entry in the device inventory, keyed by MAC address."""

    mac: str
    ip: Optional[str] = None
    friendly_name: Optional[str] = None
    hostname: Optional[str] = None  # from DHCP, if seen
    vendor: Optional[str] = None  # from MAC OUI lookup, if available
    first_seen: datetime = field(default_factory=utcnow)
    last_seen: datetime = field(default_factory=utcnow)

    def __post_init__(self) -> None:
        self.mac = normalize_mac(self.mac)
        if self.mac is None:
            raise ValueError("Device requires a MAC address")

    @property
    def is_named(self) -> bool:
        return bool(self.friendly_name)

    @property
    def display_name(self) -> str:
        """Name shown on cards; unnamed devices stay 'Unrecognized device'."""
        return self.friendly_name or UNRECOGNIZED_DEVICE

    def touch(self, ip: Optional[str] = None, when: Optional[datetime] = None) -> None:
        """Record that the device was just seen, optionally at a new IP."""
        self.last_seen = when or utcnow()
        if ip:
            self.ip = ip

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["first_seen"] = self.first_seen.isoformat()
        d["last_seen"] = self.last_seen.isoformat()
        d["display_name"] = self.display_name
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Device:
        return cls(
            mac=d["mac"],
            ip=d.get("ip"),
            friendly_name=d.get("friendly_name"),
            hostname=d.get("hostname"),
            vendor=d.get("vendor"),
            first_seen=_parse_dt(d.get("first_seen")),
            last_seen=_parse_dt(d.get("last_seen")),
        )


@dataclass
class Alert:
    """A normalized detection in one of the six categories, before translation.

    Only metadata is kept: never put raw payloads or credentials in `details`.
    `severity` is None until severity.py assigns it; `count` grows when dedup.py
    folds repeats into this alert.
    """

    category: Category
    source: AlertSource
    timestamp: datetime = field(default_factory=utcnow)
    src_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    src_port: Optional[int] = None
    dest_port: Optional[int] = None
    proto: Optional[str] = None
    device_mac: Optional[str] = None
    signature: Optional[str] = None  # Suricata rule message, if any
    signature_id: Optional[int] = None
    severity: Optional[Severity] = None
    details: dict[str, Any] = field(default_factory=dict)
    count: int = 1
    last_seen: Optional[datetime] = None
    id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def __post_init__(self) -> None:
        self.category = Category(self.category)
        self.source = AlertSource(self.source)
        if self.severity is not None:
            self.severity = Severity(self.severity)
        self.device_mac = normalize_mac(self.device_mac)
        if self.last_seen is None:
            self.last_seen = self.timestamp

    @property
    def device_key(self) -> Optional[str]:
        """Best identifier for the affected device: MAC if known, else source IP."""
        return self.device_mac or self.src_ip

    @property
    def dedup_key(self) -> tuple[Optional[str], Category]:
        """Alerts with the same device and category are repeats of each other."""
        return (self.device_key, self.category)

    def merge(self, other: Alert) -> None:
        """Fold a repeat alert into this one."""
        self.count += other.count
        if other.last_seen and (self.last_seen is None or other.last_seen > self.last_seen):
            self.last_seen = other.last_seen

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["source"] = self.source.value
        d["severity"] = self.severity.value if self.severity else None
        d["timestamp"] = self.timestamp.isoformat()
        d["last_seen"] = self.last_seen.isoformat() if self.last_seen else None
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Alert:
        return cls(
            id=d.get("id") or uuid.uuid4().hex,
            category=Category(d["category"]),
            source=AlertSource(d["source"]),
            timestamp=_parse_dt(d.get("timestamp")),
            src_ip=d.get("src_ip"),
            dest_ip=d.get("dest_ip"),
            src_port=d.get("src_port"),
            dest_port=d.get("dest_port"),
            proto=d.get("proto"),
            device_mac=d.get("device_mac"),
            signature=d.get("signature"),
            signature_id=d.get("signature_id"),
            severity=Severity(d["severity"]) if d.get("severity") else None,
            details=dict(d.get("details") or {}),
            count=d.get("count", 1),
            last_seen=_parse_dt(d["last_seen"]) if d.get("last_seen") else None,
        )

@dataclass
class AlertCard:
    """The four-part card the homeowner sees: device, severity, description, action."""

    alert_id: str
    category: Category
    device_name: str
    severity: Severity
    description: str
    action: str
    timestamp: datetime
    count: int = 1
    llm_enhanced: bool = False  # True if the LLM reworded the template text
    acknowledged: bool = False

    def __post_init__(self) -> None:
        self.category = Category(self.category)
        self.severity = Severity(self.severity)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        d["color"] = self.severity.color
        d["timestamp"] = self.timestamp.isoformat()
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AlertCard:
        return cls(
            alert_id=d["alert_id"],
            category=Category(d["category"]),
            device_name=d["device_name"],
            severity=Severity(d["severity"]),
            description=d["description"],
            action=d["action"],
            timestamp=_parse_dt(d.get("timestamp")),
            count=d.get("count", 1),
            llm_enhanced=d.get("llm_enhanced", False),
            acknowledged=d.get("acknowledged", False),
        )

def _parse_dt(value: Any) -> datetime:
    """Parse an ISO timestamp (including Suricata's '+0000' offset form)."""
    if value is None:
        return utcnow()
    if isinstance(value, datetime):
        dt = value
    else:
        s = str(value)
        #Suricata writes offsets as +0000; fromisoformat on 3.10 wants +00:00.
        if len(s) >= 5 and s[-5] in "+-" and s[-4:].isdigit():
            s = f"{s[:-2]}:{s[-2:]}"
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)