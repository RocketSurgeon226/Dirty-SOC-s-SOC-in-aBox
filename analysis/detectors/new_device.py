"""Owner: Caleb — Passive ARP/DHCP observation and MAC inventory diffing."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from analysis.config import NetworkSettings
from analysis.models import Alert, AlertSource, Category, Device, _parse_dt, normalize_mac, utcnow
from analysis.storage.db import Database


class NewDeviceDetector:
    def __init__(self, db: Database, network: NetworkSettings, enabled: bool = True) -> None:
        self.db = db
        self.network = network
        self.enabled = enabled

    def process(self, event: dict[str, Any]) -> Optional[Alert]:
        if not self.enabled:
            return None
        kind = event.get("event_type")
        if kind not in {"arp", "dhcp"}:
            return None
        mac, ip, hostname = self._device_fields(event, kind)
        try:
            mac = normalize_mac(mac)
        except ValueError:
            return None
        if not mac:
            return None
        if ip and not self.network.is_home_ip(ip):
            return None

        when = _parse_dt(event.get("timestamp"))
        existing = self.db.get_device(mac)
        self.db.upsert_device(Device(
            mac=mac, ip=ip, hostname=hostname,
            first_seen=existing.first_seen if existing else when,
            last_seen=when,
        ))
        if existing:
            return None
        return Alert(
            category=Category.NEW_DEVICE,
            source=AlertSource.PYTHON,
            timestamp=when,
            src_ip=ip,
            device_mac=mac,
            signature="New home device discovered",
            details={"home_ip": ip, "hostname": hostname, "detection_source": kind},
        )

    @staticmethod
    def _device_fields(event: dict[str, Any], kind: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
        if kind == "dhcp":
            dhcp = event.get("dhcp") or {}
            mac = dhcp.get("client_mac") or dhcp.get("mac") or event.get("src_mac")
            ip = dhcp.get("assigned_ip") or dhcp.get("client_ip") or event.get("src_ip")
            hostname = dhcp.get("hostname") or dhcp.get("client_hostname")
        else:
            arp = event.get("arp") or {}
            ether = event.get("ether") or {}
            mac = arp.get("src_mac") or event.get("src_mac") or ether.get("src_mac")
            ip = arp.get("src_ip") or event.get("src_ip")
            hostname = None
        return (str(mac) if mac else None, str(ip) if ip else None,
                str(hostname) if hostname else None)