"""Owner: Caleb — Reputation matching for known-malicious IP/domain contact."""
from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any, Optional

from analysis.config import NetworkSettings
from analysis.models import Alert, AlertSource, Category, _parse_dt


class ReputationDetector:
    def __init__(self, network: NetworkSettings, ips_path: Path, domains_path: Path) -> None:
        self.network = network
        self.ips = self._load_indicators(ips_path, "ip")
        self.domains = self._load_indicators(domains_path, "domain")

    @staticmethod
    def _load_indicators(path: Path, kind: str) -> set[str]:
        values: set[str] = set()
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return values
        for line in lines:
            value = line.split("#", 1)[0].strip().lower()
            if not value:
                continue
            if kind == "ip":
                try:
                    values.add(str(ipaddress.ip_address(value)))
                except ValueError:
                    continue
            else:
                value = value.rstrip(".").removeprefix("*.")
                if value and " " not in value and "/" not in value:
                    values.add(value)
        return values

    def process(self, event: dict[str, Any]) -> Optional[Alert]:
        kind = event.get("event_type")
        # Suricata alert events are already categorized by analysis.categorize.
        if kind not in {"dns", "flow"}:
            return None
        candidates: list[tuple[str, str]] = []
        for key in ("src_ip", "dest_ip"):
            value = event.get(key)
            if value:
                candidates.append(("ip", str(value).lower()))
        dns = event.get("dns") or {}
        for key in ("rrname",):
            value = dns.get(key)
            if value:
                candidates.append(("domain", str(value).lower().rstrip(".")))
        for section, key in (("tls", "sni"), ("http", "hostname")):
            value = (event.get(section) or {}).get(key)
            if value:
                candidates.append(("domain", str(value).lower().rstrip(".")))
        match = next(((kind, value) for kind, value in candidates if self._matches(kind, value)), None)
        if not match:
            return None
        matched_kind, indicator = match
        src, dest = event.get("src_ip"), event.get("dest_ip")
        src_home = bool(src) and self.network.is_home_ip(str(src))
        dest_home = bool(dest) and self.network.is_home_ip(str(dest))
        if src_home:
            home_ip, remote_ip = str(src), str(dest) if dest else None
        elif dest_home:
            home_ip, remote_ip = str(dest), str(src) if src else None
        else:
            return None
        rule = event.get("alert") or {}
        ether = event.get("ether") or {}
        mac = ether.get("src_mac" if src_home else "dest_mac")
        return Alert(
            category=Category.MALICIOUS_CONTACT,
            source=AlertSource.PYTHON,
            timestamp=_parse_dt(event.get("timestamp")),
            src_ip=str(src) if src else None,
            dest_ip=str(dest) if dest else None,
            src_port=event.get("src_port") if isinstance(event.get("src_port"), int) else None,
            dest_port=event.get("dest_port") if isinstance(event.get("dest_port"), int) else None,
            proto=event.get("proto"), device_mac=mac,
            signature="Threat-intelligence indicator match",
            signature_id=rule.get("signature_id") if isinstance(rule.get("signature_id"), int) else None,
            details={"home_ip": home_ip, "remote_ip": remote_ip,
                     "indicator_type": matched_kind, "indicator": indicator},
        )

    def _matches(self, kind: str, value: str) -> bool:
        if kind == "ip":
            return value in self.ips
        return any(value == d or value.endswith("." + d) for d in self.domains)