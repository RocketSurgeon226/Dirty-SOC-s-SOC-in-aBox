"""Owner: Caleb — Flag a device with > 20 tracker-domain DNS queries in 5 minutes."""
from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

from analysis.config import NetworkSettings, TrackerDnsSettings
from analysis.models import Alert, AlertSource, Category, _parse_dt
from analysis.storage.db import Database


class TrackerDNSDetector:
    def __init__(self, settings: TrackerDnsSettings, network: NetworkSettings,
                 db: Database, domains_path: Path) -> None:
        self.threshold = settings.max_queries
        self.window = timedelta(minutes=settings.window_minutes)
        self.network = network
        self.db = db
        self.domains = self._load_domains(domains_path)
        self._queries: dict[str, deque[tuple[datetime, str]]] = defaultdict(deque)
        self._alerted: dict[str, datetime] = {}

    @staticmethod
    def _load_domains(path: Path) -> set[str]:
        domains: set[str] = set()
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return domains
        for line in lines:
            line = line.split("#", 1)[0].strip().lower().rstrip(".")
            if line and not line.startswith("!") and " " not in line and "/" not in line:
                domains.add(line.removeprefix("*."))
        return domains

    def process(self, event: dict[str, Any]) -> Optional[Alert]:
        if event.get("event_type") != "dns":
            return None
        dns = event.get("dns") or {}
        dns_kind = str(dns.get("type", "query")).lower()
        if dns_kind in {"answer", "response", "reply"}:
            return None
        domain = str(dns.get("rrname") or "").lower().rstrip(".")
        if not domain or not any(domain == d or domain.endswith("." + d) for d in self.domains):
            return None
        ip = event.get("src_ip")
        if not ip or not self.network.is_home_ip(str(ip)):
            return None
        when = _parse_dt(event.get("timestamp"))
        queue = self._queries[str(ip)]
        cutoff = when - self.window
        while queue and queue[0][0] < cutoff:
            queue.popleft()
        queue.append((when, domain))
        if len(queue) <= self.threshold:
            return None
        last_alert = self._alerted.get(str(ip))
        if last_alert and when - last_alert <= self.window:
            return None
        self._alerted[str(ip)] = when
        device = self.db.find_device(ip=str(ip))
        return Alert(
            category=Category.TRACKER_DNS,
            source=AlertSource.PYTHON,
            timestamp=when,
            src_ip=str(ip),
            device_mac=device.mac if device else None,
            signature="Frequent tracking-domain lookups",
            details={"home_ip": str(ip), "domain": domain, "query_count": len(queue),
                     "window_minutes": int(self.window.total_seconds() // 60)},
        )