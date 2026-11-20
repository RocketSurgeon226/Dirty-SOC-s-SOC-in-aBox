"""Owner: Brady — Remember which website name each server address came from.

Usage:

    names = DnsNames()
    names.process(event)          # every eve.json event; only DNS answers are used
    names.name_for("93.184.216.34")  # -> "example.com", or None

Suricata's alerts don't carry the site's name (alert metadata is off so
nothing sensitive reaches eve.json), but a device almost always looks the
name up just before connecting. That lets a password card say which site it
was, instead of a bare address. Only the newest MAX_ENTRIES answers are kept.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Any, Optional

MAX_ENTRIES = 5000
ADDRESS_TYPES = {"A", "AAAA"}


class DnsNames:
    def __init__(self, max_entries: int = MAX_ENTRIES) -> None:
        self.max_entries = max_entries
        self._names: OrderedDict[str, str] = OrderedDict()

    def process(self, event: dict[str, Any]) -> None:
        if event.get("event_type") != "dns":
            return
        dns = event.get("dns") or {}
        queries = dns.get("queries") or []
        asked = dns.get("rrname") or (queries[0].get("rrname") if queries and isinstance(queries[0], dict) else None)
        for answer in dns.get("answers") or []:  #eve dns v2/v3 "detailed" format
            if isinstance(answer, dict) and answer.get("rrtype") in ADDRESS_TYPES and answer.get("rdata"):
                self._remember(str(answer["rdata"]), asked or answer.get("rrname"))
        for rrtype, values in (dns.get("grouped") or {}).items():  #"grouped" format
            if rrtype in ADDRESS_TYPES and asked:
                for value in values or []:
                    self._remember(str(value), asked)

    def name_for(self, ip: Optional[str]) -> Optional[str]:
        return self._names.get(ip) if ip else None

    def _remember(self, ip: str, name: Optional[str]) -> None:
        if not name:
            return
        self._names[ip] = str(name).rstrip(".")
        self._names.move_to_end(ip)
        while len(self._names) > self.max_entries:
            self._names.popitem(last=False)
