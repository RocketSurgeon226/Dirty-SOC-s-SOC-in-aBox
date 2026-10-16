"""Owner: Brady — Flag a device sending > 3x its rolling one-hour outbound baseline.

Usage:

    from analysis.detectors.outbound_volume import OutboundVolumeDetector

    detector = OutboundVolumeDetector(settings.detectors.outbound_volume, settings.network)
    alert = detector.process(event)  # eve.json flow event -> Alert or None

    #Or feed byte counts directly (handy in tests):
    alert = detector.add_bytes("192.168.1.20", 5_000_000, when)

How it decides, per home device:

  - Bytes the device sends out to the internet are counted into one-minute buckets.
  - "Recent" is the last 5 minutes of buckets.
  - The baseline is the average 5-minute amount over the baseline window
    (60 minutes by default) before that.
  - Alert when recent > multiplier x baseline AND recent >= min_bytes.

A device needs a full baseline window of history before it can alert, so the
first hour after startup (or after a device first appears) is quiet. min_bytes
keeps a usually-silent device from alerting on a few kilobytes, since 3x
almost nothing is still almost nothing.

Bytes come from Suricata flow records, which are written when a flow ends, so
a long upload lands all at once at its end. That's fine for "sending far more
than usual", and dedup.py keeps a sustained burst to a single card.
"""

from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime
from typing import Any, Optional

from analysis.config import NetworkSettings, OutboundVolumeSettings
from analysis.models import Alert, AlertSource, Category, _parse_dt, normalize_mac

BUCKET_SECONDS = 60
RECENT_MINUTES = 5


class OutboundVolumeDetector:
    def __init__(self, settings: OutboundVolumeSettings, network: NetworkSettings) -> None:
        self.multiplier = settings.multiplier
        self.min_bytes = settings.min_bytes
        self.baseline_buckets = math.ceil(settings.baseline_window_minutes * 60 / BUCKET_SECONDS)
        self.recent_buckets = math.ceil(RECENT_MINUTES * 60 / BUCKET_SECONDS)
        self.network = network
        #device ip -> {bucket number: bytes}
        self._buckets: dict[str, dict[int, int]] = defaultdict(dict)
        self._first_bucket: dict[str, int] = {}
        self._macs: dict[str, str] = {}

    def process(self, event: dict[str, Any]) -> Optional[Alert]:
        """Count a flow event's outbound bytes; return an Alert if the device spiked."""
        if event.get("event_type") != "flow":
            return None
        flow = event.get("flow") or {}
        src, dest = event.get("src_ip"), event.get("dest_ip")
        src_home = bool(src) and self.network.is_home_ip(src)
        dest_home = bool(dest) and self.network.is_home_ip(dest)
        ether = event.get("ether") or {}

        #Suricata's "src" is whoever opened the flow. Outbound bytes are what
        #the home side sent: to_server if it opened the flow, to_client if not.
        if src_home and not dest_home:
            device, sent, mac = src, flow.get("bytes_toserver"), ether.get("src_mac")
        elif dest_home and not src_home:
            device, sent, mac = dest, flow.get("bytes_toclient"), ether.get("dest_mac")
        else:
            return None  # internal-only or internet-only traffic

        if not isinstance(sent, int) or sent <= 0:
            return None
        when = _parse_dt(event.get("timestamp") or flow.get("end"))
        return self.add_bytes(device, sent, when, mac=mac)

    def add_bytes(
        self, device_ip: str, nbytes: int, when: datetime, mac: Optional[str] = None
    ) -> Optional[Alert]:
        """Record `nbytes` sent by `device_ip` at `when`, then check for a spike."""
        bucket = int(when.timestamp()) // BUCKET_SECONDS
        buckets = self._buckets[device_ip]
        buckets[bucket] = buckets.get(bucket, 0) + nbytes
        self._first_bucket.setdefault(device_ip, bucket)
        if mac:
            try:
                self._macs[device_ip] = normalize_mac(mac)
            except ValueError:
                pass
        self._prune(buckets, bucket)
        return self._check(device_ip, bucket, when)

    def _check(self, device_ip: str, now_bucket: int, when: datetime) -> Optional[Alert]:
        recent_start = now_bucket - self.recent_buckets + 1
        baseline_start = recent_start - self.baseline_buckets
        if self._first_bucket[device_ip] > baseline_start:
            return None  # not enough history yet

        buckets = self._buckets[device_ip]
        recent = sum(b for n, b in buckets.items() if n >= recent_start)
        baseline_total = sum(b for n, b in buckets.items() if baseline_start <= n < recent_start)
        #Average amount per recent-sized window across the baseline period.
        baseline = baseline_total * self.recent_buckets / self.baseline_buckets

        if recent < self.min_bytes or recent <= self.multiplier * baseline:
            return None

        return Alert(
            category=Category.OUTBOUND_VOLUME,
            source=AlertSource.PYTHON,
            timestamp=when,
            src_ip=device_ip,
            device_mac=self._macs.get(device_ip),
            details={
                "direction": "outbound",
                "home_ip": device_ip,
                "recent_bytes": recent,
                "recent_minutes": RECENT_MINUTES,
                "baseline_bytes": round(baseline),
                "ratio": round(recent / baseline, 1) if baseline else None,
            },
        )

    def _prune(self, buckets: dict[int, int], now_bucket: int) -> None:
        oldest = now_bucket - self.recent_buckets - self.baseline_buckets
        for n in [n for n in buckets if n < oldest]:
            del buckets[n]
