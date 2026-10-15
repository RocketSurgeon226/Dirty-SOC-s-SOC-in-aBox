"""Owner: Brady — Store alert metadata and devices (e.g. SQLite); apply log retention.

Usage:

    from analysis.storage.db import Database

    db = Database(settings.paths.database)
    db.save_alert(alert); db.save_card(card)     # a new alert
    db.update_repeat(alert)                      # dedup folded a repeat into it
    db.list_cards(limit=50)                      # newest first, for the dashboard
    db.acknowledge(alert_id)                     # homeowner clicked "got it"
    db.upsert_device(device); db.name_device(mac, "Kitchen TV")
    db.find_device(mac=..., ip=...)              # for the card's device name
    db.purge_older_than(settings.retention.days)

One SQLite file shared by the analysis service (writer) and the dashboard
(reader). WAL mode lets the dashboard read while the service writes.

Only metadata is stored: alerts arrive here already redacted, and there is no
column for payloads. Retention deletes old alerts and cards; the device
inventory is kept, since new-device detection needs to remember what it has
seen.

Timestamps are stored as UTC ISO strings so they sort and compare as text.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Optional, Union

from analysis.models import Alert, AlertCard, Device, normalize_mac, utcnow

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id           TEXT PRIMARY KEY,
    category     TEXT NOT NULL,
    source       TEXT NOT NULL,
    severity     TEXT,
    timestamp    TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    src_ip       TEXT,
    dest_ip      TEXT,
    src_port     INTEGER,
    dest_port    INTEGER,
    proto        TEXT,
    device_mac   TEXT,
    signature    TEXT,
    signature_id INTEGER,
    count        INTEGER NOT NULL DEFAULT 1,
    details      TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS alerts_last_seen ON alerts (last_seen);

CREATE TABLE IF NOT EXISTS cards (
    alert_id     TEXT PRIMARY KEY REFERENCES alerts (id) ON DELETE CASCADE,
    category     TEXT NOT NULL,
    device_name  TEXT NOT NULL,
    severity     TEXT NOT NULL,
    description  TEXT NOT NULL,
    action       TEXT NOT NULL,
    timestamp    TEXT NOT NULL,
    count        INTEGER NOT NULL DEFAULT 1,
    llm_enhanced INTEGER NOT NULL DEFAULT 0,
    acknowledged INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS cards_timestamp ON cards (timestamp);

CREATE TABLE IF NOT EXISTS devices (
    mac           TEXT PRIMARY KEY,
    ip            TEXT,
    friendly_name TEXT,
    hostname      TEXT,
    vendor        TEXT,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS devices_ip ON devices (ip);
"""

_ALERT_COLUMNS = (
    "id", "category", "source", "severity", "timestamp", "last_seen", "src_ip", "dest_ip",
    "src_port", "dest_port", "proto", "device_mac", "signature", "signature_id", "count", "details",
)
_CARD_COLUMNS = (
    "alert_id", "category", "device_name", "severity", "description", "action", "timestamp",
    "count", "llm_enhanced", "acknowledged",
)
_DEVICE_COLUMNS = ("mac", "ip", "friendly_name", "hostname", "vendor", "first_seen", "last_seen")


class Database:
    """Thread-safe wrapper around the SQLite file."""

    def __init__(self, path: Union[str, Path]) -> None:
        path = Path(path)
        if str(path) != ":memory:":
            path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False, timeout=10)
        self._conn.row_factory = sqlite3.Row
        self._lock = Lock()
        with self._lock, self._conn:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # --- alerts and cards -------------------------------------------------

    def save_alert(self, alert: Alert) -> None:
        """Insert or replace an alert."""
        d = alert.to_dict()
        d["timestamp"] = _ts(alert.timestamp)
        d["last_seen"] = _ts(alert.last_seen or alert.timestamp)
        d["details"] = json.dumps(d["details"], default=str)
        self._upsert("alerts", _ALERT_COLUMNS, "id", d)

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        row = self._one("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        if row is None:
            return None
        d = dict(row)
        d["details"] = json.loads(d["details"] or "{}")
        return Alert.from_dict(d)

    def save_card(self, card: AlertCard) -> None:
        """Insert or update a card. An update never clears `acknowledged`."""
        d = card.to_dict()
        d["timestamp"] = _ts(card.timestamp)
        d["llm_enhanced"] = int(card.llm_enhanced)
        d["acknowledged"] = int(card.acknowledged)
        self._upsert("cards", _CARD_COLUMNS, "alert_id", d, keep=("acknowledged",))

    def update_repeat(self, alert: Alert) -> None:
        """Record that dedup folded another occurrence into `alert`."""
        last_seen = _ts(alert.last_seen or alert.timestamp)
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE alerts SET count = ?, last_seen = ? WHERE id = ?",
                (alert.count, last_seen, alert.id),
            )
            self._conn.execute(
                "UPDATE cards SET count = ? WHERE alert_id = ?", (alert.count, alert.id)
            )

    def list_cards(
        self,
        limit: int = 100,
        include_acknowledged: bool = True,
        since: Optional[datetime] = None,
    ) -> list[AlertCard]:
        """Cards newest first."""
        sql, args = "SELECT * FROM cards WHERE 1=1", []
        if not include_acknowledged:
            sql += " AND acknowledged = 0"
        if since is not None:
            sql += " AND timestamp >= ?"
            args.append(_ts(since))
        sql += " ORDER BY timestamp DESC LIMIT ?"
        args.append(limit)
        return [_card(row) for row in self._all(sql, args)]

    def acknowledge(self, alert_id: str, acknowledged: bool = True) -> bool:
        """Mark a card as handled. Returns False if there's no such card."""
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE cards SET acknowledged = ? WHERE alert_id = ?",
                (int(acknowledged), alert_id),
            )
        return cur.rowcount > 0

    def purge_older_than(self, days: int, now: Optional[datetime] = None) -> int:
        """Delete alerts (and their cards) last seen more than `days` ago."""
        cutoff = _ts((now or utcnow()) - timedelta(days=days))
        with self._lock, self._conn:
            self._conn.execute(
                "DELETE FROM cards WHERE alert_id IN (SELECT id FROM alerts WHERE last_seen < ?)",
                (cutoff,),
            )
            cur = self._conn.execute("DELETE FROM alerts WHERE last_seen < ?", (cutoff,))
        return cur.rowcount

    # --- devices ----------------------------------------------------------

    def upsert_device(self, device: Device) -> None:
        """Insert or update a device. An update never clears its friendly name or first_seen."""
        d = device.to_dict()
        d["first_seen"] = _ts(device.first_seen)
        d["last_seen"] = _ts(device.last_seen)
        with self._lock, self._conn:
            self._conn.execute(
                f"INSERT INTO devices ({', '.join(_DEVICE_COLUMNS)}) "
                f"VALUES ({', '.join('?' * len(_DEVICE_COLUMNS))}) "
                "ON CONFLICT (mac) DO UPDATE SET "
                "ip = COALESCE(excluded.ip, ip), "
                "friendly_name = COALESCE(excluded.friendly_name, friendly_name), "
                "hostname = COALESCE(excluded.hostname, hostname), "
                "vendor = COALESCE(excluded.vendor, vendor), "
                "first_seen = MIN(first_seen, excluded.first_seen), "
                "last_seen = MAX(last_seen, excluded.last_seen)",
                [d[c] for c in _DEVICE_COLUMNS],
            )

    def get_device(self, mac: str) -> Optional[Device]:
        row = self._one("SELECT * FROM devices WHERE mac = ?", (normalize_mac(mac),))
        return _device(row) if row else None

    def find_device(self, mac: Optional[str] = None, ip: Optional[str] = None) -> Optional[Device]:
        """Look a device up by MAC, falling back to the device most recently seen at `ip`."""
        if mac:
            device = self.get_device(mac)
            if device:
                return device
        if ip:
            row = self._one(
                "SELECT * FROM devices WHERE ip = ? ORDER BY last_seen DESC LIMIT 1", (ip,)
            )
            if row:
                return _device(row)
        return None

    def list_devices(self) -> list[Device]:
        """All devices, unnamed ones first so the dashboard can prompt for names."""
        rows = self._all(
            "SELECT * FROM devices ORDER BY friendly_name IS NOT NULL, friendly_name, last_seen DESC"
        )
        return [_device(row) for row in rows]

    def name_device(self, mac: str, friendly_name: Optional[str]) -> bool:
        """Set (or with None, clear) a device's friendly name. False if unknown MAC."""
        name = friendly_name.strip() if friendly_name else None
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE devices SET friendly_name = ? WHERE mac = ?", (name or None, normalize_mac(mac))
            )
        return cur.rowcount > 0

    # --- helpers ----------------------------------------------------------

    def _upsert(
        self, table: str, columns: tuple[str, ...], key: str, d: dict[str, Any], keep: tuple[str, ...] = ()
    ) -> None:
        updates = ", ".join(f"{c} = excluded.{c}" for c in columns if c != key and c not in keep)
        with self._lock, self._conn:
            self._conn.execute(
                f"INSERT INTO {table} ({', '.join(columns)}) "
                f"VALUES ({', '.join('?' * len(columns))}) "
                f"ON CONFLICT ({key}) DO UPDATE SET {updates}",
                [d[c] for c in columns],
            )

    def _one(self, sql: str, args: Any = ()) -> Optional[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, args).fetchone()

    def _all(self, sql: str, args: Any = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, args).fetchall()


def _ts(dt: datetime) -> str:
    """UTC ISO string, so text comparison matches time order."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _card(row: sqlite3.Row) -> AlertCard:
    d = dict(row)
    d["llm_enhanced"] = bool(d["llm_enhanced"])
    d["acknowledged"] = bool(d["acknowledged"])
    return AlertCard.from_dict(d)


def _device(row: sqlite3.Row) -> Device:
    return Device.from_dict(dict(row))
