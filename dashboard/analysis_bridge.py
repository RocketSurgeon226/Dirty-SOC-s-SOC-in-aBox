"""
analysis_bridge.py: connects the dashboard to Brady's analysis service.

It is already wired to Brady's storage layer (analysis/storage/db.py). The two
programs run separately and share one SQLite file:

    python -m analysis.main        # Brady's service: watches eve.json, writes cards
    python3 dashboard/app.py       # the dashboard: reads cards and devices from the file

Check the connection any time with:   python3 dashboard/app.py --check

The dashboard's Python needs PyYAML for Brady's config. On the Pi:
    sudo apt install python3-yaml

If Brady's code isn't there yet, or breaks, the dashboard falls back to basic
alerts built straight from Suricata's eve.json and shows why at the top of the page.

If Brady's storage functions are ever renamed, only the functions in the first
section below need to change.

CARD KEYS the dashboard understands (the first match in each row is used; dicts or
objects with a to_dict() method both work, so Brady's AlertCard works as is):
  description   description | what_happened | summary | message | text     (required)
  severity      "high"/"medium"/"low" (also critical, med, warning, ...), or 1/2/3
  action        action | next_step | recommended_action | suggestion
  device name   device_name | device (text, or a dict with name/mac/icon) | friendly_name
  device icon   device_icon | icon
  mac           mac | device_mac
  category      category | type | alert_type
  timestamp     timestamp | time | ts | last_seen  (ISO text, epoch seconds, or datetime)
  id, count     id | alert_id,  count
DEVICES: dicts or objects with to_dict() (Brady's Device): mac, ip, name/friendly_name.
HEALTH:  {"score": 75, "label": "Fair", "color": "yellow", "trend": [...]} (Brady's health_score), or {"grade": "B+"}.
"""

import os
import re
import sys
import threading
import time
import traceback
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
for _p in (HERE, REPO_ROOT, os.path.join(REPO_ROOT, "analysis")):
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.append(_p)  # append, so we never shadow Python's own modules


# =============================================================================
# CONNECTION TO BRADY'S ANALYSIS SERVICE
# =============================================================================

_settings_cache: Dict[str, Any] = {}
_db_cache: Dict[str, Any] = {}
_db_lock = threading.Lock()


def settings():
    """Brady's Settings object (database path, eve.json path, dashboard host/port),
    or None if it can't be loaded (analysis/ missing, PyYAML not installed, bad YAML)."""
    if "value" in _settings_cache:
        return _settings_cache["value"]
    try:
        from analysis.config import load_settings
        _settings_cache["value"] = load_settings()
        return _settings_cache["value"]
    except Exception as e:
        _settings_cache["error"] = "%s: %s" % (type(e).__name__, e)
        return None


def _db():
    """One shared connection to the analysis service's SQLite file (it is thread-safe)."""
    with _db_lock:
        if "db" not in _db_cache:
            from analysis.config import load_settings
            from analysis.storage.db import Database
            _db_cache["db"] = Database(load_settings().paths.database)
        return _db_cache["db"]


def start():
    """Called once when the dashboard starts. Nothing to do: Brady's service runs as its
    own process (python -m analysis.main). It can't be started from here because its
    main() installs signal handlers, which only work in a program's main thread."""
    pass


def get_cards():
    """Current alert cards, newest first. Acknowledged ("Got it") cards are left out.
    The device name is looked up fresh, so a name given in the dashboard shows up on
    cards that were created before the device had one."""
    db = _db()
    cards = []
    for card in db.list_cards(limit=50, include_acknowledged=False):
        data = card.to_dict()
        alert = db.get_alert(card.alert_id)
        if alert is not None:
            device = db.find_device(mac=alert.device_mac,
                                    ip=alert.details.get("home_ip") or alert.src_ip)
            if device is not None:
                data["mac"] = device.mac
                if device.friendly_name:
                    data["device_name"] = device.friendly_name
        cards.append(data)
    return cards


def get_devices():
    """The device inventory, unnamed devices first."""
    return _db().list_devices()


_health_cache: Dict[str, Any] = {"at": 0.0, "value": None}
HEALTH_CACHE_SECONDS = 15  # the page refreshes every 5 s; no need to rescan a week of cards each time


def get_health():
    """Brady's network health score (0-100 with a label) plus the last 7 days of scores."""
    if _health_cache["value"] is not None and time.monotonic() - _health_cache["at"] < HEALTH_CACHE_SECONDS:
        return _health_cache["value"]
    from datetime import timedelta
    from analysis.health_score import health_score, health_trend, label_for
    from analysis.models import utcnow
    now = utcnow()
    cards = _db().list_cards(limit=10_000, since=now - timedelta(days=7))
    result = health_score(cards, now=now).to_dict()
    result["trend"] = [{"date": d.isoformat(), "score": s, "color": label_for(s)[1]}
                       for d, s in health_trend(cards, days=7, now=now)]
    _health_cache.update(at=time.monotonic(), value=result)
    return result


def on_device_named(mac, name, icon):
    """A household named a device in the dashboard: save it in Brady's inventory."""
    return _db().name_device(mac, name)


def acknowledge_card(alert_id):
    """The household pressed "Got it" on a card. Returns False if there's no such card."""
    ok = _db().acknowledge(alert_id)
    _health_cache["value"] = None  # an acknowledged card stops counting against the score
    return ok


# =============================================================================
# Nothing below needs editing.
# =============================================================================

ICON_OK = re.compile(r"^[a-z0-9-]+$")


def parse_ts(raw):
    """Parse ISO text such as 2026-10-06T18:00:00.123456+0000 into UTC."""
    if not raw:
        return None
    fixed = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", str(raw).strip())
    try:
        dt = datetime.fromisoformat(fixed)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _plain(v):
    """Enum members (like Brady's Severity / Category) -> their plain value."""
    return v.value if isinstance(v, Enum) else v


def _first(d, keys):
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return v
    return None


def _severity(v):
    v = _plain(v)
    if isinstance(v, bool):
        return "low"
    if isinstance(v, (int, float)):
        return {1: "high", 2: "medium", 3: "low"}.get(int(v), "low")
    s = str(v or "").strip().lower()
    if s in ("high", "critical", "severe", "red", "1"):
        return "high"
    if s in ("medium", "med", "moderate", "warning", "amber", "yellow", "2"):
        return "medium"
    return "low"


def _timestamp(v, now):
    if isinstance(v, datetime):
        dt = v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        secs = v / 1000.0 if v > 1e11 else v  # tolerate milliseconds
        try:
            return datetime.fromtimestamp(secs, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return now
    return parse_ts(v) or now


def _count(v):
    try:
        return max(1, int(v))
    except (TypeError, ValueError):
        return 1


def _icon(v, default):
    return v if isinstance(v, str) and ICON_OK.match(v) else default


def normalize_card(raw, index, now):
    if not isinstance(raw, dict) and hasattr(raw, "to_dict"):
        raw = raw.to_dict()  # e.g. Brady's AlertCard
    if not isinstance(raw, dict):
        raise ValueError("card %d is %s, not a dict" % (index, type(raw).__name__))
    description = _first(raw, ("description", "what_happened", "summary", "message", "text"))
    if not description:
        raise ValueError("card %d has no description" % index)
    device = _first(raw, ("device_name", "device", "friendly_name"))
    mac = _first(raw, ("mac", "device_mac"))
    icon = _first(raw, ("device_icon", "icon"))
    if isinstance(device, dict):
        mac = mac or device.get("mac")
        icon = icon or device.get("icon")
        device = _first(device, ("name", "friendly_name"))
    return {
        "id": str(_first(raw, ("id", "alert_id")) or "card-%d" % index),
        "category": str(_plain(_first(raw, ("category", "type", "alert_type"))) or "other"),
        "severity": _severity(raw.get("severity")),
        "count": _count(raw.get("count")),
        "mac": str(mac).lower() if mac else None,
        "device_name": str(device) if device else "Your network",
        "device_icon": _icon(icon, "device-unknown"),
        "description": str(description),
        "action": str(_first(raw, ("action", "next_step", "recommended_action", "suggestion")) or ""),
        "timestamp": _timestamp(_first(raw, ("timestamp", "time", "ts", "last_seen")), now).isoformat(),
    }


def normalize_device(raw, index):
    if not isinstance(raw, dict) and hasattr(raw, "to_dict"):
        raw = raw.to_dict()  # e.g. Brady's Device
    if not isinstance(raw, dict):
        raise ValueError("device %d is %s, not a dict" % (index, type(raw).__name__))
    mac = _first(raw, ("mac", "device_mac"))
    if not mac:
        raise ValueError("device %d has no mac" % index)
    name = str(_first(raw, ("name", "friendly_name", "device_name")) or "Unrecognized device")
    named = raw.get("named")
    if named is None:
        named = not name.lower().startswith(("unrecognized", "unknown"))
    return {
        "mac": str(mac).lower(),
        "ip": str(raw.get("ip") or ""),
        "name": name,
        "icon": _icon(_first(raw, ("icon", "device_icon")), "device-unknown"),
        "named": bool(named),
        "skipped": bool(raw.get("skipped", False)),
    }


_last_error: Dict[str, str] = {}


def _run(hook):
    try:
        return "ok", hook(), None
    except NotImplementedError:
        return "not_connected", None, None
    except ModuleNotFoundError as e:
        if (e.name or "").split(".")[0] == "analysis":   # his folder isn't here (yet)
            return "not_connected", None, None
        return _failed(hook, e)  # a package his code needs is missing, e.g. yaml
    except Exception as e:  # his code crashed; keep the dashboard alive
        return _failed(hook, e)


def _failed(hook, e):
    msg = "%s: %s" % (type(e).__name__, str(e)[:160])
    if _last_error.get(hook.__name__) != msg:  # print the traceback once, not every 5 seconds
        _last_error[hook.__name__] = msg
        traceback.print_exception(type(e), e, e.__traceback__)
    return "error", None, msg


def _load_list(hook, name, normalizer) -> Dict[str, Any]:
    status, raw, err = _run(hook)
    out: Dict[str, Any] = {"status": status, "items": [], "warnings": [], "error": err}
    if status != "ok":
        return out
    if not isinstance(raw, (list, tuple)):
        out.update(status="error", error="%s() must return a list, got %s" % (name, type(raw).__name__))
        return out
    now = datetime.now(timezone.utc)
    for i, item in enumerate(raw):
        try:
            out["items"].append(normalizer(item, i, now) if normalizer is normalize_card
                                else normalizer(item, i))
        except ValueError as e:
            out["warnings"].append(str(e))
    return out


def load_cards():
    r = _load_list(get_cards, "get_cards", normalize_card)
    r["cards"] = r.pop("items")
    return r


def load_devices():
    r = _load_list(get_devices, "get_devices", normalize_device)
    r["devices"] = r.pop("items")
    return r


def load_health():
    status, raw, err = _run(get_health)
    out: Dict[str, Any] = {"status": status, "health": None, "error": err}
    if status != "ok":
        return out
    try:
        if isinstance(raw, dict) and (raw.get("grade") or raw.get("score") is not None):
            h: Dict[str, Any] = {"grade": str(raw.get("grade") or ""), "note": str(raw.get("note") or "")}
            if raw.get("score") is not None:
                h["score"] = max(0, min(100, int(raw["score"])))
                h["label"] = str(raw.get("label") or "")
                h["color"] = _tone(raw.get("color"))
                h["counts"] = {k: int(raw.get(k) or 0) for k in ("high", "medium", "low")}
                h["trend"] = [{"date": str(p["date"]), "score": max(0, min(100, int(p["score"]))),
                               "color": _tone(p.get("color"))} for p in (raw.get("trend") or [])]
            out["health"] = h
        elif isinstance(raw, str) and raw.strip():
            out["health"] = {"grade": raw.strip(), "note": ""}
        else:
            raise ValueError("expected a dict with 'score' or 'grade', or a grade string")
    except (ValueError, TypeError, KeyError) as e:
        out.update(status="error", health=None, error="get_health() returned something unusable (%s)" % e)
    return out


def _tone(v):
    v = str(_plain(v) or "").lower()
    return v if v in ("green", "yellow", "red") else None


def check_report():
    """Plain-text report for:  python3 dashboard/app.py --check"""
    lines = ["Analysis bridge check", "  looking in: %s" % ", ".join(
        p for p in (HERE, REPO_ROOT, os.path.join(REPO_ROOT, "analysis")) if os.path.isdir(p))]
    s = settings()
    if s is not None:
        exists = os.path.exists(str(s.paths.database))
        lines.append("  settings:      OK")
        lines.append("  database:      %s%s" % (s.paths.database, "" if exists else "  (not created yet; start analysis.main)"))
        lines.append("  eve.json:      %s" % s.paths.eve_json)
    else:
        lines.append("  settings:      not loaded (%s)" % _settings_cache.get("error", "unknown"))
    lines.append("")

    def line(label, res, count_key=None):
        if res["status"] == "not_connected":
            return "  %-14s not connected (the dashboard uses its built-in version)" % label
        if res["status"] == "error":
            return "  %-14s ERROR: %s" % (label, res["error"])
        n = " with %d item(s)" % len(res[count_key]) if count_key else ""
        return "  %-14s OK%s" % (label, n)

    cards = load_cards()
    lines.append(line("get_cards()", cards, "cards"))
    for c in cards["cards"][:3]:
        lines.append("      %-6s | %s | %s -> %s" % (c["severity"], c["device_name"], c["description"],
                                                    c["action"] or "(no action given)"))
    for w in cards["warnings"]:
        lines.append("      skipped: %s" % w)
    devices = load_devices()
    lines.append(line("get_devices()", devices, "devices"))
    for w in devices["warnings"]:
        lines.append("      skipped: %s" % w)
    health = load_health()
    lines.append(line("get_health()", health))
    h = health["health"]
    if h:
        lines.append("      %s" % ("score %s (%s)" % (h["score"], h["label"]) if "score" in h else "grade %s" % h["grade"]))
    if cards["status"] == "not_connected":
        lines += ["", "Cards aren't connected. Is Brady's analysis/ folder in the repo next to dashboard/?"]
    return "\n".join(lines)
