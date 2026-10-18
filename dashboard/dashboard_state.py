"""
dashboard_state.py: everything the dashboard shows, in one place (no web code).

app.py asks build_state() for the current alerts, devices and health score, and calls
set_device_name() / skip_device() when a household names a device.

Cards, devices and health come from Brady's analysis service through analysis_bridge.py.
If that isn't connected (or breaks), this module falls back to basic alerts built straight
from Suricata's eve.json and the Pi's ARP table, so the dashboard still works.

Only Python's standard library is used here.
"""

import json
import os
import re
import subprocess
import threading
from datetime import datetime, timedelta, timezone

import analysis_bridge as bridge
import vendors

HERE = os.path.dirname(os.path.abspath(__file__))
NAMES_PATH = os.path.join(HERE, "device_names.json")
ACKS_PATH = os.path.join(HERE, "acknowledged.json")  # "Got it" on basic alerts: id -> {"at", "card"}
LOCK = threading.Lock()

WINDOW = timedelta(hours=24)  # how far back built-in alerts are shown
HISTORY_WINDOW = timedelta(days=bridge.HISTORY_DAYS)  # how long handled alerts stay on the History page
DEMO_START = datetime.now(timezone.utc)  # demo alerts keep fixed times, so "Got it" sticks
MAX_NAME_LEN = 40
ALLOWED_ICONS = {
    "device-unknown", "device-tv", "device-gamepad-2", "device-mobile",
    "device-laptop", "speaker", "router",
}

# category -> (severity, what happened, next step)   [built-in fallback only]
# The next steps match analysis/translate/templates.py, so the dashboard's
# "How do I do that?" help (static/js/app.js) fits either source.
TEMPLATES = {
    "malicious_contact": (
        "high",
        "This device contacted a known bad server.",
        "Disconnect this device from your network, then run a virus scan and update its software.",
    ),
    "plaintext_credentials": (
        "high",
        "A device on your network sent a password in an unprotected way.",
        "Change that password, and only sign in to sites that show a padlock in the address bar.",
    ),
    "port_scan": (
        "medium",
        "Someone or something scanned your network from outside.",
        "Make sure your router's software is up to date and its remote management is turned off.",
    ),
    "other": (
        "low",
        "Unusual activity was flagged on your network.",
        "Nothing to do right now. Check back if it keeps happening.",
    ),
}
SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}
SEVERITY_PENALTY = {"high": 25, "medium": 10, "low": 3}  # same as analysis/health_score.py

parse_ts = bridge.parse_ts


# ---------------------------------------------------------------------------
# Built-in fallback: Suricata alerts
# ---------------------------------------------------------------------------

def classify(signature):
    """Keyword heuristic: Suricata signature text -> one of our categories."""
    s = (signature or "").upper()
    if "SCAN" in s:
        return "port_scan"
    if any(k in s for k in ("BASIC AUTH", "CLEARTEXT", "PLAINTEXT", "PASSWORD", "CREDENTIAL")):
        return "plaintext_credentials"
    if any(k in s for k in ("MALWARE", "CNC", "C2 ", "TROJAN", "BOTNET",
                            "COMPROMISED", "PHISH", "ET DROP")):
        return "malicious_contact"
    return "other"


def read_eve(path, max_lines=3000, max_bytes=4_000_000):
    """Read the tail of eve.json (one JSON object per line)."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            f.seek(max(0, size - max_bytes))
            data = f.read()
    except OSError:
        return None  # file missing / unreadable
    lines = data.splitlines()
    if size > max_bytes:
        lines = lines[1:]  # first line is probably cut in half
    events = []
    for line in lines[-max_lines:]:
        try:
            events.append(json.loads(line))
        except ValueError:
            continue
    return events


def builtin_alerts(events, devices, now):
    """Group raw Suricata alerts by (device, category) into basic cards."""
    by_ip = {d["ip"]: d for d in devices if d.get("ip")}
    groups = {}
    for e in events:
        if e.get("event_type") != "alert":
            continue
        ts = parse_ts(e.get("timestamp"))
        if ts is None or now - ts > WINDOW:
            continue
        category = classify(e.get("alert", {}).get("signature"))
        dev = by_ip.get(e.get("src_ip")) or by_ip.get(e.get("dest_ip"))
        key = ((dev or {}).get("mac") or "network", category)
        g = groups.setdefault(key, {"count": 0, "latest": ts, "dev": dev, "category": category})
        g["count"] += 1
        if ts > g["latest"]:
            g["latest"] = ts

    alerts = []
    for (mac, category), g in groups.items():
        severity, what, action = TEMPLATES[category]
        dev = g["dev"]
        alerts.append({
            "id": "%s-%s" % (mac, category),
            "category": category,
            "severity": severity,
            "mac": dev["mac"] if dev else None,
            "device_name": dev["name"] if dev else "Your network",
            "device_icon": dev["icon"] if dev else "router",
            "description": what,
            "count": g["count"],
            "action": action,
            "timestamp": g["latest"].isoformat(),
        })
    return alerts


# Devices and household names
def get_neighbors():
    """Devices the Pi has seen on the LAN, from the Linux neighbor (ARP) table."""
    try:
        out = subprocess.run(["ip", "neigh", "show"], capture_output=True,
                             text=True, timeout=3).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    found = {}
    for line in out.splitlines():
        m = re.match(r"^(\S+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]{17})\s+(\S+)", line)
        if m and m.group(3) not in ("FAILED", "INCOMPLETE"):
            found[m.group(2).lower()] = {"mac": m.group(2).lower(), "ip": m.group(1)}
    return list(found.values())


def load_names():
    with LOCK:
        try:
            with open(NAMES_PATH) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}


def save_names(names):
    with LOCK:
        tmp = NAMES_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(names, f, indent=2)
        os.replace(tmp, NAMES_PATH)


def load_acks():
    with LOCK:
        try:
            with open(ACKS_PATH) as f:
                acks = json.load(f)
        except (OSError, ValueError):
            return {}
    # Early versions saved just the time.
    return {k: (v if isinstance(v, dict) else {"at": v}) for k, v in acks.items()}


def save_acks(acks):
    cutoff = datetime.now(timezone.utc) - HISTORY_WINDOW
    acks = {k: v for k, v in acks.items() if (parse_ts(v.get("at")) or cutoff) > cutoff}
    with LOCK:
        tmp = ACKS_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(acks, f, indent=2)
        os.replace(tmp, ACKS_PATH)


def _acked_since(entry, card):
    """True if "Got it" was pressed on this basic alert after it last happened."""
    at = parse_ts((entry or {}).get("at"))
    return at is not None and at >= datetime.fromisoformat(card["timestamp"])


def apply_local_names(devices, names, keep_named=False):
    """Names saved in the dashboard win over the built-in sources. With keep_named=True
    (the analysis service owns names) they only fill in icons, and names for devices
    the service has no name for."""
    for d in devices:
        entry = names.get(d["mac"])
        if entry and entry.get("name"):
            skipped = bool(entry.get("skipped"))
            if not (keep_named and d["named"]):
                d["name"] = entry["name"]
                d["named"] = not skipped
            d["icon"] = entry.get("icon", "device-unknown")
            d["skipped"] = skipped
    return devices


def builtin_devices(neighbors):
    devices = []
    for n in neighbors:
        if n.get("default_name"):
            name, icon, named = n["default_name"], n.get("default_icon", "device-unknown"), True
        else:
            name, icon, named = "Unrecognized device", "device-unknown", False
        devices.append({"mac": n["mac"], "ip": n["ip"], "name": name, "icon": icon,
                        "named": named, "skipped": False, "vendor": n.get("vendor"), "hostname": None})
    return devices


def add_device_hints(devices):
    """Clues that help a household recognize a device: who made it, and whether it uses
    a private (randomized) address, as phones and laptops do."""
    for d in devices:
        d["vendor"] = d.get("vendor") or vendors.vendor_for(d["mac"])
        d["private_address"] = vendors.is_private(d["mac"])
        d.setdefault("hostname", None)
    return devices


# Demo data (goes through the same built-in code path as real data)

def demo_neighbors():
    return [
        {"mac": "aa:bb:cc:00:00:01", "ip": "192.168.1.1", "default_name": "Router", "default_icon": "router", "vendor": "TP-Link"},
        {"mac": "aa:bb:cc:00:00:02", "ip": "192.168.1.23", "default_name": "Kitchen smart speaker", "default_icon": "speaker", "vendor": "Amazon"},
        {"mac": "aa:bb:cc:00:00:03", "ip": "192.168.1.31", "default_name": "Living room TV", "default_icon": "device-tv", "vendor": "Samsung"},
        {"mac": "aa:bb:cc:00:00:04", "ip": "192.168.1.47", "vendor": "Nintendo"},  # unnamed -> triggers first-connect flow
    ]


def demo_events():
    now = DEMO_START

    def ev(minutes_ago, src, dest, signature):
        ts = (now - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")
        return {"timestamp": ts, "event_type": "alert", "src_ip": src, "dest_ip": dest,
                "alert": {"signature": signature}}

    return [
        ev(2, "192.168.1.23", "198.51.100.7", "ET MALWARE Observed Malicious Host Contact"),
        ev(9, "192.168.1.23", "198.51.100.7", "ET MALWARE Observed Malicious Host Contact"),
        ev(14, "203.0.113.9", "192.168.1.1", "ET SCAN Suspicious inbound to multiple ports"),
    ]


# ---------------------------------------------------------------------------
# State: what the dashboard displays
# ---------------------------------------------------------------------------

def grade_for(score):
    for floor, grade in ((97, "A+"), (93, "A"), (90, "A-"), (87, "B+"), (83, "B"),
                         (80, "B-"), (77, "C+"), (73, "C"), (70, "C-"), (60, "D")):
        if score >= floor:
            return grade
    return "F"


def build_state(demo, eve_path):
    now = datetime.now(timezone.utc)
    names = load_names()
    errors = []

    # Asks the analysis service for cards, devices and health. In demo mode it isn't used.
    if demo:
        cards_res = devs_res = health_res = {"status": "demo", "error": None}
    else:
        cards_res, devs_res, health_res = bridge.load_cards(), bridge.load_devices(), bridge.load_health()
    status = {}
    for key, res in (("cards", cards_res), ("devices", devs_res), ("health", health_res)):
        status[key] = res["status"]
        if res["status"] == "error":
            errors.append("%s: %s" % (key, res["error"]))

    # Devices: analysis service if connected, otherwise the Pi's ARP table.
    devices_from_service = devs_res["status"] == "ok"
    if devices_from_service:
        devices = devs_res["devices"]
    else:
        devices = builtin_devices(demo_neighbors() if demo else get_neighbors())
    devices = apply_local_names(devices, names, keep_named=devices_from_service)
    add_device_hints(devices)

    # Alerts: analysis service cards if connected, otherwise built from eve.json.
    # "handled" is the History page: cards the household pressed "Got it" on.
    eve_ok = True
    if cards_res["status"] == "ok":
        alerts, alert_source = cards_res["cards"], "analysis"
        handled_res = bridge.load_handled()
        handled = handled_res["cards"] if handled_res["status"] == "ok" else []
    else:
        events = demo_events() if demo else read_eve(eve_path)
        eve_ok = events is not None
        alerts, alert_source = builtin_alerts(events or [], devices, now), "suricata"
        # Basic alerts only cover the last 24 hours of eve.json, so History shows the copy
        # saved when "Got it" was pressed. An alert that happens again after that comes back.
        acks = load_acks()
        alerts = [a for a in alerts if not _acked_since(acks.get(a["id"]), a)]
        handled = [dict(e["card"]) for e in acks.values() if e.get("card")]
    handled = [a for a in handled if now - datetime.fromisoformat(a["timestamp"]) <= HISTORY_WINDOW]

    # Names given in the dashboard show up on cards that carry the device's MAC.
    for a in alerts + handled:
        entry = names.get(a.get("mac") or "")
        if entry and entry.get("name") and not entry.get("skipped"):
            if alert_source != "analysis" or a["device_name"].lower().startswith("unrecognized"):
                a["device_name"] = entry["name"]
            a["device_icon"] = entry.get("icon", a["device_icon"])

    alerts.sort(key=lambda a: (SEVERITY_RANK[a["severity"]],
                               -datetime.fromisoformat(a["timestamp"]).timestamp()))
    handled.sort(key=lambda a: -datetime.fromisoformat(a["timestamp"]).timestamp())

    if health_res["status"] == "ok":
        health = health_res["health"]
    else:
        score = max(0, 100 - sum(SEVERITY_PENALTY[a["severity"]] for a in alerts))
        health = {"score": score, "note": "Based on the last 24 hours"}
    if health.get("score") is not None and not health.get("grade"):
        health["grade"] = grade_for(health["score"])  # the dashboard shows a letter grade either way

    return {
        "source": "demo" if demo else "pi",
        "alert_source": alert_source,
        "can_acknowledge": True,
        "eve_readable": True if demo else eve_ok,
        "analysis": {"status": status, "error": ("; ".join(errors)[:300] or None)},
        "generated_at": now.isoformat(),
        "alerts": alerts,
        "handled": handled,
        "devices": devices,
        "health": health,
    }


# Naming a device (called by the web routes)
MAC_RE = re.compile(r"^[0-9a-fA-F:]{17}$")


def valid_mac(mac):
    return bool(MAC_RE.match(mac or ""))


def set_device_name(mac, name, icon):
    """Save a household's name and icon for a device. Returns (saved, error_message)."""
    name = str(name or "").strip()
    if not name:
        return None, "Enter a name first"
    if len(name) > MAX_NAME_LEN:
        return None, "Keep the name under %d characters" % MAX_NAME_LEN
    if icon not in ALLOWED_ICONS:
        icon = "device-unknown"
    mac = mac.lower()
    names = load_names()
    names[mac] = {"name": name, "icon": icon}
    save_names(names)
    try:  # let the analysis service update its own inventory too
        bridge.on_device_named(mac, name, icon)
    except Exception as e:
        print("on_device_named failed: %s" % e)
    return names[mac], None


def set_acknowledged(alert_id, acknowledged, demo, eve_path):
    """"Got it" (acknowledged=True) or "Not fixed yet" (False) on a card.
    Returns False if there's no such card."""
    if not demo and bridge.load_cards()["status"] == "ok":
        if acknowledged:
            return bool(bridge.acknowledge_card(alert_id))
        return bool(bridge.unacknowledge_card(alert_id))
    acks = load_acks()
    if acknowledged:
        card = next((a for a in build_state(demo, eve_path)["alerts"] if a["id"] == alert_id), None)
        if card is None:
            return alert_id in acks  # already handled (e.g. a double click), or no such card
        acks[alert_id] = {"at": datetime.now(timezone.utc).isoformat(), "card": card}
    elif acks.pop(alert_id, None) is None:
        return False
    save_acks(acks)
    return True


def skip_device(mac):
    """The household chose not to name a device now. It can still be named later."""
    mac = mac.lower()
    names = load_names()
    existing = names.get(mac, {})
    names[mac] = {"name": existing.get("name", "Unrecognized device"),
                  "icon": existing.get("icon", "device-unknown"), "skipped": True}
    save_names(names)
    return names[mac]
